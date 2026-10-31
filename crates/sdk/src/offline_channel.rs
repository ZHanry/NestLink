//! Common original-process possession proof for consumed offline businesses.
//! Callers first authenticate the direct TLS certificate and exact ALPN.
use crate::{DeviceIdentity,SdkError};
use nestlink_identity::{offline::offline_channel_transcript,verify_device_action};
use nestlink_protocol::offline::{OfflineDirectTransport,OfflineGrantBundleClaims,channel::OfflineChannelBinding};
use nestlink_transport_quic::service::{read_message,write_message};
use serde::{Serialize,Deserialize};
use tokio::io::{AsyncRead,AsyncWrite};

pub(crate) trait Owner {
    fn claims(&self)->Result<OfflineGrantBundleClaims,SdkError>;
    fn digest(&self)->Result<[u8;32],SdkError>;
    fn sign(&self,wall:u64,binding:&OfflineChannelBinding)->Result<Vec<u8>,SdkError>;
    fn authenticate(&self,wall:u64,transport:OfflineDirectTransport,peer:&[u8;32])->Result<(),SdkError>;
}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {bundle_id:String,draft_digest:[u8;32],source_nonce:[u8;32]}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {signature:Vec<u8>,process_signature:Vec<u8>}
#[derive(Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {binding:OfflineChannelBinding,proof:Proof}
fn wall()->Result<u64,SdkError> {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(std::io::Error::other)?
        .as_millis().try_into().map_err(|_|SdkError::Invalid)
}
fn verify(claims:&OfflineGrantBundleClaims,hash:[u8;32],binding:&OfflineChannelBinding,endpoint:u8,proof:&Proof)->Result<(),SdkError> {
    let transcript=offline_channel_transcript(claims,hash,binding,endpoint)?;
    let member=&claims.members[usize::from(endpoint)];
    verify_device_action(&transcript,&member.public_key,&proof.signature)?;
    verify_device_action(&transcript,&member.process_nonce,&proof.process_signature)?;Ok(())
}
fn proof(owner:&impl Owner,identity:&DeviceIdentity,claims:&OfflineGrantBundleClaims,hash:[u8;32],binding:&OfflineChannelBinding,endpoint:u8)->Result<Proof,SdkError> {
    Ok(Proof {signature:identity.identity.sign_action(&offline_channel_transcript(claims,hash,binding,endpoint)?)?,process_signature:owner.sign(wall()?,binding)?})
}
pub(crate) async fn prove<R:AsyncRead+Unpin,W:AsyncWrite+Unpin>(
    owner:&impl Owner,identity:&DeviceIdentity,read:&mut R,write:&mut W,
    endpoint:u8,transport:OfflineDirectTransport,peer:&[u8;32],
)->Result<(),SdkError> {
    let claims=owner.claims()?;let hash=owner.digest()?;
    if endpoint>1 || claims.members[usize::from(endpoint)].installation_id!=identity.device_id
        || claims.members[usize::from(endpoint)].public_key!=identity.identity.public_key()
        || claims.members[1-usize::from(endpoint)].public_key!=*peer {return Err(SdkError::Trust);}
    if endpoint==0 {
        let source_nonce=nestlink_auth::random_bytes::<32>();
        write_message(write,&Hello{bundle_id:claims.bundle_id.clone(),draft_digest:hash,source_nonce}).await?;
        let challenge:Challenge=read_message(read).await?;
        if challenge.binding.source_nonce!=source_nonce {return Err(SdkError::Trust);}
        verify(&claims,hash,&challenge.binding,1,&challenge.proof)?;
        write_message(write,&proof(owner,identity,&claims,hash,&challenge.binding,0)?).await?;
        let ready:[u8;32]=read_message(read).await?;
        if ready!=hash {return Err(SdkError::Trust);}
    } else {
        let hello:Hello=read_message(read).await?;
        if hello.bundle_id!=claims.bundle_id || hello.draft_digest!=hash || hello.source_nonce==[0;32] {return Err(SdkError::Trust);}
        let binding=OfflineChannelBinding{bundle_id:claims.bundle_id.clone(),draft_digest:hash,source_nonce:hello.source_nonce,host_nonce:nestlink_auth::random_bytes::<32>()};
        write_message(write,&Challenge{binding:binding.clone(),proof:proof(owner,identity,&claims,hash,&binding,1)?}).await?;
        let received:Proof=read_message(read).await?;verify(&claims,hash,&binding,0,&received)?;
        owner.authenticate(wall()?,transport,peer)?;
        write_message(write,&hash).await?;
        return Ok(());
    }
    owner.authenticate(wall()?,transport,peer)
}
