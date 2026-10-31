//! Explicit per-client management and protected standard-client export.
//! No action here creates a WG interface or an original packet owner.
mod tools;
#[cfg(test)]
mod tests;
use base64::{Engine,engine::general_purpose::{STANDARD,URL_SAFE_NO_PAD}};
use nestlink_protocol::{network::GrantClaims,wireguard::management::*};
use nestlink_sdk::network::{routed::PinnedNetworkSpace,wireguard::OnlineWireGuardClient};
use std::{io,net::SocketAddr,path::{Path,PathBuf}};
use zeroize::Zeroizing;
type Result<T=()> = std::result::Result<T,Box<dyn std::error::Error+Send+Sync>>;

#[derive(clap::Args)]
pub(crate) struct WireGuardArgs {
    #[command(subcommand)]
    action:Action,
}
#[derive(clap::Args)]
struct Account {
    #[arg(long)]
    state_dir:PathBuf,
    #[arg(long)]
    space:String,
    /// Independently provisioned space authority, URL-safe unpadded base64.
    #[arg(long)]
    authority:String,
}
#[derive(clap::Subcommand)]
enum Action {
    /// Generate a fresh independent standard-client key with installed wg tools.
    GenerateKey {
        #[arg(long)]
        private_key:PathBuf,
        #[arg(long)]
        public_key:PathBuf,
    },
    /// Bind one client key to an existing destination-approved packet business.
    Issue {
        #[command(flatten)]
        account:Account,
        /// Exact owner-private WireGuardClientBindingRequest for local review.
        #[arg(long)]
        request:PathBuf,
        /// Fresh private output with the exact signed binding and original graph.
        #[arg(long)]
        output:PathBuf,
    },
    /// Review one current client's key, exact address, gateway and finite budget.
    Show {
        #[command(flatten)]
        account:Account,
        #[arg(long)]
        binding:String,
    },
    /// Revoke a client and all its original packet graph IDs.
    Revoke {
        #[command(flatten)]
        account:Account,
        #[arg(long)]
        binding:String,
        #[arg(long)]
        expected_revision:u64,
        #[arg(long)]
        expected_client_revision:u64,
    },
    /// Export one protected standard-client config and optional secret QR SVG.
    ExportConfig {
        #[command(flatten)]
        account:Account,
        #[arg(long)]
        binding:String,
        #[arg(long)]
        private_key:PathBuf,
        /// Exact independently approved kernel portal WireGuard public key.
        #[arg(long)]
        server_public_key:String,
        #[arg(long)]
        endpoint:SocketAddr,
        #[arg(long)]
        approve_binding_digest:String,
        #[arg(long)]
        approve_access_digest:String,
        #[arg(long)]
        output:PathBuf,
        /// Includes the client private key; stored only in a fresh private file.
        #[arg(long)]
        qr_svg:Option<PathBuf>,
        #[arg(long,required=true)]
        approve_private_key_export:bool,
    },
}
pub(crate) async fn run(args:WireGuardArgs)->Result {
    if rustix::process::geteuid().as_raw()==0 {return Err(io::Error::other("wireguard client management must run as the original ordinary user").into());}
    if let Action::GenerateKey{private_key,public_key}=args.action {
        fresh(&private_key)?;fresh(&public_key)?;
        if private_key==public_key {return Err(io::Error::other("client private and public key paths must differ").into());}
        let secret=tools::run("wg",&["genkey"],&[],128).await?;
        let private=Zeroizing::new(key(std::str::from_utf8(&secret)?.trim_end_matches('\n'))?);
        let public=public_key_for(&private).await?;
        let encoded=Zeroizing::new(format!("{}\n",STANDARD.encode(&*private)));
        save(&private_key,encoded.as_bytes())?;save(&public_key,format!("{}\n",STANDARD.encode(public)).as_bytes())?;
        println!("Independent WireGuard client public key: {}",STANDARD.encode(public));
        println!("Client private key saved to {}",private_key.display());
        return Ok(());
    }
    let account=match &args.action {Action::Issue{account,..}|Action::Show{account,..}|Action::Revoke{account,..}|Action::ExportConfig{account,..}=>account,Action::GenerateKey{..}=>unreachable!()};
    let pin=PinnedNetworkSpace::new(account.space.clone(),digest(&account.authority)?)?;
    let installation=nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
    let directory=installation.state_directory(&account.state_dir)?;
    nestlink_platform_security::check_private_directory(&directory)?;
    let _runtime=nestlink_local_ipc::HeadlessRuntimeLease::acquire(&directory)?;
    let sdk=crate::session_store::SessionStore::new(directory.clone()).restore().await.ok_or_else(||io::Error::other("sign in and enable protected login recovery before managing a WireGuard client"))?;
    let login=crate::space_dns::session_snapshot(&directory)?;
    let local=crate::identity(&directory)?;
    match args.action {
        Action::Issue{request,output,..}=>{
            fresh(&output)?;
            let request:WireGuardClientBindingRequest=serde_json::from_slice(&nestlink_platform_security::read_private(&request,16_384)?)?;
            let view=sdk.issue_wireguard_client_binding(pin.space_id(),&request).await?;
            let verified=OnlineWireGuardClient::inspect(&sdk,&pin,&local,&request.grant_id,&view)?;
            current(&directory,login)?;save(&output,&serde_json::to_vec(&view)?)?;
            summary(&verified,&view)?;
            println!("Exact original client binding saved to {}",output.display());
        },
        Action::Show{binding,..}=>{
            let view=sdk.wireguard_client_binding(pin.space_id(),&binding).await?;
            let verified=OnlineWireGuardClient::inspect(&sdk,&pin,&local,&binding,&view)?;
            current(&directory,login)?;summary(&verified,&view)?;
        },
        Action::Revoke{binding,expected_revision,expected_client_revision,..}=>{
            current(&directory,login)?;
            let policy=sdk.revoke_wireguard_client(pin.space_id(),&binding,&WireGuardClientRevoke{expected_revision,expected_client_revision}).await?;
            println!("WireGuard client and original packet graph revoked at policy revision {}",policy.revision);
        },
        Action::ExportConfig{binding,private_key,server_public_key,endpoint,approve_binding_digest,approve_access_digest,output,qr_svg,approve_private_key_export,..}=>{
            if !approve_private_key_export {return Err(io::Error::other("explicit private-key export approval required").into());}
            fresh(&output)?;if let Some(qr)=&qr_svg {fresh(qr)?;if qr==&output||qr==&private_key {return Err(io::Error::other("private key, config and QR paths must differ").into());}}
            if private_key==output {return Err(io::Error::other("private key and config paths must differ").into());}
            let secret=nestlink_platform_security::read_private(&private_key,128)?;
            let secret=Zeroizing::new(key(std::str::from_utf8(&secret)?.trim_end_matches('\n'))?);
            let public=public_key_for(&secret).await?;
            let view=sdk.wireguard_client_binding(pin.space_id(),&binding).await?;
            let verified=OnlineWireGuardClient::inspect(&sdk,&pin,&local,&binding,&view)?;
            if verified.digest()!=digest(&approve_binding_digest)?||verified.claims().access_digest!=digest(&approve_access_digest)?||verified.claims().client_public_key!=public {return Err(io::Error::other("approved binding, original business or independent client key differs").into());}
            let config=configuration(&verified,&secret,key(&server_public_key)?,endpoint)?;
            let qr=if qr_svg.is_some(){Some(tools::run("qrencode",&["-t","SVG","-l","M","-o","-"],config.as_bytes(),1_048_576).await?)}else{None};
            current(&directory,login)?;
            save(&output,config.as_bytes())?;
            if let (Some(path),Some(bytes))=(&qr_svg,&qr) {save(path,bytes)?;println!("Secret WireGuard QR SVG saved to {}",path.display());}
            summary(&verified,&view)?;
            println!("Protected standard WireGuard client configuration saved to {}",output.display());
        },
        Action::GenerateKey{..}=>unreachable!(),
    }
    Ok(())
}
fn current(directory:&Path,login:[u8;32])->Result {
    if nestlink_local_ipc::maintenance::requested(directory)?||crate::space_dns::session_snapshot(directory).ok()!=Some(login) {return Err(io::Error::other("original WireGuard management login changed or installation maintenance began").into());}
    Ok(())
}
fn fresh(path:&Path)->Result {
    if !path.is_absolute()||path.try_exists()? {return Err(io::Error::other("fresh absolute private output required").into());}
    nestlink_platform_security::check_private_directory(path.parent().ok_or_else(||io::Error::other("private output parent missing"))?)?;Ok(())
}
fn save(path:&Path,bytes:&[u8])->Result {fresh(path)?;nestlink_platform_security::create_private(path,bytes)?;std::fs::File::open(path.parent().ok_or_else(||io::Error::other("private output parent missing"))?)?.sync_all()?;Ok(())}
fn key(value:&str)->Result<[u8;32]> {
    let key:[u8;32]=STANDARD.decode(value)?.try_into().map_err(|_|io::Error::other("WireGuard key must contain exactly 32 bytes"))?;
    if key==[0;32]||STANDARD.encode(key)!=value {return Err(io::Error::other("canonical nonzero standard WireGuard key required").into());}Ok(key)
}
fn digest(value:&str)->Result<[u8;32]> {
    let value_bytes:[u8;32]=URL_SAFE_NO_PAD.decode(value)?.try_into().map_err(|_|io::Error::other("approved WireGuard digest must contain 32 bytes"))?;
    if value_bytes==[0;32]||URL_SAFE_NO_PAD.encode(value_bytes)!=value {return Err(io::Error::other("canonical nonzero authority/digest required").into());}Ok(value_bytes)
}
async fn public_key_for(secret:&[u8;32])->Result<[u8;32]> {
    let encoded=Zeroizing::new(format!("{}\n",STANDARD.encode(secret)));
    let public=tools::run("wg",&["pubkey"],encoded.as_bytes(),128).await?;
    key(std::str::from_utf8(&public)?.trim_end_matches('\n'))
}
fn summary(verified:&nestlink_identity::wireguard::VerifiedWireGuardClientBinding,view:&WireGuardClientBindingView)->Result {
    let claims=verified.claims();
    println!("{}",serde_json::to_string_pretty(&serde_json::json!({"client_id":claims.client_id,"client_revision":claims.client_revision,"client_public_key":STANDARD.encode(claims.client_public_key),"client_address":claims.client_address,"portal_node_id":claims.portal_node_id,"portal_runtime_generation":claims.portal_incarnation.runtime_generation,"binding_digest":URL_SAFE_NO_PAD.encode(verified.digest()),"original_business_digest":URL_SAFE_NO_PAD.encode(claims.access_digest),"committed_bytes":view.committed_bytes,"total_byte_ceiling":view.total_byte_ceiling,"expires_at_ms":claims.scope.expires_at_ms}))?);Ok(())
}
fn configuration(binding:&nestlink_identity::wireguard::VerifiedWireGuardClientBinding,private:&[u8;32],server:[u8;32],endpoint:SocketAddr)->Result<Zeroizing<String>> {
    if endpoint.port()==0||endpoint.ip().is_unspecified()||endpoint.ip().is_multicast()||server==[0;32] {return Err(io::Error::other("concrete original WireGuard endpoint and independent server key required").into());}
    let GrantClaims::NetworkAccess(access)=binding.access().claims() else {return Err(io::Error::other("original packet business required for config export").into());};
    let mut prefixes=Vec::new();
    for prefix in &access.destination_prefixes {
        prefix.validate()?;
        if prefix.prefix_len==0 {return Err(io::Error::other("WireGuard client export cannot install a default route").into());}
        let network=ipnet::IpNet::new(prefix.network,prefix.prefix_len)?;
        if network.contains(&endpoint.ip())||network.contains(&std::net::IpAddr::V4(binding.claims().client_address)) {return Err(io::Error::other("WireGuard destination routes would capture the physical endpoint or client source").into());}
        prefixes.push(format!("{}/{}",prefix.network,prefix.prefix_len));
    }
    if prefixes.is_empty()||prefixes.len()>2 {return Err(io::Error::other("bounded exact destination prefixes required").into());}
    Ok(Zeroizing::new(format!("[Interface]\nPrivateKey = {}\nAddress = {}/32\nMTU = 1280\n\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = 25\n",STANDARD.encode(private),binding.claims().client_address,STANDARD.encode(server),endpoint,prefixes.join(", "))))
}
