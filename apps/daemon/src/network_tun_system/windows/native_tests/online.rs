//! Single hosted VM integration of real online authority, the original native
//! Wintun/receipt, and the unchanged production packet loop over pinned mTLS.
//! The local HTTP fixture cannot qualify production HTTPS login restoration or
//! the full CLI; independent-device acceptance remains a separate gate.
use super::*;
use crate::network_packet_runtime::{self, OwnerGuard};
use nestlink_app_core::ManagementLoginStore;
use nestlink_protocol::{network::GrantClaims, network_access::NetworkAccessStart};
use nestlink_sdk::{
    Sdk, SdkError,
    network::{packet_access::OnlinePacketAccess, routed::PinnedNetworkSpace},
};
use nestlink_transport_quic::packet_codec::{DirectPacketEndpoint, PacketAssembler, encode_direct};
pub(super) mod cli;
mod fixture;
use fixture::Fixture;

struct Guard<'a> {
    os: &'a OwnerOs,
    plan: &'a TunPlan,
    state: &'a TunState,
    directory: &'a Path,
    login: [u8; 32],
}
impl OwnerGuard for Guard<'_> {
    fn check_local(&self) -> Result {
        if nestlink_local_ipc::maintenance::requested(self.directory)?
            || crate::space_dns::session_snapshot(self.directory)? != self.login
        {
            return Err(io::Error::other("original hosted login or installation changed").into());
        }
        self.plan.validate(true)
    }
    fn check(&self) -> network_packet_runtime::GuardFuture<'_> {
        Box::pin(async move {
            if self.os.inspect(self.plan).await?.as_ref() != Some(self.state) {
                return Err(
                    io::Error::other("original hosted full OS/receipt snapshot changed").into(),
                );
            }
            Ok(())
        })
    }
}
pub(super) async fn ordinary(case: &Path, plan_path: &Path, receipt: &Path) -> Result {
    nestlink_privileged::windows::require_normal_user_process()?;
    let f = Fixture::new(None).await?;
    nestlink_platform_security::create_private(&f.directory.join("remember-login.json"), b"true")?;
    let store = crate::session_store::SessionStore::new(f.directory.clone());
    store.save(
        &f.source
            .export_login()?
            .ok_or_else(|| io::Error::other("fixture login missing"))?,
    )?;
    let login = crate::space_dns::session_snapshot(&f.directory)?;
    let pin = PinnedNetworkSpace::new(f.space.clone(), f.authority)?;
    let mut local = OnlinePacketAccess::start(
        &f.source,
        &pin,
        &f.source_device,
        &f.view.access.grant_id,
        f.approved,
        nestlink_auth::random_id(),
    )
    .await?;
    let mut remote = OnlinePacketAccess::start(
        &f.target,
        &pin,
        &f.target_device,
        &f.view.access.grant_id,
        f.approved,
        nestlink_auth::random_id(),
    )
    .await?;
    // Both original endpoint claims are durable, even with a different owner
    // ID. Never manufacture another in-memory packet budget after this denial.
    for (sdk, device) in [(&f.source, &f.source_device), (&f.target, &f.target_device)] {
        let repeated = sdk
            .start_network_access(
                &f.space,
                &f.view.access.grant_id,
                NetworkAccessStart {
                    installation_id: device.device_id.clone(),
                    owner_id: nestlink_auth::random_id(),
                },
            )
            .await;
        assert!(
            matches!(&repeated,Err(SdkError::Api(status,_)) if status.as_u16()==403),
            "the original consumed endpoint must retain the production Forbidden contract: {repeated:?}"
        );
    }
    let interface = nestlink_platform_network::path::NetworkPathManager::interfaces()?
        .into_iter()
        .find(|row| row.up && row.default_route && row.addresses.iter().any(IpAddr::is_ipv4))
        .ok_or_else(|| io::Error::other("hosted original nonloopback underlay missing"))?;
    let bind = SocketAddr::new(
        *interface
            .addresses
            .iter()
            .find(|ip| ip.is_ipv4())
            .ok_or_else(|| io::Error::other("underlay IPv4 missing"))?,
        0,
    );
    let path = nestlink_platform_network::path::NetworkPathManager::new(
        nestlink_platform_network::path::RoutePolicy::Interface(interface.index),
    )?;
    let mut endpoint = DirectPacketEndpoint::bind(
        bind,
        &f.source_device.identity,
        local.remote_peer(),
        path.clone(),
    )?;
    let mut peer =
        DirectPacketEndpoint::bind(bind, &f.target_device.identity, remote.remote_peer(), path)?;
    let local_underlay = endpoint.local_addr();
    let remote_underlay = peer.local_addr();
    let claims = GrantClaims::decode_canonical(
        &nestlink_sdk::network_management::decode_network_grant(&f.view.access)?.claims,
    )?;
    let now = system_wall_ms()?;
    let plan = TunPlan {
        schema_version: 2,
        owner_id: local.owner_id().into(),
        space_id: f.space.clone(),
        process: process_identity(std::process::id()).await?,
        principal: plan::HostPrincipal::current()?,
        created_at_ms: now,
        expires_at_ms: claims
            .scope()
            .expires_at_ms
            .min(now + u64::try_from(local.remaining_lifetime().as_millis())?),
        deployment_id: claims.scope().deployment_id.clone(),
        authority_key: f.authority,
        local_peer: nestlink_protocol::network::PeerId(f.source_device.identity.fingerprint()),
        remote_peer: local.remote_peer(),
        local_hosts: local.local_hosts(),
        remote_hosts: local.remote_hosts(),
        approved_digest: f.approved,
        policy_epoch: claims.scope().policy_epoch,
        signed_claims: f.view.access.claims.clone(),
        signature: f.view.access.signature.clone(),
    };
    assert!(!plan.remote_hosts.contains(&bind.ip()));
    nestlink_platform_security::new_private_directory(
        plan_path
            .parent()
            .ok_or_else(|| io::Error::other("plan parent missing"))?,
    )?;
    plan.save_new(plan_path)?;
    std::fs::write(
        case.join("plan-ready.json"),
        serde_json::to_vec(
            &serde_json::json!({"plan":plan,"identity":plan.windows_binding().await?.process}),
        )?,
    )?;
    let os = OwnerOs::new(receipt.to_path_buf())?;
    let state = tokio::time::timeout(Duration::from_secs(15), async {
        let mut refreshed = Instant::now();
        loop {
            plan.validate(true)?;
            if refreshed.elapsed() >= Duration::from_secs(1) {
                local.refresh(&f.source).await?;
                remote.refresh(&f.target).await?;
                refreshed = Instant::now();
            }
            if let Some(state) = os.inspect(&plan).await? {
                return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(state);
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await??;
    let mut device = os.adopt(&plan, &state).await?;
    let guard = Guard {
        os: &os,
        plan: &plan,
        state: &state,
        directory: &f.directory,
        login,
    };
    let result=async{
        local.refresh(&f.source).await?;remote.refresh(&f.target).await?;
        tokio::try_join!(
            network_packet_runtime::establish(&mut endpoint,Some(remote_underlay),&f.source,&mut local,&guard),
            peer.establish(None,remote.business_digest(),remote.transport_group(),Instant::now()+Duration::from_secs(10))
        )?;
        let runtime=network_packet_runtime::packet_loop(&device,&mut endpoint,&f.source,&mut local,&guard);
        tokio::pin!(runtime);
        let revocation=std::sync::OnceLock::new();
        let probe=probe(case,&f,&plan,&state,&mut peer,&mut remote,&revocation);
        tokio::pin!(probe);
        let (revoked,outcome)=tokio::select!{
            outcome=&mut runtime=>{
                let started=*revocation.get().ok_or_else(||io::Error::other(format!("original production loop ended before online revocation: {outcome:?}")))?;
                // The production poll may observe the committed revocation
                // before the issuing HTTP response/readback has returned.
                // Still require that exact issuing call and readback to pass.
                let revoked=tokio::time::timeout_at(started+Duration::from_secs(5),&mut probe).await??;
                (revoked,outcome)
            },
            outcome=&mut probe=>{
                let revoked=outcome?;
                (revoked,tokio::time::timeout_at(revoked+Duration::from_secs(5),&mut runtime).await?)
            },
        };
        assert!(matches!(outcome.as_ref().err().and_then(|error|error.downcast_ref::<SdkError>()),Some(SdkError::Api(status,_)) if status.as_u16()==403),"production loop must stop on the actual online revocation response: {outcome:?}");
        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(revoked)
    }.await;
    local.stop();
    remote.stop();
    let cleanup = Instant::now();
    device.shutdown().await?;
    drop(device);
    super::super::super::owner::release_plan_with_os(&os, &plan, plan_path).await?;
    endpoint
        .close_and_wait(Instant::now() + Duration::from_secs(5))
        .await?;
    peer.close_and_wait(Instant::now() + Duration::from_secs(5))
        .await?;
    let revoked = result?;
    assert_eq!(
        local.spent_bytes(),
        5120,
        "the original ordinary budget must account for both complete requests and replies"
    );
    assert!(
        revoked.elapsed() < Duration::from_secs(5),
        "online revocation must physically release the original TUN and both packet endpoints within five seconds"
    );
    assert!(
        std::net::UdpSocket::bind(local_underlay).is_ok(),
        "original ordinary physical UDP endpoint still owned"
    );
    assert!(
        std::net::UdpSocket::bind(remote_underlay).is_ok(),
        "original peer physical UDP endpoint still owned"
    );
    std::fs::write(
        case.join("ordinary-stopped.json"),
        serde_json::to_vec(&serde_json::json!({
            "normal_cleanup_ms":cleanup.elapsed().as_millis(),"kernel_absent":os.absent(&plan).await?,
            "revocation_to_physical_cleanup_ms":revoked.elapsed().as_millis(),"online_http_403_observed":true,
            "original_udp_endpoints_rebound":true,"same_host_only":true,"production_cli_validated":false,
        "production_https_login_resume_validated":false,"one_use_replay_denials":2,"local_original_spent_bytes":local.spent_bytes(),
            "underlay":{"index":interface.index,"luid":interface.luid,"name":interface.name,"local":local_underlay,"remote":remote_underlay}
        }))?,
    )?;
    Ok(())
}

async fn probe(
    case: &Path,
    f: &Fixture,
    plan: &TunPlan,
    state: &TunState,
    peer: &mut DirectPacketEndpoint,
    access: &mut OnlinePacketAccess,
    revocation: &std::sync::OnceLock<Instant>,
) -> Result<Instant> {
    let mut assembler = PacketAssembler::new(
        access.business_digest(),
        access.wire_direction().reverse(),
        1280,
    )?;
    for family in 0..2 {
        let socket = tokio::net::UdpSocket::bind((plan.local_hosts[family], 0)).await?;
        let payload = vec![73; if family == 0 { 1252 } else { 1232 }];
        let target = SocketAddr::new(plan.remote_hosts[family], 443);
        assert_eq!(socket.send_to(&payload, target).await?, payload.len());
        let request = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let fragment = peer.connection()?.read_datagram().await?;
                if let Some(packet) = assembler.insert(&fragment, std::time::Instant::now())? {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(packet);
                }
            }
        })
        .await??;
        assert_eq!(
            request.len(),
            1280,
            "the original NRD1 carrier must reassemble the full native IP packet"
        );
        let admission = access.admit_remote(&request)?;
        assert!(!admission.reply);
        let sliced = etherparse::SlicedPacket::from_ip(&request)?;
        let Some(etherparse::TransportSlice::Udp(udp)) = sliced.transport else {
            return Err(io::Error::other("original packet was not UDP").into());
        };
        assert_eq!(udp.source_port(), socket.local_addr()?.port());
        assert_eq!(udp.destination_port(), 443);
        assert_eq!(udp.payload(), payload);
        let mut reply = Vec::new();
        match (plan.remote_hosts[family], plan.local_hosts[family]) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                etherparse::PacketBuilder::ipv4(source.octets(), destination.octets(), 64)
                    .udp(443, socket.local_addr()?.port())
                    .write(&mut reply, &payload)?
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                etherparse::PacketBuilder::ipv6(source.octets(), destination.octets(), 64)
                    .udp(443, socket.local_addr()?.port())
                    .write(&mut reply, &payload)?
            }
            _ => return Err(io::Error::other("online host family mismatch").into()),
        }
        assert!(access.admit_local(&reply)?.reply);
        for fragment in encode_direct(
            access.business_digest(),
            access.wire_direction(),
            family as u64 + 1,
            &reply,
        )? {
            peer.connection()?.send_datagram(fragment.into())?;
        }
        let mut received = [0; 1280];
        let (count, source) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut received)).await??;
        assert_eq!(source, target);
        assert_eq!(&received[..count], payload);
    }
    assert_eq!(
        access.spent_bytes(),
        5120,
        "the original remote budget must account for two complete requests and replies"
    );
    std::fs::write(
        case.join("packets-ready.json"),
        serde_json::to_vec(&serde_json::json!({
            "receipt":state,"ipv4_packet_bytes":1280,"ipv6_packet_bytes":1280,"kernel_udp_replies":2,
            "real_http_sqlite_authority":true,"original_production_packet_loop":true,"pinned_mtls_quic":true,
            "remote_original_spent_bytes":access.spent_bytes(),"one_use_replay_denials":2,"same_host_only":true,
            "production_cli_validated":plan.process.pid()!=std::process::id(),
            "production_https_login_resume_validated":plan.process.pid()!=std::process::id(),
            "application_pid":std::process::id(),"owner_pid":plan.process.pid()
        }))?,
    )?;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    let mut refreshed = Instant::now();
    while !case.join("stop.json").try_exists()? {
        tick.tick().await;
        if refreshed.elapsed() >= Duration::from_secs(1) {
            access.refresh(&f.target).await?;
            peer.validate_underlay()?;
            refreshed = Instant::now();
        }
    }
    let revision = f.target.space_details(&f.space).await?.space.revision;
    let revoked = Instant::now();
    assert!(revocation.set(revoked).is_ok());
    f.target
        .revoke_network_access(&f.space, &f.view.access.grant_id, revision)
        .await?;
    assert!(
        matches!(f.target.network_access(&f.space,&f.view.access.grant_id).await,Err(SdkError::Api(status,_)) if status.as_u16()==403)
    );
    Ok(revoked)
}
