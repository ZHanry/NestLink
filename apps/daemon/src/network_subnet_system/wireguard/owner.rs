//! Standard-client ingress retains the original ordinary login, one-use packet
//! start and shared carrier/namespace lifetime. Only its kernel ingress differs.
use super::*;
use crate::{network_packet_runtime::WireGuardAuthority,network_subnet_system::owner::{SubnetArgs,Session,operate,pin}};
use nestlink_sdk::network::{routed::PinnedNetworkSpace,wireguard::OnlineWireGuardClient};
use nestlink_transport_quic::packet_codec::DirectPacketEndpoint;

#[derive(clap::Args)]
pub(crate) struct PortalArgs {
    #[command(flatten)]owner:SubnetArgs,
    #[arg(long)]binding:String,
    #[arg(long)]approve_binding_digest:String,
    /// Stable portal X25519 public key, independently chosen by administrator.
    #[arg(long)]server_public_key:String,
    /// Exact standard-client physical UDP endpoint; roaming needs new approval.
    #[arg(long)]client_endpoint:SocketAddrV4,
    #[arg(long,value_parser=clap::value_parser!(u16).range(1..))]listen_port:u16,
    /// Explicit same-LAN next hop when the client's physical endpoint is remote.
    #[arg(long)]underlay_next_hop:Option<Ipv4Addr>,
}
pub(crate) async fn run(args:PortalArgs)->Result {
    if rustix::process::geteuid().as_raw()==0 {return Err(io::Error::other("WireGuard portal packet owner must run as its original ordinary installation").into());}
    let original=args.owner;
    if original.bind.ip().is_unspecified()||original.bind.ip().is_multicast()||original.dial.is_some_and(|address|address.port()==0||address.ip().is_unspecified()||address.ip().is_multicast()) {return Err(io::Error::other("exact original physical packet-carrier endpoints required").into());}
    let approved_access=pin(&original.approve_access_digest)?;let approved_mapping=pin(&original.approve_mapping_digest)?;
    let approved_binding=pin(&args.approve_binding_digest)?;
    let authority=pin(&original.authority)?;let space=PinnedNetworkSpace::new(original.space.clone(),authority)?;
    let server_public_key=crate::wireguard::key(&args.server_public_key)?;
    let installation=nestlink_local_ipc::maintenance::InstallationStartup::acquire(&std::env::current_exe()?)?;
    let directory=installation.state_directory(&original.state_dir)?;nestlink_platform_security::check_private_directory(&directory)?;
    let _runtime=nestlink_local_ipc::HeadlessRuntimeLease::acquire(&directory)?;
    let sdk=crate::session_store::SessionStore::new(directory.clone()).restore().await.ok_or_else(||io::Error::other("sign in and enable protected login recovery before starting this original WireGuard portal"))?;
    let login=crate::space_dns::session_snapshot(&directory)?;
    if !directory.join("installation-device.json").try_exists()? {return Err(io::Error::other("registered original portal installation required").into());}
    let local=crate::identity(&directory)?;let owner_id=nestlink_auth::random_id();
    let mut owner=OnlineWireGuardClient::start(&sdk,&space,&local,&args.binding,approved_binding,approved_access,owner_id.clone()).await?;
    if owner.claims().access_grant_id!=original.grant {owner.stop();return Err(io::Error::other("WireGuard binding differs from the explicitly selected original packet business").into());}
    let underlay=nestlink_platform_network::path::NetworkPathManager::new(nestlink_platform_network::path::RoutePolicy::Interface(original.interface))?;
    let endpoint=DirectPacketEndpoint::bind(original.bind,&local.identity,owner.remote_peer(),underlay)?;
    let view=tokio::time::timeout(Duration::from_secs(2),sdk.wireguard_client_binding(&original.space,&args.binding)).await??;
    let verified=OnlineWireGuardClient::inspect(&sdk,&space,&local,&args.binding,&view)?;
    if verified.digest()!=approved_binding {owner.stop();return Err(io::Error::other("original WireGuard binding changed before OS plan creation").into());}
    let credentials=view.packet_access;
    let now=system_wall_ms()?;
    let expires_at_ms=owner.claims().scope.expires_at_ms.min(now.checked_add(u64::try_from(owner.remaining_authorization_lifetime().as_millis())?).ok_or_else(||io::Error::other("original WireGuard authorization deadline overflow"))?);
    let mut physical_endpoints=vec![endpoint.local_addr().ip(),(*args.client_endpoint.ip()).into()];if let Some(remote)=original.dial {physical_endpoints.push(remote.ip());}
    let plan=Plan{schema_version:1,owner_id,process:process_identity(std::process::id()).await?,uid:rustix::process::geteuid().as_raw(),path:original.plan,created_at_ms:now,expires_at_ms,
        deployment_id:owner.claims().scope.deployment_id.clone(),space_id:original.space,authority,local_public:local.identity.public_key(),approved_access,approved_mapping,
        lan_name:original.lan_name,lan_index:original.lan_interface,lan_gateway:original.lan_gateway,lan_prefix_len:original.lan_prefix_len,physical_endpoints,credentials,
        wireguard:Some(Ingress{binding:view.binding,approved_binding,server_public_key,client_endpoint:args.client_endpoint,underlay_next_hop:args.underlay_next_hop,listen_port:args.listen_port})};
    let mut access=WireGuardAuthority{owner:&mut owner,local:&local};
    operate(Session{plan:&plan,sdk:&sdk,directory:&directory,login,installation,endpoint,dial:original.dial},&mut access,|_,receipt| {
        if receipt.wireguard_index.is_none_or(|index|index==0) {return Err(io::Error::other("standard client requires the exact kernel WireGuard interface receipt").into());}Ok(())
    }).await
}
