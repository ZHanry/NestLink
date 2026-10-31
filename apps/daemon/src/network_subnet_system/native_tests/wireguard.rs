//! Real distribution client and kernel WireGuard, through the same original
//! signed whole-IP business and encrypted carrier as the subnet mechanism lab.
use super::*;
use base64::engine::general_purpose::STANDARD;
use nestlink_identity::{
    network::{NetworkAuthoritySigner, NetworkVerification, verify_network_grant},
    subnet::{SubnetGatewayState, verify_subnet_mapping},
    wireguard::{WireGuardPortalState, verify_wireguard_client_binding},
};
use nestlink_protocol::{
    network::{GrantClaims, GrantScope, IpPrefix},
    subnet::SubnetMappingClaims,
    wireguard::WireGuardClientBindingClaims,
};
use zeroize::Zeroizing;

const CLIENT: &str = "10.210.7.2";
const CLIENT_PORT: u16 = 51821;
const PORTAL_PORT: u16 = 51820;

#[derive(Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Secrets {
    server: [u8; 32],
    client: [u8; 32],
    other: [u8; 32],
}
async fn secret() -> Result<Zeroizing<[u8; 32]>> {
    let bytes = crate::wireguard::tools::run("wg", &["genkey"], &[], 128).await?;
    Ok(Zeroizing::new(crate::wireguard::key(
        std::str::from_utf8(&bytes)?.trim_end_matches('\n'),
    )?))
}
fn prefix() -> Result<IpPrefix> {
    Ok(IpPrefix {
        network: CLIENT.parse()?,
        prefix_len: 32,
    })
}
fn grant(
    signed: nestlink_identity::network::SignedNetworkGrant,
) -> Result<nestlink_protocol::api::NetworkGrantView> {
    let claims = GrantClaims::decode_canonical(&signed.claims)?;
    Ok(nestlink_protocol::api::NetworkGrantView {
        schema_version: 1,
        grant_id: claims.scope().grant_id.clone(),
        claims: URL_SAFE_NO_PAD.encode(signed.claims),
        signature: URL_SAFE_NO_PAD.encode(signed.signature),
    })
}
fn fixture(
    client_key: [u8; 32],
    server_key: [u8; 32],
) -> Result<(fixture::Fixture, super::super::wireguard::Ingress)> {
    let mut fixture = fixture::Fixture::new()?;
    let signer = NetworkAuthoritySigner::from_master_seed(&[89; 32])?;
    let revoked = BTreeSet::new();
    let context = NetworkVerification {
        authority_key: &fixture.authority,
        deployment_id: fixture::DEPLOYMENT,
        space_id: fixture::SPACE,
        policy_epoch: 1,
        now_ms: fixture.created,
        revoked_grant_ids: &revoked,
    };
    let mapping = &mut fixture.view.subnet_mappings[0];
    let mut export = GrantClaims::decode_canonical(
        &nestlink_sdk::network_management::decode_network_grant(&mapping.route_export)?.claims,
    )?;
    let GrantClaims::RouteExport(export_claims) = &mut export else {
        return Err(io::Error::other("original export fixture required").into());
    };
    export_claims.prefixes = vec![prefix()?];
    let export = signer.sign(&export)?;
    let verified_export = verify_network_grant(&export, &context)?;
    let mut mapping_claims = SubnetMappingClaims::decode_canonical(&mapping.mapping.claims)?;
    mapping_claims.original = prefix()?;
    mapping_claims.alias = prefix()?;
    mapping_claims.route_export_digest = verified_export.digest();
    mapping.mapping = signer.sign_subnet_mapping(&mapping_claims)?;
    mapping.route_export = grant(export)?;
    fixture.mappings[0] = verify_subnet_mapping(
        &mapping.mapping,
        &context,
        verified_export,
        &SubnetGatewayState {
            node_id: &mapping.gateway.node_id,
            public_key: &mapping.gateway.public_key,
            incarnation: &mapping.gateway.incarnation,
            mapping_revision: 1,
            lease_expires_at_ms: fixture.expires,
        },
    )?
    .digest();
    let mut access = GrantClaims::decode_canonical(
        &nestlink_sdk::network_management::decode_network_grant(&fixture.view.access)?.claims,
    )?;
    let GrantClaims::NetworkAccess(access_claims) = &mut access else {
        return Err(io::Error::other("original access fixture required").into());
    };
    access_claims.source_prefixes = vec![prefix()?];
    let access = signer.sign(&access)?;
    let verified_access = verify_network_grant(&access, &context)?;
    fixture.access = verified_access.digest();
    fixture.view.access = grant(access)?;
    let mut connectivity = GrantClaims::decode_canonical(
        &nestlink_sdk::network_management::decode_network_grant(&fixture.view.connectivity)?.claims,
    )?;
    let GrantClaims::Connectivity(connectivity_claims) = &mut connectivity else {
        return Err(io::Error::other("original connectivity fixture required").into());
    };
    connectivity_claims.business_grant_digest = fixture.access;
    let connectivity = signer.sign(&connectivity)?;
    let connectivity_digest = verify_network_grant(&connectivity, &context)?.digest();
    fixture.view.connectivity = grant(connectivity)?;
    let mut path = GrantClaims::decode_canonical(
        &nestlink_sdk::network_management::decode_network_grant(&fixture.view.path)?.claims,
    )?;
    let GrantClaims::Path(path_claims) = &mut path else {
        return Err(io::Error::other("original path fixture required").into());
    };
    path_claims.connectivity_grant_digest = connectivity_digest;
    fixture.view.path = grant(signer.sign(&path)?)?;
    let gateway = &fixture.view.subnet_mappings[0].gateway;
    let claims = WireGuardClientBindingClaims {
        binding_version: 1,
        scope: GrantScope {
            schema_version: 1,
            deployment_id: fixture::DEPLOYMENT.into(),
            space_id: fixture::SPACE.into(),
            grant_id: nestlink_auth::random_id(),
            policy_epoch: 1,
            not_before_ms: fixture.created,
            expires_at_ms: fixture.expires,
        },
        client_id: nestlink_auth::random_id(),
        client_revision: 1,
        account_id: fixture.view.address_directory.addresses[0]
            .account_id
            .clone(),
        installation_id: fixture.view.address_directory.addresses[0]
            .installation_id
            .clone(),
        client_public_key: client_key,
        client_address: CLIENT.parse()?,
        portal_node_id: gateway.node_id.clone(),
        portal_public_key: gateway.public_key,
        portal_incarnation: gateway.incarnation.clone(),
        access_grant_id: fixture.view.access.grant_id.clone(),
        access_digest: fixture.access,
        committed_bytes: 1_048_576,
    };
    let binding = signer.sign_wireguard_client_binding(&claims)?;
    let approved_binding = verify_wireguard_client_binding(
        &binding,
        &context,
        verified_access,
        &WireGuardPortalState {
            node_id: &gateway.node_id,
            public_key: &gateway.public_key,
            incarnation: &gateway.incarnation,
            lease_expires_at_ms: fixture.expires,
            client_revision: 1,
        },
    )?
    .digest();
    Ok((
        fixture,
        super::super::wireguard::Ingress {
            binding,
            approved_binding,
            server_public_key: server_key,
            client_endpoint: format!("{}:{CLIENT_PORT}", fixture::TARGET).parse()?,
            underlay_next_hop: None,
            listen_port: PORTAL_PORT,
        },
    ))
}

#[tokio::test]
#[ignore = "actual standard WireGuard client, kernel peer, root namespace helper and original packet carrier on the dedicated GitHub-hosted VM"]
async fn standard_client_tcp_udp_key_source_acl_original_carrier_and_exact_cleanup() -> Result {
    lab_only()?;
    if std::env::var("RUNNER_ENVIRONMENT").as_deref() != Ok("github-hosted")
        || rustix::process::geteuid().as_raw() == 0
    {
        return Err(io::Error::other(
            "ordinary dedicated GitHub-hosted WireGuard qualification required",
        )
        .into());
    }
    for crash in [false, true] {
        let lab = lab::Lab::new()?;
        nestlink_platform_security::create_private(&lab.config(), &serde_json::to_vec(&lab)?)?;
        if !lab.status("setup").await? {
            return Err(io::Error::other("owned WireGuard lab setup failed").into());
        }
        let server = secret().await?;
        let client = secret().await?;
        let other = secret().await?;
        let server_public = crate::wireguard::public_key_for(&server).await?;
        let client_public = crate::wireguard::public_key_for(&client).await?;
        let secrets = Secrets {
            server: *server,
            client: *client,
            other: *other,
        };
        let secrets = Zeroizing::new(serde_json::to_vec(&secrets)?);
        nestlink_platform_security::create_private(
            &lab.ordinary.join("wireguard-test-secrets.json"),
            &secrets,
        )?;
        if !lab.status("wg-install-secrets").await? {
            return Err(
                io::Error::other("root-private test WireGuard keys were not installed").into(),
            );
        }
        std::fs::remove_file(lab.ordinary.join("wireguard-test-secrets.json"))?;
        drop(secrets);
        drop(server);
        drop(client);
        drop(other);
        let (fixture, ingress) = fixture(client_public, server_public)?;
        let mut source = fixture.plan(0, lab.plan(0), lab.bridge(0)).await?;
        source.wireguard = Some(ingress);
        let destination = fixture.plan(1, lab.plan(1), lab.bridge(1)).await?;
        let plans = [source, destination];
        for plan in &plans {
            plan.save_new()?;
        }
        let mut helpers = [
            lab.command("apply0")?.spawn()?,
            lab.command("apply1")?.spawn()?,
        ];
        let mut service = lab.command("service1")?.spawn()?;
        let outcome = async {
            let (first, second) = helpers.split_at_mut(1);
            let (source, target) = tokio::join!(
                connect(&plans[0], &mut first[0]),
                connect(&plans[1], &mut second[0])
            );
            let pipes = [source?, target?];
            assert!(
                pipes[0]
                    .receipt
                    .wireguard_index
                    .is_some_and(|index| index > 0)
            );
            assert!(pipes[1].receipt.wireguard_index.is_none());
            let (stop, receiver) = tokio::sync::watch::channel(false);
            let bridges = carrier::start(&plans, pipes, receiver).await?;
            probe(&lab, 0, "wg-setup").await?;
            probe(&lab, 0, "wg-udp").await?;
            probe(&lab, 0, "wg-tcp").await?;
            probe(&lab, 0, "wg-handshake").await?;
            probe(&lab, 0, "wg-bad-port").await?;
            probe(&lab, 0, "wg-spoofed-source").await?;
            probe(&lab, 0, "wg-wrong-key").await?;
            probe(&lab, 0, "wg-restore-key").await?;
            probe(&lab, 0, "wg-udp").await?;
            if !lab.status("verify-host").await? {
                return Err(io::Error::other("WireGuard ingress modified the host network").into());
            }
            if crash {
                if !lab.status("kill-helper0").await? {
                    return Err(
                        io::Error::other("original WireGuard root helper SIGKILL failed").into(),
                    );
                }
                assert!(!finished(&mut helpers[0]).await?);
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if lab.status("recover0").await? {
                            return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                })
                .await??;
                probe(&lab, 0, "wg-after-owner-loss").await?;
                assert!(kernel::namespace(&kernel::namespace_path(&plans[0]))?.is_none());
                assert!(!plans[0].socket()?.try_exists()?);
            }
            let _ = stop.send(true);
            let [left, right] = bridges;
            let (left, right) = tokio::join!(left, right);
            let left = left?;
            let right = right?;
            if !crash {
                let left = left?;
                let right = right?;
                assert!(left.sent > 5 && left.received > 5 && right.sent > 5 && right.received > 5);
                assert_eq!(left.spent, right.spent);
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }
        .await;
        for plan in &plans {
            if plan.path.try_exists()? {
                std::fs::remove_file(&plan.path)?;
            }
        }
        for (index, helper) in helpers.iter_mut().enumerate() {
            if !crash || index != 0 {
                let _ = finished(helper).await?;
            }
        }
        let _ = lab.status("kill-service1").await?;
        let _ = finished(&mut service).await?;
        let teardown = lab.status("teardown").await?;
        outcome?;
        if !teardown {
            return Err(io::Error::other(
                "exact WireGuard/subnet kernel cleanup failed; retain original recovery journals",
            )
            .into());
        }
        for entry in std::fs::read_dir(&lab.ordinary)? {
            let path = entry?.path();
            if path.is_file() {
                std::fs::remove_file(path)?;
            }
        }
        std::fs::remove_dir(&lab.ordinary)?;
    }
    Ok(())
}
pub(super) async fn install_secrets(lab: &lab::Lab) -> Result {
    let (bytes, uid) = crate::network_packet_runtime::read_public_plan(
        &lab.ordinary.join("wireguard-test-secrets.json"),
        4096,
    )?;
    if uid == 0 {
        return Err(
            io::Error::other("original ordinary test owner must select independent keys").into(),
        );
    }
    let bytes = Zeroizing::new(bytes);
    let secrets: Secrets = serde_json::from_slice(&bytes)?;
    for (name, key) in [
        ("server", secrets.server),
        ("client", secrets.client),
        ("other", secrets.other),
    ] {
        let key = Zeroizing::new(key);
        let encoded = Zeroizing::new(format!("{}\n", STANDARD.encode(key.as_slice())));
        nestlink_platform_security::create_private(
            &lab.root.join(format!("wireguard-{name}.key")),
            encoded.as_bytes(),
        )?;
    }
    Ok(())
}
async fn select_client_key(lab: &lab::Lab, name: &str) -> Result {
    let secret = nestlink_platform_security::read_private(
        &lab.root.join(format!("wireguard-{name}.key")),
        128,
    )?;
    crate::wireguard::tools::run(
        "wg",
        &["set", "wgclient", "private-key", "/dev/stdin"],
        &secret,
        4096,
    )
    .await?;
    Ok(())
}
async fn public_diagnostic(lab: &lab::Lab) -> Result {
    let plan = Plan::read(&lab.plan(0))?;
    let namespace = plan.namespace();
    let name = super::super::wireguard::Ingress::interface(&plan);
    for field in ["latest-handshakes", "transfer"] {
        let client =
            crate::wireguard::tools::run("wg", &["show", "wgclient", field], &[], 4096).await?;
        let portal = kernel::command(
            "ip",
            &[
                "netns",
                "exec",
                &namespace,
                "/usr/bin/wg",
                "show",
                &name,
                field,
            ],
        )
        .await?;
        eprintln!(
            "WireGuard hosted public diagnostic {field}: client={}, portal={}",
            std::str::from_utf8(&client)?.trim_end(),
            std::str::from_utf8(&portal)?.trim_end()
        );
    }
    let nft = kernel::tool("nft")?;
    let nft = nft
        .to_str()
        .ok_or_else(|| io::Error::other("native nft path must be UTF-8"))?;
    let quota = kernel::command(
        "ip",
        &[
            "netns", "exec", &namespace, nft, "list", "quota", "inet", &namespace, "budget",
        ],
    )
    .await?;
    eprintln!(
        "WireGuard hosted original kernel quota: {}",
        std::str::from_utf8(&quota)?.trim_end()
    );
    Ok(())
}
pub(super) async fn client_probe(lab: &lab::Lab) -> Result {
    let case = std::env::var("NESTLINK_SUBNET_NATIVE_CASE")?;
    if case == "wg-setup" {
        let plan = Plan::read(&lab.plan(0))?;
        let ingress = plan
            .wireguard
            .as_ref()
            .ok_or_else(|| io::Error::other("standard-client ingress fixture missing"))?;
        // The original subnet lab fixes its inner LAN MTU at 1280. Standard
        // WireGuard adds its outer IPv4/UDP/authentication overhead; retain a
        // normal 1500-byte physical client link so a full approved 1280-byte
        // inner packet does not depend on forbidden outer IP fragmentation.
        kernel::command("ip", &["link", "set", "dev", "eth0", "mtu", "1500"]).await?;
        kernel::command(
            "ip",
            &["link", "add", "dev", "wgclient", "type", "wireguard"],
        )
        .await?;
        kernel::command(
            "ip",
            &[
                "link",
                "set",
                "dev",
                "wgclient",
                "mtu",
                "1280",
                "addrgenmode",
                "none",
            ],
        )
        .await?;
        let secret =
            nestlink_platform_security::read_private(&lab.root.join("wireguard-client.key"), 128)?;
        let configuration = Zeroizing::new(format!(
            "[Interface]\nPrivateKey = {}\nListenPort = {CLIENT_PORT}\n\n[Peer]\nPublicKey = {}\nAllowedIPs = {}/24\nEndpoint = {}:{PORTAL_PORT}\nPersistentKeepalive = 25\n",
            std::str::from_utf8(&secret)?.trim_end(),
            STANDARD.encode(ingress.server_public_key),
            fixture::ALIASES[1],
            plan.lan_gateway
        ));
        crate::wireguard::tools::run(
            "wg",
            &["setconf", "wgclient", "/dev/stdin"],
            configuration.as_bytes(),
            4096,
        )
        .await?;
        kernel::command(
            "ip",
            &[
                "-4",
                "addr",
                "add",
                &format!("{CLIENT}/32"),
                "dev",
                "wgclient",
            ],
        )
        .await?;
        kernel::command("ip", &["link", "set", "dev", "wgclient", "up"]).await?;
        kernel::command(
            "ip",
            &[
                "-4",
                "route",
                "replace",
                &format!("{}/24", fixture::ALIASES[1]),
                "dev",
                "wgclient",
            ],
        )
        .await?;
        return Ok(());
    }
    if case == "wg-restore-key" {
        return select_client_key(lab, "client").await;
    }
    if case == "wg-handshake" {
        let handshakes = crate::wireguard::tools::run(
            "wg",
            &["show", "wgclient", "latest-handshakes"],
            &[],
            4096,
        )
        .await?;
        let text = std::str::from_utf8(&handshakes)?;
        let fields = text.split_whitespace().collect::<Vec<_>>();
        let plan = Plan::read(&lab.plan(0))?;
        let ingress = plan
            .wireguard
            .as_ref()
            .ok_or_else(|| io::Error::other("original WireGuard ingress missing"))?;
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0], STANDARD.encode(ingress.server_public_key));
        assert!(
            fields[1].parse::<u64>()? > 0,
            "actual kernel handshake must be observed"
        );
        return Ok(());
    }
    if case == "wg-wrong-key" {
        select_client_key(lab, "other").await?;
    }
    let target = fixture::DESTINATIONS[1];
    if case == "wg-tcp" {
        let mut stream = tokio::time::timeout(
            Duration::from_secs(3),
            TcpStream::connect((target, fixture::TCP)),
        )
        .await??;
        let payload = vec![67_u8; 16_384];
        stream.write_all(&payload).await?;
        let mut received = vec![0_u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut received)).await??;
        assert_eq!(payload, received);
        stream.shutdown().await?;
        return Ok(());
    }
    let source = if case == "wg-spoofed-source" {
        kernel::command(
            "ip",
            &["-4", "addr", "add", "10.210.7.3/32", "dev", "wgclient"],
        )
        .await?;
        "10.210.7.3"
    } else {
        CLIENT
    };
    let socket = UdpSocket::bind((source, 0)).await?;
    let port = if case == "wg-bad-port" {
        fixture::DENIED
    } else {
        fixture::UDP
    };
    let payload = vec![79_u8; 1252];
    socket.send_to(&payload, (target, port)).await?;
    let mut received = [0_u8; 2048];
    let result = tokio::time::timeout(
        Duration::from_millis(if case == "wg-udp" { 3000 } else { 800 }),
        socket.recv_from(&mut received),
    )
    .await;
    if case == "wg-udp" {
        let (count, peer) = match result {
            Ok(Ok(packet)) => packet,
            Ok(Err(error)) => {
                let _ = public_diagnostic(lab).await;
                return Err(error.into());
            }
            Err(error) => {
                let _ = public_diagnostic(lab).await;
                return Err(error.into());
            }
        };
        assert_eq!(peer.ip().to_string(), target);
        assert_eq!(peer.port(), port);
        assert_eq!(&received[..count], payload);
    } else {
        assert!(
            result.is_err(),
            "wrong client key/source/ACL or ended owner forwarded standard-client data"
        );
    }
    Ok(())
}
