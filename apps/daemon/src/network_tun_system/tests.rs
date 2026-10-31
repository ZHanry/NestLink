use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use nestlink_identity::network::{
    NetworkAuthoritySigner, NetworkVerification, verify_network_grant,
};
use nestlink_protocol::network::{
    Direction, GrantClaims, GrantScope, IpPrefix, IpProtocol, NetworkAccessClaims, NetworkRule,
    PeerId,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

pub(super) fn plan() -> Result<TunPlan> {
    let now = system_wall_ms()?;
    let signer = NetworkAuthoritySigner::from_master_seed(&[71; 32])?;
    let deployment = nestlink_auth::random_id();
    let space = nestlink_auth::random_id();
    let local_hosts = ["10.81.0.2".parse()?, "fd81::2".parse()?];
    let remote_hosts = ["10.81.0.3".parse()?, "fd81::3".parse()?];
    let claims = GrantClaims::NetworkAccess(NetworkAccessClaims {
        scope: GrantScope {
            schema_version: 1,
            deployment_id: deployment.clone(),
            space_id: space.clone(),
            grant_id: nestlink_auth::random_id(),
            policy_epoch: 3,
            not_before_ms: now.saturating_sub(1000),
            expires_at_ms: now + 60_000,
        },
        source: PeerId([2; 32]),
        destination: PeerId([3; 32]),
        source_prefixes: local_hosts
            .into_iter()
            .enumerate()
            .map(|(index, network)| IpPrefix {
                network,
                prefix_len: if index == 0 { 32 } else { 128 },
            })
            .collect(),
        destination_prefixes: remote_hosts
            .into_iter()
            .enumerate()
            .map(|(index, network)| IpPrefix {
                network,
                prefix_len: if index == 0 { 32 } else { 128 },
            })
            .collect(),
        rules: vec![
            NetworkRule {
                protocol: IpProtocol::Tcp,
                direction: Direction::Inbound,
                ports: Some([443, 443]),
            },
            NetworkRule {
                protocol: IpProtocol::Udp,
                direction: Direction::Inbound,
                ports: Some([443, 443]),
            },
        ],
        byte_limit: 1_000_000,
    });
    let signed = signer.sign(&claims)?;
    let authority_key = signer.public_key();
    let revoked = BTreeSet::new();
    let verified = verify_network_grant(
        &signed,
        &NetworkVerification {
            authority_key: &authority_key,
            deployment_id: &deployment,
            space_id: &space,
            policy_epoch: 3,
            now_ms: now,
            revoked_grant_ids: &revoked,
        },
    )?;
    Ok(TunPlan {
        schema_version: 2,
        owner_id: nestlink_auth::random_id(),
        space_id: space,
        process: serde_json::from_value(
            json!({"pid":std::process::id(),"incarnation":"test-process-start","image":std::env::current_exe()?.to_string_lossy()}),
        )?,
        principal: plan::HostPrincipal::Linux { uid: 1000 },
        created_at_ms: now,
        expires_at_ms: now + 50_000,
        deployment_id: deployment,
        authority_key,
        local_peer: PeerId([2; 32]),
        remote_peer: PeerId([3; 32]),
        local_hosts,
        remote_hosts,
        approved_digest: verified.digest(),
        policy_epoch: 3,
        signed_claims: URL_SAFE_NO_PAD.encode(signed.claims),
        signature: URL_SAFE_NO_PAD.encode(signed.signature),
    })
}

#[test]
fn public_plan_rejects_links_nonregular_widened_and_oversized_inputs() -> Result {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let temporary = tempfile::tempdir()?;
    let path = temporary.path().join("plan.json");
    nestlink_platform_security::create_private(&path, &serde_json::to_vec(&plan()?)?)?;
    let alias = temporary.path().join("alias.json");
    symlink(&path, &alias)?;
    assert!(TunPlan::read(&alias).is_err());
    assert!(TunPlan::read(temporary.path()).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(TunPlan::read(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    std::fs::write(&path, vec![b' '; plan::MAX_JSON as usize + 1])?;
    assert!(TunPlan::read(&path).is_err());
    let fifo = temporary.path().join("owner-fifo");
    if !std::process::Command::new("/usr/bin/mkfifo")
        .arg("--")
        .arg(&fifo)
        .status()?
        .success()
    {
        return Err(io::Error::other("hosted FIFO regression fixture creation failed").into());
    }
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = send.send(TunPlan::read(&fifo).is_err());
    });
    assert!(
        receive.recv_timeout(Duration::from_secs(1))?,
        "root input must reject a FIFO without blocking its monitor"
    );
    Ok(())
}
fn state(plan: &TunPlan) -> Result<TunState> {
    let name = plan.link();
    Ok(TunState{identity:InterfaceIdentity{name:name.clone(),index:71,marker:plan.marker(),uid:plan.linux_uid()?},mtu:1280,up:true,persistent:true,framing:0x1801,
        addresses:plan.local_hosts.iter().map(|ip|json!({"family":if ip.is_ipv4(){"inet"}else{"inet6"},"local":ip.to_string(),"prefixlen":if ip.is_ipv4(){32}else{128},"scope":"global","peer":null,"broadcast":null})).collect(),
        routes:plan.remote_hosts.iter().zip(plan.local_hosts).map(|(ip,local)|json!({"dst":format!("{ip}/{}",if ip.is_ipv4(){32}else{128}),"dev":name,"protocol":"static","prefsrc":local.to_string(),"metric":42420,"flags":[]})).collect()})
}
#[test]
fn signed_plan_binds_digest_pair_hosts_scope_and_deadline_and_rejects_extra_commands() -> Result {
    let plan = plan()?;
    plan.validate(true)?;
    assert_eq!(plan.link().len(), 15);
    for fault in 0..9 {
        let mut changed = plan.clone();
        match fault {
            0 => changed.approved_digest[0] ^= 1,
            1 => changed.authority_key[0] ^= 1,
            2 => changed.local_hosts[0] = "10.81.0.4".parse()?,
            3 => changed.remote_peer = PeerId([4; 32]),
            4 => changed.policy_epoch += 1,
            5 => changed.space_id = nestlink_auth::random_id(),
            6 => changed.principal = plan::HostPrincipal::Linux { uid: 0 },
            7 => changed.expires_at_ms = changed.created_at_ms + 60_001,
            8 => changed.local_hosts[0] = "127.0.0.1".parse()?,
            _ => unreachable!(),
        }
        assert!(
            changed.validate(true).is_err(),
            "signed TUN plan fault {fault}"
        );
    }
    let mut value = serde_json::to_value(&plan)?;
    value["command"] = json!(["ip", "route", "replace", "default"]);
    assert!(serde_json::from_value::<TunPlan>(value).is_err());
    Ok(())
}
#[test]
fn exact_os_readback_refuses_foreign_identity_prefix_gateway_and_route_table() -> Result {
    let plan = plan()?;
    let original = state(&plan)?;
    linux::verify(&plan, &original, true)?;
    for fault in 0..8 {
        let mut changed = original.clone();
        match fault {
            0 => changed.identity.marker = "other-vpn".into(),
            1 => changed.identity.uid += 1,
            2 => changed.addresses[0]["prefixlen"] = json!(24),
            3 => changed.routes[0]["gateway"] = json!("192.0.2.1"),
            4 => changed.routes[0]["dst"] = json!("0.0.0.0/0"),
            5 => changed.routes[0]["table"] = json!(73),
            6 => changed.routes[0]["metric"] = json!(5),
            7 => changed.routes[0]["prefsrc"] = json!("10.81.0.99"),
            _ => unreachable!(),
        }
        assert!(
            linux::verify(&plan, &changed, true).is_err(),
            "kernel TUN plan fault {fault}"
        );
    }
    Ok(())
}
#[test]
fn preflight_preserves_existing_addresses_and_nondefault_vpn_routes() -> Result {
    let plan = plan()?;
    let empty = json!([]);
    linux::check_conflicts(
        &plan,
        &empty,
        &json!([{"dst":"default"}]),
        &json!([{"dst":"::/0"}]),
    )?;
    for addresses in [
        json!([{"addr_info":[{"local":"10.81.0.2"}]}]),
        json!([{"addr_info":[{"local":"fd81::3"}]}]),
    ] {
        assert!(linux::check_conflicts(&plan, &addresses, &empty, &empty).is_err());
    }
    for route in [
        json!({"dst":"10.81.0.0/24"}),
        json!({"dst":"10.81.0.3"}),
        json!({"dst":"fd00::/8"}),
        json!({"dst":"malformed"}),
        json!({}),
    ] {
        assert!(linux::check_conflicts(&plan, &empty, &json!([route]), &empty).is_err());
    }
    Ok(())
}
#[test]
fn protected_journal_retains_durable_identity_and_rejects_replacement() -> Result {
    let temporary = tempfile::tempdir()?;
    let directory = temporary.path().join("tun-root-journal");
    nestlink_platform_security::new_private_directory(&directory)?;
    let plan = plan()?;
    let installed = state(&plan)?;
    {
        let store = JournalStore::open(&directory)?;
        store.save(&Journal {
            schema_version: 1,
            plan: plan.clone(),
            identity: Some(installed.identity.clone()),
            installed: Some(installed),
        })?;
        assert!(JournalStore::open(&directory).is_err());
    }
    let store = JournalStore::open(&directory)?;
    let mut journal = store
        .read()?
        .ok_or_else(|| io::Error::other("TUN journal missing"))?;
    assert_eq!(journal.identity.as_ref().map(|id| id.index), Some(71));
    journal
        .identity
        .as_mut()
        .ok_or_else(|| io::Error::other("identity missing"))?
        .index += 1;
    store.save(&journal)?;
    assert!(store.read().is_err());
    Ok(())
}
#[test]
fn invalid_native_rows_never_look_like_empty_route_tables() -> Result {
    let plan = plan()?;
    for invalid in [
        Value::Null,
        json!({}),
        json!(""),
        json!([{"addr_info":null}]),
    ] {
        assert!(linux::check_conflicts(&plan, &invalid, &json!([]), &json!([])).is_err());
    }
    Ok(())
}
