use super::*;
use serde_json::json;
use std::os::unix::fs::{PermissionsExt, symlink};

const OWNER: &str = "2c72ad12-a475-4dd5-91c9-7176fb82f7b8";
const BOOT: &str = "d54e0ee0-de3c-4e99-a177-b394c4055f17";

fn plan() -> io::Result<GatePlan> {
    let now = wall_ms()?;
    Ok(GatePlan {
        schema_version: 1,
        owner_id: OWNER.into(),
        endpoint: SocketAddr::from((Ipv4Addr::LOCALHOST, 34567)),
        transport: Transport::Tcp,
        process: ProcessIdentity {
            pid: 42,
            uid: 1001,
            incarnation: format!("1001:123:{BOOT}"),
            image: "/usr/bin/nestlink-daemon".into(),
            image_device: 8,
            image_inode: 991,
        },
        created_at_ms: now,
        expires_at_ms: now + 60_000,
    })
}

/// Shape of a numeric/handle nft JSON readback, including the actual complete
/// selectors and independent handles. Tests change this observation rather
/// than using the production rule builder to manufacture their expectations.
fn snapshot(plan: &GatePlan, denying: bool) -> Value {
    let mut rules = json!([
        {"family":"inet","table":plan.table(),"chain":"output","handle":4,
         "comment":format!("{}:allow",plan.marker()),"expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"127.0.0.1"}},
            {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":6}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":34567}},
            {"match":{"op":"==","left":{"meta":{"key":"skuid"}},"right":plan.process.uid}},
            {"return":null}]},
        {"family":"inet","table":plan.table(),"chain":"output","handle":5,
         "comment":format!("{}:drop",plan.marker()),"expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"127.0.0.1"}},
            {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":6}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":34567}},
            {"drop":null}]},
        {"family":"inet","table":plan.table(),"chain":"input","handle":6,
         "comment":format!("{}:outside",plan.marker()),"expr":[
            {"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"daddr"}},"right":"127.0.0.1"}},
            {"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":6}},
            {"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":34567}},
            {"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"lo"}},
            {"drop":null}]}
    ]);
    if denying {
        rules = json!([rules[1].clone(), rules[2].clone()]);
    }
    json!({
        "table":{"family":"inet","name":plan.table(),"handle":1,"comment":plan.marker()},
        "chains":[
            {"family":"inet","table":plan.table(),"name":"input","handle":2,"type":"filter","hook":"input","prio":0,"policy":"accept"},
            {"family":"inet","table":plan.table(),"name":"output","handle":3,"type":"filter","hook":"output","prio":0,"policy":"accept"}
        ],
        "rules":rules
    })
}

#[test]
fn gate_plan_rejects_other_endpoints_root_owners_and_extended_deadlines() -> io::Result<()> {
    let original = plan()?;
    original.validate(true)?;
    for endpoint in [
        "0.0.0.0:34567",
        "127.0.0.2:34567",
        "192.0.2.1:34567",
        "[::]:34567",
        "127.0.0.1:0",
    ] {
        let mut changed = original.clone();
        changed.endpoint = endpoint.parse().map_err(io::Error::other)?;
        assert!(changed.validate(true).is_err(), "accepted {endpoint}");
    }
    let mut changed = original.clone();
    changed.process.uid = 0;
    changed.process.incarnation = format!("0:123:{BOOT}");
    assert!(changed.validate(true).is_err());
    let mut changed = original.clone();
    changed.owner_id = OWNER.to_uppercase();
    assert!(changed.validate(true).is_err());
    let mut changed = original.clone();
    changed.expires_at_ms = changed.created_at_ms + 3_600_001;
    assert!(changed.validate(true).is_err());
    let mut changed = original;
    changed.created_at_ms += 60_000;
    changed.expires_at_ms = changed.created_at_ms + 60_000;
    assert!(changed.validate(true).is_err());
    Ok(())
}

#[test]
fn nft_readback_requires_both_distinct_chains_ordered_rules_and_complete_handles() -> io::Result<()>
{
    let plan = plan()?;
    let original = snapshot(&plan, false);
    nft::verify(&plan, &original, false)?;
    nft::verify(&plan, &snapshot(&plan, true), true)?;
    assert!(nft::verify(&plan, &original, true).is_err());
    let mut changed = original.clone();
    changed["chains"][1] = changed["chains"][0].clone();
    assert!(nft::verify(&plan, &changed, false).is_err());
    let mut changed = original.clone();
    changed["chains"][0]["policy"] = json!("drop");
    assert!(nft::verify(&plan, &changed, false).is_err());
    let mut changed = original.clone();
    changed["rules"] = json!([
        original["rules"][1],
        original["rules"][0],
        original["rules"][2]
    ]);
    assert!(nft::verify(&plan, &changed, false).is_err());
    for handle in [Value::Null, json!(0), json!("4")] {
        let mut changed = original.clone();
        changed["rules"][0]["handle"] = handle;
        assert!(nft::verify(&plan, &changed, false).is_err());
    }
    let mut changed = original.clone();
    changed["rules"][1]["handle"] = changed["rules"][0]["handle"].clone();
    assert!(nft::verify(&plan, &changed, false).is_err());
    let mut changed = original;
    changed["foreign"] = json!({});
    assert!(nft::verify(&plan, &changed, false).is_err());
    Ok(())
}

#[test]
fn nft_readback_rejects_uid_protocol_address_and_interface_bypasses() -> io::Result<()> {
    let plan = plan()?;
    let original = snapshot(&plan, false);
    for (expression, replacement) in [
        (0, json!("127.0.0.2")),
        (1, json!(17)),
        (2, json!(34568)),
        (3, json!(0)),
    ] {
        let mut changed = original.clone();
        changed["rules"][0]["expr"][expression]["match"]["right"] = replacement;
        assert!(nft::verify(&plan, &changed, false).is_err());
    }
    let mut changed = original;
    changed["rules"][2]["expr"][3]["match"]["op"] = json!("==");
    assert!(nft::verify(&plan, &changed, false).is_err());
    Ok(())
}

#[test]
fn nft_readback_normalizes_protocol_names_but_preserves_ipv6_udp_selectors() -> io::Result<()> {
    let mut plan = plan()?;
    plan.endpoint = SocketAddr::from((Ipv6Addr::LOCALHOST, 34567));
    plan.transport = Transport::Udp;
    plan.validate(true)?;
    let mut observed = snapshot(&plan, false);
    for index in 0..3 {
        observed["rules"][index]["expr"][0]["match"]["left"]["payload"]["protocol"] = json!("ip6");
        observed["rules"][index]["expr"][0]["match"]["right"] = json!("::1");
        observed["rules"][index]["expr"][1]["match"]["right"] = json!("udp");
        observed["rules"][index]["expr"][2]["match"]["left"]["payload"]["protocol"] = json!("udp");
    }
    nft::verify(&plan, &observed, false)?;
    observed["rules"][1]["expr"][0]["match"]["right"] = json!("::");
    assert!(nft::verify(&plan, &observed, false).is_err());
    Ok(())
}

#[test]
fn nft_compiler_can_elide_only_the_matching_transport_payload_dependency() -> io::Result<()> {
    let plan = plan()?;
    let mut observed = snapshot(&plan, false);
    for index in 0..3 {
        observed["rules"][index]["expr"]
            .as_array_mut()
            .ok_or_else(|| io::Error::other("missing fixture expressions"))?
            .remove(1);
    }
    nft::verify(&plan, &observed, false)?;
    let mut changed = observed.clone();
    changed["rules"][0]["expr"][1]["match"]["left"]["payload"]["protocol"] = json!("udp");
    assert!(nft::verify(&plan, &changed, false).is_err());
    let mut changed = observed.clone();
    changed["rules"][0]["expr"][1]["match"]["left"]["payload"]["field"] = json!("sport");
    assert!(nft::verify(&plan, &changed, false).is_err());
    let mut changed = snapshot(&plan, false);
    let duplicate = changed["rules"][0]["expr"][1].clone();
    changed["rules"][0]["expr"]
        .as_array_mut()
        .ok_or_else(|| io::Error::other("missing fixture expressions"))?
        .insert(1, duplicate);
    assert!(nft::verify(&plan, &changed, false).is_err());
    Ok(())
}

#[test]
fn deny_crash_recovery_preserves_original_table_chain_and_input_handles() -> io::Result<()> {
    let plan = plan()?;
    let installed = snapshot(&plan, false);
    let mut denied = snapshot(&plan, true);
    denied["rules"][0]["handle"] = json!(50);
    nft::verify_deny_transition(&plan, &installed, &denied)?;
    let mut changed = denied.clone();
    changed["table"]["handle"] = json!(100);
    assert!(nft::verify_deny_transition(&plan, &installed, &changed).is_err());
    let mut changed = denied.clone();
    changed["chains"][0]["handle"] = json!(101);
    assert!(nft::verify_deny_transition(&plan, &installed, &changed).is_err());
    let mut changed = denied.clone();
    changed["rules"][1]["handle"] = json!(102);
    assert!(nft::verify_deny_transition(&plan, &installed, &changed).is_err());
    // Once the deny readback was durable, a later replacement output rule is
    // not an outstanding transaction and cannot use the crash-window branch.
    assert!(nft::verify_deny_transition(&plan, &denied, &changed).is_err());
    Ok(())
}

#[test]
fn process_incarnation_exit_check_does_not_confuse_exec_with_socket_close() -> io::Result<()> {
    let original = ProcessIdentity::read(std::process::id())?;
    assert!(original.still_alive()?);
    let mut changed_image = original.clone();
    changed_image.image = "/different/image".into();
    changed_image.image_inode = original.image_inode.saturating_add(1);
    assert_ne!(changed_image, ProcessIdentity::read(std::process::id())?);
    assert!(
        changed_image.still_alive()?,
        "a changed image cannot justify deleting a live process's fence"
    );
    let mut changed_credentials = original.clone();
    changed_credentials.uid = original.uid.saturating_add(1);
    let (start, boot) = original.incarnation_parts()?;
    changed_credentials.incarnation = format!("{}:{start}:{boot}", changed_credentials.uid);
    assert!(changed_credentials.still_alive()?);
    let mut stale = original;
    stale.incarnation = format!("{}:0:{BOOT}", stale.uid);
    assert!(!stale.still_alive()?);
    Ok(())
}

#[test]
fn stat_parser_handles_parentheses_and_rejects_dead_helpers() -> io::Result<()> {
    let mut fields = vec!["0"; 20];
    fields[0] = "S";
    fields[19] = "123456";
    let stat = format!("42 (name ) with (parentheses)) {}", fields.join(" "));
    assert_eq!(process_start(&stat)?, "123456");
    require_running(&stat)?;
    for state in ["Z", "X", "x"] {
        fields[0] = state;
        let dead = format!("42 (owner) {}", fields.join(" "));
        assert!(require_running(&dead).is_err());
        assert_eq!(process_start(&dead)?, "123456");
    }
    assert!(process_start("42 (owner) S").is_err());
    let mut malformed = plan()?.process;
    malformed.incarnation = format!("0:123:{BOOT}");
    assert!(malformed.incarnation_parts().is_err());
    malformed.incarnation = format!("1001:123:{BOOT}:extra");
    assert!(malformed.incarnation_parts().is_err());
    Ok(())
}

#[test]
fn public_receipt_paths_reject_user_writable_ancestors_and_parent_traversal() -> io::Result<()> {
    assert!(ReceiptParent::open(Path::new("relative/receipt.json")).is_err());
    assert!(ReceiptParent::open(Path::new("/tmp/receipt.json")).is_err());
    assert!(ReceiptParent::open(Path::new("/etc/../run/receipt.json")).is_err());
    let root_parent = ReceiptParent::open(Path::new("/etc/nestlink-test-receipt.json"))?;
    assert_eq!(root_parent.directory.metadata()?.uid(), 0);
    let temporary = tempfile::tempdir()?;
    let link = temporary.path().join("linked");
    symlink("/etc", &link)?;
    assert!(ReceiptParent::open(&link.join("receipt.json")).is_err());
    assert!(
        trusted_ancestors(&link).is_err(),
        "canonicalization must not hide a user-replaceable ancestor"
    );
    trusted_ancestors(Path::new("/tmp"))?;
    Ok(())
}

#[test]
fn ordinary_plan_file_roundtrip_is_create_new_bounded_and_no_follow() -> io::Result<()> {
    let plan = GatePlan::for_current_process(
        OWNER.into(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 34567)),
        Transport::Tcp,
        wall_ms()? + 60_000,
    )?;
    let temporary = tempfile::tempdir()?;
    let private = temporary.path().join("private-plan");
    crate::new_private_directory(&private)?;
    let path = private.join("plan.json");
    plan.save_new(&path)?;
    assert_eq!(GatePlan::read_public(&path)?, plan);
    assert!(plan.save_new(&path).is_err());
    let link = private.join("linked.json");
    symlink(&path, &link)?;
    assert!(GatePlan::read_public(&link).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(GatePlan::read_public(&path).is_err());
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_len(MAXIMUM_JSON + 1)?;
    assert!(GatePlan::read_public(&path).is_err());
    assert!(RootGateReceipt::read_for_current_process(&path, &plan).is_err());
    Ok(())
}

#[test]
fn ordinary_receipt_liveness_checks_root_pid_without_reading_its_exe() -> io::Result<()> {
    let plan = GatePlan::for_current_process(
        OWNER.into(),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 34567)),
        Transport::Tcp,
        wall_ms()? + 60_000,
    )?;
    // PID 1 is the Linux runner's live root process. This models the fields
    // already authenticated by a root-owned receipt. Its executable is
    // deliberately unavailable here: subsequent checks must only use proc's
    // publicly observable PID/start/boot/root-UID identity.
    let start = process_start(&std::fs::read_to_string("/proc/1/stat")?)?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let helper = ProcessIdentity {
        pid: 1,
        uid: 0,
        incarnation: format!("0:{start}:{}", boot.trim()),
        image: "/unavailable/root/executable".into(),
        image_device: plan.process.image_device,
        image_inode: plan.process.image_inode,
    };
    helper.root_helper_alive()?;
    let receipt = RootGateReceipt {
        schema_version: 1,
        installed: snapshot(&plan, false),
        plan: plan.clone(),
        helper,
    };
    receipt.check_current(&plan)?;
    let mut changed = receipt.clone();
    changed.helper.incarnation = format!("0:0:{BOOT}");
    assert!(changed.check_current(&plan).is_err());
    let mut changed = receipt.clone();
    changed.installed["rules"][0]["expr"][3]["match"]["right"] = json!(0);
    assert!(changed.check_current(&plan).is_err());
    let mut changed = receipt.clone();
    changed.plan.process.image_inode = changed.plan.process.image_inode.saturating_add(1);
    assert!(changed.check_current(&changed.plan).is_err());
    let mut expired = receipt;
    expired.plan.created_at_ms = wall_ms()?.saturating_sub(2000);
    expired.plan.expires_at_ms = expired.plan.created_at_ms + 1000;
    assert!(expired.check_current(&expired.plan).is_err());
    Ok(())
}
