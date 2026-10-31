use super::*;

pub(super) fn plan() -> io::Result<GatePlan> {
    let now = wall_ms()?;
    Ok(GatePlan {
        schema_version: 1,
        owner_id: "12345678-1234-4234-8234-123456789abc".into(),
        endpoint: SocketAddr::from(([127, 0, 0, 1], 34567)),
        transport: Transport::Tcp,
        process: ProcessIdentity {
            pid: 100,
            sid: "S-1-5-21-1-2-3-1001".into(),
            session: 1,
            creation: 100,
            image: PathBuf::from(r"C:\Program Files\NestLink\nestlink-daemon.exe"),
            image_volume: 1,
            image_index: 42,
            elevated: false,
            integrity: 0x2000,
        },
        created_at_ms: now,
        expires_at_ms: now + 60_000,
    })
}

#[test]
fn exact_normal_user_plan_is_bounded_and_rejects_other_targets() -> io::Result<()> {
    let original = plan()?;
    original.validate(true)?;
    for endpoint in [
        SocketAddr::from(([127, 0, 0, 2], 34567)),
        SocketAddr::from(([0, 0, 0, 0], 34567)),
        SocketAddr::from(([127, 0, 0, 1], 0)),
    ] {
        let mut changed = original.clone();
        changed.endpoint = endpoint;
        assert!(changed.validate(true).is_err());
    }
    let mut changed = original.clone();
    changed.process.elevated = true;
    assert!(changed.validate(true).is_err());
    changed = original.clone();
    changed.process.integrity = 0x3000;
    assert!(changed.validate(true).is_err());
    changed = original.clone();
    changed.process.sid.push_str(";;;WD)");
    assert!(changed.validate(true).is_err());
    changed = original.clone();
    changed.expires_at_ms = changed.created_at_ms + 3_600_001;
    assert!(changed.validate(false).is_err());
    changed = original.clone();
    changed.owner_id = "00000000-0000-0000-0000-00000000000g".into();
    assert!(changed.validate(false).is_err());
    changed = original;
    changed.endpoint = SocketAddr::from((Ipv6Addr::LOCALHOST, 34567));
    changed.validate(true)
}

#[test]
fn real_process_handle_distinguishes_creation_reuse_from_token_assertions() -> io::Result<()> {
    let current = ProcessIdentity::read(std::process::id())?;
    assert!(current.still_alive()?);
    let handle = process_handle(current.pid)?.ok_or_else(|| invalid("current process missing"))?;
    assert_eq!(creation(&handle)?, current.creation);
    assert!(alive(&handle)?);
    let mut reused = current.clone();
    reused.creation = reused.creation.saturating_add(1);
    assert!(!reused.still_alive()?);
    let mut changed_token = current;
    changed_token.sid = "S-1-5-21-9-9-9-1001".into();
    changed_token.elevated = true;
    // Changing serialized credentials never proves that the original process
    // and all its sockets have physically exited.
    assert!(changed_token.still_alive()?);
    Ok(())
}

#[test]
fn unprotected_receipt_and_network_paths_are_never_trust_anchors() {
    assert!(store::Parents::open(Path::new(r"\\server\share\receipt")).is_err());
    assert!(store::Parents::open(Path::new(r"relative\receipt")).is_err());
    assert!(store::Parents::open(&std::env::temp_dir()).is_err());
}

#[test]
fn real_private_plan_has_captured_owner_acl_and_cannot_be_overwritten() -> io::Result<()> {
    let path = std::env::temp_dir().join(format!(
        "nestlink-wfp-plan-{}-{}",
        std::process::id(),
        wall_ms()?
    ));
    nestlink_platform_security::new_private_directory(&path)?;
    let result = (|| -> io::Result<()> {
        let plan = GatePlan::for_current_process(
            "12345678-1234-4234-8234-123456789abc".into(),
            SocketAddr::from(([127, 0, 0, 1], 34567)),
            Transport::Tcp,
            wall_ms()? + 60_000,
        )?;
        let filename = path.join("plan.json");
        plan.save_new(&filename)?;
        assert_eq!(GatePlan::read_public(&filename)?, plan);
        assert!(plan.save_new(&filename).is_err());
        // A perfectly serialized receipt in the user's own directory still
        // cannot become an administrator attestation.
        assert!(RootGateReceipt::read_for_current_process(&filename, &plan).is_err());
        Ok(())
    })();
    // This test created this one fresh directory; remove only its known file.
    let _ = std::fs::remove_file(path.join("plan.json"));
    let _ = std::fs::remove_dir(path);
    result
}
