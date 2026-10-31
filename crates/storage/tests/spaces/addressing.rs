use super::*;
use nestlink_protocol::spaces::addressing::*;

fn join(f: &mut Fixture, actor: &Principal, installation: &str, epoch: u64) -> Result {
    let revision = f.view()?.revision;
    f.store.join_space_device(actor,&f.space.space_id,SpaceDeviceJoin {
        expected_revision:revision,
        expected_membership_epoch:epoch,
        installation_id:installation.into(),
    },NOW)?;
    Ok(())
}

fn issue(f: &mut Fixture, installation: &str, name: &str) -> Result<SpaceAddressDirectory> {
    let directory = f.store.space_address_directory(&f.owner,&f.space.space_id,NOW)?;
    let epoch = directory.addresses.iter().find(|a| a.installation_id == installation).map_or(0,|a|a.address_epoch);
    let membership = f.store.space_details(&f.owner,&f.space.space_id,NOW)?.devices.into_iter().find(|d|d.installation_id == installation).ok_or("missing device")?.membership_epoch;
    Ok(f.store.issue_space_address(&f.owner,&f.space.space_id,SpaceAddressIssue {
        expected_revision:directory.revision,
        expected_address_epoch:epoch,
        expected_membership_epoch:membership,
        installation_id:installation.into(), name:name.into(),
    },NOW)?)
}

#[test]
fn dual_stack_is_stable_and_names_reservations_revocation_have_independent_cas() -> Result {
    let mut f = Fixture::new()?;
    let owner = f.owner.clone();
    let device = f.enroll(&owner)?;
    join(&mut f,&owner,&device,0)?;
    let before = f.view()?;
    let first = issue(&mut f,&device,"My-NAS")?;
    let address = &first.addresses[0];
    assert_eq!(first.revision,1);
    assert_eq!(address.name,"my-nas");
    assert_eq!(address.fqdn,format!("my-nas.s-{}.nestlink.internal",f.space.space_id));
    assert!(address.active);
    assert_eq!(address.membership_epoch,1);
    assert_eq!(first.cache_max_age_seconds,0);
    let repeated = issue(&mut f,&device,"MY-NAS")?;
    assert_eq!(repeated.revision,first.revision);
    assert_eq!(repeated.addresses[0].ipv4,address.ipv4);
    assert_eq!(repeated.addresses[0].ipv6,address.ipv6);
    assert_eq!(repeated.addresses[0].address_epoch,address.address_epoch);
    let reopened = Store::open_existing(&f.path,&f.deployment)?;
    assert_eq!(reopened.space_address_directory(&owner,&f.space.space_id,NOW)?.addresses[0].ipv4,address.ipv4);
    drop(reopened);
    let renamed = f.store.rename_space_address(&owner,&f.space.space_id,&device,SpaceAddressRename {
        expected_revision:first.revision,expected_address_epoch:address.address_epoch,name:"files".into(),
    },NOW)?;
    assert_eq!(renamed.addresses[0].name,"files");
    assert_eq!(renamed.addresses[0].ipv4,address.ipv4);
    assert_eq!(renamed.addresses[0].address_epoch,2);
    assert!(matches!(f.store.rename_space_address(&owner,&f.space.space_id,&device,SpaceAddressRename {
        expected_revision:first.revision,expected_address_epoch:2,name:"stale".into(),
    },NOW),Err(StorageError::Conflict)));
    let reserved = f.store.reserve_space_address(&owner,&f.space.space_id,&device,SpaceAddressReservation {
        expected_revision:renamed.revision,expected_address_epoch:2,ipv4:"100.100.1.8".into(),ipv6:"fd4e:6573:744c:0:0:0:0:8888".into(),
    },NOW)?;
    assert_eq!(reserved.addresses[0].ipv6,"fd4e:6573:744c::8888");
    assert!(reserved.addresses[0].reserved);
    let after = f.view()?;
    assert_eq!(before.revision,after.revision);
    assert_eq!(before.policy_epoch,after.policy_epoch);
    let revoked = f.store.revoke_space_address(&owner,&f.space.space_id,&device,SpaceAddressRevocation {
        expected_revision:reserved.revision,expected_address_epoch:3,
    },NOW)?;
    assert!(!revoked.addresses[0].active);
    assert!(revoked.addresses[0].revoked);
    let reissued = issue(&mut f,&device,"files")?;
    assert_eq!(reissued.addresses[0].address_epoch,5);
    assert_ne!(reissued.addresses[0].ipv4,address.ipv4);
    assert_ne!(reissued.addresses[0].ipv6,address.ipv6);
    assert!(reissued.addresses[0].active);
    let actions = f.store.space_audit(&owner,&f.space.space_id,NOW)?;
    for action in ["space_address_issued","space_address_renamed","space_address_reserved","space_address_revoked"] {
        assert!(actions.iter().any(|entry|entry.action == action));
    }
    assert!(matches!(f.store.space_address_directory(&owner,&f.space.space_id,NOW-1),Err(StorageError::Conflict)));
    Ok(())
}

#[test]
fn directory_permissions_duplicate_names_and_global_address_collisions_fail_closed() -> Result {
    let mut f = Fixture::new()?;
    let owner = f.owner.clone();
    let alice = f.alice.clone();
    let invitation = f.invite(&owner,Some(alice.account_id.clone()),SpaceRole::Member)?;
    f.accept(&alice,&invitation)?;
    let a = f.enroll(&alice)?;
    let b = f.enroll(&owner)?;
    join(&mut f,&alice,&a,0)?;
    join(&mut f,&owner,&b,0)?;
    let first = issue(&mut f,&a,"same")?;
    assert!(matches!(issue(&mut f,&b,"SAME"),Err(error) if error.downcast_ref::<StorageError>().is_some_and(|e|matches!(e,StorageError::Conflict))));
    let second = issue(&mut f,&b,"owner")?;
    let own = f.store.space_address_directory(&alice,&f.space.space_id,NOW)?;
    assert_eq!(own.addresses.len(),1);
    assert_eq!(own.addresses[0].installation_id,a);
    assert!(matches!(f.store.space_address_directory(&f.bob,&f.space.space_id,NOW),Err(StorageError::Forbidden)));
    assert!(matches!(f.store.issue_space_address(&alice,&f.space.space_id,SpaceAddressIssue {
        expected_revision:second.revision,expected_address_epoch:1,expected_membership_epoch:1,installation_id:a.clone(),name:"same".into(),
    },NOW),Err(StorageError::Forbidden)));
    assert!(matches!(f.store.reserve_space_address(&owner,&f.space.space_id,&b,SpaceAddressReservation {
        expected_revision:second.revision,expected_address_epoch:1,ipv4:first.addresses[0].ipv4.clone(),ipv6:"fd4e:6573:744c::1234".into(),
    },NOW),Err(StorageError::Conflict)));
    for (v4,v6) in [("100.64.0.0","fd4e:6573:744c::2"),("100.64.0.1","fd4e:6573:744c::2"),("100.64.0.255","fd4e:6573:744c::2"),("127.0.0.2","fd4e:6573:744c::2"),("100.64.0.2","fd4e:6573:744c::1"),("100.64.0.2","::1")] {
        assert!(matches!(f.store.reserve_space_address(&owner,&f.space.space_id,&b,SpaceAddressReservation {
            expected_revision:second.revision,expected_address_epoch:1,ipv4:v4.into(),ipv6:v6.into(),
        },NOW),Err(StorageError::Invalid(_))));
    }
    for name in ["a.b","-bad","bad-","中文","local name",""] {
        assert!(matches!(f.store.rename_space_address(&owner,&f.space.space_id,&b,SpaceAddressRename {
            expected_revision:second.revision,expected_address_epoch:1,name:name.into(),
        },NOW),Err(StorageError::Invalid(_))));
    }
    let other = f.store.create_space(&owner,SpaceCreateRequest { name:"other".into() },f.signer.public_key(),NOW)?;
    f.store.join_space_device(&owner,&other.space_id,SpaceDeviceJoin { expected_revision:other.revision,expected_membership_epoch:0,installation_id:b.clone() },NOW)?;
    let other_directory = f.store.issue_space_address(&owner,&other.space_id,SpaceAddressIssue { expected_revision:0,expected_address_epoch:0,expected_membership_epoch:1,installation_id:b.clone(),name:"same".into() },NOW)?;
    let other_address = &other_directory.addresses[0];
    assert_ne!(other_address.ipv4,first.addresses[0].ipv4);
    assert_ne!(other_address.ipv6,first.addresses[0].ipv6);
    assert_ne!(other_directory.suffix,first.suffix);
    assert!(matches!(f.store.reserve_space_address(&owner,&other.space_id,&b,SpaceAddressReservation {
        expected_revision:1,expected_address_epoch:1,ipv4:other_address.ipv4.clone(),ipv6:first.addresses[0].ipv6.clone(),
    },NOW),Err(StorageError::Conflict)));
    assert_eq!(f.store.space_address_directory(&owner,&other.space_id,NOW)?.revision,1);
    Ok(())
}

#[test]
fn member_epoch_key_replacement_and_archive_invalidate_without_identity_inheritance() -> Result {
    let mut f = Fixture::new()?;
    let owner = f.owner.clone();
    let alice = f.alice.clone();
    let invitation = f.invite(&owner,Some(alice.account_id.clone()),SpaceRole::Member)?;
    f.accept(&alice,&invitation)?;
    let device = f.enroll(&alice)?;
    join(&mut f,&alice,&device,0)?;
    let original = issue(&mut f,&device,"nas")?;
    let revision = f.view()?.revision;
    f.store.remove_space_device(&owner,&f.space.space_id,&device,SpaceDeviceRemoval { expected_revision:revision,expected_membership_epoch:1 },NOW)?;
    assert!(f.store.space_address_directory(&alice,&f.space.space_id,NOW)?.addresses.is_empty());
    assert!(!f.store.space_address_directory(&owner,&f.space.space_id,NOW)?.addresses[0].active);
    join(&mut f,&alice,&device,2)?;
    assert!(!f.store.space_address_directory(&owner,&f.space.space_id,NOW)?.addresses[0].active);
    assert!(issue(&mut f,&device,"nas").is_err());
    f.store.revoke_space_address(&owner,&f.space.space_id,&device,SpaceAddressRevocation { expected_revision:original.revision,expected_address_epoch:1 },NOW)?;
    let current = issue(&mut f,&device,"nas")?;
    assert_eq!(current.addresses[0].membership_epoch,3);
    assert_ne!(current.addresses[0].ipv4,original.addresses[0].ipv4);
    let replacement = InstallationIdentity::generate();
    let db = Connection::open(&f.path)?;
    db.execute("UPDATE device_details SET public_key=?1 WHERE device_id=?2",params![replacement.public_key().as_slice(),device])?;
    db.execute("UPDATE devices SET key_sha256=?1 WHERE id=?2",params![nestlink_identity::digest(&replacement.public_key()).as_slice(),device])?;
    db.execute("UPDATE network_memberships SET public_key=?1 WHERE space_id=?2 AND installation_id=?3",params![replacement.public_key().as_slice(),f.space.space_id,device])?;
    assert!(f.store.space_address_directory(&alice,&f.space.space_id,NOW)?.addresses.is_empty());
    assert!(!f.store.space_address_directory(&owner,&f.space.space_id,NOW)?.addresses[0].active);
    assert!(issue(&mut f,&device,"nas").is_err());
    let revision = f.view()?.revision;
    let archived = f.store.archive_space(&owner,&f.space.space_id,SpaceRevisionRequest { expected_revision:revision },NOW)?;
    assert!(archived.archived);
    assert!(!f.store.space_address_directory(&owner,&f.space.space_id,NOW)?.addresses[0].active);
    assert!(matches!(f.store.revoke_space_address(&owner,&f.space.space_id,&device,SpaceAddressRevocation { expected_revision:current.revision,expected_address_epoch:3 },NOW),Err(StorageError::Forbidden)));
    Ok(())
}

#[test]
fn concurrent_directory_writers_commit_one_cas_and_audit_failure_rolls_back() -> Result {
    let mut f = Fixture::new()?;
    let owner = f.owner.clone();
    let device = f.enroll(&owner)?;
    join(&mut f,&owner,&device,0)?;
    issue(&mut f,&device,"nas")?;
    let barrier = Arc::new(Barrier::new(2));
    let mut workers = Vec::new();
    for name in ["first","second"] {
        let path = f.path.clone();
        let deployment = f.deployment.clone();
        let actor = owner.clone();
        let space = f.space.space_id.clone();
        let installation = device.clone();
        let start = barrier.clone();
        workers.push(std::thread::spawn(move || -> std::result::Result<bool,StorageError> {
            let mut store = Store::open_existing(&path,&deployment)?;
            start.wait();
            match store.rename_space_address(&actor,&space,&installation,SpaceAddressRename {
                expected_revision:1,expected_address_epoch:1,name:name.into(),
            },NOW) {
                Ok(_) => Ok(true),
                Err(StorageError::Conflict) => Ok(false),
                Err(error) => Err(error),
            }
        }));
    }
    let mut committed = 0;
    for worker in workers { if worker.join().map_err(|_|"directory writer panicked")?? { committed += 1; } }
    assert_eq!(committed,1);
    let before = f.store.space_address_directory(&owner,&f.space.space_id,NOW)?;
    assert_eq!(before.revision,2);
    assert_eq!(before.addresses[0].address_epoch,2);
    let db = Connection::open(&f.path)?;
    db.execute("UPDATE audit_settings SET high_watermark=9223372036854775807",[])?;
    assert!(f.store.rename_space_address(&owner,&f.space.space_id,&device,SpaceAddressRename {
        expected_revision:2,expected_address_epoch:2,name:"must-rollback".into(),
    },NOW).is_err());
    let after = f.store.space_address_directory(&owner,&f.space.space_id,NOW)?;
    assert_eq!(after.revision,before.revision);
    assert_eq!(after.addresses[0].name,before.addresses[0].name);
    assert_eq!(after.addresses[0].address_epoch,before.addresses[0].address_epoch);
    Ok(())
}

#[test]
fn schema_38_upgrade_preserves_existing_memberships_and_starts_an_empty_directory() -> Result {
    let mut f = Fixture::new()?;
    let owner = f.owner.clone();
    let device = f.enroll(&owner)?;
    join(&mut f,&owner,&device,0)?;
    let before = f.view()?;
    let db = Connection::open(&f.path)?;
    db.execute_batch("DROP TABLE network_space_addresses; DROP TABLE network_space_address_directories; PRAGMA user_version=37;")?;
    drop(db);
    f.store = Store::open_existing(&f.path,&f.deployment)?;
    let after = f.view()?;
    assert_eq!(after.revision,before.revision);
    assert_eq!(after.policy_epoch,before.policy_epoch);
    let details = f.store.space_details(&owner,&f.space.space_id,NOW)?;
    assert!(details.devices.iter().any(|d|d.installation_id == device && d.active && d.membership_epoch == 1));
    let empty = f.store.space_address_directory(&owner,&f.space.space_id,NOW)?;
    assert_eq!(empty.revision,0);
    assert!(empty.addresses.is_empty());
    assert!(issue(&mut f,&device,"migrated")?.addresses[0].active);
    Ok(())
}

#[test]
fn dense_manual_reservations_stop_after_a_bounded_probe_window_without_a_write() -> Result {
    let mut f = Fixture::new()?;
    let owner = f.owner.clone();
    let initial = f.enroll(&owner)?;
    join(&mut f,&owner,&initial,0)?;
    issue(&mut f,&initial,"initial")?;
    let target = f.enroll(&owner)?;
    join(&mut f,&owner,&target,0)?;
    let db = Connection::open(&f.path)?;
    // Seed a durable high-water slot and dense manual reservations in its next
    // 128 positions. Stale identities intentionally still occupy reservations
    // until explicit revocation; the allocator must not walk beyond its budget.
    db.execute("UPDATE network_space_addresses SET allocation_slot=129 WHERE space_id=?1",[&f.space.space_id])?;
    let mut first_seed = None;
    for slot in 130_u32..=257 {
        let v4 = std::net::Ipv4Addr::from(u32::from(std::net::Ipv4Addr::new(100,64,0,0))+slot);
        if !(2..=254).contains(&v4.octets()[3]) { continue; }
        let installation = random_id();
        if first_seed.is_none() { first_seed = Some(installation.clone()); }
        let key = nestlink_identity::digest(&slot.to_be_bytes());
        db.execute("INSERT INTO devices(id,account_id,key_sha256) VALUES(?1,?2,?3)",params![installation,owner.account_id,key.as_slice()])?;
        db.execute("INSERT INTO network_space_addresses(space_id,installation_id,account_id,public_key,account_member_epoch,membership_epoch,address_epoch,name,ipv4,ipv6,allocation_slot,reserved,revoked) VALUES(?1,?2,?3,?4,1,1,1,?5,?6,?7,2,1,0)",
            params![f.space.space_id,installation,owner.account_id,key.as_slice(),format!("reserved-{slot}"),v4.to_string(),format!("fd4e:6573:744c::{:x}",0x10_000+slot)])?;
    }
    let before = f.store.space_address_directory(&owner,&f.space.space_id,NOW)?;
    assert!(matches!(f.store.issue_space_address(&owner,&f.space.space_id,SpaceAddressIssue {
        expected_revision:before.revision,expected_address_epoch:0,expected_membership_epoch:1,installation_id:target.clone(),name:"target".into(),
    },NOW),Err(StorageError::RateLimited)));
    let after = f.store.space_address_directory(&owner,&f.space.space_id,NOW)?;
    assert_eq!(after.revision,before.revision);
    assert_eq!(after.addresses.len(),before.addresses.len());
    assert!(!after.addresses.iter().any(|a|a.installation_id == target));
    db.execute("UPDATE network_space_addresses SET revoked=1 WHERE space_id=?1 AND installation_id=?2",params![f.space.space_id,first_seed.ok_or("missing seeded reservation")?])?;
    let recovered = issue(&mut f,&target,"target")?;
    assert!(recovered.addresses.iter().any(|a|a.installation_id == target && a.active && a.ipv4 == "100.64.0.130"));
    Ok(())
}
