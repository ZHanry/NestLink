use super::*;
use nestlink_protocol::{Path, remote_budget::*};

fn enrolled(store: &mut Store, actor: &Principal, identity: &InstallationIdentity, supports: bool) -> Result<String> {
    let challenge = store.enrollment_challenge(actor, 1000)?;
    let mut capabilities = vec!["host".into(), "controller".into(), "vp8".into()];
    if supports { capabilities.push(CAPABILITY.into()); }
    let mut body = DeviceRegistration {
        challenge_id: challenge.id,
        device: DeviceDescriptor { id:random_id(), name:"original remote budget".into(), platform:"windows".into(),
            public_key:URL_SAFE_NO_PAD.encode(identity.public_key()), capabilities, path_mode:"direct_only".into() },
        signature:String::new(),
    };
    body.signature = URL_SAFE_NO_PAD.encode(identity.sign_action(&store.registration_transcript(actor,&body,1000)?)?);
    let id = body.device.id.clone();
    store.register_device(actor,body,1000)?;
    Ok(id)
}
fn approved(store: &mut Store, c: &Principal, h: &Principal, controller: &str, host: &str, identity: &InstallationIdentity) -> Result<String> {
    let request = store.create_remote(c, RemoteRequest {id:random_id(),controller_device_id:controller.into(),host_device_id:host.into(),permissions:vec![Permission::View as i32],path_mode:"direct_only".into()},1000)?;
    let choice = ApprovalChoice {approved:true, permissions:vec![Permission::View as i32], paths:vec![Path::Direct as i32]};
    let proof = store.approval_transcript(h,&request.id,&choice,1001)?;
    store.approve_remote(h,&request.id,choice,&URL_SAFE_NO_PAD.encode(identity.sign_action(&proof)?),1001)?;
    Ok(request.id)
}
#[test]
fn remote_budget_online_reservation_is_permanent_same_owner_across_reads_and_renewal() -> Result {
    let (mut store,_,_,admin,member) = fixture()?;
    let controller = InstallationIdentity::generate(); let host = InstallationIdentity::generate();
    let c = enrolled(&mut store,&admin,&controller,true)?; let h=enrolled(&mut store,&member,&host,true)?;
    let id = approved(&mut store,&admin,&member,&c,&h,&host)?;
    let first = store.initial_permit(&admin,&id,1002)?;
    let budget = store.remote_usage_budget(&admin,&first,1002)?.ok_or("missing original budget")?;
    assert_eq!(budget.maximum_bytes, ONLINE_PROMISE_BYTES);
    assert_eq!(budget.maximum_file_write_bytes,0);
    let usage = store.remote_budget_quota(&admin,"account",&admin.account_id,1002)?.ok_or("missing original ledger")?;
    assert_eq!(usage.promised_bytes,ONLINE_PROMISE_BYTES);
    for _ in 0..2 {
        let repeat=store.initial_permit(&admin,&id,1003)?;
        assert_eq!(store.remote_usage_budget(&admin,&repeat,1003)?,Some(budget.clone()));
    }
    let cp=store.renewal_transcript(&admin,&id,2,false,1004)?; let hp=store.renewal_transcript(&admin,&id,2,true,1004)?;
    let renewed=store.renew_permit(&admin,&id,RenewalSubmission {lease_sequence:2,controller_signature:URL_SAFE_NO_PAD.encode(controller.sign_action(&cp)?),host_signature:URL_SAFE_NO_PAD.encode(host.sign_action(&hp)?)},1004)?;
    assert_eq!(store.remote_usage_budget(&admin,&renewed,1004)?,Some(budget));
    store.revoke_remote(&member,&id)?;
    assert_eq!(store.remote_budget_quota(&admin,"account",&admin.account_id,1004)?.ok_or("missing ledger")?,usage);
    assert!(store.remote_usage_budget(&admin,&renewed,1004).is_err());
    Ok(())
}
#[test]
fn remote_budget_account_exhaustion_and_failed_issuance_are_atomic_and_restore_fenced() -> Result {
    let (mut store,_,_,admin,member)=fixture()?;
    let controller=InstallationIdentity::generate(); let host=InstallationIdentity::generate();
    let c=enrolled(&mut store,&admin,&controller,true)?; let h=enrolled(&mut store,&member,&host,true)?;
    store.set_remote_budget_quota(&admin,"account",&admin.account_id,RemoteBudgetQuotaUpdate {expected_revision:0,maximum_bytes:ONLINE_PROMISE_BYTES,maximum_file_write_bytes:0,maximum_connection_attempts:64},1001)?;
    let id=approved(&mut store,&admin,&member,&c,&h,&host)?;
    store.initial_permit(&admin,&id,1002)?;
    let second=approved(&mut store,&admin,&member,&c,&h,&host)?;
    assert!(matches!(store.initial_permit(&admin,&second,1002),Err(StorageError::RateLimited)));
    assert_eq!(store.remote(&admin,&second)?.lease_sequence,0);
    assert!(store.remote_budget_quota(&admin,"resource",&second,1002)?.is_none());
    assert_eq!(store.remote_budget_quota(&admin,"device",&h,1002)?.ok_or("missing host ledger")?.promised_bytes,ONLINE_PROMISE_BYTES);
    assert!(store.set_remote_budget_quota(&member,"account",&member.account_id,RemoteBudgetQuotaUpdate {expected_revision:0,maximum_bytes:1,maximum_file_write_bytes:0,maximum_connection_attempts:1},1002).is_err());
    store.invalidate_after_restore()?;
    assert!(store.initial_permit(&admin,&second,1003).is_err());
    Ok(())
}
#[test]
fn remote_budget_requires_both_declared_native_endpoints() -> Result {
    for supports in [false,true] {
        let (mut store,_,_,admin,member)=fixture()?;
        let controller=InstallationIdentity::generate(); let host=InstallationIdentity::generate();
        let c=enrolled(&mut store,&admin,&controller,true)?;let h=enrolled(&mut store,&member,&host,supports)?;
        let id=approved(&mut store,&admin,&member,&c,&h,&host)?;
        let permit=store.initial_permit(&admin,&id,1002)?;
        assert_eq!(store.remote_usage_budget(&admin,&permit,1002)?.is_some(),supports);
    }
    Ok(())
}
