//! The original Session and carrier can use independently consumed offline
//! authority. The frozen online signature binds metadata, never its lifetime.
use super::*;
use nestlink_identity::offline::{OfflineAdmission, OfflineVerification};
use nestlink_protocol::offline::{OfflineBusiness, OfflineDirectTransport, OfflineRemoteOperation};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Clone)]
pub struct OfflineRemoteAuthority(Arc<Mutex<OfflineAdmission>>);
#[derive(Clone, Debug)]
pub struct OfflineRemoteStatus {
    pub remaining_bytes: u64,
    pub remaining_file_write_bytes: u64,
    pub connection_attempts: u32,
    pub remaining_lifetime: std::time::Duration,
    pub stopped: bool,
}
fn operation(permission: Permission) -> Result<OfflineRemoteOperation, ContractError> {
    Ok(match permission {
        Permission::View => OfflineRemoteOperation::View,
        Permission::Audio => OfflineRemoteOperation::Audio,
        Permission::Input => OfflineRemoteOperation::Input,
        Permission::ClipboardRead => OfflineRemoteOperation::ClipboardRead,
        Permission::ClipboardWrite => OfflineRemoteOperation::ClipboardWrite,
        Permission::FileRead => OfflineRemoteOperation::FileRead,
        Permission::FileWrite => OfflineRemoteOperation::FileWrite,
        _ => return Err(error(ErrorCode::PermissionRequired, "unrecognized offline remote operation")),
    })
}
impl OfflineRemoteAuthority {
    pub fn new(admission: OfflineAdmission) -> Result<Self, ContractError> {
        if !matches!(admission.claims().business, OfflineBusiness::RemoteControl {..}) {
            return Err(error(ErrorCode::PermissionRequired, "private service cannot become remote authority"));
        }
        Ok(Self(Arc::new(Mutex::new(admission))))
    }
    fn lock(&self) -> Result<MutexGuard<'_, OfflineAdmission>, ContractError> {
        self.0.lock().map_err(|_| error(ErrorCode::PolicyRevoked, "offline owner lock failed"))
    }
    pub fn claims(&self) -> Result<nestlink_protocol::offline::OfflineGrantBundleClaims, ContractError> {
        Ok(self.lock()?.claims().clone())
    }
    pub fn local_endpoint(&self) -> Result<usize, ContractError> { Ok(self.lock()?.local_endpoint()) }
    pub fn digest(&self) -> [u8; 32] {
        self.0.lock().map_or([0;32], |owner|owner.digest())
    }
    pub fn check(&self, wall: u64) -> Result<(), ContractError> { self.lock()?.check_current(wall) }
    pub fn status(&self) -> Result<OfflineRemoteStatus, ContractError> {
        let owner=self.lock()?;
        Ok(OfflineRemoteStatus {
            remaining_bytes:owner.claims().resources.byte_limit.saturating_sub(owner.spent_bytes()),
            remaining_file_write_bytes:owner.claims().resources.file_write_limit.saturating_sub(owner.written_bytes()),
            connection_attempts:owner.connections(), remaining_lifetime:owner.remaining_lifetime(), stopped:owner.is_stopped(),
        })
    }
    pub fn stop(&self) { if let Ok(mut owner)=self.0.lock() {owner.stop();} }
    pub fn reserve_attempt(&self, wall:u64, transport:OfflineDirectTransport) -> Result<(), ContractError> {
        self.lock()?.reserve_connection_attempt(wall,transport)
    }
    pub fn authenticate(&self, wall:u64, transport:OfflineDirectTransport, peer:&[u8;32]) -> Result<(),ContractError> {
        self.lock()?.authenticate_reserved_connection(wall,transport,peer)
    }
    pub fn sign_channel_proof(&self, wall:u64, binding:&nestlink_protocol::offline::channel::OfflineChannelBinding) -> Result<Vec<u8>,ContractError> {
        self.lock()?.sign_channel_proof(wall,binding)
    }
    pub fn observe_online(&self, context:&OfflineVerification<'_>) -> Result<(),ContractError> {
        self.lock()?.observe_online(context)
    }
    fn authorize(&self, permission: Permission, wall:u64) -> Result<(),ContractError> {
        self.lock()?.admit_remote_operation(wall,operation(permission)?,0)
    }
    fn charge(&self, permission:Permission, bytes:u64, wall:u64) -> Result<(),ContractError> {
        self.lock()?.admit_remote_operation(wall,operation(permission)?,bytes)
    }
}
impl Session {
    /// `original` is retained unchanged for exact scope and source metadata. Its
    /// online deadline is neither used nor renewed; authority is the independently
    /// signed, online-consumed and process-bound offline owner. Fresh original
    /// endpoint proof still precedes every business queue and reconnect.
    pub fn activate_offline(
        original:VerifiedPermit, binding:SessionBinding,
        authority:OfflineRemoteAuthority, now:ClockSample,
    ) -> Result<Self,ContractError> {
        validate_binding_with_rollout(&original,&binding,Path::Direct,false)?;
        authority.check(now.unix_ms)?;
        let owner=authority.lock()?;
        let claims=owner.claims();let c=original.claims();
        let OfflineBusiness::RemoteControl {resource_id,operations,capability_digest}=&claims.business else {
            return Err(error(ErrorCode::PermissionRequired,"remote offline business required"));
        };
        if c.is_setup() || claims.deployment_id!=c.deployment_id || claims.security_epoch!=c.security_epoch
            || resource_id!=&c.resource_id || capability_digest.as_slice()!=c.capability_sha256
            || claims.members[0].installation_id!=c.controller_device_id || claims.members[1].installation_id!=c.host_device_id
            || claims.members[0].account_id!=c.account_id
            || digest(&claims.members[0].public_key).as_slice()!=c.controller_key_sha256
            || digest(&claims.members[1].public_key).as_slice()!=c.host_key_sha256
            || !operations.contains(&OfflineRemoteOperation::View)
            || operations.iter().any(|op|!c.permissions.contains(&(op.permission() as i32)))
            || owner.connections()==0 || owner.remaining_lifetime().is_zero()
        {return Err(error(ErrorCode::IdentityMismatch,"offline authority differs from original approved remote scope"));}
        let remaining:u64=owner.remaining_lifetime().min(std::time::Duration::from_millis(claims.expires_at_ms.saturating_sub(now.unix_ms))).as_millis().try_into().map_err(|_|error(ErrorCode::LeaseExpired,"offline lifetime overflow"))?;
        let deadline_ms=now.monotonic_ms.checked_add(remaining).ok_or_else(||error(ErrorCode::LeaseExpired,"offline deadline overflow"))?;
        drop(owner);
        let mut challenge=[0;32];OsRng.fill_bytes(&mut challenge);
        Ok(Self {
            #[cfg(feature="media-runtime-test-support")]
            media_regression:false,
            binding,permit:original,offline:Some(authority),path:Path::Direct,state:SessionState::AwaitingProof,
            deadline_ms,lifetime_deadline_ms:Some(deadline_ms),last_monotonic_ms:now.monotonic_ms,
            last_unix_ms:now.unix_ms,last_request_ms:now.monotonic_ms,proved:0,challenge,
        })
    }
    pub fn is_offline(&self) -> bool {self.offline.is_some()}
    /// Original delivery boundary shared by stream, QUIC, file and media paths.
    pub fn charge_business(&mut self, permission:Permission, path:Path, bytes:u64, now:ClockSample) -> Result<(),ContractError> {
        self.check_clock(now)?;self.authorize(permission,path,now.monotonic_ms)?;
        match &self.offline {
            Some(offline)=>offline.charge(permission,bytes,now.unix_ms),
            None=>match self.permit.remote_budget() {Some(budget)=>budget.charge(permission,bytes),None=>Ok(())},
        }
    }
}
