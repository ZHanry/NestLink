//! Original online remote budget verification and process-wide cumulative
//! ownership. Renewed or freshly decoded copies retain the same spent state.
use crate::{PermitSigner, VerifiedPermit, domain_message, verify_signature};
use ed25519_dalek::Signer;
use nestlink_protocol::{ContractError, ErrorCode, Permission, remote_budget::*};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, OnceLock},
};

const DOMAIN: &[u8] = b"NestLink/remote-business-budget/v1\0";
const MAX_PROCESS_BUDGETS: usize = 4096;
#[derive(Default)]
struct Spent {
    bytes: u64,
    file_write: u64,
    connections: u32,
    terminal: bool,
}
#[derive(Clone)]
pub struct VerifiedRemoteUsageBudget {
    claims: RemoteUsageBudgetClaims,
    spent: Arc<Mutex<Spent>>,
}
type Registry = BTreeMap<String, ([u8; 32], Arc<Mutex<Spent>>)>;
static ORIGINAL_BUDGETS: OnceLock<Mutex<Registry>> = OnceLock::new();
fn denied() -> ContractError {
    ContractError::new(
        ErrorCode::CapacityExceeded,
        "original remote cumulative reservation exhausted or changed",
    )
}
impl PermitSigner {
    pub fn sign_remote_usage_budget(
        &self,
        claims: &RemoteUsageBudgetClaims,
    ) -> Result<SignedRemoteUsageBudget, ContractError> {
        let claims = claims.canonical_bytes()?;
        Ok(SignedRemoteUsageBudget {
            signature: self
                .key
                .sign(&domain_message(DOMAIN, &claims))
                .to_bytes()
                .to_vec(),
            claims,
        })
    }
}
pub fn verify_remote_usage_budget(
    signed: &SignedRemoteUsageBudget,
    permit: &VerifiedPermit,
) -> Result<VerifiedRemoteUsageBudget, ContractError> {
    if signed.claims.is_empty() || signed.claims.len() > MAX_BYTES || signed.signature.len() != 64 {
        return Err(denied());
    }
    verify_signature(&permit.issuer(), DOMAIN, &signed.claims, &signed.signature)?;
    let claims: RemoteUsageBudgetClaims =
        serde_json::from_slice(&signed.claims).map_err(|_| denied())?;
    if claims.canonical_bytes()? != signed.claims {
        return Err(denied());
    }
    claims.check_permit(permit.claims())?;
    let hash = crate::digest(&signed.claims);
    let mut registry = ORIGINAL_BUDGETS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .map_err(|_| denied())?;
    let spent = if let Some((original, spent)) = registry.get(&claims.reservation_id) {
        if *original != hash {
            return Err(denied());
        }
        spent.clone()
    } else {
        if registry.len() >= MAX_PROCESS_BUDGETS {
            return Err(denied());
        }
        let spent = Arc::new(Mutex::new(Spent::default()));
        registry.insert(claims.reservation_id.clone(), (hash, spent.clone()));
        spent
    };
    drop(registry);
    Ok(VerifiedRemoteUsageBudget { claims, spent })
}
impl VerifiedRemoteUsageBudget {
    pub fn claims(&self) -> &RemoteUsageBudgetClaims {
        &self.claims
    }
    pub fn check(&self) -> Result<(), ContractError> {
        if self.spent.lock().map_err(|_| denied())?.terminal {
            return Err(denied());
        }
        Ok(())
    }
    pub fn reserve_connection_attempt(&self) -> Result<(), ContractError> {
        let mut spent = self.spent.lock().map_err(|_| denied())?;
        if spent.terminal || spent.connections >= self.claims.maximum_connection_attempts {
            spent.terminal = true;
            return Err(denied());
        }
        spent.connections += 1;
        Ok(())
    }
    /// Debit before the original socket/OS delivery. Failure or cancellation
    /// never refunds a promise; queue insertion and permission checks do not debit.
    pub fn charge(&self, permission: Permission, bytes: u64) -> Result<(), ContractError> {
        let mut spent = self.spent.lock().map_err(|_| denied())?;
        let file = if permission == Permission::FileWrite {
            bytes
        } else {
            0
        };
        let next = spent.bytes.checked_add(bytes);
        let next_file = spent.file_write.checked_add(file);
        if spent.terminal
            || next.is_none_or(|n| n > self.claims.maximum_bytes)
            || next_file.is_none_or(|n| n > self.claims.maximum_file_write_bytes)
        {
            spent.terminal = true;
            return Err(denied());
        }
        spent.bytes = next.ok_or_else(denied)?;
        spent.file_write = next_file.ok_or_else(denied)?;
        Ok(())
    }
    pub fn spent_bytes(&self) -> Result<u64, ContractError> {
        Ok(self.spent.lock().map_err(|_| denied())?.bytes)
    }
    pub fn connection_attempts(&self) -> Result<u32, ContractError> {
        Ok(self.spent.lock().map_err(|_| denied())?.connections)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn fixture() -> Result<(PermitSigner, VerifiedPermit, SignedRemoteUsageBudget)> {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/vectors/session-permit-v1.json"
        ))?;
        let hex = vector["claims_hex"].as_str().ok_or("claims vector")?;
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut claims = nestlink_protocol::PermitClaims::decode(bytes.as_slice())?;
        claims.required_capabilities.push(CAPABILITY.into());
        let signer = PermitSigner::generate();
        let permit =
            crate::verify_permit(&signer.sign(&claims)?.encode_to_vec(), &signer.public_key())?;
        let budget = RemoteUsageBudgetClaims {
            version: 1,
            reservation_id: uuid::Uuid::new_v4().to_string(),
            deployment_id: claims.deployment_id.clone(),
            security_epoch: claims.security_epoch,
            session_id: claims.session_id.clone(),
            account_id: claims.account_id.clone(),
            controller_device_id: claims.controller_device_id.clone(),
            host_device_id: claims.host_device_id.clone(),
            controller_key_sha256: claims.controller_key_sha256.as_slice().try_into()?,
            host_key_sha256: claims.host_key_sha256.as_slice().try_into()?,
            resource_id: claims.resource_id.clone(),
            connection_generation: claims.connection_generation,
            policy_revision: claims.policy_revision,
            capability_sha256: claims.capability_sha256.as_slice().try_into()?,
            permissions: claims.permissions.clone(),
            paths: claims.paths.clone(),
            maximum_bytes: 100,
            maximum_file_write_bytes: 0,
            maximum_connection_attempts: 2,
        };
        let signed = signer.sign_remote_usage_budget(&budget)?;
        Ok((signer, permit, signed))
    }
    #[test]
    fn remote_budget_reverification_clones_and_owner_drop_cannot_reset_spent_bytes() -> Result {
        let (_, permit, signed) = fixture()?;
        let first = permit.clone().with_remote_budget(&signed)?;
        first
            .remote_budget()
            .ok_or("budget")?
            .charge(Permission::View, 60)?;
        let copy = first.clone();
        drop(first);
        let restored = permit.with_remote_budget(&signed)?;
        assert_eq!(restored.remote_budget().ok_or("budget")?.spent_bytes()?, 60);
        copy.remote_budget()
            .ok_or("budget")?
            .charge(Permission::View, 30)?;
        assert!(
            restored
                .remote_budget()
                .ok_or("budget")?
                .charge(Permission::View, 11)
                .is_err()
        );
        assert!(copy.remote_budget().ok_or("budget")?.check().is_err());
        Ok(())
    }
    #[test]
    fn remote_budget_failed_connections_are_permanent_and_file_write_is_separate() -> Result {
        let (_, permit, signed) = fixture()?;
        let verified = permit.with_remote_budget(&signed)?;
        let budget = verified.remote_budget().ok_or("budget")?;
        budget.reserve_connection_attempt()?;
        budget.reserve_connection_attempt()?;
        assert_eq!(budget.connection_attempts()?, 2);
        assert!(budget.reserve_connection_attempt().is_err());
        let (_, permit, signed) = fixture()?;
        let verified = permit.with_remote_budget(&signed)?;
        assert!(
            verified
                .remote_budget()
                .ok_or("budget")?
                .charge(Permission::FileWrite, 1)
                .is_err()
        );
        Ok(())
    }
    #[test]
    fn remote_budget_wrong_scope_signature_or_same_id_expansion_is_rejected() -> Result {
        let (signer, permit, mut signed) = fixture()?;
        let original = permit.clone().with_remote_budget(&signed)?;
        signed.signature[0] ^= 1;
        assert!(permit.clone().with_remote_budget(&signed).is_err());
        let mut claims = original.remote_budget().ok_or("budget")?.claims().clone();
        claims.maximum_bytes += 1;
        assert!(
            permit
                .clone()
                .with_remote_budget(&signer.sign_remote_usage_budget(&claims)?)
                .is_err()
        );
        claims.reservation_id = uuid::Uuid::new_v4().to_string();
        claims.capability_sha256 = [3; 32];
        assert!(
            permit
                .with_remote_budget(&signer.sign_remote_usage_budget(&claims)?)
                .is_err()
        );
        Ok(())
    }
}
