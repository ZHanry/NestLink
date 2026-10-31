use super::{REQUEST_TIMEOUT, SpaceDnsError};
use crate::Sdk;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ipnet::{Ipv4Net, Ipv6Net};
use nestlink_protocol::spaces::addressing::SpaceAddressDirectory;
use std::{collections::HashSet, sync::{Arc, atomic::{AtomicU64, Ordering}}, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio::sync::{RwLock, RwLockReadGuard};

const IPV4_POOL: &str = "100.64.0.0/10";
const IPV6_POOL: &str = "fd4e:6573:744c::/48";
const MAX_OBSERVATION_AGE: Duration = Duration::from_secs(5);

#[derive(PartialEq, Eq)]
struct Session {
    origin: String,
    deployment: String,
    issuer: [u8; 32],
    security_epoch: u64,
    account: String,
    session: String,
    generation: u64,
    access_expires: u64,
}

impl Session {
    fn read(sdk: &Sdk) -> Result<Self, SpaceDnsError> {
        let login = sdk.login.as_ref().ok_or(SpaceDnsError::SessionChanged)?;
        if login.principal.access_expires <= wall_ms()? / 1000 {
            return Err(SpaceDnsError::SessionChanged);
        }
        Ok(Self {
            origin: sdk.management_origin().into(), deployment: sdk.trust.deployment_id.clone(),
            issuer: sdk.trust.permit_issuer, security_epoch: sdk.health.security_epoch,
            account: login.principal.account_id.clone(), session: login.principal.session_id.clone(),
            generation: login.generation, access_expires: login.principal.access_expires,
        })
    }
}

pub(super) struct Authority {
    current: Arc<RwLock<Sdk>>,
    session: Session,
    space: String,
    pub(super) suffix: String,
    authority_key: String,
    member_epoch: u64,
    highest_revision: AtomicU64,
}

/// The read guard remains held through response enqueue. A completed SDK
/// replacement can therefore never publish an answer from the previous session.
pub(super) struct Observation<'a> {
    pub(super) directory: SpaceAddressDirectory,
    pub(super) account: &'a str,
    pub(super) deadline: tokio::time::Instant,
    _session: RwLockReadGuard<'a, Sdk>,
}

impl Authority {
    pub(super) async fn bind(current: Arc<RwLock<Sdk>>, space: &str) -> Result<Self, SpaceDnsError> {
        let sdk = current.read().await;
        let session = Session::read(&sdk)?;
        let directory = tokio::time::timeout(REQUEST_TIMEOUT, sdk.space_address_directory(space))
            .await.map_err(|_| SpaceDnsError::Timeout)??;
        let result = Self {
            current: current.clone(), session, space: space.into(),
            suffix: format!("s-{space}.nestlink.internal"),
            authority_key: directory.space.authority_public_key.clone(),
            member_epoch: directory.space.member_epoch,
            highest_revision: AtomicU64::new(directory.revision),
        };
        result.validate(&sdk, &directory)?;
        Ok(result)
    }

    pub(super) async fn observe(&self) -> Result<Observation<'_>, SpaceDnsError> {
        tokio::time::timeout(REQUEST_TIMEOUT, async {
            let sdk = self.current.read().await;
            if Session::read(&sdk)? != self.session { return Err(SpaceDnsError::SessionChanged); }
            let directory = sdk.space_address_directory(&self.space).await?;
            self.validate(&sdk, &directory)?;
            let expires = directory.space.observed_at_unix_ms.saturating_add(MAX_OBSERVATION_AGE.as_millis() as u64)
                .min(self.session.access_expires.saturating_mul(1000));
            let remaining = expires.checked_sub(wall_ms()?).filter(|ms| *ms > 0)
                .ok_or(SpaceDnsError::InvalidDirectory)?;
            let deadline = tokio::time::Instant::now() + Duration::from_millis(remaining);
            Ok(Observation { directory, account: &self.session.account, deadline, _session: sdk })
        }).await.map_err(|_| SpaceDnsError::Timeout)?
    }

    fn validate(&self, sdk: &Sdk, directory: &SpaceAddressDirectory) -> Result<(), SpaceDnsError> {
        let now = wall_ms()?;
        let observed = directory.space.observed_at_unix_ms;
        let key = URL_SAFE_NO_PAD.decode(&directory.space.authority_public_key)
            .map_err(|_| SpaceDnsError::InvalidDirectory)?;
        if Session::read(sdk)? != self.session
            || directory.space.space_id != self.space
            || directory.space.deployment_id != self.session.deployment
            || directory.space.archived || directory.space.member_epoch != self.member_epoch
            || self.member_epoch == 0 || key.len() != 32
            || directory.space.authority_public_key != self.authority_key
            || directory.suffix != self.suffix || directory.cache_max_age_seconds != 0
            || directory.ipv4_pool != IPV4_POOL || directory.ipv6_pool != IPV6_POOL
            || directory.addresses.len() > 4096
            || directory.revision > i64::MAX as u64
            || observed > now.saturating_add(1000)
            || now.saturating_sub(observed) > MAX_OBSERVATION_AGE.as_millis() as u64
        { return Err(SpaceDnsError::InvalidDirectory); }
        let pool4: Ipv4Net = IPV4_POOL.parse().map_err(|_| SpaceDnsError::InvalidDirectory)?;
        let pool6: Ipv6Net = IPV6_POOL.parse().map_err(|_| SpaceDnsError::InvalidDirectory)?;
        let mut names = HashSet::new();
        let mut devices = HashSet::new();
        let mut ipv4s = HashSet::new();
        let mut ipv6s = HashSet::new();
        // Managers can read other accounts' directory rows. The local resolver
        // deliberately narrows that capability, even for the deployment admin.
        for row in directory.addresses.iter().filter(|row| row.active && !row.revoked && row.account_id == self.session.account) {
            let bytes = row.name.as_bytes();
            let public = URL_SAFE_NO_PAD.decode(&row.public_key).map_err(|_| SpaceDnsError::InvalidDirectory)?;
            let v4: std::net::Ipv4Addr = row.ipv4.parse().map_err(|_| SpaceDnsError::InvalidDirectory)?;
            let v6: std::net::Ipv6Addr = row.ipv6.parse().map_err(|_| SpaceDnsError::InvalidDirectory)?;
            if bytes.is_empty() || bytes.len() > 63
                || !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len()-1].is_ascii_alphanumeric()
                || !bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
                || row.fqdn != format!("{}.{}", row.name, self.suffix)
                || !nestlink_protocol::valid_id(&row.installation_id) || public.len() != 32
                || URL_SAFE_NO_PAD.encode(&public) != row.public_key
                || row.account_member_epoch == 0 || row.membership_epoch == 0 || row.address_epoch == 0
                || !pool4.contains(&v4) || !(2..=254).contains(&v4.octets()[3])
                || !pool6.contains(&v6) || u128::from(v6) - u128::from(pool6.network()) <= 1
                || row.ipv4 != v4.to_string() || row.ipv6 != v6.to_string()
                || !names.insert(&row.name) || !devices.insert(&row.installation_id)
                || !ipv4s.insert(v4) || !ipv6s.insert(v6)
            { return Err(SpaceDnsError::InvalidDirectory); }
        }
        if directory.revision < self.highest_revision.fetch_max(directory.revision, Ordering::SeqCst) {
            return Err(SpaceDnsError::InvalidDirectory);
        }
        Ok(())
    }
}

fn wall_ms() -> Result<u64, SpaceDnsError> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok()).ok_or(SpaceDnsError::SessionChanged)
}
