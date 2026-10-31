//! Exact Windows loopback admission through the native WFP ALE layers.
//! The administrator owns only this local fence, not remote service authority.
//! Ordinary Win32 clients share admission by user SID. Session/process-specific
//! native streams continue to use the separate authenticated named-pipe path.
//!
//! Persistent filters survive controller crashes. Expiry removes the permit;
//! only the original process handle becoming signaled permits final cleanup.
#![allow(unsafe_code)]
mod store;
#[cfg(test)]
mod tests;
mod wfp;

use super::{installation, security};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    fs::File,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, FILETIME, GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT},
    System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        WaitForSingleObject,
    },
};

const MAXIMUM_JSON: u64 = 65_536;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}
impl Transport {
    fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub sid: String,
    pub session: u32,
    pub creation: u64,
    pub image: PathBuf,
    pub image_volume: u32,
    pub image_index: u64,
    pub elevated: bool,
    pub integrity: u32,
}
impl ProcessIdentity {
    pub fn read(pid: u32) -> io::Result<Self> {
        Self::from_peer(&security::Peer::open(pid)?)
    }
    fn from_peer(peer: &security::Peer) -> io::Result<Self> {
        let (image_volume, image_index) = store::image(&peer.image)?;
        peer.alive()?;
        Ok(Self {
            pid: peer.pid,
            sid: peer.sid.clone(),
            session: peer.session,
            creation: peer.creation,
            image: peer.image.clone(),
            image_volume,
            image_index,
            elevated: peer.elevated,
            integrity: peer.integrity,
        })
    }
    fn validate(&self) -> io::Result<()> {
        if self.pid == 0
            || !valid_sid(&self.sid)
            || self.session == 0
            || self.creation == 0
            || !self.image.is_absolute()
            || self.image.as_os_str().len() > 32760
            || self.image_index == 0
        {
            return Err(invalid("invalid captured Windows process identity"));
        }
        Ok(())
    }
    fn normal(&self) -> bool {
        !self.elevated && (0x2000..0x3000).contains(&self.integrity)
    }
    fn administrator(&self) -> bool {
        self.elevated && self.integrity == 0x3000
    }
    fn same_image(&self, other: &Self) -> bool {
        self.image_volume == other.image_volume
            && self.image_index == other.image_index
            && security::same_image(&self.image, &other.image)
    }
    /// Do not equate a changed token/image or an access error with physical
    /// exit. Inherited sockets can outlive such changes and still need a fence.
    fn still_alive(&self) -> io::Result<bool> {
        let Some(handle) = process_handle(self.pid)? else {
            return Ok(false);
        };
        if creation(&handle)? != self.creation {
            return Ok(false);
        }
        alive(&handle)
    }
    /// The administrator-owned receipt already attests the helper's token and
    /// image. Medium-integrity clients need only query the original kernel
    /// incarnation and liveness, without querying another user's admin token.
    fn helper_alive(&self) -> io::Result<()> {
        self.validate()?;
        if !self.administrator() || !self.still_alive()? {
            return Err(invalid(
                "original administrative WFP helper is no longer alive",
            ));
        }
        Ok(())
    }
}
fn process_handle(pid: u32) -> io::Result<Option<security::Handle>> {
    if pid == 0 {
        return Err(invalid("invalid process ID"));
    }
    // SAFETY: query/synchronize-only access to one concrete local process.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        let error = unsafe { GetLastError() };
        return if error == ERROR_INVALID_PARAMETER {
            Ok(None)
        } else {
            Err(io::Error::from_raw_os_error(error as i32))
        };
    }
    Ok(Some(security::Handle(raw)))
}
fn creation(handle: &security::Handle) -> io::Result<u64> {
    let (mut created, mut exited, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: owned process handle and complete writable output structures.
    if unsafe { GetProcessTimes(handle.0, &mut created, &mut exited, &mut kernel, &mut user) } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::from(created.dwLowDateTime) | u64::from(created.dwHighDateTime) << 32)
}
fn alive(handle: &security::Handle) -> io::Result<bool> {
    // SAFETY: zero-time wait on an owned synchronize-capable process handle.
    match unsafe { WaitForSingleObject(handle.0, 0) } {
        WAIT_TIMEOUT => Ok(true),
        WAIT_OBJECT_0 => Ok(false),
        _ => Err(io::Error::last_os_error()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatePlan {
    pub schema_version: u16,
    pub owner_id: String,
    pub endpoint: SocketAddr,
    pub transport: Transport,
    pub process: ProcessIdentity,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
}
impl GatePlan {
    pub fn for_current_process(
        owner_id: String,
        endpoint: SocketAddr,
        transport: Transport,
        expires_at_ms: u64,
    ) -> io::Result<Self> {
        let plan = Self {
            schema_version: 1,
            owner_id,
            endpoint,
            transport,
            process: ProcessIdentity::read(std::process::id())?,
            created_at_ms: wall_ms()?,
            expires_at_ms,
        };
        plan.validate(true)?;
        Ok(plan)
    }
    pub fn validate(&self, fresh: bool) -> io::Result<()> {
        self.process.validate()?;
        let now = wall_ms()?;
        let loopback = match self.endpoint.ip() {
            IpAddr::V4(ip) => ip == Ipv4Addr::LOCALHOST,
            IpAddr::V6(ip) => ip == Ipv6Addr::LOCALHOST,
        };
        if self.schema_version != 1
            || !uuid(&self.owner_id)
            || !loopback
            || self.endpoint.port() == 0
            || !self.process.normal()
            || self.expires_at_ms <= self.created_at_ms
            || self.expires_at_ms - self.created_at_ms > 3_600_000
            || fresh
                && (self.created_at_ms > now.saturating_add(1000)
                    || now.saturating_sub(self.created_at_ms) > 300_000
                    || now >= self.expires_at_ms)
        {
            return Err(invalid(
                "invalid or expired ordinary-user Windows loopback plan",
            ));
        }
        Ok(())
    }
    pub fn save_new(&self, path: &Path) -> io::Result<()> {
        self.validate(true)?;
        if !path.is_absolute() || ProcessIdentity::read(std::process::id())? != self.process {
            return Err(invalid("plan must belong to this exact ordinary process"));
        }
        let parent = path
            .parent()
            .ok_or_else(|| invalid("plan parent missing"))?;
        nestlink_platform_security::check_private_directory(parent)?;
        store::save_plan(path, self)
    }
    pub fn read_public(path: &Path) -> io::Result<Self> {
        store::read_plan(path)
    }
    fn marker(&self) -> String {
        format!("NestLink:local-port:v1:{}", self.owner_id)
    }
}
/// Administrator attestation for one pre-existing normal-user plan. Public
/// serialization is OS policy information, never remote service authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootGateReceipt {
    pub schema_version: u16,
    pub plan: GatePlan,
    pub installed: Value,
    pub helper: ProcessIdentity,
}
impl RootGateReceipt {
    pub fn read_for_current_process(path: &Path, expected: &GatePlan) -> io::Result<Self> {
        let parent = store::Parents::open(
            path.parent()
                .ok_or_else(|| invalid("receipt parent missing"))?,
        )?;
        let bytes = parent.read(
            path.file_name()
                .ok_or_else(|| invalid("receipt filename missing"))?,
            false,
        )?;
        let receipt: Self = serde_json::from_slice(&bytes)?;
        receipt.check_current(expected)?;
        Ok(receipt)
    }
    pub fn check_current(&self, expected: &GatePlan) -> io::Result<()> {
        expected.validate(false)?;
        let now = wall_ms()?;
        if self.schema_version != 1
            || self.plan != *expected
            || expected.created_at_ms > now.saturating_add(1000)
            || now >= expected.expires_at_ms
            || ProcessIdentity::read(std::process::id())? != expected.process
            || self.helper.pid == expected.process.pid
            || !self.helper.administrator()
            || !self.helper.same_image(&expected.process)
        {
            return Err(invalid(
                "WFP receipt does not attest this exact live process and unexpired plan",
            ));
        }
        wfp::verify(expected, &self.installed, false)?;
        self.helper.helper_alive()
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u16,
    plan: GatePlan,
    installed: Option<Value>,
    denying: bool,
}
/// No Drop removal. Retained handles hold the original owner, image and
/// journal admission; WFP itself retains the persistent fence after a crash.
pub struct GateOwner {
    store: store::Store,
    engine: wfp::Engine,
    journal: Journal,
    original_owner: security::Peer,
    _image: store::ImageLock,
}
impl GateOwner {
    pub fn initialize_journal(directory: &Path) -> io::Result<()> {
        store::initialize(directory)
    }
    pub async fn install(plan: GatePlan, directory: &Path) -> io::Result<Self> {
        require_admin()?;
        plan.validate(true)?;
        let original_owner = security::Peer::open(plan.process.pid)?;
        let owner_identity = ProcessIdentity::from_peer(&original_owner)?;
        let helper = ProcessIdentity::read(std::process::id())?;
        let image = store::lock_image(&plan.process.image)?;
        if !original_owner.is_normal()
            || owner_identity != plan.process
            || !helper.same_image(&plan.process)
            || image.identity != (plan.process.image_volume, plan.process.image_index)
        {
            return Err(invalid(
                "WFP plan must identify a live ordinary owner of this exact protected executable",
            ));
        }
        let store = store::Store::open(directory)?;
        if store.read()?.is_some() {
            return Err(invalid(
                "recover the original WFP journal before installing another owner",
            ));
        }
        let engine = wfp::Engine::open()?;
        if engine.inspect(&plan)?.is_some() {
            return Err(invalid(
                "WFP gate identity occupied; existing policy is never adopted",
            ));
        }
        let mut journal = Journal {
            schema_version: 1,
            plan,
            installed: None,
            denying: false,
        };
        store.save(&journal)?;
        journal.installed = Some(engine.install(&journal.plan)?);
        store.save(&journal)?;
        let mut owner = Self {
            store,
            engine,
            journal,
            original_owner,
            _image: image,
        };
        if !owner.owner_alive()? || wall_ms()? >= owner.plan().expires_at_ms {
            owner.deny_all().await?;
            return Err(invalid(
                "original owner ended during WFP installation; deny fence retained for recovery",
            ));
        }
        Ok(owner)
    }
    pub fn plan(&self) -> &GatePlan {
        &self.journal.plan
    }
    pub fn is_denied(&self) -> bool {
        self.journal.denying
    }
    pub fn owner_alive(&self) -> io::Result<bool> {
        alive(&self.original_owner.handle)
    }
    pub fn receipt(&self) -> io::Result<Value> {
        Ok(
            serde_json::json!({"schema_version":1,"plan":self.journal.plan,"denying":self.journal.denying,"installed":self.journal.installed.as_ref().ok_or_else(|| invalid("WFP receipt pending"))?}),
        )
    }
    pub async fn publish_receipt(&self, path: &Path) -> io::Result<RootGateReceipt> {
        require_admin()?;
        self.plan().validate(true)?;
        if self.journal.denying
            || ProcessIdentity::read(self.plan().process.pid)? != self.plan().process
        {
            return Err(invalid(
                "a denied or changed owner cannot receive a WFP receipt",
            ));
        }
        self.verify_unchanged().await?;
        let helper = ProcessIdentity::read(std::process::id())?;
        if !helper.administrator() || !helper.same_image(&self.plan().process) {
            return Err(invalid(
                "WFP helper must own this exact protected executable",
            ));
        }
        let receipt = RootGateReceipt {
            schema_version: 1,
            plan: self.plan().clone(),
            installed: self
                .journal
                .installed
                .clone()
                .ok_or_else(|| invalid("WFP receipt pending"))?,
            helper,
        };
        wfp::verify(&receipt.plan, &receipt.installed, false)?;
        let parent = store::Parents::open(
            path.parent()
                .ok_or_else(|| invalid("receipt parent missing"))?,
        )?;
        parent.write(
            path.file_name()
                .ok_or_else(|| invalid("receipt filename missing"))?,
            &serde_json::to_vec_pretty(&receipt)?,
            Some(&receipt.plan.process.sid),
            false,
        )?;
        Ok(receipt)
    }
    pub async fn verify_unchanged(&self) -> io::Result<()> {
        if self.engine.inspect(self.plan())? != self.journal.installed {
            return Err(invalid(
                "WFP gate changed or disappeared; stop listeners and preserve foreign objects",
            ));
        }
        Ok(())
    }
    pub async fn deny_all(&mut self) -> io::Result<()> {
        self.verify_unchanged().await?;
        if self.journal.denying {
            return Ok(());
        }
        let installed = self
            .journal
            .installed
            .as_ref()
            .ok_or_else(|| invalid("original WFP snapshot missing"))?
            .clone();
        self.journal.denying = true;
        self.store.save(&self.journal)?;
        self.journal.installed = Some(self.engine.deny(self.plan(), &installed)?);
        self.store.save(&self.journal)
    }
    pub async fn cleanup_after_owner_exit(self) -> io::Result<()> {
        if self.owner_alive()? {
            return Err(invalid(
                "original Windows socket owner is still alive; fence retained",
            ));
        }
        self.verify_unchanged().await?;
        let installed = self
            .journal
            .installed
            .as_ref()
            .ok_or_else(|| invalid("original WFP snapshot missing"))?;
        self.engine.remove(self.plan(), installed)?;
        if self.engine.inspect(self.plan())?.is_some() {
            return Err(invalid("WFP removal not confirmed"));
        }
        self.store.clear()
    }
    pub async fn inspect_journal(directory: &Path) -> io::Result<Value> {
        let store = store::Store::open(directory)?;
        let journal = store.read()?;
        let current = match &journal {
            Some(journal) => wfp::Engine::open()?.inspect(&journal.plan)?,
            None => None,
        };
        Ok(serde_json::json!({"journal":journal,"current":current}))
    }
    pub async fn recover(directory: &Path) -> io::Result<()> {
        let store = store::Store::open(directory)?;
        let Some(journal) = store.read()? else {
            return Ok(());
        };
        if journal.plan.process.still_alive()? {
            return Err(invalid(
                "original Windows socket owner is still alive; expiry or helper loss is not physical exit",
            ));
        }
        let engine = wfp::Engine::open()?;
        if let Some(current) = engine.inspect(&journal.plan)? {
            match &journal.installed {
                Some(installed) if *installed == current => {
                    // A persisted deny intent may precede the transaction.
                    // The original complete permit snapshot is also safe to
                    // remove once its actual socket process has exited.
                    wfp::verify(&journal.plan, &current, journal.denying).or_else(|error| {
                        if journal.denying {
                            wfp::verify(&journal.plan, &current, false)
                        } else {
                            Err(error)
                        }
                    })?;
                }
                None => wfp::verify(&journal.plan, &current, journal.denying)?,
                Some(installed) if journal.denying => {
                    wfp::verify_deny_transition(&journal.plan, installed, &current)?
                }
                _ => {
                    return Err(invalid(
                        "WFP object IDs/configuration changed; recovery preserves them",
                    ));
                }
            }
            engine.remove(&journal.plan, &current)?;
            if engine.inspect(&journal.plan)?.is_some() {
                return Err(invalid("WFP recovery removal not confirmed"));
            }
        }
        store.clear()
    }
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
fn valid_sid(value: &str) -> bool {
    value.starts_with("S-1-")
        && value.len() <= 184
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'S' || byte == b'-')
}
pub fn wall_ms() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}
fn invalid(message: &str) -> io::Error {
    io::Error::other(message)
}
fn require_admin() -> io::Result<()> {
    super::require_administrator_process()
}
