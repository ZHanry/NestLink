//! Narrow Linux nftables socket-owner gate. This grants no private service
//! authority and never opens a raw listener. An administrator installs the gate
//! before the normal-user owner creates its exact loopback TCP/UDP socket.
//!
//! Dropping an owner never removes rules: a helper crash must not open a live
//! listener. Expiry becomes deny-all; deletion requires the original process's
//! actual exit. Recovery compares the original table/chain/rule handles and
//! complete configuration, preserving foreign or changed objects.
mod command;
mod nft;
#[cfg(test)]
mod tests;

use crate::{
    MetadataCommit, check_private_directory, create_private, read_private, replace_private_metadata,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    ffi::OsString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const JOURNAL: &str = "local-port-owner.json";
const MAXIMUM_JSON: u64 = 65_536;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}
impl Transport {
    fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
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
    pub uid: u32,
    pub incarnation: String,
    pub image: String,
    pub image_device: u64,
    pub image_inode: u64,
}
impl ProcessIdentity {
    /// Same kernel PID/start-time/boot/UID ownership model as the existing DNS
    /// owner, with a second stat observation and the actual executable inode.
    pub fn read(pid: u32) -> io::Result<Self> {
        if pid == 0 {
            return Err(invalid("invalid process ID"));
        }
        let root = PathBuf::from(format!("/proc/{pid}"));
        let first = std::fs::read_to_string(root.join("stat"))?;
        let start = process_start(&first)?;
        require_running(&first)?;
        let status = std::fs::read_to_string(root.join("status"))?;
        let ids: Vec<u32> = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .ok_or_else(|| invalid("process UID missing"))?
            .split_whitespace()
            .map(|field| field.parse().map_err(|_| invalid("invalid process UID")))
            .collect::<io::Result<_>>()?;
        let uid = *ids.first().ok_or_else(|| invalid("process UID missing"))?;
        if ids.len() != 4
            || ids.iter().any(|id| *id != uid)
            || std::fs::metadata(&root)?.uid() != uid
        {
            return Err(invalid(
                "set-ID or changing process credentials are not admitted",
            ));
        }
        let executable = std::fs::metadata(root.join("exe"))?;
        let image = std::fs::read_link(root.join("exe"))?
            .to_str()
            .ok_or_else(|| invalid("non-Unicode process image"))?
            .to_owned();
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let final_stat = std::fs::read_to_string(root.join("stat"))?;
        require_running(&final_stat)?;
        if process_start(&final_stat)? != start {
            return Err(invalid("process incarnation changed while inspecting it"));
        }
        Ok(Self {
            pid,
            uid,
            incarnation: format!("{uid}:{start}:{}", boot.trim()),
            image,
            image_device: executable.dev(),
            image_inode: executable.ino(),
        })
    }
    fn incarnation_parts(&self) -> io::Result<(&str, &str)> {
        let mut fields = self.incarnation.split(':');
        let uid = fields.next().and_then(|field| field.parse::<u32>().ok());
        let start = fields
            .next()
            .ok_or_else(|| invalid("missing process start identity"))?;
        let boot = fields
            .next()
            .ok_or_else(|| invalid("missing process boot identity"))?;
        if uid != Some(self.uid)
            || start.is_empty()
            || !start.bytes().all(|byte| byte.is_ascii_digit())
            || !uuid(boot)
            || fields.next().is_some()
        {
            return Err(invalid("invalid process incarnation"));
        }
        Ok((start, boot))
    }
    /// This is a physical-exit check, not permission to reuse an identity.
    /// Exec or credential changes do not close inherited sockets. Even a
    /// zombie group leader can have live threads, so retain the fence until
    /// this original kernel PID/start/boot incarnation actually disappears.
    fn still_alive(&self) -> io::Result<bool> {
        let (start, boot) = self.incarnation_parts()?;
        if std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() != boot {
            return Ok(false);
        }
        match std::fs::read_to_string(format!("/proc/{}/stat", self.pid)) {
            Ok(current) => Ok(process_start(&current)? == start),
            Err(error) if !Path::new(&format!("/proc/{}", self.pid)).try_exists()? => {
                if error.kind() == io::ErrorKind::NotFound {
                    Ok(false)
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }
    /// Ordinary users cannot generally dereference a root process's exe.
    /// The trusted receipt already binds that inode. Only the observable
    /// kernel incarnation and all four root UIDs are rechecked here.
    fn root_helper_alive(&self) -> io::Result<()> {
        let (start, boot) = self.incarnation_parts()?;
        if self.pid == 0
            || self.uid != 0
            || std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() != boot
        {
            return Err(invalid("root gate helper identity is no longer current"));
        }
        let root = PathBuf::from(format!("/proc/{}", self.pid));
        let first = std::fs::read_to_string(root.join("stat"))?;
        require_running(&first)?;
        let status = std::fs::read_to_string(root.join("status"))?;
        let ids = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:"))
            .ok_or_else(|| invalid("helper UID missing"))?
            .split_whitespace()
            .collect::<Vec<_>>();
        let final_stat = std::fs::read_to_string(root.join("stat"))?;
        require_running(&final_stat)?;
        if process_start(&first)? != start
            || process_start(&final_stat)? != start
            || ids != ["0", "0", "0", "0"]
            || std::fs::metadata(&root)?.uid() != 0
        {
            return Err(invalid(
                "original root gate helper is no longer running as root",
            ));
        }
        Ok(())
    }
}
fn require_running(stat: &str) -> io::Result<()> {
    let state = stat
        .get(
            stat.rfind(')')
                .ok_or_else(|| invalid("invalid process stat"))?
                + 1..,
        )
        .and_then(|fields| fields.split_whitespace().next())
        .ok_or_else(|| invalid("process state missing"))?;
    if matches!(state, "Z" | "X" | "x") {
        return Err(invalid("process has exited"));
    }
    Ok(())
}
fn process_start(stat: &str) -> io::Result<String> {
    let fields = stat
        .get(
            stat.rfind(')')
                .ok_or_else(|| invalid("invalid process stat"))?
                + 1..,
        )
        .ok_or_else(|| invalid("invalid process stat"))?
        .split_whitespace()
        .collect::<Vec<_>>();
    let start = fields
        .get(19)
        .ok_or_else(|| invalid("process start identity missing"))?;
    if start.is_empty() || !start.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid("invalid process start identity"));
    }
    Ok((*start).into())
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
    /// The normal user chooses one fixed nonzero loopback endpoint. The caller
    /// supplies its existing mature random UUID source; no socket is opened.
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
        self.process.incarnation_parts()?;
        let now = wall_ms()?;
        let loopback = match self.endpoint.ip() {
            IpAddr::V4(ip) => ip == Ipv4Addr::LOCALHOST,
            IpAddr::V6(ip) => ip == Ipv6Addr::LOCALHOST,
        };
        if self.schema_version != 1
            || !uuid(&self.owner_id)
            || !loopback
            || self.endpoint.port() == 0
            || self.process.pid == 0
            || self.process.uid == 0
            || !Path::new(&self.process.image).is_absolute()
            || self.process.image.len() > 32768
            || self.process.image_inode == 0
            || self.process.incarnation.is_empty()
            || self.process.incarnation.len() > 128
            || self.expires_at_ms <= self.created_at_ms
            || self.expires_at_ms - self.created_at_ms > 3_600_000
            || fresh
                && (self.created_at_ms > now.saturating_add(1000)
                    || now.saturating_sub(self.created_at_ms) > 300_000
                    || now >= self.expires_at_ms)
        {
            return Err(invalid(
                "invalid or expired ordinary-user loopback gate plan",
            ));
        }
        Ok(())
    }
    pub fn save_new(&self, path: &Path) -> io::Result<()> {
        self.validate(true)?;
        let parent = path
            .parent()
            .ok_or_else(|| invalid("plan parent missing"))?;
        if !path.is_absolute() {
            return Err(invalid("absolute plan path required"));
        }
        check_private_directory(parent)?;
        create_private(path, &serde_json::to_vec_pretty(self)?)?;
        File::open(parent)?.sync_all()
    }
    /// Public plan chosen explicitly by the administrator. Bounded no-follow,
    /// nonblocking regular-file read; ownership must match the captured user.
    pub fn read_public(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("absolute plan path required"));
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            )
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o077 != 0 || metadata.len() > MAXIMUM_JSON {
            return Err(invalid("plan must be a bounded owner-private regular file"));
        }
        let mut bytes = Vec::new();
        file.take(MAXIMUM_JSON + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAXIMUM_JSON as usize {
            return Err(invalid("gate plan exceeds limit"));
        }
        let plan: Self = serde_json::from_slice(&bytes)?;
        plan.validate(false)?;
        if metadata.uid() != plan.process.uid {
            return Err(invalid(
                "gate plan file does not belong to its captured user",
            ));
        }
        Ok(plan)
    }
    fn table(&self) -> String {
        format!("nlp_{}", self.owner_id.replace('-', ""))
    }
    fn marker(&self) -> String {
        format!("NestLink:local-port:v1:{}", self.owner_id)
    }
}
/// Public root attestation for one existing ordinary-user plan, not a network
/// credential. The helper retains its original journal lock and kernel gate;
/// ordinary users cannot change either while this attestation is current.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootGateReceipt {
    pub schema_version: u16,
    pub plan: GatePlan,
    pub installed: Value,
    pub helper: ProcessIdentity,
}
impl RootGateReceipt {
    /// Open through protected root-owned directory descriptors, never through
    /// a user-replaceable ancestor or a final symlink, pipe or device.
    pub fn read_for_current_process(path: &Path, expected: &GatePlan) -> io::Result<Self> {
        let parent = ReceiptParent::open(path)?;
        let descriptor = rustix::fs::openat(
            &parent.directory,
            &parent.leaf,
            rustix::fs::OFlags::RDONLY
                | rustix::fs::OFlags::NOFOLLOW
                | rustix::fs::OFlags::NONBLOCK
                | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?;
        let file = File::from(descriptor);
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o7777 != 0o644
            || metadata.len() > MAXIMUM_JSON
        {
            return Err(invalid(
                "gate receipt must be a bounded root-owned 0644 regular file",
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAXIMUM_JSON + 1).read_to_end(&mut bytes)?;
        if bytes.len() > MAXIMUM_JSON as usize {
            return Err(invalid("gate receipt exceeds its bound"));
        }
        let receipt: Self = serde_json::from_slice(&bytes)?;
        receipt.check_current(expected)?;
        Ok(receipt)
    }
    /// Recheck before opening a listener and throughout its lifetime. A
    /// missing, expired or changed helper is terminal for that raw listener;
    /// this method neither installs a gate nor extends the captured deadline.
    pub fn check_current(&self, expected: &GatePlan) -> io::Result<()> {
        expected.validate(false)?;
        let now = wall_ms()?;
        if self.schema_version != 1
            || self.plan != *expected
            || expected.created_at_ms > now.saturating_add(1000)
            || now >= expected.expires_at_ms
            || ProcessIdentity::read(std::process::id())? != expected.process
            || self.helper.pid == expected.process.pid
            || self.helper.uid != 0
            || self.helper.image_device != expected.process.image_device
            || self.helper.image_inode != expected.process.image_inode
            || !Path::new(&self.helper.image).is_absolute()
        {
            return Err(invalid(
                "root gate receipt does not match this exact live process and unexpired plan",
            ));
        }
        nft::verify(expected, &self.installed, false)?;
        self.helper.root_helper_alive()
    }
}
/// Each parent stays open while resolving the next component. Every opened
/// directory is checked after no-follow resolution from its checked parent. Sticky /tmp
/// alone is insufficient for a public trust anchor: use e.g. /run/nestlink.
struct ReceiptParent {
    directory: File,
    leaf: OsString,
}
impl ReceiptParent {
    fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(invalid("absolute root receipt path required"));
        }
        let leaf = path
            .file_name()
            .ok_or_else(|| invalid("receipt leaf missing"))?
            .to_owned();
        let parent = path
            .parent()
            .ok_or_else(|| invalid("receipt parent missing"))?;
        Ok(Self {
            directory: root_directory(parent, false)?,
            leaf,
        })
    }
    fn publish(&self, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > MAXIMUM_JSON as usize {
            return Err(invalid("invalid gate receipt size"));
        }
        static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mut selected = None;
        for _ in 0..16 {
            let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let temporary = format!(".nestlink-gate-{}-{sequence}", std::process::id());
            match rustix::fs::openat(
                &self.directory,
                temporary.as_str(),
                rustix::fs::OFlags::WRONLY
                    | rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::EXCL
                    | rustix::fs::OFlags::NOFOLLOW
                    | rustix::fs::OFlags::NONBLOCK
                    | rustix::fs::OFlags::CLOEXEC,
                rustix::fs::Mode::from_bits_truncate(0o600),
            ) {
                Ok(descriptor) => {
                    selected = Some((temporary, File::from(descriptor)));
                    break;
                }
                Err(error) if error == rustix::io::Errno::EXIST => {}
                Err(error) => return Err(error.into()),
            }
        }
        let (temporary, mut file) =
            selected.ok_or_else(|| invalid("gate receipt temporary-file budget exhausted"))?;
        let publication = (|| -> io::Result<()> {
            file.write_all(bytes)?;
            file.sync_all()?;
            rustix::fs::fchmod(&file, rustix::fs::Mode::from_bits_truncate(0o644))?;
            file.sync_all()?;
            // linkat creates the final name atomically only if absent. Its
            // complete 0644 inode is observable at once; neither a half-written
            // receipt nor a replacement of a previous owner becomes visible.
            rustix::fs::linkat(
                &self.directory,
                temporary.as_str(),
                &self.directory,
                &self.leaf,
                rustix::fs::AtFlags::empty(),
            )?;
            self.directory.sync_all()
        })();
        let cleanup = rustix::fs::unlinkat(
            &self.directory,
            temporary.as_str(),
            rustix::fs::AtFlags::empty(),
        );
        publication?;
        cleanup?;
        self.directory.sync_all()
    }
}
fn uuid(id: &str) -> bool {
    id.len() == 36
        && id.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
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
fn require_root() -> io::Result<()> {
    if rustix::process::geteuid().as_raw() != 0 {
        return Err(invalid(
            "local port gate installation/recovery requires a separate root helper; raw clients remain ordinary users",
        ));
    }
    Ok(())
}
fn trusted_ancestors(path: &Path) -> io::Result<()> {
    root_directory(path, true).map(drop)
}
fn root_directory(path: &Path, allow_sticky: bool) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(invalid("absolute root-controlled directory required"));
    }
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::DIRECTORY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::NONBLOCK
        | rustix::fs::OFlags::CLOEXEC;
    let check = |directory: &File| -> io::Result<()> {
        let metadata = directory.metadata()?;
        let protected_writes =
            metadata.mode() & 0o022 == 0 || allow_sticky && metadata.mode() & 0o1000 != 0;
        if !metadata.is_dir() || metadata.uid() != 0 || !protected_writes {
            return Err(invalid(
                "gate ancestors must be root-owned and protected against replacement",
            ));
        }
        Ok(())
    };
    let mut directory = File::from(rustix::fs::open("/", flags, rustix::fs::Mode::empty())?);
    check(&directory)?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                directory = File::from(rustix::fs::openat(
                    &directory,
                    name,
                    flags,
                    rustix::fs::Mode::empty(),
                )?);
                check(&directory)?;
            }
            _ => {
                return Err(invalid(
                    "gate directory must not contain relative components",
                ));
            }
        }
    }
    Ok(directory)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema_version: u16,
    plan: GatePlan,
    installed: Option<Value>,
    denying: bool,
}
struct Store {
    directory: PathBuf,
    lock: File,
}
impl Store {
    fn open(directory: &Path) -> io::Result<Self> {
        require_root()?;
        if !directory.is_absolute() {
            return Err(invalid("absolute root-private journal directory required"));
        }
        check_private_directory(directory)?;
        trusted_ancestors(directory)?;
        let directory = directory.canonicalize()?;
        let path = directory.join("local-port-owner.lock");
        match create_private(&path, &[]) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = read_private(&path, 1)?;
            }
            Err(error) => return Err(error),
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)?;
        if !lock.metadata()?.is_file() || lock.metadata()?.len() != 0 {
            return Err(invalid("invalid gate journal lock"));
        }
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(
            |_| invalid("the original gate owner or nft transaction still holds this journal"),
        )?;
        Ok(Self { directory, lock })
    }
    fn read(&self) -> io::Result<Option<Journal>> {
        let bytes = match read_private(&self.directory.join(JOURNAL), MAXIMUM_JSON) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let journal: Journal = serde_json::from_slice(&bytes)?;
        if journal.schema_version != 1 {
            return Err(invalid("unsupported local port gate journal"));
        }
        journal.plan.validate(false)?;
        Ok(Some(journal))
    }
    fn save(&self, journal: &Journal) -> io::Result<()> {
        if replace_private_metadata(&self.directory.join(JOURNAL), &serde_json::to_vec(journal)?)?
            != MetadataCommit::Durable
        {
            return Err(invalid(
                "gate journal persistence unconfirmed; recovery required",
            ));
        }
        Ok(())
    }
    fn clear(&self) -> io::Result<()> {
        if self.read()?.is_none() {
            return Err(invalid("gate journal disappeared before confirmed cleanup"));
        }
        std::fs::remove_file(self.directory.join(JOURNAL))?;
        File::open(&self.directory)?.sync_all()
    }
}
/// Root-owned guard. No Drop cleanup: kernel rules and recovery state survive
/// this controller's crash. All mutation waits own the original flock/child.
pub struct GateOwner {
    store: Store,
    journal: Journal,
}
impl GateOwner {
    pub fn initialize_journal(directory: &Path) -> io::Result<()> {
        require_root()?;
        if !directory.is_absolute() {
            return Err(invalid("absolute gate journal path required"));
        }
        trusted_ancestors(
            directory
                .parent()
                .ok_or_else(|| invalid("journal parent missing"))?,
        )?;
        match crate::new_private_directory(directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                check_private_directory(directory)
            }
            Err(error) => Err(error),
        }
    }
    pub async fn install(plan: GatePlan, directory: &Path) -> io::Result<Self> {
        require_root()?;
        plan.validate(true)?;
        let process = ProcessIdentity::read(plan.process.pid)?;
        let helper = ProcessIdentity::read(std::process::id())?;
        if process != plan.process
            || process.image_device != helper.image_device
            || process.image_inode != helper.image_inode
        {
            return Err(invalid(
                "gate plan must identify the live ordinary-user owner of this exact executable",
            ));
        }
        let store = Store::open(directory)?;
        if store.read()?.is_some() {
            return Err(invalid(
                "recover the original gate journal before installing another owner",
            ));
        }
        if nft::inspect(&store, &plan).await?.is_some() {
            return Err(invalid(
                "gate table name is occupied; no existing policy is adopted",
            ));
        }
        let mut journal = Journal {
            schema_version: 1,
            plan,
            installed: None,
            denying: false,
        };
        store.save(&journal)?;
        nft::install(&store, &journal.plan).await?;
        let observed = nft::inspect(&store, &journal.plan)
            .await?
            .ok_or_else(|| invalid("installed gate was not observed"))?;
        nft::verify(&journal.plan, &observed, false)?;
        journal.installed = Some(observed);
        store.save(&journal)?;
        let mut owner = Self { store, journal };
        if !owner.journal.plan.process.still_alive()?
            || wall_ms()? >= owner.journal.plan.expires_at_ms
        {
            owner.deny_all().await?;
            return Err(invalid(
                "original owner ended during gate installation; deny-all gate retained for recovery",
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
        self.journal.plan.process.still_alive()
    }
    /// The complete readback receipt is public OS policy, never a service grant.
    pub fn receipt(&self) -> io::Result<Value> {
        Ok(
            serde_json::json!({"schema_version":1,"plan":self.journal.plan,"denying":self.journal.denying,"installed":self.journal.installed.as_ref().ok_or_else(|| invalid("gate receipt pending"))?}),
        )
    }
    /// Root publishes an immutable create-new receipt only after a complete
    /// kernel readback. Dropping this owner or this receipt retains the fence.
    pub async fn publish_receipt(&self, path: &Path) -> io::Result<RootGateReceipt> {
        require_root()?;
        self.journal.plan.validate(true)?;
        if self.journal.denying
            || ProcessIdentity::read(self.journal.plan.process.pid)? != self.journal.plan.process
        {
            return Err(invalid(
                "a denied or changed owner cannot receive a root gate receipt",
            ));
        }
        self.verify_unchanged().await?;
        let helper = ProcessIdentity::read(std::process::id())?;
        if helper.uid != 0
            || helper.image_device != self.journal.plan.process.image_device
            || helper.image_inode != self.journal.plan.process.image_inode
        {
            return Err(invalid(
                "root gate receipt helper must run this exact executable",
            ));
        }
        let receipt = RootGateReceipt {
            schema_version: 1,
            plan: self.journal.plan.clone(),
            installed: self
                .journal
                .installed
                .clone()
                .ok_or_else(|| invalid("gate receipt pending"))?,
            helper,
        };
        nft::verify(&receipt.plan, &receipt.installed, false)?;
        ReceiptParent::open(path)?.publish(&serde_json::to_vec_pretty(&receipt)?)?;
        Ok(receipt)
    }
    pub async fn verify_unchanged(&self) -> io::Result<()> {
        if nft::inspect(&self.store, &self.journal.plan).await? != self.journal.installed {
            return Err(invalid(
                "gate policy changed or disappeared; listener must stop and foreign objects must be preserved",
            ));
        }
        Ok(())
    }
    /// Atomically remove the allow rule while retaining the exact deny fence.
    /// Save intent first so a controller crash is recoverable in either state.
    pub async fn deny_all(&mut self) -> io::Result<()> {
        self.verify_unchanged().await?;
        if self.journal.denying {
            return Ok(());
        }
        self.journal.denying = true;
        self.store.save(&self.journal)?;
        nft::deny(&self.store, &self.journal.plan).await?;
        let observed = nft::inspect(&self.store, &self.journal.plan)
            .await?
            .ok_or_else(|| invalid("deny-all gate disappeared"))?;
        nft::verify(&self.journal.plan, &observed, true)?;
        self.journal.installed = Some(observed);
        self.store.save(&self.journal)
    }
    /// A live process cannot obtain deletion by claiming that its port closed.
    /// The dedicated raw command must join its real sockets, then exit first.
    pub async fn cleanup_after_owner_exit(self) -> io::Result<()> {
        if self.owner_alive()? {
            return Err(invalid(
                "original ordinary-user owner is still alive; gate and journal retained",
            ));
        }
        self.verify_unchanged().await?;
        nft::remove(&self.store, &self.journal.plan).await?;
        if nft::inspect(&self.store, &self.journal.plan)
            .await?
            .is_some()
        {
            return Err(invalid("gate removal not confirmed"));
        }
        self.store.clear()
    }
    pub async fn inspect_journal(directory: &Path) -> io::Result<Value> {
        let store = Store::open(directory)?;
        let journal = store.read()?;
        let current = match &journal {
            Some(journal) => nft::inspect(&store, &journal.plan).await?,
            None => None,
        };
        Ok(serde_json::json!({"journal":journal,"current":current}))
    }
    pub async fn recover(directory: &Path) -> io::Result<()> {
        let store = Store::open(directory)?;
        let Some(journal) = store.read()? else {
            return Ok(());
        };
        if journal.plan.process.still_alive()? {
            return Err(invalid(
                "original gate socket owner is still alive; expiry or a missing helper is not a physical-close receipt",
            ));
        }
        let current = nft::inspect(&store, &journal.plan).await?;
        if let Some(current) = current {
            match &journal.installed {
                Some(installed) if *installed == current => {}
                // A crash may fall between the atomic kernel transaction and
                // its durable readback. Only the complete exact planned gate
                // is accepted, never a partial/foreign ruleset.
                _ if journal.installed.is_none() => {
                    nft::verify(&journal.plan, &current, journal.denying)?
                }
                Some(installed) if journal.denying => {
                    nft::verify_deny_transition(&journal.plan, installed, &current)?
                }
                _ => {
                    return Err(invalid(
                        "gate object handles/configuration changed; recovery preserves it",
                    ));
                }
            }
            nft::remove(&store, &journal.plan).await?;
            if nft::inspect(&store, &journal.plan).await?.is_some() {
                return Err(invalid("gate recovery removal not confirmed"));
            }
        }
        store.clear()
    }
}
