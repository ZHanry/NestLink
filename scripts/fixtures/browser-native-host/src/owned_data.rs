//! Tool-only, explicitly opted-in data devices. No user input or file adapter.
use nestlink_auth::random_id;
use nestlink_identity::VerifiedPermit;
use nestlink_platform_files::{
    ApprovedReadRoot, FileRoots, ReadRootConsent,
    browse::{BrowseConsent, BrowseLimits, BrowseSelection, network::BrowseRoots},
    upload::{WriteRootConsent, WriteRootSelection, WriteRoots},
};
use nestlink_protocol::{FILE_PAYLOAD_BYTES, Path as WirePath, Permission};
use nestlink_remote::{
    RemoteError,
    files::{FileReadServer, FileShutdown, FileWorkerMonitor},
    input::{Button, InputAction, InputDevice, PlatformInput},
    upload::{FileWriteMonitor, FileWriteServer},
};
use nestlink_sdk::webrtc_host::{HostDataClaims, HostDataFactory, HostDataOwner, WebRtcHostError};
use nestlink_session::StopReason;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    future::Future,
    io::{self, Write},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

const MAXIMUM_FILE_BYTES: u64 = 4 * 1024 * 1024;
pub const DOWNLOAD_NAME: &str = "owned-download.bin";
pub const UPLOAD_NAME: &str = "owned-upload.bin";
pub const EXPECTED_TEXT: &str = "NestLink-G1-中文";

fn lock<T>(value: &Mutex<T>) -> MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub fn payload(upload: bool) -> Vec<u8> {
    let length = FILE_PAYLOAD_BYTES as usize * if upload { 2 } else { 3 } + 7919;
    (0..length)
        .map(|index| {
            ((index * if upload { 31 } else { 17 } + if upload { 7 } else { 11 }) % 251) as u8
        })
        .collect()
}

struct InputState {
    events: Vec<Value>,
    held: BTreeSet<Button>,
    output: File,
}
struct InputFacts {
    state: Mutex<InputState>,
    resets: AtomicUsize,
    dropped: AtomicBool,
}
impl InputFacts {
    fn append(state: &mut InputState, value: Value) -> io::Result<()> {
        if state.events.len() >= 512 {
            return Err(io::Error::other("owned input recording budget exceeded"));
        }
        writeln!(state.output, "{value}")?;
        state.output.flush()?;
        state.events.push(value);
        Ok(())
    }
}
pub struct OwnedInput(Arc<InputFacts>);
impl InputDevice for OwnedInput {
    fn inject(&mut self, input: PlatformInput<'_>) -> io::Result<()> {
        let mut state = lock(&self.0.state);
        let record = match input {
            PlatformInput::Action(InputAction::Key { code, down }) => {
                let button = Button::Key(*code);
                if *down {
                    state.held.insert(button);
                } else {
                    state.held.remove(&button);
                }
                json!({"kind":"key","code":code,"down":down})
            }
            PlatformInput::Action(InputAction::Pointer { button, down, x, y }) => {
                if let Some(button) = button {
                    let button = Button::Pointer(*button);
                    if *down {
                        state.held.insert(button);
                    } else {
                        state.held.remove(&button);
                    }
                }
                json!({"kind":"pointer","button":button,"down":down,"x":x,"y":y})
            }
            PlatformInput::Action(InputAction::Text(text)) => {
                json!({"kind":"text","text":text})
            }
            PlatformInput::Release(button) => {
                state.held.remove(&button);
                match button {
                    Button::Key(code) => json!({"kind":"release","button_type":"key","code":code}),
                    Button::Pointer(code) => {
                        json!({"kind":"release","button_type":"pointer","code":code})
                    }
                }
            }
        };
        InputFacts::append(&mut state, record)
    }
    fn reset(&mut self) -> io::Result<()> {
        self.0.resets.fetch_add(1, Ordering::AcqRel);
        InputFacts::append(&mut lock(&self.0.state), json!({"kind":"reset"}))
    }
}
impl Drop for OwnedInput {
    fn drop(&mut self) {
        self.0.dropped.store(true, Ordering::Release);
    }
}

struct Monitors {
    read: FileWorkerMonitor,
    write: FileWriteMonitor,
}
pub struct OwnedData {
    scratch: Mutex<Option<tempfile::TempDir>>,
    source: PathBuf,
    receiving: PathBuf,
    input: Arc<InputFacts>,
    monitors: Mutex<Option<Monitors>>,
    workers_started: AtomicUsize,
    shutdown_calls: AtomicUsize,
    owner_dropped: AtomicBool,
}
impl OwnedData {
    /// The fixture CLI explicitly opts into this owned sandbox. No caller can
    /// nominate a desktop device, ambient file root or installed state path.
    pub fn new(evidence: &Path) -> io::Result<Arc<Self>> {
        let scratch = tempfile::Builder::new()
            .prefix("nestlink-owned-data-")
            .tempdir()?;
        let private = scratch.path().join("data");
        nestlink_platform_security::new_private_directory(&private)?;
        let source = private.join("source");
        nestlink_platform_security::new_private_directory(&source)?;
        std::fs::write(source.join(DOWNLOAD_NAME), payload(false))?;
        let receiving = private.join("receiving");
        let output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(evidence.join("input-records.jsonl"))?;
        Ok(Arc::new(Self {
            scratch: Mutex::new(Some(scratch)),
            source,
            receiving,
            input: Arc::new(InputFacts {
                state: Mutex::new(InputState {
                    events: Vec::new(),
                    held: BTreeSet::new(),
                    output,
                }),
                resets: AtomicUsize::new(0),
                dropped: AtomicBool::new(false),
            }),
            monitors: Mutex::new(None),
            workers_started: AtomicUsize::new(0),
            shutdown_calls: AtomicUsize::new(0),
            owner_dropped: AtomicBool::new(false),
        }))
    }
    pub fn descriptor(&self) -> Value {
        let download = payload(false);
        let upload = payload(true);
        json!({"enabled":true,"local_approval":"Explicit owned-data fixture CLI; only fresh temporary roots and recording InputDevice",
            "download":{"filename":DOWNLOAD_NAME,"bytes":download.len(),"sha256":hash(&download)},
            "upload":{"filename":UPLOAD_NAME,"bytes":upload.len(),"sha256":hash(&upload)},
            "expected_text":EXPECTED_TEXT,"user_desktop_or_files_accessed":false})
    }
    pub fn input_device(&self) -> OwnedInput {
        OwnedInput(self.input.clone())
    }
    pub fn prepare(self: &Arc<Self>, permit: &VerifiedPermit) -> io::Result<HostDataFactory> {
        let claims = permit.claims();
        if claims.paths != vec![WirePath::Direct as i32]
            || ![
                Permission::View,
                Permission::Input,
                Permission::FileRead,
                Permission::FileWrite,
            ]
            .iter()
            .all(|permission| claims.permissions.contains(&(*permission as i32)))
            || claims.permissions.iter().any(|permission| {
                ![
                    Permission::View as i32,
                    Permission::Audio as i32,
                    Permission::Input as i32,
                    Permission::FileRead as i32,
                    Permission::FileWrite as i32,
                ]
                .contains(permission)
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "owned data permission set differs",
            ));
        }
        let read_id = random_id();
        let (read, read_consent) =
            ApprovedReadRoot::open(&read_id, &self.source, MAXIMUM_FILE_BYTES)?;
        let (browse, browse_consent) = BrowseSelection::new_with_display_name(
            &read_id,
            "Owned download sandbox",
            &self.source,
            BrowseLimits::default(),
        )?;
        let read = BrowseRoots::new(FileRoots::new(vec![read])?, vec![browse])?;
        let (write, write_consent) = WriteRootSelection::new_with_display_name(
            &random_id(),
            "Owned upload sandbox",
            &self.receiving,
            MAXIMUM_FILE_BYTES,
            MAXIMUM_FILE_BYTES * 2,
        )?;
        let write = WriteRoots::new(vec![write])?;
        let sandbox = self.clone();
        let generation = claims.connection_generation;
        Ok(Box::new(move |mut claims: HostDataClaims| {
            if claims.clipboard.is_some()
                || claims
                    .file_read
                    .as_ref()
                    .is_none_or(|claim| claim.generation() != generation)
                || claims
                    .file_write
                    .as_ref()
                    .is_none_or(|claim| claim.generation() != generation)
                || sandbox.workers_started.fetch_add(1, Ordering::AcqRel) != 0
            {
                return Err(WebRtcHostError::Permit);
            }
            let read = FileReadServer::start_claimed(
                claims.file_read.take().ok_or(WebRtcHostError::Permit)?,
                read,
            )?;
            let write = FileWriteServer::start_claimed(
                claims.file_write.take().ok_or(WebRtcHostError::Permit)?,
                write,
            )?;
            *lock(&sandbox.monitors) = Some(Monitors {
                read: read.monitor(),
                write: write.monitor(),
            });
            Ok(Box::new(Owner {
                sandbox,
                read: Some(read),
                write: Some(write),
                read_consent,
                browse_consent,
                write_consent,
            }) as Box<dyn HostDataOwner>)
        }))
    }
    pub fn finish(&self, evidence: &Path, host_cleanup_succeeded: bool) -> io::Result<bool> {
        let source = std::fs::read(self.source.join(DOWNLOAD_NAME))?;
        let uploaded = std::fs::read(self.receiving.join(UPLOAD_NAME)).ok();
        let entries = std::fs::read_dir(&self.receiving)
            .map(|entries| entries.count())
            .unwrap_or(0);
        let (workers_clean, worker_facts) = match lock(&self.monitors).as_ref() {
            Some(monitors) => {
                let read = monitors.read.status();
                let write = monitors.write.status();
                let transfers_clean = write
                    .transfers
                    .values()
                    .all(|state| state.file_closed && state.temporary_removed && !state.poisoned);
                (
                    read.finished
                        && write.finished
                        && read.error.is_none()
                        && write.error.is_none()
                        && write.cleanup_error.is_none()
                        && !read.cleanup_timed_out
                        && !write.cleanup_timed_out
                        && transfers_clean,
                    json!({"read_finished":read.finished,"write_finished":write.finished,
                        "read_error":read.error.map(|error| format!("{error:?}")),
                        "write_error":write.error.map(|error| format!("{error:?}")),
                        "write_cleanup_error":write.cleanup_error.map(|error| format!("{error:?}")),
                        "read_cleanup_timed_out":read.cleanup_timed_out,"write_cleanup_timed_out":write.cleanup_timed_out,
                        "write_transfer_count":write.transfers.len(),"transfers_physically_clean":transfers_clean,
                        "shutdown_calls":self.shutdown_calls.load(Ordering::Acquire),"owner_dropped":self.owner_dropped.load(Ordering::Acquire)}),
                )
            }
            None => (false, json!({"workers_started":false})),
        };
        let state = lock(&self.input.state);
        let text: String = state
            .events
            .iter()
            .filter_map(|event| {
                (event["kind"] == "text")
                    .then(|| event["text"].as_str())
                    .flatten()
            })
            .collect();
        let input_clean = state.held.is_empty()
            && self.input.resets.load(Ordering::Acquire) > 0
            && self.input.dropped.load(Ordering::Acquire);
        let input_exercised = state
            .events
            .iter()
            .any(|event| event["kind"] == "key" && event["code"] == 4 && event["down"] == true)
            && state.events.iter().any(|event| {
                event["kind"] == "key" && event["code"] == 4 && event["down"] == false
            })
            && state.events.iter().any(|event| {
                event["kind"] == "pointer" && event["button"] == 1 && event["down"] == true
            })
            && state.events.iter().any(|event| {
                event["kind"] == "release" && event["button_type"] == "key" && event["code"] == 225
            })
            && text == EXPECTED_TEXT;
        let files_exact = source == payload(false)
            && uploaded.as_deref() == Some(payload(true).as_slice())
            && entries == 1;
        let success = host_cleanup_succeeded
            && workers_clean
            && input_clean
            && input_exercised
            && files_exact
            && self.owner_dropped.load(Ordering::Acquire);
        let scratch_path = lock(&self.scratch)
            .as_ref()
            .map(|directory| directory.path().to_owned());
        let can_remove = host_cleanup_succeeded
            && (workers_clean || self.workers_started.load(Ordering::Acquire) == 0);
        let removed = if can_remove {
            match lock(&self.scratch).take() {
                Some(directory) => {
                    directory.close()?;
                    true
                }
                None => false,
            }
        } else {
            false
        };
        let result = json!({"scope":"Real Web UI input and SCTP files using only owned recording/tempfile devices",
            "passed":success && removed,"input_events":state.events,"held_buttons":state.held.len(),
            "input_resets":self.input.resets.load(Ordering::Acquire),"input_device_dropped":self.input.dropped.load(Ordering::Acquire),
            "input_exercised":input_exercised,"workers":worker_facts,"files_exact":files_exact,
            "source":{"bytes":source.len(),"sha256":hash(&source)},
            "uploaded":uploaded.as_ref().map(|bytes| json!({"bytes":bytes.len(),"sha256":hash(bytes)})),
            "receiving_entries":entries,"owned_sandbox_removed":removed && scratch_path.is_none_or(|path| !path.exists()),
            "user_desktop_or_files_accessed":false});
        std::fs::write(
            evidence.join("data-result.json"),
            serde_json::to_vec_pretty(&result)?,
        )?;
        Ok(success && removed)
    }
}

struct Owner {
    sandbox: Arc<OwnedData>,
    read: Option<FileReadServer>,
    write: Option<FileWriteServer>,
    read_consent: ReadRootConsent,
    browse_consent: BrowseConsent,
    write_consent: WriteRootConsent,
}
impl HostDataOwner for Owner {
    fn shutdown<'a>(
        &'a mut self,
        reason: StopReason,
    ) -> Pin<Box<dyn Future<Output = Result<(), RemoteError>> + Send + 'a>> {
        Box::pin(async move {
            self.sandbox.shutdown_calls.fetch_add(1, Ordering::AcqRel);
            self.read_consent.revoke();
            self.browse_consent.revoke();
            self.write_consent.revoke();
            if let Some(read) = self.read.as_mut() {
                if read.shutdown(reason).await? != FileShutdown::Finished {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "owned read worker cleanup pending",
                    )
                    .into());
                }
                self.read.take();
            }
            if let Some(write) = self.write.as_mut() {
                if write.shutdown(reason).await? != FileShutdown::Finished {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "owned write worker cleanup pending",
                    )
                    .into());
                }
                self.write.take();
            }
            Ok(())
        })
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.sandbox.owner_dropped.store(true, Ordering::Release);
    }
}
