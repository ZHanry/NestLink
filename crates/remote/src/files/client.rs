use super::*;
use nestlink_protocol::{FileReadNext, FileReadOpen, FileRoot, FileRootsRequest};
use sha2::{Digest, Sha256};
use std::sync::atomic::AtomicU8;

const ACTIVE: u8 = 0;
const VERIFIED: u8 = 1;
const CLOSED: u8 = 2;

#[derive(Debug, thiserror::Error)]
pub enum FileReadError {
    #[error("file channel failed: {0}")]
    Remote(#[from] RemoteError),
    #[error("file source rejected the request: {0:?}")]
    Source(FileReadErrorCode),
}
/// A manifest/offset belongs to one exact client instance. Reconnection opens a
/// new transfer after checking the old content digest and local partial prefix.
pub struct FileDownload {
    transfer_id: String,
    source: (String, String),
    recovery_scope: nestlink_protocol::file_recovery::DownloadRecoveryScope,
    manifest: FileReadManifest,
    offset: u64,
    owner: Arc<()>,
    phase: Arc<AtomicU8>,
}
/// Opaque local identity of one transfer from one proven session client.
#[derive(Clone)]
pub struct FileDownloadBinding {
    transfer_id: String,
    owner: Arc<()>,
}
impl FileDownloadBinding {
    pub(super) fn same_client(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.owner, &other.owner)
    }
    pub fn matches(&self, download: &impl FileDownloadView) -> bool {
        let other = download.binding();
        self.transfer_id == other.transfer_id && Arc::ptr_eq(&self.owner, &other.owner)
    }
}
mod sealed {
    pub trait Sealed {}
}
/// Only this module creates valid live transfer views. Snapshots are immutable
/// and retain the original cancellation fact; they cannot create mutable clients.
pub trait FileDownloadView: sealed::Sealed {
    fn manifest(&self) -> &FileReadManifest;
    fn offset(&self) -> u64;
    fn finished(&self) -> bool;
    fn source_verified(&self) -> bool;
    fn binding(&self) -> FileDownloadBinding;
}
#[derive(Clone)]
pub struct FileDownloadSnapshot {
    recovery_scope: nestlink_protocol::file_recovery::DownloadRecoveryScope,
    source: (String, String),
    manifest: FileReadManifest,
    offset: u64,
    binding: FileDownloadBinding,
    verified_observed: bool,
    phase: Arc<AtomicU8>,
}
impl FileDownloadSnapshot {
    /// Facts captured only after the actual current client passed FileRead
    /// authorization. This does not reconstruct or serialize that authority.
    pub fn recovery_facts(
        &self,
    ) -> io::Result<nestlink_protocol::file_recovery::DownloadRecoveryFacts> {
        let sha256 = self
            .manifest
            .sha256
            .as_slice()
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid source digest"))?;
        Ok(nestlink_protocol::file_recovery::DownloadRecoveryFacts {
            scope: self.recovery_scope.clone(),
            root_id: self.source.0.clone(),
            relative_path: self.source.1.clone(),
            size: self.manifest.size,
            sha256,
        })
    }
    pub(super) fn cancelled(&self) -> bool {
        self.phase.load(Ordering::Acquire) == CLOSED
    }
}
impl sealed::Sealed for FileDownloadSnapshot {}
impl FileDownloadView for FileDownloadSnapshot {
    fn manifest(&self) -> &FileReadManifest {
        &self.manifest
    }
    fn offset(&self) -> u64 {
        self.offset
    }
    fn finished(&self) -> bool {
        self.phase.load(Ordering::Acquire) != ACTIVE
    }
    fn source_verified(&self) -> bool {
        self.verified_observed && self.phase.load(Ordering::Acquire) == VERIFIED
    }
    fn binding(&self) -> FileDownloadBinding {
        self.binding.clone()
    }
}
impl sealed::Sealed for FileDownload {}
impl FileDownloadView for FileDownload {
    fn manifest(&self) -> &FileReadManifest {
        self.manifest()
    }
    fn offset(&self) -> u64 {
        self.offset()
    }
    fn finished(&self) -> bool {
        self.finished()
    }
    fn source_verified(&self) -> bool {
        self.source_verified()
    }
    fn binding(&self) -> FileDownloadBinding {
        self.binding()
    }
}
impl FileDownload {
    pub fn transfer_id(&self) -> &str {
        &self.transfer_id
    }
    pub fn manifest(&self) -> &FileReadManifest {
        &self.manifest
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn finished(&self) -> bool {
        self.phase.load(Ordering::Acquire) != ACTIVE
    }
    /// True only after the exact matching End, never after cancel or failure.
    pub fn source_verified(&self) -> bool {
        self.phase.load(Ordering::Acquire) == VERIFIED
    }
    pub fn binding(&self) -> FileDownloadBinding {
        FileDownloadBinding {
            transfer_id: self.transfer_id.clone(),
            owner: self.owner.clone(),
        }
    }
    pub fn snapshot(&self) -> FileDownloadSnapshot {
        FileDownloadSnapshot {
            recovery_scope: self.recovery_scope.clone(),
            source: self.source.clone(),
            manifest: self.manifest.clone(),
            offset: self.offset,
            binding: self.binding(),
            verified_observed: self.source_verified(),
            phase: self.phase.clone(),
        }
    }
}
impl Drop for FileDownload {
    fn drop(&mut self) {
        self.phase.store(CLOSED, Ordering::Release);
    }
}
pub struct FileReadClient {
    receiver: ChannelReceiver,
    sender: ChannelSender,
    pub(super) lease: LeaseControl,
    pub(super) generation: u64,
    sequence: u64,
    in_flight: bool,
    response_deadline: Option<Instant>,
    active: BTreeSet<String>,
    seen: BTreeSet<String>,
    pub(super) owner: Arc<()>,
}
impl FileReadClient {
    pub fn attach(runtime: &mut ChannelRuntime, generation: u64) -> Result<Self, RemoteError> {
        Self::from_claimed(ClaimedFileRead::claim(runtime, generation)?)
    }
    /// Consume a FileRead claim captured when this exact proved session was
    /// established. No second runtime claim can replace the channel.
    pub fn from_claimed(claim: ClaimedFileRead) -> Result<Self, RemoteError> {
        let ClaimedFileRead {
            receiver,
            sender,
            lease,
            generation,
        } = claim;
        lease.check_channel_binding(Channel::FileRead, generation)?;
        Ok(Self {
            receiver,
            sender,
            lease,
            generation,
            sequence: 0,
            in_flight: false,
            response_deadline: None,
            active: BTreeSet::new(),
            seen: BTreeSet::new(),
            owner: Arc::new(()),
        })
    }
    pub(super) fn protocol(&self, reason: &'static str) -> RemoteError {
        let _ = self.lease.stop(StopReason::ProtocolViolation);
        rejected(reason).into()
    }
    /// Permanently retire this FileRead claim after consuming every exact
    /// response and every opened source's End, Cancel or Failure. Viewing and
    /// other channels remain authorized. Use the idle client itself for another
    /// download on the same connection; a retired claim cannot be reattached.
    /// Read stable task identity facts from a currently FileRead-authorized,
    /// both-endpoints-proved session. Stored facts never bypass this check.
    pub fn recovery_scope(
        &self,
    ) -> Result<nestlink_protocol::file_recovery::DownloadRecoveryScope, RemoteError> {
        let binding = self.lease.file_resume_binding(self.generation)?;
        Ok(nestlink_protocol::file_recovery::DownloadRecoveryScope {
            deployment_id: binding.deployment_id,
            security_epoch: binding.security_epoch,
            account_id: binding.account_id,
            controller_device_id: binding.controller_device_id,
            host_device_id: binding.host_device_id,
            controller_key_sha256: binding.controller_key_sha256,
            host_key_sha256: binding.host_key_sha256,
            resource_id: binding.resource_id,
        })
    }
    pub fn retire(self) -> Result<(), RemoteError> {
        if self.in_flight || !self.active.is_empty() {
            return Err(self.protocol("file reader has an unconsumed request or open source"));
        }
        self.receiver.retire_file_reader()
    }
    pub(super) async fn request(
        &mut self,
        transfer: &str,
        action: Action,
    ) -> Result<Action, FileReadError> {
        let deadline = Instant::now() + Duration::from_millis(FILE_OPERATION_MS);
        self.request_until(transfer, action, deadline).await
    }
    async fn request_until(
        &mut self,
        transfer: &str,
        action: Action,
        deadline: Instant,
    ) -> Result<Action, FileReadError> {
        if self.in_flight {
            return Err(self
                .protocol("a cancelled file request cannot be replaced by another request")
                .into());
        }
        self.lease
            .check_channel_binding(Channel::FileRead, self.generation)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| self.protocol("file request sequence exhausted"))?;
        let request = NativeFileRead {
            schema_version: SCHEMA_VERSION,
            connection_generation: self.generation,
            sequence,
            transfer_id: transfer.into(),
            action: Some(action.clone()),
        };
        let bytes = file_operation(deadline, || Ok(request.encode_validated()?))?;
        if matches!(action, Action::Open(_) | Action::BrowseBegin(_)) {
            if self.seen.contains(transfer) {
                return Err(RemoteError::from(rejected(
                    "file transfer ID is retired or already open",
                ))
                .into());
            }
            if self.seen.len() as u64 >= FILE_READ_TRANSFERS
                || self.active.len() as u64 >= FILE_READ_ACTIVE
            {
                return Err(FileReadError::Source(FileReadErrorCode::FileReadCapacity));
            }
            // Both identity and resource bounds are enforced locally; even a
            // peer with valid TLS keys cannot create duplicate bindings or grow
            // this client's source tracking without limit. Never reuse an ID.
            self.seen.insert(transfer.into());
        }
        // Sticky until the complete matching reply arrives: cancelling this
        // future cannot let a late response answer a different operation.
        self.in_flight = true;
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            self.sender.send(Channel::FileRead, &bytes).await?;
            let frame = self.receiver.receive().await?;
            self.validate_response(&frame.payload, transfer, sequence, &action, deadline)
        })
        .await;
        let reply = match result {
            Ok(result) => {
                if result.is_err() {
                    crate::queues::stop_io_result(&self.lease, &result);
                }
                result?
            }
            Err(_) => {
                let _ = self.lease.stop(StopReason::TransportLost);
                return Err(RemoteError::Io(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "file request timed out",
                ))
                .into());
            }
        };
        self.response_deadline = Some(deadline);
        self.check_response_deadline()?;
        self.sequence = sequence;
        self.in_flight = false;
        match (&action, &reply) {
            (Action::Open(_), Action::Manifest(_)) => {
                self.active.insert(transfer.into());
            }
            (Action::BrowseBegin(_) | Action::BrowseNext(_), Action::BrowsePage(page)) => {
                if page.next_cursor.is_empty() {
                    self.active.remove(transfer);
                } else {
                    self.active.insert(transfer.into());
                }
            }
            (Action::Next(_), Action::End(_) | Action::Failure(_))
            | (Action::Cancel(true), Action::Cancelled(true))
            | (_, Action::Failure(_)) => {
                self.active.remove(transfer);
            }
            _ => {}
        }
        if let Action::Failure(failure) = &reply {
            return Err(FileReadError::Source(
                FileReadErrorCode::try_from(failure.code)
                    .map_err(|_| self.protocol("invalid file source failure"))?,
            ));
        }
        self.check_response_deadline()?;
        Ok(reply)
    }
    pub(super) fn check_response_deadline(&self) -> Result<(), RemoteError> {
        let result = self.response_deadline.map_or(Ok(()), file_deadline);
        if result.is_err() {
            crate::queues::stop_io_result(&self.lease, &result);
        }
        result
    }
    fn validate_response(
        &self,
        payload: &[u8],
        transfer: &str,
        sequence: u64,
        action: &Action,
        deadline: Instant,
    ) -> Result<Action, RemoteError> {
        file_operation(deadline, || {
            let reply = NativeFileRead::decode_validated(payload).map_err(|error| {
                let _ = self.lease.stop(StopReason::ProtocolViolation);
                RemoteError::from(error)
            })?;
            self.lease
                .check_channel_binding(Channel::FileRead, self.generation)?;
            if reply.connection_generation != self.generation
                || reply.sequence != sequence
                || reply.transfer_id != transfer
            {
                return Err(self.protocol("file response does not match the exact request"));
            }
            let reply = reply
                .action
                .ok_or_else(|| self.protocol("missing file response"))?;
            if !matches!(
                (action, &reply),
                (_, Action::Failure(_))
                    | (Action::Open(_), Action::Manifest(_))
                    | (Action::Next(_), Action::Chunk(_) | Action::End(_))
                    | (Action::Cancel(true), Action::Cancelled(true))
                    | (
                        Action::BrowseBegin(_) | Action::BrowseNext(_),
                        Action::BrowsePage(_)
                    )
                    | (Action::RootsRequest(_), Action::Roots(_))
            ) {
                return Err(self.protocol("unexpected file response action"));
            }
            Ok::<_, RemoteError>(reply)
        })
    }
    pub async fn open(
        &mut self,
        transfer_id: &str,
        root_id: &str,
        path: &str,
        offset: u64,
        expected_sha256: Option<[u8; 32]>,
    ) -> Result<FileDownload, FileReadError> {
        let action = Action::Open(FileReadOpen {
            root_id: root_id.into(),
            path: path.into(),
            offset,
            expected_sha256: expected_sha256
                .map(|hash| hash.to_vec())
                .unwrap_or_default(),
        });
        let Action::Manifest(manifest) = self.request(transfer_id, action).await? else {
            return Err(self.protocol("file open did not return a manifest").into());
        };
        if manifest.offset != offset || expected_sha256.is_some_and(|hash| manifest.sha256 != hash)
        {
            return Err(self
                .protocol("file manifest does not match the requested resume identity")
                .into());
        }
        self.check_response_deadline()?;
        Ok(FileDownload {
            transfer_id: transfer_id.into(),
            source: (root_id.into(), path.into()),
            recovery_scope: self.recovery_scope()?,
            manifest,
            offset,
            owner: self.owner.clone(),
            phase: Arc::new(AtomicU8::new(ACTIVE)),
        })
    }
    /// Discover names of currently approved remote roots. Root labels are
    /// metadata only; this never returns an operating-system path.
    pub async fn list_roots(&mut self, request_id: &str) -> Result<Vec<FileRoot>, FileReadError> {
        match self
            .request(request_id, Action::RootsRequest(FileRootsRequest {}))
            .await?
        {
            Action::Roots(roots) => Ok(roots.roots),
            _ => Err(self
                .protocol("root discovery did not return a root list")
                .into()),
        }
    }
    fn check_download(&self, download: &FileDownload) -> Result<(), RemoteError> {
        if download.finished() || !Arc::ptr_eq(&download.owner, &self.owner) {
            return Err(
                rejected("file download is closed or belongs to another session client").into(),
            );
        }
        Ok(())
    }
    pub(super) fn worker_context(
        &self,
        download: &FileDownload,
    ) -> Result<super::destination::Context, RemoteError> {
        self.check_download(download)?;
        Ok(super::destination::Context {
            lease: self.lease.clone(),
            generation: self.generation,
            identity: self.lease.file_resume_binding(self.generation)?,
            source: download.source.clone(),
            snapshot: download.snapshot(),
        })
    }
    /// Pulling one bounded chunk provides backpressure. None means the source
    /// was reverified; the caller must also finish its own whole-file verifier.
    pub async fn next(
        &mut self,
        download: &mut FileDownload,
    ) -> Result<Option<FileReadChunk>, FileReadError> {
        self.check_download(download)?;
        let reply = match self
            .request(
                &download.transfer_id,
                Action::Next(FileReadNext {
                    offset: download.offset,
                }),
            )
            .await
        {
            Ok(reply) => reply,
            Err(error) => {
                download.phase.store(CLOSED, Ordering::Release);
                return Err(error);
            }
        };
        match reply {
            Action::Chunk(chunk) => {
                let expected =
                    (download.manifest.size - download.offset).min(FILE_PAYLOAD_BYTES) as usize;
                if chunk.offset != download.offset
                    || chunk.data.len() != expected
                    || digest(&chunk.data).as_slice() != chunk.sha256
                {
                    download.phase.store(CLOSED, Ordering::Release);
                    return Err(self
                        .protocol("file chunk offset, size or checksum differs")
                        .into());
                }
                self.check_response_deadline()?;
                download.offset += chunk.data.len() as u64;
                Ok(Some(chunk))
            }
            Action::End(end) => {
                if download.offset != download.manifest.size
                    || end.size != download.manifest.size
                    || end.sha256 != download.manifest.sha256
                {
                    download.phase.store(CLOSED, Ordering::Release);
                    return Err(self
                        .protocol("file ended before the complete original object")
                        .into());
                }
                self.check_response_deadline()?;
                download.phase.store(VERIFIED, Ordering::Release);
                Ok(None)
            }
            _ => {
                download.phase.store(CLOSED, Ordering::Release);
                Err(self.protocol("unexpected file chunk response").into())
            }
        }
    }
    pub async fn cancel(&mut self, download: &mut FileDownload) -> Result<(), FileReadError> {
        self.check_download(download)?;
        // Invalidate queued local work before any potentially slow source RPC.
        download.phase.store(CLOSED, Ordering::Release);
        let result = self
            .request(&download.transfer_id, Action::Cancel(true))
            .await;
        result?;
        self.check_response_deadline()?;
        Ok(())
    }
}

/// Validates the actual complete local bytes, including a resumed prefix.
/// Call seed_prefix/accept on bounded blocks on the destination's file worker;
/// publish the destination only after finish succeeds.
#[derive(Clone)]
pub struct FileReadVerifier {
    manifest: FileReadManifest,
    offset: u64,
    hasher: Sha256,
}
impl FileReadVerifier {
    pub fn new(manifest: FileReadManifest) -> io::Result<Self> {
        if manifest.size > nestlink_protocol::FILE_SIZE_BYTES
            || manifest.offset > manifest.size
            || manifest.sha256.len() != 32
        {
            return Err(rejected("invalid file verifier manifest"));
        }
        Ok(Self {
            manifest,
            offset: 0,
            hasher: Sha256::new(),
        })
    }
    pub fn seed_prefix(&mut self, bytes: &[u8]) -> io::Result<()> {
        let next = self
            .offset
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| rejected("prefix size overflow"))?;
        if next > self.manifest.offset || bytes.len() as u64 > FILE_PAYLOAD_BYTES {
            return Err(rejected("resumed prefix exceeds its exact bounded offset"));
        }
        self.hasher.update(bytes);
        self.offset = next;
        Ok(())
    }
    pub fn accept(&mut self, chunk: &FileReadChunk) -> io::Result<()> {
        let end = chunk
            .offset
            .checked_add(chunk.data.len() as u64)
            .ok_or_else(|| rejected("chunk offset overflow"))?;
        if self.offset < self.manifest.offset
            || chunk.offset != self.offset
            || chunk.data.is_empty()
            || chunk.data.len() as u64 > FILE_PAYLOAD_BYTES
            || end > self.manifest.size
            || chunk.sha256 != digest(&chunk.data)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "file verifier rejected chunk geometry or checksum",
            ));
        }
        self.hasher.update(&chunk.data);
        self.offset = end;
        Ok(())
    }
    pub fn finish(self) -> io::Result<()> {
        if self.offset != self.manifest.size
            || self.hasher.finalize().as_slice() != self.manifest.sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "complete file or resumed prefix checksum differs",
            ));
        }
        Ok(())
    }
}
