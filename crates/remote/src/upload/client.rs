use super::*;
use crate::files::FileReadConsent;

#[derive(Debug, thiserror::Error)]
pub enum FileWriteError {
    #[error(transparent)]
    Remote(#[from] RemoteError),
    #[error("file destination refused upload: {0:?}")]
    Destination(FileWriteFailure),
    #[error("local upload source failed: {0}")]
    Source(#[from] io::Error),
}
/// An exact, non-cloneable upload belongs to the client that received Ready.
pub struct FileUpload {
    owner: Arc<()>,
    id: String,
    open: FileWriteOpen,
    offset: u64,
    closed: bool,
    receipt: Option<FileWriteReceipt>,
    state: Option<FileWriteState>,
}
impl FileUpload {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn offset(&self) -> u64 {
        self.offset
    }
    pub fn manifest(&self) -> &FileWriteOpen {
        &self.open
    }
    pub fn finished(&self) -> bool {
        self.closed
    }
    pub fn committed(&self) -> Option<&FileWriteReceipt> {
        self.receipt.as_ref()
    }
    pub fn destination_state(&self) -> Option<&FileWriteState> {
        self.state.as_ref()
    }
}
pub struct FileWriteClient {
    receiver: ChannelReceiver,
    sender: ChannelSender,
    lease: LeaseControl,
    generation: u64,
    sequence: u64,
    in_flight: bool,
    seen: BTreeSet<String>,
    active: BTreeSet<String>,
    unclean: BTreeSet<String>,
    owner: Arc<()>,
    last_source: Option<FileUploadSourceMonitor>,
}
#[derive(Clone)]
pub struct FileUploadProgress {
    pub size: Option<u64>,
    /// Bytes confirmed by exact disk acknowledgements, never local reads alone.
    pub confirmed_bytes: u64,
    pub destination: Option<FileWriteState>,
    pub source: FileUploadSourceMonitor,
}
impl FileWriteClient {
    pub fn attach(runtime: &mut ChannelRuntime, generation: u64) -> Result<Self, RemoteError> {
        Self::from_claimed(ClaimedFileWrite::claim(runtime, generation)?)
    }
    /// Consume the exact one-shot FileWrite claim captured from the proved
    /// session, retaining its original lease and connection generation.
    pub fn from_claimed(claim: ClaimedFileWrite) -> Result<Self, RemoteError> {
        let ClaimedFileWrite {
            receiver,
            sender,
            lease,
            generation,
        } = claim;
        lease.check_channel_binding(Channel::FileWrite, generation)?;
        Ok(Self {
            receiver,
            sender,
            lease,
            generation,
            sequence: 0,
            in_flight: false,
            seen: BTreeSet::new(),
            active: BTreeSet::new(),
            unclean: BTreeSet::new(),
            owner: Arc::new(()),
            last_source: None,
        })
    }
    fn protocol(&self, reason: &'static str) -> RemoteError {
        let _ = self.lease.stop(StopReason::ProtocolViolation);
        rejected(reason).into()
    }
    /// Retire a protocol-clean writer after exact Commit/Cancel/Failure replies.
    /// It permanently consumes only FileWrite; viewing remains authorized.
    pub fn retire(self) -> Result<(), RemoteError> {
        if !self.is_idle() {
            return Err(
                self.protocol("upload writer has unconsumed requests, sources or destinations")
            );
        }
        self.receiver.retire_file_writer()
    }
    pub fn is_idle(&self) -> bool {
        self.is_protocol_idle()
            && self.last_source.as_ref().is_none_or(|source| {
                let status = source.status();
                status.finished && status.source_closed
            })
    }
    /// Only exact remote replies establish destination closure. Local source
    /// closure is a separate fact and is also required before writer reuse.
    pub fn is_protocol_idle(&self) -> bool {
        !self.in_flight && self.active.is_empty() && self.unclean.is_empty()
    }
    fn check(&self, upload: &FileUpload) -> Result<(), RemoteError> {
        self.lease
            .check_channel_binding(Channel::FileWrite, self.generation)?;
        if !Arc::ptr_eq(&self.owner, &upload.owner)
            || upload.closed
            || !self.active.contains(&upload.id)
        {
            return Err(self.protocol("upload does not belong to this active writer"));
        }
        Ok(())
    }
    async fn request(
        &mut self,
        id: &str,
        action: Action,
        guard: Option<Arc<dyn FileReadConsent>>,
    ) -> Result<Action, FileWriteError> {
        if self.in_flight {
            return Err(self
                .protocol("an abandoned upload request cannot be replaced")
                .into());
        }
        let deadline = Instant::now() + Duration::from_millis(FILE_OPERATION_MS);
        self.lease
            .check_channel_binding(Channel::FileWrite, self.generation)?;
        let sequence = self
            .sequence
            .checked_add(1)
            .filter(|n| *n <= i64::MAX as u64)
            .ok_or_else(|| self.protocol("upload sequence exhausted"))?;
        let request = NativeFileWrite {
            schema_version: SCHEMA_VERSION,
            connection_generation: self.generation,
            sequence,
            transfer_id: id.into(),
            action: Some(action.clone()),
        };
        let bytes = request.encode_validated().map_err(RemoteError::from)?;
        if matches!(action, Action::Open(_)) {
            if self.seen.contains(id) {
                return Err(rejected("upload UUID is already used").into());
            }
            if self.seen.len() as u64 >= FILE_WRITE_TRANSFERS
                || self.active.len() as u64 >= FILE_WRITE_ACTIVE
            {
                return Err(FileWriteError::Destination(FileWriteFailure {
                    code: FileWriteErrorCode::FileWriteCapacity as i32,
                    state: None,
                }));
            }
            self.seen.insert(id.into());
        }
        let guarded = guard.is_some();
        let cancel = if guarded {
            Some(
                NativeFileWrite {
                    action: Some(Action::Cancel(true)),
                    ..request.clone()
                }
                .encode_validated()
                .map_err(RemoteError::from)?,
            )
        } else {
            None
        };
        deadline_check(deadline)?;
        self.in_flight = true;
        let reply = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            if let (Some(guard), Some(cancel)) = (guard, cancel) {
                self.sender
                    .send_checked_file_write(&bytes, guard, cancel)
                    .await?;
            } else {
                self.sender.send(Channel::FileWrite, &bytes).await?;
            }
            let frame = self.receiver.receive().await?;
            deadline_check(deadline)?;
            let reply = NativeFileWrite::decode_validated(&frame.payload).map_err(|error| {
                let _ = self.lease.stop(StopReason::ProtocolViolation);
                RemoteError::from(error)
            })?;
            deadline_check(deadline)?;
            self.lease
                .check_channel_binding(Channel::FileWrite, self.generation)?;
            if reply.connection_generation != self.generation
                || reply.sequence != sequence
                || reply.transfer_id != id
            {
                return Err(self.protocol("upload response did not match the exact request"));
            }
            let reply = reply
                .action
                .ok_or_else(|| self.protocol("upload reply missing action"))?;
            if !(matches!(
                (&action, &reply),
                (_, Action::Failure(_))
                    | (Action::Open(_), Action::Ready(_))
                    | (Action::Chunk(_), Action::Ack(_))
                    | (Action::Commit(_), Action::Committed(_))
                    | (Action::Cancel(true), Action::Cancelled(_))
                    | (Action::RootsRequest(_), Action::Roots(_))
            ) || guarded && matches!(&reply, Action::Cancelled(_)))
            {
                return Err(self.protocol("unexpected upload reply action"));
            }
            Ok::<_, RemoteError>(reply)
        })
        .await;
        let reply = match reply {
            Ok(result) => {
                if result.is_err() {
                    crate::queues::stop_io_result(&self.lease, &result);
                }
                result?
            }
            Err(_) => {
                let _ = self.lease.stop(StopReason::TransportLost);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "upload request deadline expired",
                )
                .into());
            }
        };
        deadline_check(deadline).inspect_err(|_| {
            let _ = self.lease.stop(StopReason::TransportLost);
        })?;
        self.sequence = sequence;
        self.in_flight = false;
        match &reply {
            Action::Ready(_) => {
                self.active.insert(id.into());
            }
            Action::Committed(_) | Action::Cancelled(_) => {
                self.active.remove(id);
                self.unclean.remove(id);
            }
            Action::Failure(failure) => {
                self.active.remove(id);
                if failure
                    .state
                    .as_ref()
                    .is_some_and(|state| !state.file_closed || !state.temporary_removed)
                {
                    self.unclean.insert(id.into());
                } else {
                    self.unclean.remove(id);
                }
            }
            _ => {}
        }
        if let Action::Failure(failure) = reply {
            return Err(FileWriteError::Destination(failure));
        }
        Ok(reply)
    }
    /// Discover local destination labels from the proved host. This response
    /// is consent-bound and contains no native destination path.
    pub async fn list_roots(&mut self, request_id: &str) -> Result<Vec<FileRoot>, FileWriteError> {
        match self
            .request(request_id, Action::RootsRequest(FileRootsRequest {}), None)
            .await?
        {
            Action::Roots(roots) => Ok(roots.roots),
            _ => Err(self
                .protocol("root discovery did not return a root list")
                .into()),
        }
    }
    pub async fn open(
        &mut self,
        transfer: &str,
        root: &str,
        path: &str,
        size: u64,
        sha256: [u8; 32],
    ) -> Result<FileUpload, FileWriteError> {
        let open = FileWriteOpen {
            root_id: root.into(),
            path: path.into(),
            size,
            sha256: sha256.to_vec(),
        };
        let reply = self
            .request(transfer, Action::Open(open.clone()), None)
            .await?;
        let Action::Ready(ready) = reply else {
            return Err(self.protocol("upload did not become ready").into());
        };
        if ready.size != size || ready.sha256 != sha256 || ready.offset != 0 {
            return Err(self
                .protocol("upload ready changed the complete manifest")
                .into());
        }
        Ok(FileUpload {
            owner: self.owner.clone(),
            id: transfer.into(),
            open,
            offset: 0,
            closed: false,
            receipt: None,
            state: None,
        })
    }
    pub async fn write_chunk(
        &mut self,
        upload: &mut FileUpload,
        chunk: FileWriteChunk,
    ) -> Result<(), FileWriteError> {
        self.write_guarded(upload, chunk, None).await
    }
    async fn write_guarded(
        &mut self,
        upload: &mut FileUpload,
        chunk: FileWriteChunk,
        guard: Option<Arc<dyn FileReadConsent>>,
    ) -> Result<(), FileWriteError> {
        self.check(upload)?;
        if chunk.offset != upload.offset
            || chunk.data.is_empty()
            || chunk.data.len() as u64 > FILE_PAYLOAD_BYTES
            || digest(&chunk.data).as_slice() != chunk.sha256
            || chunk
                .offset
                .checked_add(chunk.data.len() as u64)
                .is_none_or(|end| end > upload.open.size)
        {
            return Err(rejected("invalid local upload chunk geometry or checksum").into());
        }
        let end = chunk.offset + chunk.data.len() as u64;
        let result = self.request(&upload.id, Action::Chunk(chunk), guard).await;
        match result {
            Ok(Action::Ack(ack)) if ack.offset == end => {
                upload.offset = end;
                Ok(())
            }
            Ok(Action::Cancelled(cancelled)) => {
                upload.closed = true;
                upload.state = cancelled.state;
                Err(denied("upload source consent withdrew queued bytes").into())
            }
            Ok(_) => Err(self
                .protocol("upload acknowledgement changed the exact disk offset")
                .into()),
            Err(error) => {
                Self::remember_failure(upload, &error);
                Err(error)
            }
        }
    }
    fn remember_failure(upload: &mut FileUpload, error: &FileWriteError) {
        if let FileWriteError::Destination(failure) = error {
            upload.closed = true;
            upload.state = failure.state;
        }
    }
    pub async fn commit(
        &mut self,
        upload: &mut FileUpload,
    ) -> Result<FileWriteReceipt, FileWriteError> {
        self.commit_guarded(upload, None).await
    }
    async fn commit_guarded(
        &mut self,
        upload: &mut FileUpload,
        guard: Option<Arc<dyn FileReadConsent>>,
    ) -> Result<FileWriteReceipt, FileWriteError> {
        self.check(upload)?;
        if upload.offset != upload.open.size {
            return Err(rejected("upload bytes are incomplete").into());
        }
        let result = self
            .request(
                &upload.id,
                Action::Commit(FileWriteCommit {
                    size: upload.open.size,
                    sha256: upload.open.sha256.clone(),
                }),
                guard,
            )
            .await;
        match result {
            Ok(Action::Committed(receipt))
                if receipt.size == upload.open.size && receipt.sha256 == upload.open.sha256 =>
            {
                upload.closed = true;
                upload.state = receipt.state;
                upload.receipt = Some(receipt.clone());
                Ok(receipt)
            }
            Ok(Action::Cancelled(cancelled)) => {
                upload.closed = true;
                upload.state = cancelled.state;
                Err(denied("upload source consent withdrew queued commit").into())
            }
            Ok(_) => Err(self
                .protocol("upload commit changed the complete manifest")
                .into()),
            Err(error) => {
                Self::remember_failure(upload, &error);
                Err(error)
            }
        }
    }
    pub async fn cancel(
        &mut self,
        upload: &mut FileUpload,
    ) -> Result<FileWriteState, FileWriteError> {
        if self.unclean.contains(&upload.id) {
            self.lease
                .check_channel_binding(Channel::FileWrite, self.generation)?;
            if !Arc::ptr_eq(&self.owner, &upload.owner) {
                return Err(self
                    .protocol("cleanup retry belongs to another writer")
                    .into());
            }
        } else {
            self.check(upload)?;
        }
        let result = self.request(&upload.id, Action::Cancel(true), None).await;
        match result {
            Ok(Action::Cancelled(cancelled)) => {
                upload.closed = true;
                upload.state = cancelled.state;
                cancelled
                    .state
                    .ok_or_else(|| self.protocol("cancel cleanup facts missing").into())
            }
            Ok(_) => Err(self.protocol("upload cancel response differs").into()),
            Err(error) => {
                Self::remember_failure(upload, &error);
                Err(error)
            }
        }
    }
    pub fn source_monitor(&self) -> Option<FileUploadSourceMonitor> {
        self.last_source.clone()
    }
    /// A complete application-facing flow: open/read/rehash the selected local
    /// source on its owned thread, await each actual remote disk Ack, then await
    /// a complete atomic-publication receipt. No byte queue counts as success.
    pub async fn upload_source(
        &mut self,
        transfer: &str,
        root: &str,
        path: &str,
        factory: impl FileUploadSourceFactory,
    ) -> Result<FileWriteReceipt, FileWriteError> {
        self.upload_source_with_progress(transfer, root, path, factory, |_| {})
            .await
    }
    pub async fn upload_source_with_progress(
        &mut self,
        transfer: &str,
        root: &str,
        path: &str,
        factory: impl FileUploadSourceFactory,
        mut progress: impl FnMut(FileUploadProgress),
    ) -> Result<FileWriteReceipt, FileWriteError> {
        if self.last_source.as_ref().is_some_and(|source| {
            let status = source.status();
            !status.finished || !status.source_closed
        }) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "the original upload source has not actually closed",
            )
            .into());
        }
        let mut source =
            source::SourceWorker::start(self.lease.clone(), self.generation, Box::new(factory))?;
        self.last_source = Some(source.monitor());
        progress(FileUploadProgress {
            size: None,
            confirmed_bytes: 0,
            destination: None,
            source: source.monitor(),
        });
        let result = async {
            let manifest = source.describe().await?;
            let hash: [u8; 32] = manifest
                .sha256
                .as_slice()
                .try_into()
                .map_err(|_| rejected("local source digest is not complete"))?;
            let mut upload = self.open(transfer, root, path, manifest.size, hash).await?;
            progress(FileUploadProgress {
                size: Some(manifest.size),
                confirmed_bytes: 0,
                destination: None,
                source: source.monitor(),
            });
            let result = async {
                while upload.offset < manifest.size {
                    let count = (manifest.size - upload.offset).min(FILE_PAYLOAD_BYTES) as usize;
                    let data = source.read(upload.offset, count).await?;
                    let chunk = FileWriteChunk {
                        offset: upload.offset,
                        sha256: digest(&data).to_vec(),
                        data,
                    };
                    self.write_guarded(&mut upload, chunk, Some(source.consent()))
                        .await?;
                    progress(FileUploadProgress {
                        size: Some(manifest.size),
                        confirmed_bytes: upload.offset,
                        destination: upload.state,
                        source: source.monitor(),
                    });
                }
                source.verify().await?;
                self.commit_guarded(&mut upload, Some(source.consent()))
                    .await
            }
            .await;
            if result.is_err()
                && (!upload.closed || self.unclean.contains(&upload.id))
                && !self.in_flight
            {
                let _ = self.cancel(&mut upload).await;
            }
            progress(FileUploadProgress {
                size: Some(manifest.size),
                confirmed_bytes: upload.offset,
                destination: upload.state,
                source: source.monitor(),
            });
            result
        }
        .await;
        let shutdown = source.shutdown().await;
        if result.is_ok() && shutdown != FileShutdown::Finished {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "local upload source did not actually close",
            )
            .into());
        }
        result
    }
}
