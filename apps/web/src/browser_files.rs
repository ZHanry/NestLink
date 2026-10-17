//! File selection uses browser File snapshots. Downloads stream into a unique
//! origin-private file; only a complete digest-verified file becomes saveable.
use crate::{
    browser_data::LocalDataConsent,
    browser_rpc::{BrowserRpc, BrowserRpcError},
    browser_storage::{PrivateStorage, remove_directory},
};
use futures_channel::oneshot;
use js_sys::{Array, Function, Object, Reflect, Uint8Array};
use nestlink_protocol::{
    DIRECTORY_PAGE_ENTRIES, DirectoryBrowseBegin, DirectoryBrowseNext, DirectoryBrowsePage,
    FILE_PAYLOAD_BYTES, FILE_SIZE_BYTES, FileReadNext, FileReadOpen, FileRoot, FileRootsRequest,
    FileWriteChunk, FileWriteCommit, FileWriteOpen, files::validate_relative_path,
    native_file_read::Action as Read, native_file_write::Action as Write,
    webrtc_data::WebRtcDataChannel,
};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    rc::Rc,
};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, File, HtmlAnchorElement, Url};
use zeroize::Zeroizing;

const ARTIFACTS: usize = 8;
const PRIVATE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FilePhase {
    Preparing,
    Transferring,
    Verifying,
    Complete,
    Cleaning,
}
#[derive(Clone, Copy)]
pub struct BrowserFileProgress {
    pub phase: FilePhase,
    pub confirmed_bytes: u64,
    pub total_bytes: u64,
}
pub type FileProgress = Rc<dyn Fn(BrowserFileProgress)>;

struct Stage {
    parent: JsValue,
    directory: JsValue,
    id: String,
    writable: Option<JsValue>,
    file: JsValue,
}
impl Stage {
    fn new(id: String, parent: JsValue) -> Self {
        // Retain the exact name before the first mutation. A rejected browser
        // Promise must still leave its cleanup owner intact.
        Self {
            parent,
            directory: JsValue::UNDEFINED,
            id,
            writable: None,
            file: JsValue::UNDEFINED,
        }
    }
    async fn prepare(&mut self) -> Result<(), BrowserRpcError> {
        self.directory = call(
            &self.parent,
            "getDirectoryHandle",
            &[self.id.clone().into(), create_options()],
        )
        .await?;
        self.file = call(
            &self.directory,
            "getFileHandle",
            &["content".into(), create_options()],
        )
        .await?;
        self.writable = Some(call(&self.file, "createWritable", &[]).await?);
        Ok(())
    }
    async fn write(&self, bytes: &[u8]) -> Result<(), BrowserRpcError> {
        let writable = self.writable.as_ref().ok_or(BrowserRpcError::Storage)?;
        let buffer = Uint8Array::from(bytes);
        let result = call(writable, "write", &[buffer.clone().into()]).await;
        buffer.fill(0, 0, buffer.length());
        result.map(|_| ())
    }
    async fn finish(
        &mut self,
        size: u64,
        expected_digest: &[u8],
        consent: &LocalDataConsent,
    ) -> Result<Blob, BrowserRpcError> {
        let writable = self.writable.as_ref().ok_or(BrowserRpcError::Storage)?;
        call(writable, "close", &[]).await?;
        self.writable = None;
        let blob = call(&self.file, "getFile", &[])
            .await?
            .dyn_into::<Blob>()
            .map_err(|_| BrowserRpcError::Storage)?;
        if blob.size() != size as f64 {
            return Err(BrowserRpcError::Storage);
        }
        // Validate the actual committed private file, rather than treating the
        // bytes submitted to write() as proof of what the browser stored.
        let mut hash = Sha256::new();
        let mut offset = 0;
        while offset < size {
            if !consent() {
                return Err(BrowserRpcError::Cancelled);
            }
            let bytes = selected_chunk(&blob, offset, size).await?;
            offset += bytes.len() as u64;
            hash.update(&bytes);
        }
        if hash.finalize().as_slice() != expected_digest {
            return Err(BrowserRpcError::Storage);
        }
        Ok(blob)
    }
    async fn remove(&mut self) -> Result<(), BrowserRpcError> {
        if let Some(writable) = &self.writable {
            call(writable, "abort", &[]).await?;
            self.writable = None;
        }
        remove_directory(&self.parent, &self.id).await
    }
}

struct Artifact {
    stage: Stage,
    filename: String,
    size: u64,
    url: Option<String>,
    verified: bool,
}
impl Drop for Artifact {
    fn drop(&mut self) {
        if let Some(url) = &self.url {
            let _ = Url::revoke_object_url(url);
        }
    }
}
struct Owner {
    rpc: BrowserRpc,
    read_busy: Cell<bool>,
    write_busy: Cell<bool>,
    artifacts: RefCell<BTreeMap<String, Artifact>>,
    reserved: Cell<u64>,
    pending_discards: Cell<usize>,
    storage: RefCell<Option<PrivateStorage>>,
    closing: Cell<bool>,
    cleanup_busy: Cell<bool>,
}
#[derive(Clone)]
pub struct BrowserFiles(Rc<Owner>);
#[derive(Clone, Debug)]
pub struct BrowserFileArtifact {
    pub id: String,
    pub filename: String,
    pub size: u64,
    pub verified: bool,
}

impl BrowserFiles {
    pub fn new(rpc: BrowserRpc) -> Self {
        Self(Rc::new(Owner {
            rpc,
            read_busy: Cell::new(false),
            write_busy: Cell::new(false),
            artifacts: RefCell::new(BTreeMap::new()),
            reserved: Cell::new(0),
            pending_discards: Cell::new(0),
            storage: RefCell::new(None),
            closing: Cell::new(false),
            cleanup_busy: Cell::new(false),
        }))
    }
    pub fn artifacts(&self) -> Vec<BrowserFileArtifact> {
        self.0
            .artifacts
            .borrow()
            .iter()
            .map(|(id, item)| BrowserFileArtifact {
                id: id.clone(),
                filename: item.filename.clone(),
                size: item.size,
                verified: item.verified,
            })
            .collect()
    }
    pub async fn roots(
        &self,
        write: bool,
        consent: LocalDataConsent,
    ) -> Result<Vec<FileRoot>, BrowserRpcError> {
        if self.0.closing.get() {
            return Err(BrowserRpcError::Cancelled);
        }
        let id = uuid::Uuid::new_v4().to_string();
        if write {
            if self.0.write_busy.get() {
                return Err(BrowserRpcError::Busy);
            }
            match self
                .0
                .rpc
                .write(id, Write::RootsRequest(FileRootsRequest {}), consent)
                .await?
            {
                Write::Roots(roots) => Ok(roots.roots),
                Write::Failure(failure) => Err(refused(failure.code)),
                _ => self.protocol(),
            }
        } else {
            if self.0.read_busy.get() {
                return Err(BrowserRpcError::Busy);
            }
            match self
                .0
                .rpc
                .read(id, Read::RootsRequest(FileRootsRequest {}), consent)
                .await?
            {
                Read::Roots(roots) => Ok(roots.roots),
                Read::Failure(failure) => Err(refused(failure.code)),
                _ => self.protocol(),
            }
        }
    }
    /// A directory snapshot remains tied to the exact request id/cursor; pages
    /// must match root, path, snapshot, total, offset and strict name order.
    pub async fn browse(
        &self,
        root_id: String,
        directory: String,
        consent: LocalDataConsent,
    ) -> Result<Vec<nestlink_protocol::DirectoryEntry>, BrowserRpcError> {
        if self.0.closing.get() {
            return Err(BrowserRpcError::Cancelled);
        }
        if self.0.read_busy.replace(true) {
            return Err(BrowserRpcError::Busy);
        }
        let guard = ReadGuard(self.0.clone());
        let owner = self.clone();
        let (sent, waiting) = oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let result = owner.browse_owned(root_id, directory, consent).await;
            drop(guard);
            let _ = sent.send(result);
        });
        waiting.await.map_err(|_| BrowserRpcError::Cancelled)?
    }
    async fn browse_owned(
        &self,
        root_id: String,
        directory: String,
        consent: LocalDataConsent,
    ) -> Result<Vec<nestlink_protocol::DirectoryEntry>, BrowserRpcError> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut action = Read::BrowseBegin(DirectoryBrowseBegin {
            root_id: root_id.clone(),
            directory: directory.clone(),
            maximum: DIRECTORY_PAGE_ENTRIES as u32,
        });
        let mut entries: Vec<nestlink_protocol::DirectoryEntry> = Vec::new();
        let mut first: Option<DirectoryBrowsePage> = None;
        let result = async {
            loop {
                let page = match self.0.rpc.read(id.clone(), action, consent.clone()).await? {
                    Read::BrowsePage(page) => page,
                    Read::Failure(failure) => return Err(refused(failure.code)),
                    _ => return self.protocol(),
                };
                if page.root_id != root_id
                    || page.directory != directory
                    || page.offset as usize != entries.len()
                    || first.as_ref().is_some_and(|old| {
                        old.snapshot_id != page.snapshot_id
                            || old.total_entries != page.total_entries
                    })
                    || entries
                        .last()
                        .zip(page.entries.first())
                        .is_some_and(|(old, new)| old.name >= new.name)
                {
                    return self.protocol();
                }
                if first.is_none() {
                    first = Some(page.clone());
                }
                entries.extend(page.entries);
                if page.next_cursor.is_empty() {
                    return Ok(entries);
                }
                action = Read::BrowseNext(DirectoryBrowseNext {
                    cursor: page.next_cursor,
                    maximum: DIRECTORY_PAGE_ENTRIES as u32,
                });
            }
        }
        .await;
        let cleanup = self.cancel_read(&id).await;
        match (result, cleanup) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }
    pub async fn download(
        &self,
        root_id: String,
        path: String,
        consent: LocalDataConsent,
        progress: FileProgress,
    ) -> Result<BrowserFileArtifact, BrowserRpcError> {
        if self.0.closing.get() {
            return Err(BrowserRpcError::Cancelled);
        }
        validate_relative_path(&path).map_err(|_| BrowserRpcError::Protocol)?;
        if self.0.read_busy.replace(true) {
            return Err(BrowserRpcError::Busy);
        }
        let guard = ReadGuard(self.0.clone());
        let owner = self.clone();
        let (sent, waiting) = oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let result = owner.download_owned(root_id, path, consent, progress).await;
            drop(guard);
            let _ = sent.send(result);
        });
        waiting.await.map_err(|_| BrowserRpcError::Cancelled)?
    }
    async fn download_owned(
        &self,
        root_id: String,
        path: String,
        consent: LocalDataConsent,
        progress: FileProgress,
    ) -> Result<BrowserFileArtifact, BrowserRpcError> {
        let id = uuid::Uuid::new_v4().to_string();
        let filename = path
            .rsplit('/')
            .next()
            .ok_or(BrowserRpcError::Protocol)?
            .to_owned();
        let mut stage: Option<Stage> = None;
        let mut reserved = 0;
        let mut may_have_opened = false;
        let result = async {
            // Hold this origin's real Web Lock before asking for remote bytes.
            // Previous page leftovers must be removed before allocating more.
            if self.0.storage.borrow().is_none() {
                let storage = PrivateStorage::open().await?;
                *self.0.storage.borrow_mut() = Some(storage);
            }
            let mut storage = self
                .0
                .storage
                .borrow_mut()
                .take()
                .ok_or(BrowserRpcError::Storage)?;
            let recovered = storage.recover().await;
            let parent = storage.parent.clone();
            *self.0.storage.borrow_mut() = Some(storage);
            recovered?;
            if !consent() {
                return Err(BrowserRpcError::Cancelled);
            }
            may_have_opened = true;
            let manifest = match self
                .0
                .rpc
                .read(
                    id.clone(),
                    Read::Open(FileReadOpen {
                        root_id,
                        path,
                        offset: 0,
                        expected_sha256: Vec::new(),
                    }),
                    consent.clone(),
                )
                .await?
            {
                Read::Manifest(manifest) => manifest,
                Read::Failure(failure) => return Err(refused(failure.code)),
                _ => return self.protocol(),
            };
            if manifest.offset != 0 {
                return self.protocol();
            }
            if self.0.artifacts.borrow().len() + self.0.pending_discards.get() >= ARTIFACTS
                || manifest.size > PRIVATE_BYTES.saturating_sub(self.0.reserved.get())
            {
                return Err(BrowserRpcError::Capacity);
            }
            self.0.reserved.set(self.0.reserved.get() + manifest.size);
            reserved = manifest.size;
            stage = Some(Stage::new(id.clone(), parent));
            stage
                .as_mut()
                .ok_or(BrowserRpcError::Storage)?
                .prepare()
                .await?;
            let mut offset = 0;
            let mut hash = Sha256::new();
            loop {
                if !consent() {
                    return Err(BrowserRpcError::Cancelled);
                }
                progress(BrowserFileProgress {
                    phase: FilePhase::Transferring,
                    confirmed_bytes: offset,
                    total_bytes: manifest.size,
                });
                match self
                    .0
                    .rpc
                    .read(
                        id.clone(),
                        Read::Next(FileReadNext { offset }),
                        consent.clone(),
                    )
                    .await?
                {
                    Read::Chunk(mut chunk) => {
                        let bytes = Zeroizing::new(std::mem::take(&mut chunk.data));
                        if chunk.offset != offset
                            || offset + bytes.len() as u64 > manifest.size
                            || Sha256::digest(&bytes).as_slice() != chunk.sha256
                        {
                            return self.protocol();
                        }
                        if !consent() {
                            return Err(BrowserRpcError::Cancelled);
                        }
                        stage
                            .as_ref()
                            .ok_or(BrowserRpcError::Storage)?
                            .write(&bytes)
                            .await?;
                        hash.update(&bytes);
                        offset += bytes.len() as u64;
                    }
                    Read::End(end) => {
                        progress(BrowserFileProgress {
                            phase: FilePhase::Verifying,
                            confirmed_bytes: offset,
                            total_bytes: manifest.size,
                        });
                        if end.size != manifest.size
                            || end.sha256 != manifest.sha256
                            || offset != manifest.size
                            || hash.finalize().as_slice() != manifest.sha256
                        {
                            return self.protocol();
                        }
                        if !consent() {
                            return Err(BrowserRpcError::Cancelled);
                        }
                        let blob = stage
                            .as_mut()
                            .ok_or(BrowserRpcError::Storage)?
                            .finish(offset, &manifest.sha256, &consent)
                            .await?;
                        if !consent() {
                            return Err(BrowserRpcError::Cancelled);
                        }
                        let url = Url::create_object_url_with_blob(&blob)
                            .map_err(|_| BrowserRpcError::Storage)?;
                        return Ok((offset, url));
                    }
                    Read::Failure(failure) => return Err(refused(failure.code)),
                    _ => return self.protocol(),
                }
            }
        }
        .await;
        match result {
            Ok((size, url)) => {
                let stage = stage.take().ok_or(BrowserRpcError::Storage)?;
                self.0.artifacts.borrow_mut().insert(
                    id.clone(),
                    Artifact {
                        stage,
                        filename: filename.clone(),
                        size,
                        url: Some(url),
                        verified: true,
                    },
                );
                progress(BrowserFileProgress {
                    phase: FilePhase::Complete,
                    confirmed_bytes: size,
                    total_bytes: size,
                });
                Ok(BrowserFileArtifact {
                    id,
                    filename,
                    size,
                    verified: true,
                })
            }
            Err(primary) => {
                progress(BrowserFileProgress {
                    phase: FilePhase::Cleaning,
                    confirmed_bytes: 0,
                    total_bytes: reserved,
                });
                let remote_cleanup = if may_have_opened {
                    self.cancel_read(&id).await
                } else {
                    Ok(())
                };
                if let Some(mut area) = stage
                    && area.remove().await.is_err()
                {
                    self.0.artifacts.borrow_mut().insert(
                        id,
                        Artifact {
                            stage: area,
                            filename,
                            size: reserved,
                            url: None,
                            verified: false,
                        },
                    );
                    return Err(BrowserRpcError::Storage);
                }
                self.0
                    .reserved
                    .set(self.0.reserved.get().saturating_sub(reserved));
                remote_cleanup.and(Err(primary))
            }
        }
    }
    /// Invoke from an explicit user click. The browser owns its Save dialog and
    /// destination; NestLink retains the verified source until explicit discard.
    pub fn save(&self, id: &str) -> Result<(), BrowserRpcError> {
        let items = self.0.artifacts.borrow();
        let item = items
            .get(id)
            .filter(|item| item.verified)
            .ok_or(BrowserRpcError::Storage)?;
        let document = web_sys::window()
            .and_then(|window| window.document())
            .ok_or(BrowserRpcError::Storage)?;
        let anchor = document
            .create_element("a")
            .map_err(|_| BrowserRpcError::Storage)?
            .dyn_into::<HtmlAnchorElement>()
            .map_err(|_| BrowserRpcError::Storage)?;
        anchor.set_href(item.url.as_deref().ok_or(BrowserRpcError::Storage)?);
        anchor.set_download(&item.filename);
        anchor.click();
        Ok(())
    }
    pub async fn discard(&self, id: String) -> Result<(), BrowserRpcError> {
        let Some(mut item) = self.0.artifacts.borrow_mut().remove(&id) else {
            return Ok(());
        };
        self.0
            .pending_discards
            .set(self.0.pending_discards.get() + 1);
        let owner = self.clone();
        let (sent, waiting) = oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let result = item.stage.remove().await;
            if result.is_err() {
                owner.0.artifacts.borrow_mut().insert(id, item);
            } else {
                owner
                    .0
                    .reserved
                    .set(owner.0.reserved.get().saturating_sub(item.size));
            }
            owner
                .0
                .pending_discards
                .set(owner.0.pending_discards.get() - 1);
            let _ = sent.send(result);
        });
        waiting.await.map_err(|_| BrowserRpcError::Cancelled)?
    }
    pub async fn cleanup(&self) -> Result<(), BrowserRpcError> {
        self.0.closing.set(true);
        if self.0.cleanup_busy.replace(true) {
            return Err(BrowserRpcError::Busy);
        }
        let owner = self.clone();
        let (sent, waiting) = oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let result = owner.cleanup_owned().await;
            owner.0.cleanup_busy.set(false);
            let _ = sent.send(result);
        });
        waiting.await.map_err(|_| BrowserRpcError::Cancelled)?
    }
    async fn cleanup_owned(&self) -> Result<(), BrowserRpcError> {
        // Retain this owner while browser disk promises are still running.
        // Closing a page waiter cannot make a partial file count as removed.
        while self.0.read_busy.get()
            || self.0.write_busy.get()
            || self.0.pending_discards.get() != 0
        {
            gloo_timers::future::TimeoutFuture::new(20).await;
        }
        let ids: Vec<_> = self.0.artifacts.borrow().keys().cloned().collect();
        let mut result = Ok(());
        for id in ids {
            if let Err(error) = self.discard(id).await {
                result = Err(error);
            }
        }
        result?;
        let storage = self.0.storage.borrow_mut().take();
        if let Some(mut storage) = storage {
            let result = async {
                storage.recover().await?;
                storage.close().await
            }
            .await;
            if let Err(error) = result {
                *self.0.storage.borrow_mut() = Some(storage);
                return Err(error);
            }
        }
        Ok(())
    }
    pub async fn upload(
        &self,
        file: File,
        root_id: String,
        path: String,
        consent: LocalDataConsent,
        progress: FileProgress,
    ) -> Result<(), BrowserRpcError> {
        if self.0.closing.get() {
            return Err(BrowserRpcError::Cancelled);
        }
        validate_relative_path(&path).map_err(|_| BrowserRpcError::Protocol)?;
        let size = file_size(&file)?;
        if self.0.write_busy.replace(true) {
            return Err(BrowserRpcError::Busy);
        }
        let guard = WriteGuard(self.0.clone());
        let owner = self.clone();
        let (sent, waiting) = oneshot::channel();
        wasm_bindgen_futures::spawn_local(async move {
            let result = owner
                .upload_owned(file, root_id, path, size, consent, progress)
                .await;
            drop(guard);
            let _ = sent.send(result);
        });
        waiting.await.map_err(|_| BrowserRpcError::Cancelled)?
    }
    async fn upload_owned(
        &self,
        file: File,
        root_id: String,
        path: String,
        size: u64,
        consent: LocalDataConsent,
        progress: FileProgress,
    ) -> Result<(), BrowserRpcError> {
        let mut hash = Sha256::new();
        let mut offset = 0;
        while offset < size {
            if !consent() {
                return Err(BrowserRpcError::Cancelled);
            }
            progress(BrowserFileProgress {
                phase: FilePhase::Preparing,
                confirmed_bytes: offset,
                total_bytes: size,
            });
            let bytes = selected_chunk(&file, offset, size).await?;
            hash.update(&bytes);
            offset += bytes.len() as u64;
        }
        let digest = hash.finalize().to_vec();
        let id = uuid::Uuid::new_v4().to_string();
        let mut may_have_opened = false;
        let result = async {
            may_have_opened = true;
            match self
                .0
                .rpc
                .write(
                    id.clone(),
                    Write::Open(FileWriteOpen {
                        root_id,
                        path,
                        size,
                        sha256: digest.clone(),
                    }),
                    consent.clone(),
                )
                .await?
            {
                Write::Ready(ready)
                    if ready.size == size && ready.sha256 == digest && ready.offset == 0 => {}
                Write::Failure(failure) => return Err(refused(failure.code)),
                _ => return self.protocol(),
            }
            let mut offset = 0;
            while offset < size {
                if !consent() {
                    return Err(BrowserRpcError::Cancelled);
                }
                let bytes = selected_chunk(&file, offset, size).await?;
                let end = offset + bytes.len() as u64;
                let response = self
                    .0
                    .rpc
                    .write(
                        id.clone(),
                        Write::Chunk(FileWriteChunk {
                            offset,
                            data: bytes.to_vec(),
                            sha256: Sha256::digest(&bytes).to_vec(),
                        }),
                        consent.clone(),
                    )
                    .await?;
                match response {
                    Write::Ack(ack) if ack.offset == end => offset = end,
                    Write::Failure(failure) => return Err(refused(failure.code)),
                    _ => return self.protocol(),
                }
                progress(BrowserFileProgress {
                    phase: FilePhase::Transferring,
                    confirmed_bytes: offset,
                    total_bytes: size,
                });
            }
            match self
                .0
                .rpc
                .write(
                    id.clone(),
                    Write::Commit(FileWriteCommit {
                        size,
                        sha256: digest.clone(),
                    }),
                    consent.clone(),
                )
                .await?
            {
                Write::Committed(receipt) if receipt.size == size && receipt.sha256 == digest => {
                    progress(BrowserFileProgress {
                        phase: FilePhase::Complete,
                        confirmed_bytes: size,
                        total_bytes: size,
                    });
                    Ok(())
                }
                Write::Failure(failure) => Err(refused(failure.code)),
                _ => self.protocol(),
            }
        }
        .await;
        if result.is_err() && may_have_opened {
            progress(BrowserFileProgress {
                phase: FilePhase::Cleaning,
                confirmed_bytes: 0,
                total_bytes: size,
            });
            match self
                .0
                .rpc
                .write(id, Write::Cancel(true), Rc::new(|| true))
                .await
            {
                Ok(Write::Cancelled(_)) => {}
                Err(_) => self.0.rpc.close(),
                _ => return self.protocol(),
            }
        }
        result
    }
    async fn cancel_read(&self, id: &str) -> Result<(), BrowserRpcError> {
        match self
            .0
            .rpc
            .read(id.to_owned(), Read::Cancel(true), Rc::new(|| true))
            .await
        {
            Ok(Read::Cancelled(true)) => Ok(()),
            Err(error) => Err(error),
            _ => self.protocol(),
        }
    }
    fn protocol<T>(&self) -> Result<T, BrowserRpcError> {
        self.0.rpc.close();
        Err(BrowserRpcError::Protocol)
    }
    pub fn has(&self, kind: WebRtcDataChannel) -> bool {
        self.0.rpc.has(kind)
    }
    pub fn has_pending(&self) -> bool {
        self.0.read_busy.get()
            || self.0.write_busy.get()
            || self.0.pending_discards.get() != 0
            || self.0.cleanup_busy.get()
            || self.0.storage.borrow().is_some()
            || !self.0.artifacts.borrow().is_empty()
    }
}
struct ReadGuard(Rc<Owner>);
impl Drop for ReadGuard {
    fn drop(&mut self) {
        self.0.read_busy.set(false);
    }
}
struct WriteGuard(Rc<Owner>);
impl Drop for WriteGuard {
    fn drop(&mut self) {
        self.0.write_busy.set(false);
    }
}
fn refused(code: i32) -> BrowserRpcError {
    BrowserRpcError::Refused {
        code,
        write_effect: 0,
    }
}
fn create_options() -> JsValue {
    let options = Object::new();
    // A fresh ordinary object is extensible; a failed Reflect::set is still
    // handled by the ensuing browser API call instead of a panic.
    let _ = Reflect::set(&options, &"create".into(), &true.into());
    options.into()
}
async fn call(
    object: &JsValue,
    method: &str,
    arguments: &[JsValue],
) -> Result<JsValue, BrowserRpcError> {
    let method = Reflect::get(object, &method.into())
        .map_err(|_| BrowserRpcError::Storage)?
        .dyn_into::<Function>()
        .map_err(|_| BrowserRpcError::Storage)?;
    let args = Array::new();
    for argument in arguments {
        args.push(argument);
    }
    let promise = method
        .apply(object, &args)
        .map_err(|_| BrowserRpcError::Storage)?
        .dyn_into::<js_sys::Promise>()
        .map_err(|_| BrowserRpcError::Storage)?;
    JsFuture::from(promise)
        .await
        .map_err(|_| BrowserRpcError::Storage)
}
fn file_size(file: &File) -> Result<u64, BrowserRpcError> {
    let size = file.size();
    if !size.is_finite() || size < 0.0 || size.fract() != 0.0 || size > FILE_SIZE_BYTES as f64 {
        return Err(BrowserRpcError::Capacity);
    }
    Ok(size as u64)
}
async fn selected_chunk(
    file: &Blob,
    offset: u64,
    size: u64,
) -> Result<Zeroizing<Vec<u8>>, BrowserRpcError> {
    let end = (offset + FILE_PAYLOAD_BYTES).min(size);
    let blob = file
        .slice_with_f64_and_f64(offset as f64, end as f64)
        .map_err(|_| BrowserRpcError::Storage)?;
    let value = JsFuture::from(blob.array_buffer())
        .await
        .map_err(|_| BrowserRpcError::Storage)?;
    let buffer = Uint8Array::new(&value);
    if buffer.length() as u64 != end - offset {
        buffer.fill(0, 0, buffer.length());
        return Err(BrowserRpcError::Storage);
    }
    let bytes = Zeroizing::new(buffer.to_vec());
    buffer.fill(0, 0, buffer.length());
    Ok(bytes)
}
