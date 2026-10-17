//! Pinned native metadata adapter for the existing authorized file worker.
use super::*;
use nestlink_protocol::{
    DIRECTORY_TOKEN_BYTES, DirectoryBrowsePage, DirectoryEntry, DirectoryEntryKind,
    FILE_READ_ROOTS, FileRoot,
};
use nestlink_remote::files::{
    DirectoryBrowseSource, FileReadConsent, FileReadDevice, FileReadRootListing, FileReadSource,
};
use rand_core::{OsRng, RngCore};
use std::collections::BTreeMap;

struct Root {
    selection: Option<BrowseSelection>,
    approved: Option<ApprovedBrowseRoot>,
    display_name: String,
    consent: Arc<super::ConsentState>,
}
/// Wrap a file-read provider with independently approved metadata roots. No I/O
/// happens during construction; the owned FileRead worker opens selections once.
pub struct BrowseRoots<D> {
    files: D,
    roots: BTreeMap<String, Root>,
}
impl<D: FileReadDevice> BrowseRoots<D> {
    pub fn new(files: D, selections: Vec<BrowseSelection>) -> io::Result<Self> {
        if selections.len() as u64 > FILE_READ_ROOTS {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "too many approved directory roots",
            ));
        }
        let mut roots = BTreeMap::new();
        for selection in selections {
            let id = selection.id.clone();
            let display_name = selection.display_name.clone();
            let consent = selection.consent.clone();
            if roots
                .insert(
                    id,
                    Root {
                        selection: Some(selection),
                        approved: None,
                        display_name,
                        consent,
                    },
                )
                .is_some()
            {
                return Err(invalid("duplicate directory root identity"));
            }
        }
        Ok(Self { files, roots })
    }
}
impl<D: FileReadDevice> FileReadDevice for BrowseRoots<D> {
    fn retire_revoked(&mut self) {
        self.files.retire_revoked();
        self.roots.retain(|_, root| root.consent.active());
    }
    fn list_roots(
        &mut self,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<FileReadRootListing> {
        authorized()?;
        self.retire_revoked();
        let mut roots = Vec::with_capacity(self.roots.len());
        let mut approvals: Vec<Arc<super::ConsentState>> = Vec::with_capacity(self.roots.len());
        for (id, root) in &self.roots {
            root.consent.check()?;
            roots.push(FileRoot {
                root_id: id.clone(),
                display_name: root.display_name.clone(),
            });
            approvals.push(root.consent.clone());
        }
        authorized()?;
        let consent: Arc<dyn FileReadConsent> = Arc::new(RootListConsent(approvals));
        consent.check()?;
        Ok(FileReadRootListing { roots, consent })
    }
    fn open(&mut self, root: &str, relative_path: &str) -> io::Result<Box<dyn FileReadSource>> {
        self.files.open(root, relative_path)
    }
    fn browse(
        &mut self,
        root: &str,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<Box<dyn DirectoryBrowseSource>> {
        let started = Instant::now();
        authorized()?;
        self.retire_revoked();
        let slot = self
            .roots
            .get_mut(root)
            .ok_or_else(|| denied("directory root was not locally approved"))?;
        let budget = slot
            .approved
            .as_ref()
            .map(|approved| approved.limits.operation_budget)
            .or_else(|| {
                slot.selection
                    .as_ref()
                    .map(|selection| selection.limits.operation_budget)
            })
            .ok_or_else(|| denied("directory root selection has ended"))?;
        let operation_deadline = started + budget;
        let mut check = || {
            authorized()?;
            if Instant::now() >= operation_deadline {
                return Err(expired());
            }
            Ok(())
        };
        check()?;
        if slot.approved.is_none() {
            let selection = slot
                .selection
                .take()
                .ok_or_else(|| denied("directory root selection has ended"))?;
            slot.approved = Some(selection.open(&mut check)?);
        }
        let approved = slot
            .approved
            .as_ref()
            .ok_or_else(|| denied("directory root unavailable"))?;
        approved.consent.check()?;
        check()?;
        // Clone the actual original directory handle. Never reopen its ambient
        // selected path when a new peer UUID requests another snapshot.
        let directory = approved.directory.try_clone()?;
        check()?;
        approved.consent.check()?;
        Ok(Box::new(Source {
            root: ApprovedBrowseRoot {
                id: approved.id.clone(),
                directory,
                device: approved.device,
                limits: approved.limits,
                consent: approved.consent.clone(),
                owner: Arc::new(()),
                snapshot: None,
            },
            started: false,
            snapshot_id: Vec::new(),
            cursor: None,
            offset: 0,
            deadline: None,
            operation_deadline,
        }))
    }
}

struct RootListConsent(Vec<Arc<super::ConsentState>>);
impl FileReadConsent for RootListConsent {
    fn check(&self) -> io::Result<()> {
        for consent in &self.0 {
            consent.check()?;
        }
        Ok(())
    }
}
fn token() -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; DIRECTORY_TOKEN_BYTES as usize];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| io::Error::other("directory token entropy unavailable"))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(io::Error::other("directory token entropy invalid"));
    }
    Ok(bytes)
}
struct Source {
    root: ApprovedBrowseRoot,
    started: bool,
    snapshot_id: Vec<u8>,
    cursor: Option<(Vec<u8>, BrowseCursor)>,
    offset: u32,
    deadline: Option<Instant>,
    operation_deadline: Instant,
}
impl Source {
    fn convert(&mut self, page: BrowsePage) -> io::Result<DirectoryBrowsePage> {
        page.check_lifetime()?;
        if Instant::now() >= self.operation_deadline {
            return Err(expired());
        }
        let deadline = page.snapshot_started + page.cursor_lifetime;
        if self.deadline.is_some_and(|previous| previous != deadline) {
            return Err(changed());
        }
        self.deadline = Some(deadline);
        let entries = page
            .entries
            .iter()
            .map(|entry| {
                let (negative, duration) =
                    match entry.modified.duration_since(SystemTime::UNIX_EPOCH) {
                        Ok(duration) => (false, duration),
                        Err(error) => (true, error.duration()),
                    };
                let milliseconds = i128::try_from(duration.as_millis())
                    .map_err(|_| invalid("directory timestamp exceeds wire range"))?;
                let milliseconds = if negative {
                    -milliseconds
                } else {
                    milliseconds
                };
                Ok(DirectoryEntry {
                    name: entry.name.clone(),
                    kind: match entry.kind {
                        BrowseEntryKind::File => DirectoryEntryKind::DirectoryEntryFile as i32,
                        BrowseEntryKind::Directory => {
                            DirectoryEntryKind::DirectoryEntryDirectory as i32
                        }
                    },
                    size: entry.size,
                    modified_unix_ms: i64::try_from(milliseconds)
                        .map_err(|_| invalid("directory timestamp exceeds wire range"))?,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        let next_cursor = if page.next.is_some() {
            token()?
        } else {
            Vec::new()
        };
        let reply = DirectoryBrowsePage {
            root_id: page.root_id.clone(),
            directory: page.directory.clone().unwrap_or_default(),
            snapshot_id: self.snapshot_id.clone(),
            offset: self.offset,
            total_entries: page.total_entries as u32,
            entries,
            next_cursor: next_cursor.clone(),
        };
        reply
            .validate()
            .map_err(|_| io::Error::other("native directory page violates wire bounds"))?;
        page.check_lifetime()?;
        if Instant::now() >= self.operation_deadline {
            return Err(expired());
        }
        self.offset += reply.entries.len() as u32;
        self.cursor = page.next.map(|cursor| (next_cursor, cursor));
        Ok(reply)
    }
}
impl DirectoryBrowseSource for Source {
    fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.root.consent.clone()
    }
    fn begin(
        &mut self,
        directory: Option<&str>,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<DirectoryBrowsePage> {
        if self.started {
            return Err(invalid("directory source already started"));
        }
        self.started = true;
        let operation_deadline = self.operation_deadline;
        let mut check = || {
            authorized()?;
            if Instant::now() >= operation_deadline {
                return Err(expired());
            }
            Ok(())
        };
        check()?;
        self.snapshot_id = token()?;
        let page = self.root.begin(directory, maximum, &mut check)?;
        let reply = self.convert(page)?;
        check()?;
        self.root.consent.check()?;
        Ok(reply)
    }
    fn next(
        &mut self,
        cursor: &[u8],
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<DirectoryBrowsePage> {
        self.operation_deadline = Instant::now() + self.root.limits.operation_budget;
        let operation_deadline = self.operation_deadline;
        let mut check = || {
            authorized()?;
            if Instant::now() >= operation_deadline {
                return Err(expired());
            }
            Ok(())
        };
        let (expected, local) = self
            .cursor
            .take()
            .ok_or_else(|| invalid("directory source has ended"))?;
        if cursor != expected {
            self.root.retire();
            return Err(changed());
        }
        let page = self.root.next(&local, maximum, &mut check)?;
        let reply = self.convert(page)?;
        check()?;
        self.root.consent.check()?;
        Ok(reply)
    }
    fn snapshot_deadline(&self) -> io::Result<Instant> {
        self.deadline
            .ok_or_else(|| invalid("directory source has no snapshot"))
    }
    fn reply_deadline(&self) -> io::Result<Instant> {
        Ok(self.operation_deadline)
    }
}
