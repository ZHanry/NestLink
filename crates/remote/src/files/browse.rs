//! Directory metadata shares FileRead's single claimant, strict sequence and quotas.
use super::*;
use nestlink_protocol::{
    DIRECTORY_SNAPSHOT_MS, DirectoryBrowseBegin, DirectoryBrowseNext, DirectoryBrowsePage,
};
use std::time::Instant;

/// Metadata operations run on the existing owned file worker. A source is
/// derived from a locally selected, pinned root, never from an ambient peer path.
pub trait DirectoryBrowseSource: Send {
    fn consent(&self) -> Arc<dyn FileReadConsent>;
    fn begin(
        &mut self,
        directory: Option<&str>,
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<DirectoryBrowsePage>;
    fn next(
        &mut self,
        cursor: &[u8],
        maximum: usize,
        authorized: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<DirectoryBrowsePage>;
    /// Pure local fact: the original snapshot's fixed deadline, including any
    /// tighter local limit. Page progress must never renew this instant.
    fn snapshot_deadline(&self) -> io::Result<Instant>;
    /// Pure local fact: the just-completed operation's original deadline.
    /// This includes any tighter local budget and survives queue backpressure.
    fn reply_deadline(&self) -> io::Result<Instant>;
}

struct BrowseLifetime {
    consent: Arc<dyn FileReadConsent>,
    deadline: Instant,
    abandoned: Arc<AtomicBool>,
}
impl FileReadConsent for BrowseLifetime {
    fn check(&self) -> io::Result<()> {
        self.consent.check()?;
        if self.abandoned.load(Ordering::Acquire) || Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "directory snapshot expired",
            ));
        }
        Ok(())
    }
}
struct PageDisclosure {
    lifetime: Arc<BrowseLifetime>,
    operation_deadline: Instant,
}
impl FileReadConsent for PageDisclosure {
    fn check(&self) -> io::Result<()> {
        self.lifetime.check()?;
        if Instant::now() >= self.operation_deadline {
            self.lifetime.abandoned.store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "directory reply expired",
            ));
        }
        Ok(())
    }
}
pub(super) struct BrowseTransfer {
    source: Box<dyn DirectoryBrowseSource>,
    lifetime: Arc<BrowseLifetime>,
    source_deadline: Instant,
    page: DirectoryBrowsePage,
    last_name: Option<String>,
}
impl BrowseTransfer {
    pub(super) fn open(
        device: &mut impl FileReadDevice,
        begin: &DirectoryBrowseBegin,
        started: Instant,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<(Self, DirectoryBrowsePage, Arc<dyn FileReadConsent>)> {
        let operation_deadline = started + Duration::from_millis(FILE_OPERATION_MS);
        let mut authorized = || {
            check()?;
            if Instant::now() >= operation_deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "directory operation expired",
                ));
            }
            Ok(())
        };
        authorized()?;
        let mut source = device.browse(&begin.root_id, &mut authorized)?;
        let consent = source.consent();
        consent.check()?;
        let page = source.begin(
            (!begin.directory.is_empty()).then_some(begin.directory.as_str()),
            begin.maximum as usize,
            &mut authorized,
        )?;
        page.validate()
            .map_err(|_| io::Error::other("invalid directory adapter page"))?;
        if page.root_id != begin.root_id
            || page.directory != begin.directory
            || page.offset != 0
            || page.entries.len() > begin.maximum as usize
        {
            return Err(io::Error::other(
                "directory adapter page does not match selection",
            ));
        }
        let source_deadline = source.snapshot_deadline()?;
        let lifetime = Arc::new(BrowseLifetime {
            consent,
            deadline: source_deadline.min(started + Duration::from_millis(DIRECTORY_SNAPSHOT_MS)),
            abandoned: Arc::new(AtomicBool::new(false)),
        });
        let transfer = Self {
            source,
            lifetime,
            source_deadline,
            last_name: page.entries.last().map(|entry| entry.name.clone()),
            page: page.clone(),
        };
        let disclosure = transfer.disclosure(started, transfer.source.reply_deadline()?);
        disclosure.check()?;
        authorized()?;
        Ok((transfer, page, disclosure))
    }
    pub(super) fn consent(&self) -> Arc<dyn FileReadConsent> {
        self.lifetime.clone()
    }
    fn disclosure(&self, started: Instant, local_deadline: Instant) -> Arc<dyn FileReadConsent> {
        Arc::new(PageDisclosure {
            lifetime: self.lifetime.clone(),
            operation_deadline: local_deadline
                .min(started + Duration::from_millis(FILE_OPERATION_MS)),
        })
    }
    pub(super) fn next(
        &mut self,
        next: &DirectoryBrowseNext,
        started: Instant,
        check: &mut dyn FnMut() -> io::Result<()>,
    ) -> io::Result<(DirectoryBrowsePage, Arc<dyn FileReadConsent>)> {
        self.lifetime.check()?;
        if self.page.next_cursor != next.cursor || self.page.next_cursor.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "directory cursor is not the expected successor",
            ));
        }
        let operating =
            self.disclosure(started, started + Duration::from_millis(FILE_OPERATION_MS));
        let mut authorized = || {
            check()?;
            operating.check()
        };
        let page = self
            .source
            .next(&next.cursor, next.maximum as usize, &mut authorized)?;
        page.validate()
            .map_err(|_| io::Error::other("invalid directory adapter successor page"))?;
        if page.root_id != self.page.root_id
            || page.directory != self.page.directory
            || page.snapshot_id != self.page.snapshot_id
            || page.total_entries != self.page.total_entries
            || page.offset as usize != self.page.offset as usize + self.page.entries.len()
            || page.entries.len() > next.maximum as usize
            || self.source.snapshot_deadline()? != self.source_deadline
            || self.last_name.as_ref().is_some_and(|previous| {
                page.entries
                    .first()
                    .is_some_and(|first| previous >= &first.name)
            })
            || (!page.next_cursor.is_empty() && page.next_cursor == next.cursor)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "directory adapter changed the fixed snapshot",
            ));
        }
        authorized()?;
        let disclosure = self.disclosure(started, self.source.reply_deadline()?);
        disclosure.check()?;
        self.last_name = page.entries.last().map(|entry| entry.name.clone());
        self.page = page.clone();
        Ok((page, disclosure))
    }
}

/// A single non-cloneable browse belongs to one exact FileReadClient instance.
/// Its page contains metadata only; downloading still requires independent open.
pub struct DirectoryBrowse {
    transfer_id: String,
    owner: Arc<()>,
    page: DirectoryBrowsePage,
    closed: bool,
}
impl DirectoryBrowse {
    pub fn page(&self) -> &DirectoryBrowsePage {
        &self.page
    }
    pub fn finished(&self) -> bool {
        self.closed || self.page.next_cursor.is_empty()
    }
}
impl FileReadClient {
    pub async fn begin_browse(
        &mut self,
        transfer_id: &str,
        root_id: &str,
        directory: Option<&str>,
        maximum: u32,
    ) -> Result<DirectoryBrowse, FileReadError> {
        let directory = directory.unwrap_or_default();
        let reply = self
            .request(
                transfer_id,
                Action::BrowseBegin(DirectoryBrowseBegin {
                    root_id: root_id.into(),
                    directory: directory.into(),
                    maximum,
                }),
            )
            .await?;
        let Action::BrowsePage(page) = reply else {
            return Err(self
                .protocol("directory begin did not return a page")
                .into());
        };
        if page.root_id != root_id
            || page.directory != directory
            || page.offset != 0
            || page.entries.len() > maximum as usize
        {
            return Err(self
                .protocol("directory first page does not match the request")
                .into());
        }
        self.check_response_deadline()?;
        Ok(DirectoryBrowse {
            transfer_id: transfer_id.into(),
            owner: self.owner.clone(),
            page,
            closed: false,
        })
    }
    pub async fn next_browse(
        &mut self,
        browse: &mut DirectoryBrowse,
        maximum: u32,
    ) -> Result<Option<DirectoryBrowsePage>, FileReadError> {
        if !Arc::ptr_eq(&browse.owner, &self.owner) {
            return Err(
                RemoteError::from(rejected("directory cursor belongs to another client")).into(),
            );
        }
        self.lease
            .check_channel_binding(Channel::FileRead, self.generation)?;
        if browse.finished() {
            return Ok(None);
        }
        let next = DirectoryBrowseNext {
            cursor: browse.page.next_cursor.clone(),
            maximum,
        };
        next.validate().map_err(RemoteError::from)?;
        let response = self
            .request(&browse.transfer_id, Action::BrowseNext(next))
            .await;
        let reply = match response {
            Ok(reply) => reply,
            Err(error) => {
                browse.closed = true;
                return Err(error);
            }
        };
        let Action::BrowsePage(page) = reply else {
            return Err(self.protocol("directory next did not return a page").into());
        };
        if page.root_id != browse.page.root_id
            || page.directory != browse.page.directory
            || page.snapshot_id != browse.page.snapshot_id
            || page.total_entries != browse.page.total_entries
            || page.offset as usize != browse.page.offset as usize + browse.page.entries.len()
            || page.entries.len() > maximum as usize
            || browse.page.entries.last().is_some_and(|previous| {
                page.entries
                    .first()
                    .is_some_and(|first| previous.name >= first.name)
            })
            || (!page.next_cursor.is_empty() && page.next_cursor == browse.page.next_cursor)
        {
            return Err(self
                .protocol("directory successor changed its fixed snapshot or extent")
                .into());
        }
        browse.page = page.clone();
        self.check_response_deadline()?;
        Ok(Some(page))
    }
    pub async fn cancel_browse(
        &mut self,
        browse: &mut DirectoryBrowse,
    ) -> Result<(), FileReadError> {
        if !Arc::ptr_eq(&browse.owner, &self.owner) {
            return Err(
                RemoteError::from(rejected("directory cursor belongs to another client")).into(),
            );
        }
        self.lease
            .check_channel_binding(Channel::FileRead, self.generation)?;
        if browse.finished() {
            return Ok(());
        }
        self.request(&browse.transfer_id, Action::Cancel(true))
            .await?;
        self.check_response_deadline()?;
        browse.closed = true;
        Ok(())
    }
}
