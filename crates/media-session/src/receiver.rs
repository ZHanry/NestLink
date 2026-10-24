use crate::video::streams;
use crate::worker::{self, Worker};
use crate::{ShutdownReport, VideoStream, WorkerMonitor};
use nestlink_media_codec::{VideoCodec, VideoConfig, VideoDecoder};
use nestlink_protocol::{
    NativeVideo, NativeVideoFeedback, SCHEMA_VERSION, VIDEO_KEYFRAME_INTERVAL_MS,
    VIDEO_RECOVERY_ATTEMPTS, VIDEO_RECOVERY_MS, VIDEO_RECOVERY_WINDOW_MS, VideoRecoveryReason,
};
use nestlink_remote::{
    ChannelReceiver, ChannelRuntime, ChannelSender, LeaseControl, video::VideoEpoch,
};
use nestlink_session::StopReason;
use nestlink_transport_stream::{Channel, Frame};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{sync::watch, task::JoinHandle};
use zeroize::{Zeroize, Zeroizing};

use nestlink_protocol::native_displays::{
    DisplayCatalogKey, DisplayDescriptor, DisplayEnvelope, DisplaySelection, catalog_key,
    validate_displays,
};

const EVENT_CAPACITY: usize = 4;

/// Packed BGRA for presentation. Every encoded reference is decoded before an
/// older presentation image may be replaced in this per-source mailbox.
pub struct DecodedVideo {
    /// Encoded YUV source conversion; does not label the returned BGRA as
    /// limited-range RGB, establish capture transfer, or prove display HDR.
    pub source_color: nestlink_protocol::media_format::Color,
    pub codec: u8,
    pub hardware_decode: bool,
    pub epoch: VideoEpoch,
    pub source: u32,
    pub sequence: u64,
    pub pts_90khz: u64,
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
    pub repeated_source: bool,
}
impl Drop for DecodedVideo {
    fn drop(&mut self) {
        self.pixels.zeroize();
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VideoLayout {
    pub epoch: VideoEpoch,
    pub source: u32,
    pub width: u32,
    pub height: u32,
}
struct ScheduledVideo {
    at: Instant,
    frame: DecodedVideo,
}
struct State {
    scheduled: VecDeque<ScheduledVideo>,
    videos: BTreeMap<u32, DecodedVideo>,
    layouts: BTreeMap<u32, VideoLayout>,
    ready: VecDeque<u32>,
    events: VecDeque<Frame>,
    closed: bool,
    advertised: bool,
    catalog: Option<(DisplayCatalogKey, Vec<DisplayDescriptor>)>,
    selected: Option<VideoLayout>,
    last_selected: Option<VideoLayout>,
    stats: VideoReceiverStats,
}
impl State {
    fn queue_video(
        &mut self,
        clock: &crate::SessionPlayoutClock,
        frame: DecodedVideo,
        now: Instant,
    ) -> io::Result<()> {
        while self.scheduled.front().is_some_and(|pending| {
            now.saturating_duration_since(pending.at) > crate::MAX_PLAYOUT_LATE
        }) {
            self.scheduled.pop_front();
            self.stats.discarded_late_frames = self.stats.discarded_late_frames.saturating_add(1);
        }
        match clock.schedule(frame.pts_90khz, 90_000, now)? {
            crate::PlayoutDecision::At(at) => {
                let bytes = self
                    .scheduled
                    .iter()
                    .map(|pending| pending.frame.pixels.len())
                    .sum::<usize>();
                if self.scheduled.len() < 16
                    && bytes.saturating_add(frame.pixels.len()) <= 128 * 1024 * 1024
                {
                    self.scheduled.push_back(ScheduledVideo { at, frame });
                } else {
                    // Decode every reference, but retain an older due image
                    // under pressure so large geometry cannot starve output.
                    self.stats.discarded_budget_frames =
                        self.stats.discarded_budget_frames.saturating_add(1);
                }
            }
            crate::PlayoutDecision::DropLate => {
                self.stats.discarded_late_frames =
                    self.stats.discarded_late_frames.saturating_add(1);
            }
            crate::PlayoutDecision::DropFuture => {
                self.stats.discarded_future_frames =
                    self.stats.discarded_future_frames.saturating_add(1);
            }
        }
        Ok(())
    }

    fn poll_scheduled(&mut self, now: Instant) -> Option<DecodedVideo> {
        let mut newest = None;
        while self
            .scheduled
            .front()
            .is_some_and(|pending| pending.at <= now)
        {
            let Some(pending) = self.scheduled.pop_front() else {
                break;
            };
            if now.duration_since(pending.at) > crate::MAX_PLAYOUT_LATE {
                self.stats.discarded_late_frames =
                    self.stats.discarded_late_frames.saturating_add(1);
            } else {
                newest = Some(pending.frame);
            }
        }
        newest
    }
}
#[derive(Debug, Clone, Copy, Default)]
pub struct VideoReceiverStats {
    pub feedback_requests: u64,
    pub discarded_frames: u64,
    pub completed_recoveries: u64,
    pub discarded_late_frames: u64,
    pub discarded_future_frames: u64,
    pub discarded_budget_frames: u64,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum DecoderReadiness {
    Unprepared,
    Fixed,
    Display(VideoLayout, u64),
}
struct Output {
    consumer_revision: std::sync::atomic::AtomicU64,
    external: Mutex<Option<crate::external::ExternalSink>>,
    playout: Option<crate::SessionPlayoutClock>,
    state: Mutex<State>,
    changes: watch::Sender<u64>,
    recovery_deadline: watch::Sender<Option<Instant>>,
    prepared: watch::Sender<DecoderReadiness>,
}
impl Output {
    fn advance_consumer(&self) -> io::Result<()> {
        self.consumer_revision
            .fetch_update(
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
                |v| v.checked_add(1).filter(|n| *n <= i64::MAX as u64),
            )
            .map(|_| ())
            .map_err(|_| io::Error::other("video consumer generation exhausted"))
    }
    fn check_recovery_deadline(&self) -> io::Result<()> {
        if self
            .recovery_deadline
            .borrow()
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "video keyframe recovery budget exhausted",
            ));
        }
        Ok(())
    }
    fn new() -> Arc<Self> {
        Self::with_clock(None)
    }
    fn with_clock(playout: Option<crate::SessionPlayoutClock>) -> Arc<Self> {
        let (changes, _) = watch::channel(0);
        let (recovery_deadline, _) = watch::channel(None);
        let (prepared, _) = watch::channel(DecoderReadiness::Unprepared);
        Arc::new(Self {
            consumer_revision: std::sync::atomic::AtomicU64::new(1),
            external: Mutex::new(None),
            playout,
            state: Mutex::new(State {
                scheduled: VecDeque::new(),
                videos: BTreeMap::new(),
                layouts: BTreeMap::new(),
                ready: VecDeque::new(),
                events: VecDeque::new(),
                closed: false,
                advertised: false,
                catalog: None,
                selected: None,
                last_selected: None,
                stats: VideoReceiverStats::default(),
            }),
            changes,
            recovery_deadline,
            prepared,
        })
    }
    fn set_recovery_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        let mut expired = false;
        self.recovery_deadline.send_if_modified(|current| {
            let now = Instant::now();
            if current.is_some_and(|old| now >= old) || deadline.is_some_and(|new| now >= new) {
                expired = true;
                return false;
            }
            let changed = *current != deadline;
            *current = deadline;
            changed
        });
        if expired {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "video keyframe recovery budget exhausted",
            ));
        }
        Ok(())
    }
    fn wake(&self) {
        self.changes.send_modify(|v| *v = v.saturating_add(1));
    }
    fn close(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.closed = true;
        state.scheduled.clear();
        state.videos.clear();
        state.layouts.clear();
        state.ready.clear();
        state.events.clear();
        state.catalog = None;
        state.selected = None;
        state.last_selected = None;
        drop(state);
        if let Ok(mut external) = self.external.lock()
            && let Some(sink) = external.as_mut()
        {
            let c = sink.context.clone();
            let _ = sink.feedback(&c, crate::external::VideoSinkFeedback::Fence);
        }
        self.prepared.send_replace(DecoderReadiness::Unprepared);
        self.wake();
    }
}
struct CloseOutput(Arc<Output>);
impl Drop for CloseOutput {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// A nonblocking presentation mailbox. It holds no codec or thread owner and
/// checks the original View lease again whenever pixels leave the mailbox.
#[derive(Clone)]
pub struct VideoPresentation {
    output: Arc<Output>,
    lease: LeaseControl,
    connection_generation: u64,
}
/// Cleanup-only capability retained independently of revoked display routes.
/// It cannot consume bytes, prepare a decoder, extend a lease or present.
#[derive(Clone)]
pub struct ExternalVideoCleanup {
    output: Arc<Output>,
    stream_id: [u8; 16],
}
impl ExternalVideoCleanup {
    pub fn fence(&self) -> io::Result<()> {
        let mut external = self
            .output
            .external
            .lock()
            .map_err(|_| io::Error::other("external sink poisoned"))?;
        if let Some(sink) = external
            .as_mut()
            .filter(|s| s.context.stream_id == self.stream_id)
        {
            let context = sink.context.clone();
            sink.feedback(&context, crate::external::VideoSinkFeedback::Fence)?;
        }
        Ok(())
    }
    pub fn joined(&self, context: &crate::external::VideoSinkContext) -> io::Result<()> {
        let mut external = self
            .output
            .external
            .lock()
            .map_err(|_| io::Error::other("external sink poisoned"))?;
        let sink = external
            .as_mut()
            .filter(|s| s.context.stream_id == self.stream_id)
            .ok_or_else(|| io::Error::other("external owner retired"))?;
        sink.feedback(
            context,
            crate::external::VideoSinkFeedback::Stopped { joined: true },
        )?;
        self.output.advance_consumer()?;
        *external = None;
        drop(external);
        self.output.wake();
        Ok(())
    }
}
impl VideoPresentation {
    pub fn external_cleanup(
        &self,
        context: &crate::external::VideoSinkContext,
    ) -> io::Result<ExternalVideoCleanup> {
        let external = self
            .output
            .external
            .lock()
            .map_err(|_| io::Error::other("external sink poisoned"))?;
        if !external.as_ref().is_some_and(|s| &s.context == context) {
            return Err(io::Error::other("external owner differs"));
        }
        Ok(ExternalVideoCleanup {
            output: self.output.clone(),
            stream_id: context.stream_id,
        })
    }
    pub fn authority_remaining(&self) -> io::Result<Duration> {
        self.lease
            .media_authority_remaining(Channel::Video, self.connection_generation)
            .map_err(io::Error::other)
    }
    /// Atomically replaces the CPU consumer; the network channel remains owned
    /// by its original authorized receiver worker.
    pub fn open_external(&self, context: crate::external::VideoSinkContext) -> io::Result<()> {
        self.lease
            .check_media_binding(Channel::Video, self.connection_generation)
            .map_err(io::Error::other)?;
        if !self
            .lease
            .media_capability(nestlink_protocol::media::H264_CAPABILITY)
            .map_err(io::Error::other)?
        {
            return Err(io::Error::other(
                "external decoding requires negotiated H264",
            ));
        }
        let mut external = self
            .output
            .external
            .lock()
            .map_err(|_| io::Error::other("external sink poisoned"))?;
        if external.is_some() {
            return Err(io::Error::other("video consumer already claimed"));
        }
        let mut state = self
            .output
            .state
            .lock()
            .map_err(|_| io::Error::other("media output poisoned"))?;
        let layout = state
            .selected
            .filter(|v| {
                v.source == context.source
                    && v.epoch.connection == context.connection_generation
                    && v.epoch.layout == context.layout_epoch
            })
            .ok_or_else(|| io::Error::other("external selection differs"))?;
        if state.closed
            || state.catalog.as_ref().map(|(key, _)| key.revision) != Some(context.catalog_revision)
        {
            return Err(io::Error::other("external catalogue differs"));
        }
        self.output.advance_consumer()?;
        *external = Some(crate::external::ExternalSink::new(
            context,
            layout.width,
            layout.height,
        )?);
        state.videos.clear();
        state.scheduled.clear();
        state.ready.clear();
        self.output
            .prepared
            .send_replace(DecoderReadiness::Unprepared);
        drop(state);
        drop(external);
        self.output.wake();
        Ok(())
    }
    pub fn external_context(
        &self,
    ) -> io::Result<Option<(crate::external::VideoSinkContext, u32, u32)>> {
        self.lease
            .check_media_binding(Channel::Video, self.connection_generation)
            .map_err(io::Error::other)?;
        let external = self
            .output
            .external
            .lock()
            .map_err(|_| io::Error::other("external sink poisoned"))?;
        Ok(external
            .as_ref()
            .map(|s| (s.context.clone(), s.width, s.height)))
    }
    pub fn external_surface(&self) -> io::Result<Option<crate::LegacySurface>> {
        self.lease
            .check_media_binding(Channel::Video, self.connection_generation)
            .map_err(io::Error::other)?;
        let external = self
            .output
            .external
            .lock()
            .map_err(|_| io::Error::other("external sink poisoned"))?;
        Ok(external.as_ref().map(|sink| sink.surface()))
    }
    pub fn poll_external(&self) -> io::Result<Option<crate::external::ExternalAccessUnit>> {
        self.lease
            .check_media_binding(Channel::Video, self.connection_generation)
            .map_err(io::Error::other)?;
        let mut external = self
            .output
            .external
            .lock()
            .map_err(|_| io::Error::other("external sink poisoned"))?;
        Ok(external
            .as_mut()
            .and_then(crate::external::ExternalSink::pop))
    }
    pub fn external_feedback(
        &self,
        context: &crate::external::VideoSinkContext,
        feedback: crate::external::VideoSinkFeedback,
    ) -> io::Result<()> {
        self.lease
            .check_media_binding(Channel::Video, self.connection_generation)
            .map_err(io::Error::other)?;
        let mut external = self
            .output
            .external
            .lock()
            .map_err(|_| io::Error::other("external sink poisoned"))?;
        let sink = external
            .as_mut()
            .ok_or_else(|| io::Error::other("no external consumer"))?;
        sink.feedback(context, feedback)?;
        if sink.prepared {
            let layout = VideoLayout {
                epoch: VideoEpoch {
                    connection: context.connection_generation,
                    layout: context.layout_epoch,
                },
                source: context.source,
                width: sink.width,
                height: sink.height,
            };
            self.output
                .prepared
                .send_replace(DecoderReadiness::Display(layout, context.catalog_revision));
        }
        drop(external);
        self.output.wake();
        Ok(())
    }
    /// Only a joined presenter may release ownership and reopen the CPU sink.
    pub fn close_external(&self, context: &crate::external::VideoSinkContext) -> io::Result<()> {
        let mut external = self
            .output
            .external
            .lock()
            .map_err(|_| io::Error::other("external sink poisoned"))?;
        if !external
            .as_ref()
            .is_some_and(|s| &s.context == context && s.stopped)
        {
            return Err(io::Error::other("external cleanup ownership pending"));
        }
        self.output.advance_consumer()?;
        *external = None;
        drop(external);
        self.output.wake();
        Ok(())
    }
    async fn wait_prepared(&self, expected: DecoderReadiness) -> io::Result<()> {
        let mut prepared = self.output.prepared.subscribe();
        let mut reports = self.lease.subscribe_stopped();
        let waiting = async {
            loop {
                self.lease
                    .check_media_binding(Channel::Video, self.connection_generation)
                    .map_err(io::Error::other)?;
                {
                    let state = self
                        .output
                        .state
                        .lock()
                        .map_err(|_| io::Error::other("media output poisoned"))?;
                    if state.closed
                        || matches!(expected, DecoderReadiness::Display(layout, revision)
                            if state.selected != Some(layout)
                                || state.catalog.as_ref().map(|(key, _)| key.revision) != Some(revision))
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "decoder preparation retired",
                        ));
                    }
                }
                if *prepared.borrow_and_update() == expected {
                    return Ok(());
                }
                tokio::select! { biased;
                    _ = reports.changed() => {},
                    result = prepared.changed() => { result.map_err(|_| io::Error::other("decoder preparation closed"))?; }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(2), waiting)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "decoder preparation budget exhausted",
                )
            })?
    }
    /// Wait before acknowledging the host's selected display. No media/input
    /// authority is granted here; the exact live selection remains required.
    pub async fn wait_display_ready(&self, selection: &DisplaySelection) -> io::Result<()> {
        let layout = {
            let state = self
                .output
                .state
                .lock()
                .map_err(|_| io::Error::other("media output poisoned"))?;
            state
                .selected
                .filter(|layout| {
                    layout.source == selection.source
                        && layout.epoch.layout == selection.layout_epoch
                        && state
                            .catalog
                            .as_ref()
                            .is_some_and(|(key, _)| key == &selection.catalog)
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "display preparation binding changed",
                    )
                })?
        };
        self.wait_prepared(DecoderReadiness::Display(
            layout,
            selection.catalog.revision,
        ))
        .await
    }
    /// Install the exact host/local-consent catalogue before acknowledging it.
    /// The receive worker starts with no allowed source and never guesses IDs.
    pub fn install_display_catalog(
        &self,
        key: DisplayCatalogKey,
        displays: Vec<DisplayDescriptor>,
    ) -> io::Result<()> {
        validate_displays(&displays).map_err(io::Error::other)?;
        if key.connection_generation != self.connection_generation
            || catalog_key(
                &key.request_id,
                key.connection_generation,
                key.revision,
                &displays,
            )
            .map_err(io::Error::other)?
                != key
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "display catalogue binding differs",
            ));
        }
        self.lease
            .check_media_binding(Channel::Video, self.connection_generation)
            .map_err(io::Error::other)?;
        let mut state = self
            .output
            .state
            .lock()
            .map_err(|_| io::Error::other("media output poisoned"))?;
        if !state.advertised || state.closed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "catalogue already bound or output closed",
            ));
        }
        if let Some((previous, approved)) = state.catalog.as_ref() {
            if previous.request_id != key.request_id
                || previous.connection_generation != key.connection_generation
                || previous.revision.checked_add(1) != Some(key.revision)
                || approved.iter().map(|d| d.source).collect::<Vec<_>>()
                    != displays.iter().map(|d| d.source).collect::<Vec<_>>()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "catalogue refresh changed original source grant",
                ));
            }
            state.selected = None;
            state.scheduled.clear();
            state.videos.clear();
            state.layouts.clear();
            state.ready.clear();
        }
        state.catalog = Some((key, displays));
        self.output
            .prepared
            .send_replace(DecoderReadiness::Unprepared);
        drop(state);
        self.output.wake();
        Ok(())
    }
    /// Called only after a strict Selected envelope. Purge every previous image
    /// synchronously, before the controller acknowledges the new host epoch.
    pub fn select_display(&self, selection: &DisplaySelection) -> io::Result<()> {
        self.output.check_recovery_deadline()?;
        self.lease
            .check_media_binding(Channel::Video, self.connection_generation)
            .map_err(io::Error::other)?;
        let mut state = self
            .output
            .state
            .lock()
            .map_err(|_| io::Error::other("media output poisoned"))?;
        let (key, displays) = state
            .catalog
            .as_ref()
            .ok_or_else(|| io::Error::other("no display catalogue"))?;
        let descriptor = displays
            .iter()
            .find(|d| d.source == selection.source)
            .filter(|_| key == &selection.catalog)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unapproved display selection",
                )
            })?;
        let layout = VideoLayout {
            epoch: VideoEpoch {
                connection: self.connection_generation,
                layout: selection.layout_epoch,
            },
            source: selection.source,
            width: descriptor.width,
            height: descriptor.height,
        };
        if state
            .last_selected
            .is_some_and(|old| layout.epoch.layout <= old.epoch.layout && old != layout)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "display selection epoch replay",
            ));
        }
        state.scheduled.clear();
        state.videos.clear();
        state.ready.clear();
        state.layouts.clear();
        state.layouts.insert(layout.source, layout);
        if state.selected != Some(layout) {
            self.output
                .prepared
                .send_replace(DecoderReadiness::Unprepared);
        }
        state.selected = Some(layout);
        state.last_selected = Some(layout);
        drop(state);
        // A user-selected new source retires the previous decoder. Its request
        // history remains per source, but its retired recovery cannot schedule
        // packets on the newly selected source.
        self.output.recovery_deadline.send_replace(None);
        self.output.wake();
        Ok(())
    }
    pub fn suspend_display(&self) -> io::Result<()> {
        self.lease
            .check_media_binding(Channel::Video, self.connection_generation)
            .map_err(io::Error::other)?;
        let mut state = self
            .output
            .state
            .lock()
            .map_err(|_| io::Error::other("media output poisoned"))?;
        state.selected = None;
        state.scheduled.clear();
        state.videos.clear();
        state.layouts.clear();
        state.ready.clear();
        drop(state);
        self.output
            .prepared
            .send_replace(DecoderReadiness::Unprepared);
        self.output.wake();
        Ok(())
    }
    /// Permanently clears this mailbox when its product session is retired.
    pub fn retire(&self) {
        self.output.close();
    }
    pub fn layout(&self, source: u32) -> io::Result<Option<VideoLayout>> {
        if let Err(error) = self
            .lease
            .check_media_binding(Channel::Video, self.connection_generation)
        {
            self.output.close();
            return Err(io::Error::other(error));
        }
        let state = self
            .output
            .state
            .lock()
            .map_err(|_| io::Error::other("media output poisoned"))?;
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "media output closed",
            ));
        }
        if state.advertised {
            return Ok(state.selected.filter(|layout| layout.source == source));
        }
        Ok(state.layouts.get(&source).copied())
    }
    pub fn poll_video(&self) -> io::Result<Option<DecodedVideo>> {
        if let Err(error) = self
            .lease
            .check_media_binding(Channel::Video, self.connection_generation)
        {
            self.output.close();
            return Err(io::Error::other(error));
        }
        let mut state = self
            .output
            .state
            .lock()
            .map_err(|_| io::Error::other("media output poisoned"))?;
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "media output closed",
            ));
        }
        let frame = if self.output.playout.is_some() {
            state.poll_scheduled(Instant::now())
        } else {
            state
                .ready
                .pop_front()
                .and_then(|source| state.videos.remove(&source))
        };
        drop(state);
        if let Err(error) = self
            .lease
            .check_media_binding(Channel::Video, self.connection_generation)
        {
            self.output.close();
            return Err(io::Error::other(error));
        }
        Ok(frame)
    }
}

/// Owns the receiving half of an authorized native session. Video is decoded
/// on a dedicated thread. Other business frames remain in a bounded FIFO for
/// the caller's input/audio/file/clipboard dispatcher; none are silently lost.
pub struct VideoReceiver {
    worker: Worker,
    output: Arc<Output>,
    epoch: VideoEpoch,
    terminal: Option<JoinHandle<()>>,
}
enum ReceiveSources {
    Fixed(Vec<VideoStream>),
    Dynamic(BTreeSet<u32>),
    Advertised,
}
impl VideoReceiver {
    /// Fixed-stream callers must prepare decoders before enabling the sender.
    pub async fn wait_ready(&self) -> io::Result<()> {
        self.presentation()
            .wait_prepared(DecoderReadiness::Fixed)
            .await
    }
    pub fn attach(
        mut runtime: ChannelRuntime,
        epoch: VideoEpoch,
        selected: Vec<VideoStream>,
    ) -> io::Result<Self> {
        streams(epoch, &selected)?;
        let lease = runtime.lease_control();
        lease
            .check_media_binding(Channel::Video, epoch.connection)
            .map_err(io::Error::other)?;
        let video = runtime
            .claim_channel(Channel::Video)
            .map_err(io::Error::other)?;
        let sender = runtime.sender();
        let output = Output::new();
        let terminal_output = output.clone();
        let dispatch_lease = lease.clone();
        let executor = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let terminal = executor.spawn(async move {
            let _close = CloseOutput(terminal_output.clone());
            let mut runtime = runtime;
            let deadlines = terminal_output.recovery_deadline.subscribe();
            let (result, reason) = tokio::select! { biased;
                result = supervise_recovery(deadlines) => (result, StopReason::PlatformChanged),
                result = dispatch(&mut runtime, &dispatch_lease, epoch, terminal_output) => (result, StopReason::Revoked),
            };
            if result.is_err() {
                let _ = dispatch_lease.stop(reason);
            }
        });
        let worker_output = output.clone();
        let worker_lease = lease.clone();
        let worker = match Worker::spawn("nestlink-video-receive", lease, move |stop| {
            let _close = CloseOutput(worker_output.clone());
            receive(
                video,
                sender,
                worker_lease,
                epoch,
                ReceiveSources::Fixed(selected),
                worker_output,
                stop,
            )
        }) {
            Ok(worker) => worker,
            Err(error) => {
                terminal.abort();
                return Err(error);
            }
        };
        Ok(Self {
            worker,
            output,
            epoch,
            terminal: Some(terminal),
        })
    }
    /// Receives host-authenticated layout changes on explicitly selected source
    /// IDs. The caller retains the other channels and the session owner. A new
    /// layout destroys the old decoder and presentation image; sequence, PTS
    /// and outstanding recovery deadlines remain continuous across layouts.
    pub fn attach_advertised_channel(
        runtime: &mut ChannelRuntime,
        connection_generation: u64,
    ) -> io::Result<Self> {
        Self::attach_dynamic_inner(runtime, connection_generation, Vec::new(), true, None)
    }
    pub fn attach_advertised_channel_timed(
        runtime: &mut ChannelRuntime,
        connection_generation: u64,
        clock: crate::SessionPlayoutClock,
    ) -> io::Result<Self> {
        Self::attach_dynamic_inner(
            runtime,
            connection_generation,
            Vec::new(),
            true,
            Some(clock),
        )
    }
    pub fn attach_dynamic_channel(
        runtime: &mut ChannelRuntime,
        connection_generation: u64,
        sources: Vec<u32>,
    ) -> io::Result<Self> {
        Self::attach_dynamic_inner(runtime, connection_generation, sources, false, None)
    }
    fn attach_dynamic_inner(
        runtime: &mut ChannelRuntime,
        connection_generation: u64,
        sources: Vec<u32>,
        advertised: bool,
        playout: Option<crate::SessionPlayoutClock>,
    ) -> io::Result<Self> {
        let allowed: BTreeSet<_> = sources.iter().copied().collect();
        if connection_generation == 0
            || connection_generation > i64::MAX as u64
            || (!advertised && sources.is_empty())
            || sources.len() > 64
            || allowed.len() != sources.len()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid dynamic video sources",
            ));
        }
        let lease = runtime.lease_control();
        lease
            .check_media_binding(Channel::Video, connection_generation)
            .map_err(io::Error::other)?;
        let video = runtime
            .claim_channel(Channel::Video)
            .map_err(io::Error::other)?;
        let sender = runtime.sender();
        let output = Output::with_clock(playout);
        output
            .state
            .lock()
            .map_err(|_| io::Error::other("media output poisoned"))?
            .advertised = advertised;
        let watchdog_output = output.clone();
        let mut reports = lease.subscribe_stopped();
        let deadlines = output.recovery_deadline.subscribe();
        let watchdog_lease = lease.clone();
        let executor = tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let terminal = executor.spawn(async move {
            let _close = CloseOutput(watchdog_output);
            if reports.borrow().is_some() {
                return;
            }
            tokio::select! { biased;
                _ = reports.changed() => {},
                result = supervise_recovery(deadlines) => {
                    if result.is_err() {
                        let _ = watchdog_lease.stop(StopReason::PlatformChanged);
                    }
                }
            }
        });
        let worker_output = output.clone();
        let worker_lease = lease.clone();
        let epoch = VideoEpoch {
            connection: connection_generation,
            layout: 1,
        };
        let worker = match Worker::spawn("nestlink-dynamic-video-receive", lease, move |stop| {
            let _close = CloseOutput(worker_output.clone());
            receive(
                video,
                sender,
                worker_lease,
                epoch,
                if advertised {
                    ReceiveSources::Advertised
                } else {
                    ReceiveSources::Dynamic(allowed)
                },
                worker_output,
                stop,
            )
        }) {
            Ok(worker) => worker,
            Err(error) => {
                terminal.abort();
                return Err(error);
            }
        };
        Ok(Self {
            worker,
            output,
            epoch,
            terminal: Some(terminal),
        })
    }
    pub fn presentation(&self) -> VideoPresentation {
        VideoPresentation {
            output: self.output.clone(),
            lease: self.worker.lease.clone(),
            connection_generation: self.epoch.connection,
        }
    }
    pub fn monitor(&self) -> WorkerMonitor {
        self.worker.monitor()
    }
    pub fn stats(&self) -> VideoReceiverStats {
        self.output
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stats
    }
    #[cfg(test)]
    pub(crate) fn event_count_for_test(&self) -> usize {
        self.output
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .events
            .len()
    }
    #[cfg(test)]
    pub(crate) fn scheduled_count_for_test(&self) -> usize {
        self.output
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .scheduled
            .len()
    }

    pub fn poll_video(&mut self) -> io::Result<Option<DecodedVideo>> {
        self.presentation().poll_video()
    }
    pub fn poll_event(&mut self) -> io::Result<Option<Frame>> {
        // Get the channel without taking it out before its permission is checked.
        let channel = {
            let state = self
                .output
                .state
                .lock()
                .map_err(|_| io::Error::other("media output poisoned"))?;
            if state.closed {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "media output closed",
                ));
            }
            state.events.front().map(|frame| frame.channel)
        };
        let channel = channel.unwrap_or(Channel::Video);
        if let Err(error) = self
            .worker
            .lease
            .check_channel_binding(channel, self.epoch.connection)
        {
            self.output.close();
            return Err(io::Error::other(error));
        }
        let mut state = self
            .output
            .state
            .lock()
            .map_err(|_| io::Error::other("media output poisoned"))?;
        if state.closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "media output closed",
            ));
        }
        let frame = state.events.pop_front();
        drop(state);
        if frame.is_some() {
            self.output.wake();
        }
        Ok(frame)
    }
    pub fn shutdown(&mut self, reason: StopReason) -> io::Result<ShutdownReport> {
        self.output.close();
        let worker = self.worker.shutdown(reason)?;
        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            let pending = self
                .output
                .external
                .lock()
                .map_err(|_| io::Error::other("external sink poisoned"))?
                .as_ref()
                .is_some_and(|s| !s.stopped);
            if !pending {
                return Ok(worker);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "external presenter ownership pending",
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}
impl Drop for VideoReceiver {
    fn drop(&mut self) {
        self.output.close();
        let _ = self.worker.cleanup();
        if let Some(terminal) = self.terminal.take() {
            terminal.abort();
        }
    }
}
struct Recovery {
    started: Instant,
    next_request: Instant,
    reason: VideoRecoveryReason,
}
struct Decoder {
    stream: VideoStream,
    layout: u64,
    codec: Option<VideoDecoder>,
    prepare: Option<crate::legacy_format::LegacyPrepare>,
    awaiting_keyframe: bool,
    pending: BTreeMap<u64, (u64, bool)>,
    sequence: u64,
    pts: Option<u64>,
    request_sequence: u64,
    recovery: Option<Recovery>,
    attempts: VecDeque<Instant>,
}
impl Decoder {
    fn new(stream: VideoStream, layout: u64) -> Self {
        Self {
            stream,
            layout,
            codec: None,
            prepare: None,
            awaiting_keyframe: true,
            pending: BTreeMap::new(),
            sequence: 0,
            pts: None,
            request_sequence: 0,
            recovery: None,
            attempts: VecDeque::new(),
        }
    }
    fn recovery_deadline(&self) -> Option<Instant> {
        self.recovery
            .as_ref()
            .map(|recovery| recovery.started + Duration::from_millis(VIDEO_RECOVERY_MS))
    }
    fn deadline(&self, now: Instant) -> io::Result<()> {
        if self.recovery.as_ref().is_some_and(|recovery| {
            now.saturating_duration_since(recovery.started)
                >= Duration::from_millis(VIDEO_RECOVERY_MS)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "video keyframe recovery budget exhausted",
            ));
        }
        Ok(())
    }
    fn recover(&mut self, reason: VideoRecoveryReason, now: Instant) -> io::Result<()> {
        self.deadline(now)?;
        self.pending.clear();
        self.prepare = None;
        if reason == VideoRecoveryReason::DecoderFailure {
            self.codec = None;
        } else if !self.awaiting_keyframe {
            // Recreating a GPU transform for every omitted reference can stall
            // the reliable reader long enough to exhaust its video deadline.
            // A flush drops all delayed output; only a fresh IDR may follow it.
            let reused = self
                .codec
                .as_mut()
                .is_some_and(|codec| codec.reset_for_keyframe().unwrap_or(false));
            if !reused {
                self.codec = None;
            }
        }
        self.awaiting_keyframe = true;
        if self.recovery.is_none() || reason == VideoRecoveryReason::DecoderFailure {
            while self.attempts.front().is_some_and(|at| {
                now.saturating_duration_since(*at)
                    >= Duration::from_millis(VIDEO_RECOVERY_WINDOW_MS)
            }) {
                self.attempts.pop_front();
            }
            if self.attempts.len() >= VIDEO_RECOVERY_ATTEMPTS as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "video recovery attempt budget exhausted",
                ));
            }
            self.attempts.push_back(now);
        }
        let recovery = self.recovery.get_or_insert(Recovery {
            started: now,
            next_request: now,
            reason,
        });
        if reason == VideoRecoveryReason::DecoderFailure {
            recovery.reason = reason;
        }
        Ok(())
    }
    fn feedback(
        &mut self,
        sender: &ChannelSender,
        epoch: VideoEpoch,
        now: Instant,
    ) -> io::Result<bool> {
        self.deadline(now)?;
        let Some(recovery) = &mut self.recovery else {
            return Ok(false);
        };
        if now < recovery.next_request {
            return Ok(false);
        }
        let sequence = self
            .request_sequence
            .checked_add(1)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or_else(|| io::Error::other("video feedback sequence exhausted"))?;
        let message = DisplayEnvelope::Recovery(NativeVideoFeedback {
            schema_version: SCHEMA_VERSION,
            connection_generation: epoch.connection,
            layout_epoch: epoch.layout,
            source: self.stream.source,
            request_sequence: sequence,
            last_sequence: self.sequence,
            reason: recovery.reason as i32,
        })
        .encode()
        .map_err(io::Error::other)?;
        let inserted = sender
            .try_send_video_feedback(&message)
            .map_err(io::Error::other)?;
        if inserted {
            self.request_sequence = sequence;
        }
        // A full outgoing reliable queue neither stalls the decoder nor extends
        // recovery. Only a successful insertion consumes the request sequence.
        recovery.next_request = now
            + Duration::from_millis(if inserted {
                VIDEO_KEYFRAME_INTERVAL_MS
            } else {
                10
            });
        Ok(inserted)
    }
    fn wakeup(&self) -> Option<Instant> {
        self.recovery.as_ref().map(|recovery| {
            recovery
                .next_request
                .min(recovery.started + Duration::from_millis(VIDEO_RECOVERY_MS))
        })
    }
    fn accept_input(
        &mut self,
        packet: &NativeVideo,
        epoch: VideoEpoch,
        now: Instant,
    ) -> io::Result<bool> {
        self.deadline(now)?;
        if packet.connection_generation != epoch.connection
            || packet.layout_epoch != epoch.layout
            || packet.source != self.stream.source
            || packet.width != self.stream.codec.width
            || packet.height != self.stream.codec.height
            || packet.sequence <= self.sequence
            || self.pts.is_some_and(|pts| packet.pts_90khz <= pts)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "video stream identity, replay or timestamp changed",
            ));
        }
        let gap = self.sequence.checked_add(1) != Some(packet.sequence);
        // Valid metadata is consumed even for discarded/undecodable frames;
        // none of them can later replay and reset decoder history.
        self.sequence = packet.sequence;
        self.pts = Some(packet.pts_90khz);
        if gap {
            self.recover(VideoRecoveryReason::ReferenceGap, now)?;
        }
        if self.awaiting_keyframe && !packet.keyframe {
            self.recover(VideoRecoveryReason::KeyframeMissing, now)?;
            return Ok(false);
        }
        Ok(true)
    }
    fn decode(
        &mut self,
        packet: NativeVideo,
        payload: Zeroizing<Vec<u8>>,
        epoch: VideoEpoch,
        now: Instant,
    ) -> io::Result<Option<(DecodedVideo, bool)>> {
        if !self.accept_input(&packet, epoch, now)? {
            return Ok(None);
        }
        if self.prepare.is_none() {
            self.prepare = Some(crate::legacy_format::LegacyPrepare::from_wire(
                packet.codec,
                packet.width,
                packet.height,
            )?);
        }
        let prepare = self
            .prepare
            .as_mut()
            .ok_or_else(|| io::Error::other("missing legacy Prepare"))?;
        prepare.validate(&payload, packet.keyframe)?;
        let color = prepare.surface().color;
        if self.codec.is_none() {
            let kind = match nestlink_protocol::NativeVideoCodec::try_from(packet.codec) {
                Ok(nestlink_protocol::NativeVideoCodec::Vp8) => VideoCodec::Vp8,
                Ok(nestlink_protocol::NativeVideoCodec::H264Baseline) => VideoCodec::H264Baseline,
                Err(_) => return Err(io::Error::other("unknown video codec")),
            };
            self.codec = Some(VideoDecoder::new(kind, packet.width, packet.height)?);
        }
        self.awaiting_keyframe = false;
        if self.pending.len() >= 8 {
            self.recover(VideoRecoveryReason::DecoderFailure, now)?;
            return Ok(None);
        }
        self.pending
            .insert(packet.pts_90khz, (packet.sequence, packet.repeated_source));
        let decoded = match self
            .codec
            .as_mut()
            .ok_or_else(|| io::Error::other("missing video decoder"))?
            .decode(&payload, packet.pts_90khz)
        {
            Ok(decoded) => decoded,
            Err(_) => {
                // A failed libvpx reference context is destroyed. Repeated
                // entropy failures are bounded, never presented as good pixels.
                self.recover(VideoRecoveryReason::DecoderFailure, Instant::now())?;
                return Ok(None);
            }
        };
        let Some((pixels, output_pts)) = decoded else {
            return Ok(None);
        };
        let (output_sequence, repeated_source) =
            self.pending.remove(&output_pts).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "decoder output has no submitted timestamp",
                )
            })?;
        if self
            .pending
            .keys()
            .next()
            .is_some_and(|older| *older < output_pts)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "decoder reordered or skipped baseline output",
            ));
        }
        // Baseline has no reordering. A platform transform may buffer output;
        // present its real PTS, never relabel it with the latest input time.
        let mut pixels = Zeroizing::new(pixels);
        // A late decode cannot revive an expired recovery budget.
        self.deadline(Instant::now())?;
        let recovered = self.recovery.take().is_some();
        Ok(Some((
            DecodedVideo {
                source_color: color,
                codec: packet.codec as u8,
                hardware_decode: self.codec.as_ref().is_some_and(VideoDecoder::hardware),
                epoch,
                source: packet.source,
                sequence: output_sequence,
                pts_90khz: output_pts,
                width: packet.width,
                height: packet.height,
                pixels: std::mem::take(&mut *pixels),
                repeated_source,
            },
            recovered,
        )))
    }
}

/// Other business events use their own asynchronous dispatcher. A full file
/// mailbox does not hold the Video consumer or its keyframe feedback timer.
async fn dispatch(
    connection: &mut ChannelRuntime,
    lease: &LeaseControl,
    epoch: VideoEpoch,
    output: Arc<Output>,
) -> io::Result<()> {
    let mut reports = lease.subscribe_stopped();
    loop {
        if reports.borrow().is_some() {
            return Ok(());
        }
        let frame = tokio::select! { biased;
            _ = reports.changed() => { return Ok(()); }
            frame = connection.receive() => frame.map_err(io::Error::other)?,
        };
        lease
            .check_channel_binding(frame.channel, epoch.connection)
            .map_err(io::Error::other)?;
        let mut changed = output.changes.subscribe();
        let mut frame = Some(frame);
        loop {
            let _ = changed.borrow_and_update();
            let inserted = {
                let mut state = output
                    .state
                    .lock()
                    .map_err(|_| io::Error::other("media output poisoned"))?;
                if state.closed {
                    return Ok(());
                }
                if state.events.len() < EVENT_CAPACITY {
                    state.events.push_back(
                        frame
                            .take()
                            .ok_or_else(|| io::Error::other("event already delivered"))?,
                    );
                    true
                } else {
                    false
                }
            };
            if inserted {
                break;
            }
            tokio::select! { biased;
                _ = reports.changed() => { return Ok(()); }
                _ = changed.changed() => {},
            }
        }
    }
}

async fn supervise_recovery(mut deadlines: watch::Receiver<Option<Instant>>) -> io::Result<()> {
    loop {
        let deadline = *deadlines.borrow_and_update();
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "video keyframe recovery budget exhausted",
            ));
        }
        tokio::select! { biased;
            changed = deadlines.changed() => { changed.map_err(io::Error::other)?; }
            _ = async { match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                None => std::future::pending::<()>().await,
            } } => {}
        }
    }
}

fn prepare_display_decoder(
    codecs: &mut BTreeMap<u32, Decoder>,
    current: Option<(VideoLayout, u64)>,
    kind: VideoCodec,
    lease: &LeaseControl,
    output: &Output,
) -> io::Result<()> {
    for codec in codecs.values_mut() {
        codec.codec = None;
        codec.prepare = None;
        codec.awaiting_keyframe = true;
        codec.pending.clear();
        if current.is_none_or(|(layout, _)| layout.source != codec.stream.source) {
            codec.recovery = None;
        }
    }
    output.set_recovery_deadline(codecs.values().filter_map(Decoder::recovery_deadline).min())?;
    if let Some((layout, revision)) = current {
        lease
            .check_media_binding(Channel::Video, layout.epoch.connection)
            .map_err(io::Error::other)?;
        let decoder = codecs.entry(layout.source).or_insert_with(|| {
            Decoder::new(
                VideoStream {
                    source: layout.source,
                    codec: VideoConfig {
                        width: layout.width,
                        height: layout.height,
                        fps: 30,
                        bitrate_kbps: 1000,
                    },
                },
                layout.epoch.layout,
            )
        });
        decoder.layout = layout.epoch.layout;
        decoder.stream.codec.width = layout.width;
        decoder.stream.codec.height = layout.height;
        let external = output
            .external
            .lock()
            .map_err(|_| io::Error::other("external sink poisoned"))?;
        let uses_external = external.is_some();
        if !uses_external {
            // Validate typed surface before creating the selected decoder.
            decoder.prepare = Some(crate::legacy_format::LegacyPrepare::new(
                kind,
                layout.width,
                layout.height,
            )?);
            decoder.codec = Some(VideoDecoder::new(kind, layout.width, layout.height)?);
        }
        let external_prepared = external.as_ref().is_none_or(|s| {
            s.prepared
                && s.context.source == layout.source
                && s.context.layout_epoch == layout.epoch.layout
        });
        drop(external);
        lease
            .check_media_binding(Channel::Video, layout.epoch.connection)
            .map_err(io::Error::other)?;
        let state = output
            .state
            .lock()
            .map_err(|_| io::Error::other("media output poisoned"))?;
        if external_prepared
            && state.selected == Some(layout)
            && state.catalog.as_ref().map(|(key, _)| key.revision) == Some(revision)
            && !state.closed
        {
            output
                .prepared
                .send_replace(DecoderReadiness::Display(layout, revision));
        }
    }
    Ok(())
}

fn receive(
    mut video: ChannelReceiver,
    sender: ChannelSender,
    lease: LeaseControl,
    epoch: VideoEpoch,
    sources: ReceiveSources,
    output: Arc<Output>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let runtime = worker::runtime()?;
    let codec_kind = if lease
        .media_capability(nestlink_protocol::media::H264_CAPABILITY)
        .map_err(io::Error::other)?
    {
        1
    } else {
        0
    };
    let mut reports = lease.subscribe_stopped();
    let advertised = matches!(&sources, ReceiveSources::Advertised);
    let fixed = matches!(&sources, ReceiveSources::Fixed(_));
    let kind = if codec_kind == 1 {
        VideoCodec::H264Baseline
    } else {
        VideoCodec::Vp8
    };
    let (selected, dynamic_sources) = match sources {
        ReceiveSources::Fixed(selected) => (selected, None),
        ReceiveSources::Dynamic(sources) => (Vec::new(), Some(sources)),
        ReceiveSources::Advertised => (Vec::new(), Some(BTreeSet::new())),
    };
    let mut codecs: BTreeMap<_, _> = selected
        .into_iter()
        .map(|stream| (stream.source, Decoder::new(stream, epoch.layout)))
        .collect();
    if fixed {
        for decoder in codecs.values_mut() {
            lease
                .check_media_binding(Channel::Video, epoch.connection)
                .map_err(io::Error::other)?;
            decoder.prepare = Some(crate::legacy_format::LegacyPrepare::new(
                kind,
                decoder.stream.codec.width,
                decoder.stream.codec.height,
            )?);
            decoder.codec = Some(VideoDecoder::new(
                kind,
                decoder.stream.codec.width,
                decoder.stream.codec.height,
            )?);
        }
        lease
            .check_media_binding(Channel::Video, epoch.connection)
            .map_err(io::Error::other)?;
        output.prepared.send_replace(DecoderReadiness::Fixed);
    }
    runtime.block_on(async {
        let mut selected_layout: Option<(VideoLayout, u64)>=None;
        let mut external_stamp=None;
        let mut changes=output.changes.subscribe();
        loop {
            if advertised {
                let current={
                    let state=output.state.lock().map_err(|_| io::Error::other("media output poisoned"))?;
                    state.selected.zip(state.catalog.as_ref().map(|(key, _)| key.revision))
                };
                if current!=selected_layout {
                    prepare_display_decoder(&mut codecs, current, kind, &lease, &output)?;
                    selected_layout=current;
                }
            }
            {
                let mut external=output.external.lock().map_err(|_|io::Error::other("external sink poisoned"))?;
                if let Some(sink)=external.as_mut(){
                    if selected_layout.is_none_or(|(layout,_)|layout.source!=sink.context.source || layout.epoch.layout!=sink.context.layout_epoch){
                        let context=sink.context.clone();sink.feedback(&context,crate::external::VideoSinkFeedback::Fence)?;
                    }
                    if sink.check_pressure(Instant::now())? && let Some(codec)=codecs.get_mut(&sink.context.source) {
                        codec.recover(VideoRecoveryReason::ReferenceGap,Instant::now())?;
                    }
                }
                let stamp=external.as_ref().map(|s|(s.context.stream_id,s.context.decode_epoch));
                if stamp!=external_stamp {
                    if let Some((layout,_))=selected_layout && let Some(codec)=codecs.get_mut(&layout.source) {
                            codec.codec=None;
                            codec.pending.clear();
                            codec.awaiting_keyframe=true;
                            if stamp.is_none(){codec.recover(VideoRecoveryReason::ReferenceGap,Instant::now())?;}
                    }
                    external_stamp=stamp;
                    if stamp.is_none(){selected_layout=None;}
                }
                if let Some(sink)=external.as_mut() && let Some(codec)=codecs.get_mut(&sink.context.source) {
                        if sink.prepared && codec.awaiting_keyframe && codec.recovery.is_none(){codec.recover(VideoRecoveryReason::KeyframeMissing,Instant::now())?;}
                        while let Some((sequence,pts,idr))=sink.completed.pop_front() {
                            let expected=codec.pending.first_key_value().map(|(pts,(seq,_))|(*seq,*pts));
                            if expected!=Some((sequence,pts)) { return Err(io::Error::other("external decoder output ledger mismatch")); }
                            codec.pending.remove(&pts);
                            codec.deadline(Instant::now())?;
                            if idr && codec.recovery.take().is_some() {
                                let mut state=output.state.lock().map_err(|_|io::Error::other("media output poisoned"))?;
                                state.stats.completed_recoveries=state.stats.completed_recoveries.saturating_add(1);
                            }
                        }
                }
            }
            output.check_recovery_deadline()?;
            if worker::stopped(&stop) || reports.borrow().is_some() {
                return Ok(());
            }
            for codec in codecs.values_mut() {
                if advertised && selected_layout.is_none_or(|(layout, _)| layout.source!=codec.stream.source) {continue;}
                let codec_epoch = VideoEpoch { layout: codec.layout, connection: epoch.connection };
                if codec.feedback(&sender, codec_epoch, Instant::now())? {
                    let mut state = output
                        .state
                        .lock()
                        .map_err(|_| io::Error::other("media output poisoned"))?;
                    state.stats.feedback_requests = state.stats.feedback_requests.saturating_add(1);
                }
            }
            output.set_recovery_deadline(codecs.values().filter_map(Decoder::recovery_deadline).min())?;
            let wake = codecs.values().filter_map(Decoder::wakeup).chain(external_stamp.map(|_|Instant::now()+Duration::from_millis(10))).min();
            let frame = tokio::select! { biased;
                _ = stop.changed() => { output.check_recovery_deadline()?; return Ok(()); }
                _ = reports.changed() => { output.check_recovery_deadline()?; return Ok(()); }
                _ = changes.changed(), if advertised => {continue;}
                _ = async { match wake {
                    Some(wake) => tokio::time::sleep_until(wake.into()).await,
                    None => std::future::pending::<()>().await,
                } } => { continue; }
                frame = video.receive() => match frame {
                    Ok(frame) => frame,
                    Err(error) => { output.check_recovery_deadline()?; return Err(io::Error::other(error)); }
                },
            };
            let encoded_frame = Zeroizing::new(frame.payload);
            let mut packet = NativeVideo::decode_validated(&encoded_frame).map_err(io::Error::other)?;
            // Own the copied bitstream separately so metadata/layout failures
            // scrub it too, before any decoder is selected.
            let payload = Zeroizing::new(std::mem::take(&mut packet.payload));
            lease
                .check_media_binding(Channel::Video, packet.connection_generation)
                .map_err(io::Error::other)?;
            let source = packet.source;
            if let Some(sources) = &dynamic_sources {
                let allowed=if advertised {
                    let state=output.state.lock().map_err(|_| io::Error::other("media output poisoned"))?;
                    let approved=state.catalog.as_ref().is_some_and(|(_,ds)| ds.iter().any(|d| d.source==source));
                    if !approved || packet.connection_generation!=epoch.connection {
                        return Err(io::Error::new(io::ErrorKind::InvalidData,"video preceded consent catalogue acknowledgement"));
                    }
                    if state.selected.is_none_or(|selected| packet.source!=selected.source || packet.layout_epoch!=selected.epoch.layout) {
                        if state.last_selected.is_some_and(|last| packet.layout_epoch<last.epoch.layout || (state.selected.is_none() && packet.layout_epoch==last.epoch.layout)) {
                            // A frame already in a different QUIC stream at
                            // the switch boundary cannot revive old pixels.
                            continue;
                        }
                        return Err(io::Error::new(io::ErrorKind::InvalidData,"video preceded exact selection acknowledgement"));
                    }
                    if !state.selected.is_some_and(|layout| packet.width==layout.width && packet.height==layout.height) {
                        return Err(io::Error::new(io::ErrorKind::InvalidData,"selected video geometry differs"));
                    }
                    // Selection may have changed while this thread awaited a
                    // frame. Reconcile before decoding its first keyframe.
                    let current = state.selected.zip(state.catalog.as_ref().map(|(key, _)| key.revision));
                    drop(state);
                    if current != selected_layout {
                        prepare_display_decoder(&mut codecs, current, kind, &lease, &output)?;
                        selected_layout=current;
                    }
                    true
                } else {sources.contains(&source)};
                if !allowed || packet.connection_generation != epoch.connection {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "unapproved dynamic video source"));
                }
                if update_dynamic_layout(&packet, &mut codecs, Instant::now())? {
                    // Retire old pixels before decoding; a stalled or failed
                    // new decoder cannot leave an old layout in the mailbox.
                    let mut state = output.state.lock().map_err(|_| io::Error::other("media output poisoned"))?;
                    if state.closed { return Ok(()); }
                    if advertised && state.selected.is_none_or(|layout| layout.source!=source
                        || layout.epoch.layout!=packet.layout_epoch || layout.width!=packet.width || layout.height!=packet.height) {
                        continue;
                    }
                    state.scheduled.retain(|pending|pending.frame.source!=source);
                    state.videos.remove(&source);
                    state.ready.retain(|ready| *ready != source);
                    state.layouts.insert(source, VideoLayout {
                        epoch: VideoEpoch { layout: packet.layout_epoch, connection: epoch.connection },
                        source,
                        width: packet.width,
                        height: packet.height,
                    });
                }
            }
            if packet.codec != codec_kind {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "video codec differs from signed negotiation"));
            }
            let codec = codecs.get_mut(&source).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "unapproved video source")
            })?;
            // libvpx runs outside all authorization/output locks on this thread.
            let codec_epoch = VideoEpoch { layout: codec.layout, connection: epoch.connection };
            // Establish the shared A/V mapping at validated media ingress,
            // before CPU decode or the external FIFO can add scheduling delay.
            let now=Instant::now();
            let due=if let Some(clock)=output.playout.as_ref(){clock.presentation_time(packet.pts_90khz,90_000,now)?}else{now};
            let mut external=output.external.lock().map_err(|_|io::Error::other("external sink poisoned"))?;
            let consumer_revision=output.consumer_revision.load(std::sync::atomic::Ordering::Acquire);
            let decoded=if let Some(sink)=external.as_mut() {
                if sink.context.source!=packet.source || sink.context.layout_epoch!=packet.layout_epoch {
                    return Err(io::Error::other("external selection changed before fencing"));
                }
                let reference_gap=codec.sequence.checked_add(1)!=Some(packet.sequence);
                if sink.prepared && codec.accept_input(&packet,codec_epoch,now)? {
                    let gap=reference_gap || codec.pending.len()>=8;
                    if gap { sink.reset()?; codec.recover(VideoRecoveryReason::ReferenceGap,now)?; }
                    else {
                        let pts=packet.pts_90khz;
                        let sequence=packet.sequence;
                        if sink.push(sequence,pts,packet.keyframe,packet.repeated_source,due,payload,now)? {
                            codec.awaiting_keyframe=false;
                            codec.pending.insert(pts,(sequence,packet.repeated_source));
                        }else { codec.recover(VideoRecoveryReason::ReferenceGap,now)?; }
                    }
                }
                None
            }else{codec.decode(packet,payload,codec_epoch,now)?};
            drop(external);
            output.set_recovery_deadline(codecs.values().filter_map(Decoder::recovery_deadline).min())?;
            lease
                .check_media_binding(Channel::Video, epoch.connection)
                .map_err(io::Error::other)?;
            if worker::stopped(&stop) || reports.borrow().is_some() {
                return Ok(());
            }
            let mut state = output
                .state
                .lock()
                .map_err(|_| io::Error::other("media output poisoned"))?;
            if state.closed {
                return Ok(());
            }
            if advertised && state.selected.is_none_or(|layout| layout.source!=source || layout.epoch!=codec_epoch) {continue;}
            if let Some((decoded, recovered)) = decoded {
                if output.consumer_revision.load(std::sync::atomic::Ordering::Acquire)!=consumer_revision{continue;}
                if let Some(clock)=output.playout.as_ref(){
                    state.queue_video(clock, decoded, Instant::now())?;
                }else{
                    if !state.videos.contains_key(&source){state.ready.push_back(source);}
                    state.videos.insert(source,decoded);
                }
                if recovered {
                    state.stats.completed_recoveries =
                        state.stats.completed_recoveries.saturating_add(1);
                }
            } else if codecs.get(&source).is_some_and(|codec| codec.recovery.is_some()) {
                state.scheduled.retain(|pending|pending.frame.source!=source);
                    state.videos.remove(&source);
                state.ready.retain(|ready| *ready != source);
                state.stats.discarded_frames = state.stats.discarded_frames.saturating_add(1);
            }
        }
    })
}

fn update_dynamic_layout(
    packet: &NativeVideo,
    codecs: &mut BTreeMap<u32, Decoder>,
    now: Instant,
) -> io::Result<bool> {
    let bytes = codecs
        .iter()
        .filter(|(source, _)| **source != packet.source)
        .map(|(_, codec)| {
            u64::from(codec.stream.codec.width) * u64::from(codec.stream.codec.height) * 4
        })
        .sum::<u64>()
        + u64::from(packet.width) * u64::from(packet.height) * 4;
    if bytes > 128 * 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dynamic video output exceeds 128 MiB",
        ));
    }
    if let Some(codec) = codecs.get_mut(&packet.source) {
        codec.deadline(now)?;
        if packet.layout_epoch < codec.layout
            || packet.sequence <= codec.sequence
            || codec.pts.is_some_and(|pts| packet.pts_90khz <= pts)
            || (packet.layout_epoch == codec.layout
                && (packet.width != codec.stream.codec.width
                    || packet.height != codec.stream.codec.height))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "dynamic video layout, sequence or PTS replay",
            ));
        }
        if packet.layout_epoch == codec.layout {
            return Ok(false);
        }
        codec.layout = packet.layout_epoch;
        codec.stream.codec.width = packet.width;
        codec.stream.codec.height = packet.height;
        codec.codec = None;
        codec.prepare = None;
        codec.awaiting_keyframe = true;
        codec.pending.clear();
        // Do not reset recovery, request sequence, attempt budget or media
        // sequence. A resize cannot extend any pending keyframe deadline.
    } else {
        codecs.insert(
            packet.source,
            Decoder {
                stream: VideoStream {
                    source: packet.source,
                    codec: VideoConfig {
                        width: packet.width,
                        height: packet.height,
                        fps: 30,
                        bitrate_kbps: 1000,
                    },
                },
                layout: packet.layout_epoch,
                codec: None,
                prepare: None,
                awaiting_keyframe: true,
                pending: BTreeMap::new(),
                sequence: 0,
                pts: None,
                request_sequence: 0,
                recovery: None,
                attempts: VecDeque::new(),
            },
        );
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Parser fixtures intentionally do not pretend to be a decodable picture.
    // Bad input traverses real Decoder::decode and must fail before a platform
    // decoder can be created/submitted. Good input below proves admission only.
    fn admission_test_idr(width: u32, height: u32) -> Vec<u8> {
        fn ue(bits: &mut String, value: u32) {
            let value = format!("{:b}", value + 1);
            bits.push_str(&"0".repeat(value.len() - 1));
            bits.push_str(&value);
        }
        let mut bits = String::from("010000101100000000011111");
        for value in [0, 0, 2, 1] {
            ue(&mut bits, value);
        }
        bits.push('0');
        ue(&mut bits, width / 16 - 1);
        ue(&mut bits, height / 16 - 1);
        bits.push_str("11001"); // progressive/direct, no crop/VUI, RBSP stop
        while !bits.len().is_multiple_of(8) {
            bits.push('0');
        }
        let mut data = vec![0, 0, 0, 1, 0x67];
        for chunk in bits.as_bytes().chunks(8) {
            let byte = chunk.iter().fold(0, |value, bit| value * 2 + (bit - b'0'));
            if data.ends_with(&[0, 0]) && byte <= 3 {
                data.push(3);
            }
            data.push(byte);
        }
        data.extend_from_slice(&[0, 0, 1, 0x68, 0xce, 0x38, 0x80, 0, 0, 1, 0x65, 0xb8, 0x40]);
        data
    }
    fn admission_test_decoder() -> Decoder {
        Decoder::new(
            VideoStream {
                source: 42,
                codec: VideoConfig {
                    width: 320,
                    height: 240,
                    fps: 30,
                    bitrate_kbps: 1000,
                },
            },
            1,
        )
    }
    fn admission_test_packet(
        sequence: u64,
        layout: u64,
        width: u32,
        height: u32,
        keyframe: bool,
    ) -> NativeVideo {
        NativeVideo {
            schema_version: SCHEMA_VERSION,
            codec: 1,
            connection_generation: 9,
            layout_epoch: layout,
            source: 42,
            sequence,
            pts_90khz: sequence * 90,
            width,
            height,
            keyframe,
            payload: Vec::new(),
            repeated_source: false,
        }
    }

    #[test]
    fn cpu_admission_rejects_bad_au_and_geometry_without_pending_or_submission() -> io::Result<()> {
        let mut decoder = admission_test_decoder();
        // An existing accounting entry must not be cleared or replaced by an
        // admission error. No fabricated codec or successful GPU output exists.
        decoder.pending.insert(777, (55, false));
        let pending = decoder.pending.clone();
        let epoch = VideoEpoch {
            connection: 9,
            layout: 1,
        };
        let now = Instant::now();
        for (sequence, bytes) in [(1, vec![1, 2, 3]), (2, admission_test_idr(640, 480))] {
            let error = match decoder.decode(
                admission_test_packet(sequence, 1, 320, 240, true),
                Zeroizing::new(bytes),
                epoch,
                now,
            ) {
                Err(error) => error,
                Ok(_) => panic!("bad AU must reject before CPU decoder creation/submission"),
            };
            // In particular, reaching the unavailable H264 backend on Linux
            // and returning Unsupported must not masquerade as this rejection.
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("H.264"));
            assert!(decoder.codec.is_none());
            assert_eq!(decoder.pending, pending);
            // Valid metadata remains consumed, matching existing anti-replay.
            assert_eq!(decoder.sequence, sequence);
            assert_eq!(decoder.pts, Some(sequence * 90));
        }
        // Metadata geometry conflicts reject before consuming even metadata.
        assert!(
            decoder
                .decode(
                    admission_test_packet(3, 1, 640, 480, true),
                    Zeroizing::new(admission_test_idr(640, 480)),
                    epoch,
                    now
                )
                .is_err()
        );
        assert_eq!(decoder.sequence, 2);
        assert_eq!(decoder.pending, pending);
        assert!(decoder.codec.is_none());
        Ok(())
    }

    #[test]
    fn cpu_resize_recovery_retires_old_sps_and_requires_new_epoch_keyframe() -> io::Result<()> {
        let now = Instant::now();
        let mut decoder = admission_test_decoder();
        let mut prepare = crate::LegacyPrepare::new(VideoCodec::H264Baseline, 320, 240)?;
        prepare.validate(&admission_test_idr(320, 240), true)?;
        prepare.validate(&[0, 0, 1, 0x41, 0xe0], false)?;
        decoder.prepare = Some(prepare);
        decoder.awaiting_keyframe = false;
        decoder.sequence = 7;
        decoder.pts = Some(630);
        decoder.request_sequence = 5;
        decoder.recover(VideoRecoveryReason::ReferenceGap, now)?;
        let deadline = decoder.recovery_deadline();
        let attempts = decoder.attempts.len();
        assert!(decoder.prepare.is_none());
        assert!(decoder.awaiting_keyframe);

        // Test recovery independently of resize: its replacement admission
        // history cannot accept a delta. Reaccept an old-layout IDR at this
        // admission-only boundary so resize must retire nonempty history too.
        let mut old_layout_prepare = crate::LegacyPrepare::new(VideoCodec::H264Baseline, 320, 240)?;
        assert!(
            old_layout_prepare
                .validate(&[0, 0, 1, 0x41, 0xe0], false)
                .is_err()
        );
        old_layout_prepare.validate(&admission_test_idr(320, 240), true)?;
        decoder.prepare = Some(old_layout_prepare);

        let mut codecs = BTreeMap::from([(42, decoder)]);
        let delta = admission_test_packet(8, 2, 640, 480, false);
        assert!(update_dynamic_layout(&delta, &mut codecs, now)?);
        let decoder = codecs
            .get_mut(&42)
            .ok_or_else(|| io::Error::other("fixture decoder missing"))?;
        assert_eq!(decoder.layout, 2);
        assert!(decoder.prepare.is_none());
        let epoch = VideoEpoch {
            connection: 9,
            layout: 2,
        };
        assert!(
            decoder
                .decode(delta, Zeroizing::new(vec![0, 0, 1, 0x41, 0xe0]), epoch, now)?
                .is_none()
        );
        assert!(decoder.codec.is_none());
        assert!(decoder.pending.is_empty());
        assert_eq!(decoder.sequence, 8);
        assert_eq!(decoder.pts, Some(720));
        // Replaying the dropped delta is still rejected; reset never launders
        // sequence/PTS or extends the original recovery budget.
        assert!(
            decoder
                .decode(
                    admission_test_packet(8, 2, 640, 480, false),
                    Zeroizing::new(vec![0, 0, 1, 0x41, 0xe0]),
                    epoch,
                    now
                )
                .is_err()
        );
        assert_eq!(decoder.recovery_deadline(), deadline);
        assert_eq!(decoder.attempts.len(), attempts);
        assert_eq!(decoder.request_sequence, 5);
        // Lying about the keyframe bit cannot reuse old SPS/PPS history either.
        let error = match decoder.decode(
            admission_test_packet(9, 2, 640, 480, true),
            Zeroizing::new(vec![0, 0, 1, 0x41, 0xe0]),
            epoch,
            now,
        ) {
            Err(error) => error,
            Ok(_) => panic!("old delta cannot bootstrap a new epoch"),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(decoder.codec.is_none());
        assert!(decoder.pending.is_empty());
        let fresh_packet = admission_test_packet(10, 2, 640, 480, true);
        assert!(decoder.accept_input(&fresh_packet, epoch, now)?);
        let prepare = decoder
            .prepare
            .as_mut()
            .ok_or_else(|| io::Error::other("new epoch Prepare missing"))?;
        // Exercise the same real admission gate used by Decoder::decode, but
        // stop before platform resources: this is not a fake decode success.
        assert!(
            prepare
                .validate(&admission_test_idr(320, 240), true)
                .is_err()
        );
        assert!(
            prepare
                .validate(&admission_test_idr(640, 480), true)?
                .is_some()
        );
        assert_eq!(
            (prepare.surface().width, prepare.surface().height),
            (640, 480)
        );
        assert_eq!(decoder.recovery_deadline(), deadline);
        assert_eq!(decoder.sequence, 10);
        assert_eq!(decoder.pts, Some(900));
        assert!(decoder.pending.is_empty());
        assert!(decoder.codec.is_none());
        Ok(())
    }

    fn image(sequence: u64, pts_90khz: u64) -> DecodedVideo {
        DecodedVideo {
            source_color: nestlink_protocol::media_format::Color::LEGACY_VP8_BT601,
            codec: 0,
            hardware_decode: false,
            epoch: VideoEpoch {
                connection: 9,
                layout: 1,
            },
            source: 42,
            sequence,
            pts_90khz,
            width: 1,
            height: 1,
            pixels: vec![0; 4],
            repeated_source: false,
        }
    }

    #[test]
    fn timed_mailbox_holds_until_due_and_keeps_an_older_image_under_pressure() -> io::Result<()> {
        let now = Instant::now();
        let clock = crate::SessionPlayoutClock::default();
        let output = Output::with_clock(Some(clock.clone()));
        let mut state = output
            .state
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?;
        for index in 0..20 {
            state.queue_video(&clock, image(index + 1, 90_000 + index * 90), now)?;
        }
        assert_eq!(state.scheduled.len(), 16);
        assert_eq!(state.stats.discarded_budget_frames, 4);
        assert!(
            state
                .poll_scheduled(now + Duration::from_millis(59))
                .is_none()
        );
        let first = state
            .poll_scheduled(now + Duration::from_millis(60))
            .ok_or_else(|| io::Error::other("first due image was not retained"))?;
        assert_eq!(first.sequence, 1);
        let newest = state
            .poll_scheduled(now + Duration::from_millis(75))
            .ok_or_else(|| io::Error::other("newest due image missing"))?;
        assert_eq!(newest.sequence, 16);
        assert!(state.scheduled.is_empty());
        Ok(())
    }

    #[test]
    fn timed_mailbox_drops_future_and_stale_pixels_and_terminal_close_flushes() -> io::Result<()> {
        let now = Instant::now();
        let clock = crate::SessionPlayoutClock::default();
        let output = Output::with_clock(Some(clock.clone()));
        {
            let mut state = output
                .state
                .lock()
                .map_err(|_| io::Error::other("fixture poisoned"))?;
            state.queue_video(&clock, image(1, 90_000), now)?;
            state.queue_video(&clock, image(2, 900_000), now)?;
            assert_eq!(state.stats.discarded_future_frames, 1);
            assert_eq!(state.scheduled.len(), 1);
            assert!(
                state
                    .poll_scheduled(now + Duration::from_millis(101))
                    .is_none()
            );
            assert_eq!(state.stats.discarded_late_frames, 1);
            state.queue_video(&clock, image(3, 108_000), now + Duration::from_millis(200))?;
            assert_eq!(state.scheduled.len(), 1);
        }
        output.close();
        let state = output
            .state
            .lock()
            .map_err(|_| io::Error::other("fixture poisoned"))?;
        assert!(state.closed);
        assert!(state.scheduled.is_empty());
        Ok(())
    }

    #[test]
    fn repeated_resizes_preserve_the_original_recovery_deadline_and_budget() -> io::Result<()> {
        let started = Instant::now();
        let mut packet = NativeVideo {
            codec: 0,
            schema_version: SCHEMA_VERSION,
            connection_generation: 7,
            layout_epoch: 3,
            source: 42,
            sequence: 1,
            pts_90khz: 1,
            width: 64,
            height: 48,
            keyframe: false,
            repeated_source: false,
            payload: vec![0; 3],
        };
        let mut codecs = BTreeMap::new();
        update_dynamic_layout(&packet, &mut codecs, started)?;
        let codec = codecs
            .get_mut(&42)
            .ok_or_else(|| io::Error::other("missing selected decoder"))?;
        codec.sequence = 1;
        codec.pts = Some(1);
        codec.request_sequence = 9;
        codec.recover(VideoRecoveryReason::KeyframeMissing, started)?;
        let deadline = codec.recovery_deadline();
        for (elapsed, width, height) in [(500, 80, 40), (1500, 96, 32)] {
            packet.layout_epoch += 1;
            packet.sequence += 1;
            packet.pts_90khz += 1;
            packet.width = width;
            packet.height = height;
            let now = started + Duration::from_millis(elapsed);
            assert!(update_dynamic_layout(&packet, &mut codecs, now)?);
            let codec = codecs
                .get_mut(&42)
                .ok_or_else(|| io::Error::other("missing selected decoder"))?;
            // Another missing keyframe in the replacement geometry still
            // belongs to the outstanding recovery, not a new attempt.
            codec.recover(VideoRecoveryReason::KeyframeMissing, now)?;
            assert_eq!(codec.recovery_deadline(), deadline);
            assert_eq!(codec.request_sequence, 9);
            assert_eq!(codec.attempts.len(), 1);
            assert_eq!(codec.sequence, 1);
            assert_eq!(codec.pts, Some(1));
        }
        packet.layout_epoch += 1;
        assert_eq!(
            update_dynamic_layout(
                &packet,
                &mut codecs,
                started + Duration::from_millis(VIDEO_RECOVERY_MS),
            )
            .err()
            .map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut),
        );
        assert_eq!(codecs[&42].layout, 5);
        assert_eq!(codecs[&42].recovery_deadline(), deadline);
        Ok(())
    }

    #[tokio::test]
    async fn independent_watchdog_preserves_an_expired_deadline_against_late_success()
    -> io::Result<()> {
        let output = Output::new();
        let deadline = Instant::now() + Duration::from_millis(20);
        output.set_recovery_deadline(Some(deadline))?;
        // No decoder or event dispatcher is making progress during this wait.
        let result = tokio::time::timeout(
            Duration::from_secs(1),
            supervise_recovery(output.recovery_deadline.subscribe()),
        )
        .await
        .map_err(io::Error::other)?;
        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        for replacement in [None, Some(Instant::now() + Duration::from_secs(1))] {
            assert_eq!(
                output
                    .set_recovery_deadline(replacement)
                    .err()
                    .map(|error| error.kind()),
                Some(io::ErrorKind::TimedOut)
            );
            assert_eq!(*output.recovery_deadline.borrow(), Some(deadline));
        }
        assert_eq!(
            output
                .check_recovery_deadline()
                .err()
                .map(|error| error.kind()),
            Some(io::ErrorKind::TimedOut)
        );
        Ok(())
    }
}
