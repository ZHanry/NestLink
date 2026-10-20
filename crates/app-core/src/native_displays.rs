//! Session-owned local consent and acknowledged native display switching.
use super::*;
use nestlink_protocol::native_displays::{
    CatalogAssembler, DisplayEnvelope, catalog_key, validate_candidates, validate_displays,
};
pub use nestlink_protocol::native_displays::{
    DisplayCatalogKey, DisplayDescriptor, DisplaySelection,
};
use nestlink_remote::input::InputLayout;
use serde::{Deserialize, Serialize};

const DISPLAY_SEND_BUDGET: Duration = Duration::from_secs(2);
const DISPLAY_HANDSHAKE_BUDGET: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDisplayRequest {
    pub catalog: DisplayCatalogKey,
    pub sequence: u64,
    pub source: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeDisplayState {
    pub is_host: bool,
    pub catalog: Option<DisplayCatalogKey>,
    pub displays: Vec<DisplayDescriptor>,
    pub local_approval_required: bool,
    pub approved_sources: Vec<u32>,
    pub initial_source: Option<u32>,
    pub catalog_acknowledged: bool,
    pub selected: Option<DisplaySelection>,
    pub pending: Option<NativeDisplayRequest>,
}
struct State {
    view: NativeDisplayState,
    candidates: Option<(DisplayCatalogKey, Vec<DisplayDescriptor>)>,
    system_approved: bool,
    assembler: CatalogAssembler,
    published: bool,
    prepared: Option<DisplaySelection>,
    deadline: Option<Instant>,
}
pub(super) struct NativeDisplayRoute {
    shared: Weak<Shared>,
    binding: NativeSessionBinding,
    generation: u64,
    input_authorized: bool,
    active: AtomicBool,
    lease: LeaseControl,
    sender: ChannelSender,
    order: AsyncMutex<()>,
    state: Mutex<State>,
}
fn denied(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}
fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}
fn logical(display: &DisplayDescriptor) -> InputLayout {
    InputLayout {
        left: display.left,
        top: display.top,
        width: display.width,
        height: display.height,
    }
}
impl NativeDisplayRoute {
    pub(super) fn attach(
        shared: &Arc<Shared>,
        channels: &mut ChannelRuntime,
        key: &NativeSessionKey,
        generation: u64,
    ) -> io::Result<(Arc<Self>, JoinHandle<io::Result<()>>)> {
        let receiver = channels
            .claim_channel(Channel::VideoFeedback)
            .map_err(io::Error::other)?;
        let route = Arc::new(Self {
            shared: Arc::downgrade(shared),
            binding: NativeSessionBinding {
                request_id: key.request_id.clone(),
                connection_generation: key.connection_generation,
            },
            generation,
            input_authorized: key.input_authorized,
            active: AtomicBool::new(true),
            lease: channels.lease_control(),
            sender: channels.sender(),
            order: AsyncMutex::new(()),
            state: Mutex::new(State {
                view: NativeDisplayState {
                    is_host: key.host_view_authorized,
                    catalog: None,
                    displays: Vec::new(),
                    local_approval_required: false,
                    approved_sources: Vec::new(),
                    initial_source: None,
                    catalog_acknowledged: false,
                    selected: None,
                    pending: None,
                },
                candidates: None,
                system_approved: false,
                assembler: CatalogAssembler::default(),
                published: false,
                prepared: None,
                deadline: None,
            }),
        });
        let owned = route.clone();
        let worker = tokio::spawn(async move {
            let result = owned.receive(receiver).await;
            if result.is_err() {
                owned.retire();
                let lease = owned.lease.clone();
                let _ =
                    tokio::task::spawn_blocking(move || lease.stop(StopReason::ProtocolViolation))
                        .await;
            }
            result
        });
        Ok((route, worker))
    }
    fn check(&self) -> io::Result<()> {
        if !self.active.load(Ordering::Acquire) {
            return Err(denied("display route retired"));
        }
        self.lease
            .check_channel_binding(Channel::VideoFeedback, self.binding.connection_generation)
            .map_err(io::Error::other)
    }
    fn check_catalog(&self, key: &DisplayCatalogKey) -> io::Result<()> {
        if key.request_id != self.binding.request_id
            || key.connection_generation != self.binding.connection_generation
        {
            return Err(denied(
                "display catalogue belongs to another proved session",
            ));
        }
        key.validate().map_err(io::Error::other)
    }
    fn retire(&self) {
        self.active.store(false, Ordering::Release);
        if let Ok(mut state) = self.state.lock() {
            state.view.displays.clear();
            state.view.approved_sources.clear();
            state.view.selected = None;
            state.view.pending = None;
            state.prepared = None;
            state.deadline = None;
        }
    }
    async fn send(&self, message: DisplayEnvelope) -> io::Result<()> {
        self.check()?;
        let bytes = message.encode().map_err(io::Error::other)?;
        match tokio::time::timeout(
            DISPLAY_SEND_BUDGET,
            self.sender.send(Channel::VideoFeedback, &bytes),
        )
        .await
        {
            Ok(Ok(())) => self.check(),
            Ok(Err(error)) => Err(io::Error::other(error)),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "display control delivery exceeded budget",
            )),
        }
    }
    fn shared(&self) -> io::Result<Arc<Shared>> {
        self.shared
            .upgrade()
            .ok_or_else(|| denied("product core ended"))
    }
    fn video(&self) -> io::Result<Arc<NativeVideoRoute>> {
        self.shared()?
            .native_video_route()
            .filter(|v| {
                v.request_id == self.binding.request_id
                    && v.connection_generation == self.binding.connection_generation
            })
            .ok_or_else(|| denied("host video binding changed"))
    }
    fn presentation(&self) -> io::Result<Arc<NativeVideoPresentationRoute>> {
        let shared = self.shared()?;
        let presentation = shared
            .native_video_presentation
            .lock()
            .map_err(|_| io::Error::other("presentation poisoned"))?
            .as_ref()
            .filter(|p| {
                p.request_id == self.binding.request_id
                    && p.connection_generation == self.binding.connection_generation
            })
            .cloned()
            .ok_or_else(|| denied("controller video binding changed"))?;
        Ok(presentation)
    }
    async fn receive(&self, mut receiver: ChannelReceiver) -> io::Result<()> {
        let mut stopped = self.lease.subscribe_stopped();
        loop {
            if stopped.borrow().is_some() {
                return Ok(());
            }
            // Check before every receive, including a continuously busy stream;
            // biased frame readiness must not starve the handshake deadline.
            if self
                .state
                .lock()
                .map_err(|_| io::Error::other("display state poisoned"))?
                .deadline
                .is_some_and(|until| Instant::now() >= until)
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "display acknowledgement budget exhausted",
                ));
            }
            let frame = tokio::select! {biased;
                frame=native_channel::receive(receiver.receive(), &mut stopped)=>{
                    let Some(frame) = frame? else { return Ok(()); };
                    frame
                },
                _=tokio::time::sleep(Duration::from_millis(250))=>{
                    if self.state.lock().map_err(|_|io::Error::other("display state poisoned"))?.deadline
                        .is_some_and(|until|Instant::now()>=until) {
                        return Err(io::Error::new(io::ErrorKind::TimedOut,"display acknowledgement budget exhausted"));
                    }
                    continue;
                }
            };
            let payload = Zeroizing::new(frame.payload);
            if let Err(error) = self.check() {
                if native_channel::completed_stop(&stopped) {
                    return Ok(());
                }
                return Err(error);
            }
            let message = DisplayEnvelope::decode(&payload).map_err(io::Error::other)?;
            if let Err(error) = self.handle(message).await {
                if native_channel::terminal_io_error(&error, &stopped) {
                    return Ok(());
                }
                return Err(error);
            }
        }
    }
    async fn handle(&self, message: DisplayEnvelope) -> io::Result<()> {
        let is_host = self
            .state
            .lock()
            .map_err(|_| io::Error::other("display state poisoned"))?
            .view
            .is_host;
        match message {
            DisplayEnvelope::Recovery(request) if is_host => {
                if request.connection_generation != self.binding.connection_generation {
                    return Err(invalid("feedback connection changed"));
                }
                self.video()?
                    .cursor
                    .lock()
                    .map_err(|_| io::Error::other("video cursor poisoned"))?
                    .feedback(request)
                    .map_err(io::Error::other)?;
            }
            DisplayEnvelope::CatalogBegin { catalog, count } if !is_host => {
                self.check_catalog(&catalog)?;
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| io::Error::other("display state poisoned"))?;
                let replacing = state.view.catalog.is_some();
                if let Some(previous) = state.view.catalog.as_ref() {
                    if previous.revision.checked_add(1) != Some(catalog.revision)
                        || state.view.pending.is_some()
                        || !state.view.catalog_acknowledged
                    {
                        return Err(invalid(
                            "display catalogue revision or pending layout changed",
                        ));
                    }
                    let selected =
                        state.view.selected.as_ref().ok_or_else(|| {
                            invalid("layout refresh requires confirmed selection")
                        })?;
                    let sequence = selected
                        .sequence
                        .checked_add(1)
                        .ok_or_else(|| invalid("selection sequence exhausted"))?;
                    let source = selected.source;
                    state.view.pending = Some(NativeDisplayRequest {
                        catalog: catalog.clone(),
                        sequence,
                        source,
                    });
                    state.view.catalog_acknowledged = false;
                } else if state.published {
                    return Err(invalid("display catalogue is already published"));
                }
                state
                    .assembler
                    .begin(catalog, count)
                    .map_err(io::Error::other)?;
                state.deadline = Some(Instant::now() + DISPLAY_HANDSHAKE_BUDGET);
                drop(state);
                if replacing {
                    self.presentation()?.presentation.suspend_display()?;
                }
            }
            DisplayEnvelope::CatalogEntry {
                catalog,
                index,
                display,
            } if !is_host => {
                self.check_catalog(&catalog)?;
                self.state
                    .lock()
                    .map_err(|_| io::Error::other("display state poisoned"))?
                    .assembler
                    .entry(catalog, index, display)
                    .map_err(io::Error::other)?;
            }
            DisplayEnvelope::CatalogCommit(catalog) if !is_host => {
                self.check_catalog(&catalog)?;
                let displays = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| io::Error::other("display state poisoned"))?;
                    let displays = state.assembler.commit(&catalog).map_err(io::Error::other)?;
                    if state.view.catalog.is_some()
                        && (displays.iter().map(|d| d.source).collect::<Vec<_>>()
                            != state.view.approved_sources
                            || !state.view.catalog.as_ref().is_some_and(|old| {
                                old.revision.checked_add(1) == Some(catalog.revision)
                            }))
                    {
                        return Err(denied(
                            "layout refresh cannot expand or replace the originally granted sources",
                        ));
                    }
                    state.view.catalog = Some(catalog.clone());
                    state.view.displays = displays.clone();
                    state.view.approved_sources = displays.iter().map(|d| d.source).collect();
                    state.view.catalog_acknowledged = true;
                    state.published = true;
                    displays
                };
                self.presentation()?
                    .presentation
                    .install_display_catalog(catalog.clone(), displays)?;
                // The receive allowlist is installed before this ACK. Separate
                // QUIC streams cannot race an uninitialized source allowlist.
                self.send(DisplayEnvelope::CatalogAck(catalog)).await?;
            }
            DisplayEnvelope::CatalogAck(catalog) if is_host => {
                self.check_catalog(&catalog)?;
                let mut state = self
                    .state
                    .lock()
                    .map_err(|_| io::Error::other("display state poisoned"))?;
                if !state.published || state.view.catalog.as_ref() != Some(&catalog) {
                    return Err(invalid("unpublished catalogue acknowledged"));
                }
                if !state.view.catalog_acknowledged {
                    let source = state
                        .view
                        .initial_source
                        .ok_or_else(|| invalid("no locally approved initial display"))?;
                    let sequence = state
                        .view
                        .selected
                        .as_ref()
                        .map_or(Some(1), |selected| selected.sequence.checked_add(1))
                        .ok_or_else(|| invalid("selection sequence exhausted"))?;
                    state.view.catalog_acknowledged = true;
                    state.view.pending = Some(NativeDisplayRequest {
                        catalog,
                        sequence,
                        source,
                    });
                    state.deadline = Some(Instant::now() + DISPLAY_HANDSHAKE_BUDGET);
                }
            }
            DisplayEnvelope::Select {
                catalog,
                sequence,
                source,
            } if is_host => {
                self.check_catalog(&catalog)?;
                let request = NativeDisplayRequest {
                    catalog,
                    sequence,
                    source,
                };
                let replay = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| io::Error::other("display state poisoned"))?;
                    validate_request(&state, &request)?;
                    if state.view.pending.as_ref() == Some(&request) {
                        state.prepared.clone()
                    } else if state
                        .view
                        .selected
                        .as_ref()
                        .is_some_and(|s| same_request(s, &request))
                    {
                        state.view.selected.clone()
                    } else {
                        state.view.pending = Some(request);
                        state.deadline = Some(Instant::now() + DISPLAY_HANDSHAKE_BUDGET);
                        None
                    }
                };
                if let Some(selection) = replay {
                    self.send(DisplayEnvelope::Selected(selection)).await?;
                } else {
                    let video = self.video()?;
                    video.gate.pause();
                    video.sender.discard_video().map_err(io::Error::other)?;
                }
            }
            DisplayEnvelope::Selected(selection) if !is_host => {
                self.check_catalog(&selection.catalog)?;
                let (display, duplicate) = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| io::Error::other("display state poisoned"))?;
                    if state.view.catalog.as_ref() != Some(&selection.catalog)
                        || !state.view.catalog_acknowledged
                    {
                        return Err(invalid("selection catalogue unacknowledged"));
                    }
                    let display = state
                        .view
                        .displays
                        .iter()
                        .find(|d| d.source == selection.source)
                        .cloned()
                        .ok_or_else(|| denied("source not in approved catalogue"))?;
                    let duplicate = state.view.selected.as_ref() == Some(&selection);
                    if !duplicate {
                        if let Some(previous) = &state.view.selected {
                            if !state
                                .view
                                .pending
                                .as_ref()
                                .is_some_and(|r| same_request(&selection, r))
                                || previous.sequence.checked_add(1) != Some(selection.sequence)
                                || previous.layout_epoch.checked_add(1)
                                    != Some(selection.layout_epoch)
                                || (self.input_authorized
                                    && previous.input_epoch.checked_add(1)
                                        != Some(selection.input_epoch))
                            {
                                return Err(invalid(
                                    "selection does not acknowledge the exact pending switch",
                                ));
                            }
                        } else if selection.sequence != 1 || selection.layout_epoch != 1 {
                            return Err(invalid("invalid initial display epoch"));
                        }
                        if self.input_authorized != (selection.input_epoch > 0)
                            || (selection.sequence == 1
                                && self.input_authorized
                                && selection.input_epoch != 1)
                        {
                            return Err(invalid("input epoch does not match proved permission"));
                        }
                        state.view.selected = Some(selection.clone());
                        state.view.pending = None;
                        state.deadline = None;
                    }
                    (display, duplicate)
                };
                let presentation = self.presentation()?.presentation.clone();
                if !duplicate {
                    presentation.select_display(&selection)?;
                }
                presentation.wait_display_ready(&selection).await?;
                if !duplicate && self.input_authorized {
                    let shared = self.shared()?;
                    let input = shared
                        .native_input
                        .lock()
                        .map_err(|_| io::Error::other("input route poisoned"))?
                        .clone()
                        .ok_or_else(|| denied("input route unavailable"))?;
                    input.commit_display_layout(&selection, &display)?;
                }
                self.send(DisplayEnvelope::SelectionAck(selection)).await?;
            }
            DisplayEnvelope::SelectionAck(selection) if is_host => {
                self.check_catalog(&selection.catalog)?;
                let activate = {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| io::Error::other("display state poisoned"))?;
                    if state.view.selected.as_ref() == Some(&selection) {
                        false
                    } else {
                        if state.prepared.as_ref() != Some(&selection) {
                            return Err(invalid("selection ACK changed prepared binding"));
                        }
                        state.view.selected = Some(selection);
                        state.view.pending = None;
                        state.prepared = None;
                        state.deadline = None;
                        true
                    }
                };
                if activate {
                    self.video()?.gate.open().map_err(io::Error::other)?;
                }
            }
            _ => return Err(invalid("display control direction or kind is unauthorized")),
        }
        Ok(())
    }
}
fn same_request(selection: &DisplaySelection, request: &NativeDisplayRequest) -> bool {
    selection.catalog == request.catalog
        && selection.sequence == request.sequence
        && selection.source == request.source
}
fn validate_request(state: &State, request: &NativeDisplayRequest) -> io::Result<()> {
    if !state.view.catalog_acknowledged
        || state.view.catalog.as_ref() != Some(&request.catalog)
        || !state.view.approved_sources.contains(&request.source)
    {
        return Err(denied("selection is outside locally approved catalogue"));
    }
    if state.view.pending.as_ref() == Some(request)
        || state
            .view
            .selected
            .as_ref()
            .is_some_and(|s| same_request(s, request))
    {
        return Ok(());
    }
    if state.view.pending.is_some()
        || state.prepared.is_some()
        || !state.view.selected.as_ref().is_some_and(|s| {
            s.sequence.checked_add(1) == Some(request.sequence) && s.source != request.source
        })
    {
        return Err(invalid(
            "display selection sequence replay or concurrent switch",
        ));
    }
    Ok(())
}
impl Shared {
    pub(super) fn set_native_display_route(&self, route: Option<Arc<NativeDisplayRoute>>) {
        let mut current = self
            .native_displays
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(previous) = std::mem::replace(&mut *current, route) {
            previous.retire();
        }
    }
}
impl CoreHandle {
    fn display_route(&self, binding: &NativeSessionBinding) -> io::Result<Arc<NativeDisplayRoute>> {
        let snapshot = self.snapshot();
        if self.shared.closing.load(Ordering::Acquire)
            || !snapshot.native_session.data.as_ref().is_some_and(|s| {
                s.status == NativeSessionStatus::Connected
                    && s.request_id == binding.request_id
                    && s.connection_generation == binding.connection_generation
            })
        {
            return Err(denied("native display session changed"));
        }
        let route = self
            .shared
            .native_displays
            .lock()
            .map_err(|_| io::Error::other("display route poisoned"))?
            .as_ref()
            .filter(|r| {
                &r.binding == binding
                    && r.generation == snapshot.generation
                    && r.generation == self.shared.generation.load(Ordering::Acquire)
            })
            .cloned()
            .ok_or_else(|| denied("no native display route"))?;
        route.check()?;
        Ok(route)
    }
    pub fn native_displays(
        &self,
        binding: &NativeSessionBinding,
    ) -> io::Result<NativeDisplayState> {
        let route = self.display_route(binding)?;
        let view = route
            .state
            .lock()
            .map_err(|_| io::Error::other("display state poisoned"))?
            .view
            .clone();
        route.check()?;
        Ok(view)
    }
    /// Read only a frame from this exact acknowledged selection. Holding the
    /// display state through mailbox extraction prevents an old IPC stream
    /// from consuming the first frame of a replacement source or epoch.
    pub fn poll_native_video_for_selection(
        &self,
        binding: &NativeSessionBinding,
        selection: &DisplaySelection,
    ) -> io::Result<Option<DecodedVideo>> {
        let route = self.display_route(binding)?;
        let state = route
            .state
            .lock()
            .map_err(|_| io::Error::other("display state poisoned"))?;
        if state.view.is_host
            || state.view.pending.is_some()
            || state.view.selected.as_ref() != Some(selection)
        {
            return Err(denied("video subscription selection retired"));
        }
        let presentation = route.presentation()?;
        let frame = presentation.presentation.poll_video()?;
        if frame.as_ref().is_some_and(|frame| {
            frame.source != selection.source || frame.epoch.layout != selection.layout_epoch
        }) {
            return Err(invalid("video frame differs from selected epoch"));
        }
        Ok(frame)
    }
    /// Windows/X11 call this after bounded read-only enumeration. Portal calls
    /// it with exactly the OS-approved stable source set. No remote input can
    /// turn an unapproved candidate into capture authority.
    pub fn publish_native_display_candidates(
        &self,
        binding: &NativeSessionBinding,
        mut displays: Vec<DisplayDescriptor>,
        system_approved: bool,
    ) -> io::Result<()> {
        displays.sort_by_key(|d| d.source);
        validate_candidates(&displays).map_err(io::Error::other)?;
        if system_approved {
            validate_displays(&displays).map_err(io::Error::other)?;
        }
        let key = catalog_key(
            &binding.request_id,
            binding.connection_generation,
            1,
            &displays,
        )
        .map_err(io::Error::other)?;
        let route = self.display_route(binding)?;
        let mut state = route
            .state
            .lock()
            .map_err(|_| io::Error::other("display state poisoned"))?;
        if !state.view.is_host || state.candidates.is_some() {
            return Err(denied("candidate set is already bound"));
        }
        state.system_approved = system_approved;
        state.candidates = Some((key.clone(), displays.clone()));
        state.view.catalog = Some(key);
        state.view.displays = displays.clone();
        state.view.local_approval_required = !system_approved;
        if system_approved {
            state.view.approved_sources = displays.iter().map(|d| d.source).collect();
            state.view.initial_source = displays.first().map(|d| d.source);
        }
        Ok(())
    }
    /// OS resize of an already granted, fixed source set. This supports
    /// Android View-only projection rotation without acquiring a new grant.
    /// An attached Input owner keeps its existing terminal rotation policy.
    pub async fn refresh_system_native_display_layout(
        &self,
        binding: &NativeSessionBinding,
        mut displays: Vec<DisplayDescriptor>,
        layout_epoch: u64,
    ) -> io::Result<()> {
        displays.sort_by_key(|d| d.source);
        validate_displays(&displays).map_err(io::Error::other)?;
        let route = self.display_route(binding)?;
        let _order = route.order.lock().await;
        let video = route.video()?;
        let _send_order = video.ordered_send().await.map_err(io::Error::other)?;
        {
            let mut state = route
                .state
                .lock()
                .map_err(|_| io::Error::other("display state poisoned"))?;
            if !state.view.is_host
                || !state.system_approved
                || route.input_authorized
                || state.view.pending.is_some()
                || !state.view.catalog_acknowledged
            {
                return Err(denied(
                    "system layout refresh requires a confirmed View-only OS grant",
                ));
            }
            let previous = state
                .view
                .selected
                .as_ref()
                .ok_or_else(|| invalid("no confirmed display"))?;
            if previous.layout_epoch.checked_add(1) != Some(layout_epoch)
                || displays.iter().map(|d| d.source).collect::<Vec<_>>()
                    != state.view.approved_sources
            {
                return Err(denied(
                    "system layout refresh changed granted sources or epoch",
                ));
            }
            let sequence = previous
                .sequence
                .checked_add(1)
                .ok_or_else(|| invalid("selection sequence exhausted"))?;
            let source = previous.source;
            let revision = state
                .view
                .catalog
                .as_ref()
                .and_then(|key| key.revision.checked_add(1))
                .ok_or_else(|| invalid("catalogue revision exhausted"))?;
            let catalog = catalog_key(
                &binding.request_id,
                binding.connection_generation,
                revision,
                &displays,
            )
            .map_err(io::Error::other)?;
            state.view.catalog = Some(catalog.clone());
            state.view.displays = displays;
            state.view.catalog_acknowledged = false;
            state.view.initial_source = Some(source);
            state.view.pending = Some(NativeDisplayRequest {
                catalog,
                sequence,
                source,
            });
            state.published = false;
            state.deadline = Some(Instant::now() + DISPLAY_HANDSHAKE_BUDGET);
        }
        video.gate.pause();
        video.sender.discard_video().map_err(io::Error::other)?;
        Ok(())
    }
    pub fn approve_native_displays(
        &self,
        binding: &NativeSessionBinding,
        candidates: &DisplayCatalogKey,
        sources: Vec<u32>,
        initial_source: u32,
    ) -> io::Result<NativeDisplayState> {
        let route = self.display_route(binding)?;
        let mut state = route
            .state
            .lock()
            .map_err(|_| io::Error::other("display state poisoned"))?;
        let (key, displays) = state
            .candidates
            .as_ref()
            .ok_or_else(|| denied("no local candidate set"))?;
        if !state.view.is_host
            || key != candidates
            || !state.view.local_approval_required
            || sources.is_empty()
            || sources.len() > 64
            || !sources.contains(&initial_source)
        {
            return Err(denied("stale or invalid local display approval"));
        }
        let mut sources = sources;
        sources.sort_unstable();
        if sources.windows(2).any(|w| w[0] == w[1]) {
            return Err(invalid("duplicate approved display"));
        }
        let approved: Vec<_> = displays
            .iter()
            .filter(|d| sources.contains(&d.source))
            .cloned()
            .collect();
        if approved.len() != sources.len() {
            return Err(denied("local approval includes an unenumerated source"));
        }
        validate_displays(&approved).map_err(io::Error::other)?;
        let key = catalog_key(
            &binding.request_id,
            binding.connection_generation,
            1,
            &approved,
        )
        .map_err(io::Error::other)?;
        state.view.catalog = Some(key);
        state.view.displays = approved;
        state.view.approved_sources = sources;
        state.view.initial_source = Some(initial_source);
        state.view.local_approval_required = false;
        Ok(state.view.clone())
    }
    pub async fn advertise_native_displays(
        &self,
        binding: &NativeSessionBinding,
    ) -> io::Result<()> {
        let route = self.display_route(binding)?;
        let _order = route.order.lock().await;
        let (catalog, displays) = {
            let mut state = route
                .state
                .lock()
                .map_err(|_| io::Error::other("display state poisoned"))?;
            if !state.view.is_host
                || state.view.local_approval_required
                || state.view.approved_sources.is_empty()
            {
                return Err(denied("local display consent required"));
            }
            if state.published {
                return Ok(());
            }
            state.published = true;
            state.deadline = Some(Instant::now() + DISPLAY_HANDSHAKE_BUDGET);
            (
                state
                    .view
                    .catalog
                    .clone()
                    .ok_or_else(|| invalid("no approved catalogue"))?,
                state.view.displays.clone(),
            )
        };
        route.video()?.gate.pause();
        let result = async {
            route
                .send(DisplayEnvelope::CatalogBegin {
                    catalog: catalog.clone(),
                    count: displays.len() as u8,
                })
                .await?;
            for (index, display) in displays.into_iter().enumerate() {
                route
                    .send(DisplayEnvelope::CatalogEntry {
                        catalog: catalog.clone(),
                        index: index as u8,
                        display,
                    })
                    .await?;
            }
            route.send(DisplayEnvelope::CatalogCommit(catalog)).await
        }
        .await;
        if result.is_err() {
            let _ = route.lease.stop(StopReason::TransportLost);
        }
        result
    }
    pub async fn select_native_display(
        &self,
        binding: &NativeSessionBinding,
        request: NativeDisplayRequest,
    ) -> io::Result<NativeDisplayState> {
        let route = self.display_route(binding)?;
        let _order = route.order.lock().await;
        {
            let mut state = route
                .state
                .lock()
                .map_err(|_| io::Error::other("display state poisoned"))?;
            if state.view.is_host {
                return Err(denied("host cannot submit remote source selection"));
            }
            validate_request(&state, &request)?;
            if state.view.pending.as_ref() == Some(&request)
                || state
                    .view
                    .selected
                    .as_ref()
                    .is_some_and(|s| same_request(s, &request))
            {
                return Ok(state.view.clone());
            }
            state.view.pending = Some(request.clone());
            state.deadline = Some(Instant::now() + DISPLAY_HANDSHAKE_BUDGET);
        }
        route.presentation()?.presentation.suspend_display()?;
        let sent = route
            .send(DisplayEnvelope::Select {
                catalog: request.catalog,
                sequence: request.sequence,
                source: request.source,
            })
            .await;
        if sent.is_err() {
            let _ = route.lease.stop(StopReason::TransportLost);
        }
        sent?;
        self.native_displays(binding)
    }
    pub fn native_display_switch_request(
        &self,
        binding: &NativeSessionBinding,
    ) -> io::Result<Option<NativeDisplayRequest>> {
        let route = self.display_route(binding)?;
        let state = route
            .state
            .lock()
            .map_err(|_| io::Error::other("display state poisoned"))?;
        Ok(
            (state.view.is_host && state.view.catalog_acknowledged && state.prepared.is_none())
                .then(|| state.view.pending.clone())
                .flatten(),
        )
    }
    /// The daemon invokes this from its single owned capture worker. Input
    /// release and exact source handoff complete before any new epoch is sent.
    /// A matching network retry returns the already prepared binding unchanged.
    pub async fn commit_native_display_switch(
        &self,
        binding: &NativeSessionBinding,
        request: &NativeDisplayRequest,
    ) -> io::Result<DisplaySelection> {
        let route = self.display_route(binding)?;
        let _order = route.order.lock().await;
        let (display, previous, already) = {
            let state = route
                .state
                .lock()
                .map_err(|_| io::Error::other("display state poisoned"))?;
            if !state.view.is_host {
                return Err(denied("controller cannot commit host capture"));
            }
            if let Some(completed) = state
                .view
                .selected
                .as_ref()
                .filter(|s| same_request(s, request))
            {
                return Ok(completed.clone());
            }
            if state.view.pending.as_ref() != Some(request) {
                return Err(denied("display switch is not the current approved request"));
            }
            let display = state
                .view
                .displays
                .iter()
                .find(|d| d.source == request.source)
                .cloned()
                .ok_or_else(|| denied("source is not locally approved"))?;
            (display, state.view.selected.clone(), state.prepared.clone())
        };
        if let Some(selection) = already {
            return Ok(selection);
        }
        // From this point a cancellation or platform failure owns terminal
        // cleanup. A successful Selected hands ownership to the bounded ACK.
        let mut cancelled = DisplaySwitchGuard {
            route: route.clone(),
            committed: false,
        };
        let video = route.video()?;
        let _send_order = video.ordered_send().await.map_err(io::Error::other)?;
        video.gate.pause();
        video.sender.discard_video().map_err(io::Error::other)?;
        let layout_epoch = previous
            .as_ref()
            .map_or(Some(1), |s| s.layout_epoch.checked_add(1))
            .filter(|e| *e <= i64::MAX as u64)
            .ok_or_else(|| invalid("layout epoch exhausted"))?;
        let input_epoch = if route.input_authorized {
            let shared = route.shared()?;
            let input = shared
                .native_input
                .lock()
                .map_err(|_| io::Error::other("input route poisoned"))?
                .clone()
                .ok_or_else(|| denied("input owner unavailable"))?;
            let source = display.source;
            let layout = logical(&display);
            let session = binding.clone();
            tokio::task::spawn_blocking(move || {
                input.switch_display(&session, source, layout, layout_epoch)
            })
            .await
            .map_err(io::Error::other)??
        } else {
            0
        };
        let selection = DisplaySelection {
            catalog: request.catalog.clone(),
            sequence: request.sequence,
            source: display.source,
            layout_epoch,
            input_epoch,
        };
        {
            let mut cursor = video
                .cursor
                .lock()
                .map_err(|_| io::Error::other("video cursor poisoned"))?;
            let next = NativeVideoBinding {
                source: display.source,
                width: display.width,
                height: display.height,
                layout_epoch,
            };
            if cursor.binding != Some(next) {
                cursor.bind(next, false).map_err(io::Error::other)?;
            }
        }
        route
            .state
            .lock()
            .map_err(|_| io::Error::other("display state poisoned"))?
            .prepared = Some(selection.clone());
        if let Err(error) = route
            .send(DisplayEnvelope::Selected(selection.clone()))
            .await
        {
            let _ = route.lease.stop(StopReason::TransportLost);
            return Err(error);
        }
        route.check()?;
        cancelled.committed = true;
        Ok(selection)
    }
}
struct DisplaySwitchGuard {
    route: Arc<NativeDisplayRoute>,
    committed: bool,
}
impl Drop for DisplaySwitchGuard {
    fn drop(&mut self) {
        if !self.committed {
            self.route.retire();
            let _ = self.route.lease.stop(StopReason::PlatformChanged);
        }
    }
}
