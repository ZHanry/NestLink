//! A bounded finite set of exact targets; actual CPU direction evidence only.
//! Probe resources are closed historical observations. Live media owners are
//! owned/stopped/joined by the media runtime and have independent UUIDs.
use nestlink_media_codec::VideoConfig;
#[cfg(windows)]
use nestlink_protocol::media_format::{FrameRate, Geometry};
use nestlink_protocol::{
    media_authority::{MediaAnnouncement, MediaDirection, ProbeIdentity},
    media_format::VideoFormat,
};
use std::{
    io,
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct NativeMediaProvider {
    target: VideoConfig,
    targets: Arc<[VideoConfig]>,
    state: Arc<Mutex<ProviderState>>,
}
#[derive(Default)]
struct ProviderState {
    encode: Option<MediaAnnouncement>,
    decode: Option<MediaAnnouncement>,
    fallback_reason: Option<String>,
}
struct ProbeResult {
    format: VideoFormat,
    additional_formats: Vec<VideoFormat>,
    resource_id: String,
}
struct ProbeJob {
    id: u64,
    cancel: Arc<AtomicBool>,
    worker: thread::JoinHandle<io::Result<ProbeResult>>,
    prewarm: Option<Prewarm>,
}
struct Prewarm {
    state: Weak<Mutex<ProviderState>>,
    device_id: String,
    direction: MediaDirection,
    fence: crate::sdk_call::DispatchFence,
    start: Instant,
}
#[derive(Default)]
enum ProbeSlot {
    #[default]
    Idle,
    Running(ProbeJob),
    // An io::Error cannot prove every native owner completed checked close.
    // Neither cancellation nor join alone may authorize a replacement owner.
    Poisoned,
}
impl ProbeSlot {
    fn finish(&mut self) -> io::Result<(u64, ProbeResult)> {
        let Self::Running(job) = std::mem::replace(self, Self::Poisoned) else {
            return Err(io::Error::other("probe owner unavailable"));
        };
        let receipt = job
            .worker
            .join()
            .map_err(|_| io::Error::other("CPU probe worker panicked; slot poisoned"))??;
        *self = Self::Idle;
        Ok((job.id, receipt))
    }
}
fn reap_abandoned(slot: &mut ProbeSlot) {
    let ProbeSlot::Running(job) = slot else {
        return;
    };
    if let Some(prewarm) = &job.prewarm
        && (prewarm.fence.check().is_err()
            || prewarm.state.upgrade().is_none()
            || prewarm.start.elapsed() >= Duration::from_secs(30))
    {
        job.cancel.store(true, Ordering::Release);
    }
    if !job.worker.is_finished() || (job.prewarm.is_none() && !job.cancel.load(Ordering::Acquire)) {
        return;
    }
    let cancelled = job.cancel.load(Ordering::Acquire);
    let prewarm = job.prewarm.take();
    let result = slot.finish();
    if let Some(prewarm) = prewarm
        && !cancelled
        && prewarm.fence.check().is_ok()
        && let Some(state) = prewarm.state.upgrade()
        && let Ok(mut state) = state.lock()
        && prewarm.fence.check().is_ok()
    {
        match result.and_then(|(id, receipt)| {
            make_announcement(id, &prewarm.device_id, prewarm.direction, receipt)
        }) {
            Ok(local) => {
                match prewarm.direction {
                    MediaDirection::Encode => state.encode = Some(local),
                    MediaDirection::Decode => state.decode = Some(local),
                }
                state.fallback_reason = None;
            }
            Err(error) => state.fallback_reason = Some(error.to_string()),
        }
    }
}
fn make_announcement(
    id: u64,
    device_id: &str,
    direction: MediaDirection,
    receipt: ProbeResult,
) -> io::Result<MediaAnnouncement> {
    let formats = nestlink_protocol::media_format::FormatSet::new(
        std::iter::once(receipt.format)
            .chain(receipt.additional_formats)
            .collect(),
    )
    .map_err(io::Error::other)?;
    let announcement = MediaAnnouncement {
        version: 2,
        device_id: device_id.into(),
        direction,
        revision: id,
        expires_at_unix_ms: now()?
            .checked_add(240_000)
            .ok_or_else(|| io::Error::other("probe expiry overflow"))?,
        probe: ProbeIdentity {
            generation: id,
            resource_id: receipt.resource_id,
            backend: "cpu-software".into(),
            adapter_luid: None,
            driver_version: None,
        },
        formats: formats
            .formats()
            .iter()
            .map(|format| format.encode().map_err(io::Error::other))
            .collect::<io::Result<Vec<_>>>()?,
    };
    announcement.validate(now()?).map_err(io::Error::other)?;
    Ok(announcement)
}
struct ProbeRequest(Arc<AtomicBool>);
impl Drop for ProbeRequest {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
fn slot() -> &'static Mutex<ProbeSlot> {
    static SLOT: OnceLock<Mutex<ProbeSlot>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(ProbeSlot::Idle))
}
fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}
fn checked_next_id(old: u64, wall: u64) -> Option<u64> {
    let next = wall.max(old.checked_add(1)?);
    (next <= i64::MAX as u64).then_some(next)
}
fn next_id() -> io::Result<u64> {
    static ID: AtomicU64 = AtomicU64::new(0);
    let wall = now()?;
    ID.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
        checked_next_id(old, wall)
    })
    .ok()
    .and_then(|old| checked_next_id(old, wall))
    .ok_or_else(|| io::Error::other("probe generation exhausted"))
}
impl NativeMediaProvider {
    pub fn cpu_software(target: VideoConfig) -> io::Result<Self> {
        if target.width == 0
            || target.height == 0
            || target.width > 8192
            || target.height > 8192
            || !target.width.is_multiple_of(2)
            || !target.height.is_multiple_of(2)
            || u64::from(target.width) * u64::from(target.height) * 4 > 64 * 1024 * 1024
            || !(1..=120).contains(&target.fps)
            || !(64..=100_000).contains(&target.bitrate_kbps)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unsupported CPU product target",
            ));
        }
        Ok(Self {
            target,
            targets: Arc::from([target]),
            state: Arc::new(Mutex::new(ProviderState::default())),
        })
    }
    /// Each of at most three budgets runs the original full direction probe.
    /// No lower rate or bitrate is inferred from the maximum target's receipt.
    pub fn cpu_software_adaptive(target: VideoConfig) -> io::Result<Self> {
        let mut provider = Self::cpu_software(target)?;
        let mut targets = vec![target];
        for (numerator, denominator) in [(3, 4), (1, 2)] {
            let next = VideoConfig {
                fps: (target.fps * numerator / denominator).max(target.fps.min(15)),
                bitrate_kbps: (target.bitrate_kbps * numerator / denominator).max(64),
                ..target
            };
            if !targets
                .iter()
                .any(|value| value.fps == next.fps && value.bitrate_kbps == next.bitrate_kbps)
            {
                targets.push(next);
            }
        }
        provider.targets = targets.into();
        Ok(provider)
    }
    pub fn target(&self) -> VideoConfig {
        self.target
    }
    pub fn fallback_reason(&self) -> Option<String> {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.fallback_reason.clone())
    }
    /// Called only from an asynchronous app-core operation. Never holds a UI
    /// lock or waits synchronously for a native driver call.
    pub(crate) async fn announcement(
        &self,
        device_id: &str,
        direction: MediaDirection,
        cancelled: &AtomicBool,
    ) -> io::Result<MediaAnnouncement> {
        let wall = now()?;
        {
            let state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("media provider poisoned"))?;
            let existing = match direction {
                MediaDirection::Encode => &state.encode,
                MediaDirection::Decode => &state.decode,
            };
            if let Some(a) = existing.as_ref().filter(|a| {
                a.device_id == device_id && a.expires_at_unix_ms > wall.saturating_add(60_000)
            }) {
                return Ok(a.clone());
            }
        }
        let result = self.execute(device_id, direction, cancelled).await;
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("media provider poisoned"))?;
        match &result {
            Ok(a) => {
                match direction {
                    MediaDirection::Encode => state.encode = Some(a.clone()),
                    MediaDirection::Decode => state.decode = Some(a.clone()),
                };
                state.fallback_reason = None;
            }
            Err(e) => state.fallback_reason = Some(e.to_string()),
        }
        result
    }
    pub(crate) async fn publish(
        &self,
        sdk: &nestlink_sdk::Sdk,
        identity: &nestlink_sdk::DeviceIdentity,
        direction: MediaDirection,
        fence: &crate::sdk_call::DispatchFence,
    ) -> io::Result<MediaAnnouncement> {
        fence.check().map_err(|_| {
            io::Error::new(io::ErrorKind::Interrupted, "media publication superseded")
        })?;
        let local = self
            .announcement(&identity.device_id, direction, &fence.cancelled)
            .await?;
        fence.check().map_err(|_| {
            io::Error::new(io::ErrorKind::Interrupted, "media publication superseded")
        })?;
        let previous = fenced_network(
            fence,
            sdk.media_announcement(&identity.device_id, direction),
        )
        .await?;
        if previous.as_ref() != Some(&local) {
            fence.check().map_err(|_| {
                io::Error::new(io::ErrorKind::Interrupted, "media publication superseded")
            })?;
            fenced_network(
                fence,
                sdk.publish_media_announcement(identity, local.clone(), now()?),
            )
            .await?;
        }
        Ok(local)
    }
    /// Renewal polls supervise the retained native worker; no detached async task.
    /// A valid cached receipt keeps its original expiry while the next real probe runs.
    pub(crate) async fn publish_for_renewal(
        &self,
        sdk: &nestlink_sdk::Sdk,
        identity: &nestlink_sdk::DeviceIdentity,
        direction: MediaDirection,
        fence: &crate::sdk_call::DispatchFence,
    ) -> io::Result<MediaAnnouncement> {
        let start = Instant::now();
        let local = loop {
            fence.check().map_err(|_| {
                io::Error::new(io::ErrorKind::Interrupted, "renewal preparation superseded")
            })?;
            let (existing, poisoned) = self.renewal_poll(&identity.device_id, direction, fence)?;
            if let Some(local) = existing {
                break local;
            }
            if poisoned {
                return Err(io::Error::other(
                    "CPU probe cleanup unknown; replacement prohibited",
                ));
            }
            if start.elapsed() >= Duration::from_secs(30) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "renewal preparation budget; native owner retained",
                ));
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        fence.check().map_err(|_| {
            io::Error::new(io::ErrorKind::Interrupted, "renewal publication superseded")
        })?;
        local.validate(now()?).map_err(io::Error::other)?;
        let previous = fenced_network(
            fence,
            sdk.media_announcement(&identity.device_id, direction),
        )
        .await?;
        if previous.as_ref() != Some(&local) {
            local.validate(now()?).map_err(io::Error::other)?;
            fenced_network(
                fence,
                sdk.publish_media_announcement(identity, local.clone(), now()?),
            )
            .await?;
        }
        fence.check().map_err(|_| {
            io::Error::new(io::ErrorKind::Interrupted, "renewal publication superseded")
        })?;
        local.validate(now()?).map_err(io::Error::other)?;
        Ok(local)
    }
    fn renewal_poll(
        &self,
        device_id: &str,
        direction: MediaDirection,
        fence: &crate::sdk_call::DispatchFence,
    ) -> io::Result<(Option<MediaAnnouncement>, bool)> {
        let mut registry = slot()
            .lock()
            .map_err(|_| io::Error::other("probe slot poisoned"))?;
        reap_abandoned(&mut registry);
        let wall = now()?;
        let existing = {
            let state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("media provider poisoned"))?;
            cached(&state, device_id, direction, wall)
        };
        let needs_probe = prewarm_needed(existing.as_ref(), wall);
        if needs_probe && matches!(*registry, ProbeSlot::Idle) {
            let id = next_id()?;
            let cancel = Arc::new(AtomicBool::new(false));
            let worker_cancel = cancel.clone();
            let targets = self.targets.clone();
            let worker = thread::Builder::new()
                .name("nestlink-media-renewal-probe".into())
                .spawn(move || run_probes(&targets, direction, &worker_cancel))?;
            *registry = ProbeSlot::Running(ProbeJob {
                id,
                cancel,
                worker,
                prewarm: Some(Prewarm {
                    state: Arc::downgrade(&self.state),
                    device_id: device_id.into(),
                    direction,
                    fence: fence.clone(),
                    start: Instant::now(),
                }),
            });
        }
        let poisoned = matches!(*registry, ProbeSlot::Poisoned);
        Ok((existing, poisoned))
    }
    async fn execute(
        &self,
        device_id: &str,
        direction: MediaDirection,
        cancelled: &AtomicBool,
    ) -> io::Result<MediaAnnouncement> {
        let id = next_id()?;
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut guard = slot()
                .lock()
                .map_err(|_| io::Error::other("probe slot poisoned"))?;
            // A timed out caller cannot release an owner still inside a driver.
            // Reap it only after the real OS thread has ended and been joined.
            reap_abandoned(&mut guard);
            if !matches!(*guard, ProbeSlot::Idle) {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "previous CPU probe owner still active or quarantined",
                ));
            }
            let targets = self.targets.clone();
            let worker_cancel = cancel.clone();
            let worker = thread::Builder::new()
                .name("nestlink-media-direction-probe".into())
                .spawn(move || run_probes(&targets, direction, &worker_cancel))?;
            *guard = ProbeSlot::Running(ProbeJob {
                id,
                cancel: cancel.clone(),
                worker,
                prewarm: None,
            });
        }
        let _request = ProbeRequest(cancel.clone());
        let start = Instant::now();
        let receipt = loop {
            if cancelled.load(Ordering::Acquire) || start.elapsed() > Duration::from_secs(30) {
                cancel.store(true, Ordering::Release);
                // Job remains globally retained until actual join. No new
                // driver worker can be created, even after provider drop.
                return Err(io::Error::new(
                    if cancelled.load(Ordering::Acquire) {
                        io::ErrorKind::Interrupted
                    } else {
                        io::ErrorKind::TimedOut
                    },
                    "CPU probe cancelled/timed out; owner retained until join",
                ));
            }
            {
                let mut guard = slot()
                    .lock()
                    .map_err(|_| io::Error::other("probe slot poisoned"))?;
                if matches!(&*guard, ProbeSlot::Running(job) if job.id == id && job.worker.is_finished())
                {
                    break guard.finish()?.1;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        make_announcement(id, device_id, direction, receipt)
    }
}
fn prewarm_needed(value: Option<&MediaAnnouncement>, wall: u64) -> bool {
    value.is_none_or(|a| a.expires_at_unix_ms <= wall.saturating_add(60_000))
}
fn cached(
    state: &ProviderState,
    device_id: &str,
    direction: MediaDirection,
    wall: u64,
) -> Option<MediaAnnouncement> {
    let value = match direction {
        MediaDirection::Encode => &state.encode,
        MediaDirection::Decode => &state.decode,
    };
    value
        .as_ref()
        .filter(|a| {
            a.device_id == device_id && a.direction == direction && a.validate(wall).is_ok()
        })
        .cloned()
}
async fn fenced_network<T>(
    fence: &crate::sdk_call::DispatchFence,
    future: impl std::future::Future<Output = Result<T, nestlink_sdk::SdkError>>,
) -> io::Result<T> {
    tokio::select! { biased;
        _=async {loop {if fence.check().is_err() {break;} tokio::time::sleep(Duration::from_millis(20)).await;}} =>
            Err(io::Error::new(io::ErrorKind::Interrupted,"media network operation superseded")),
        result=tokio::time::timeout(Duration::from_secs(5),future)=>result
            .map_err(|_|io::Error::new(io::ErrorKind::TimedOut,"media publication network budget"))?
            .map_err(io::Error::other),
    }
}
fn run_probes(
    targets: &[VideoConfig],
    direction: MediaDirection,
    cancel: &AtomicBool,
) -> io::Result<ProbeResult> {
    let mut receipts = Vec::with_capacity(targets.len());
    for target in targets {
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "CPU target probes cancelled",
            ));
        }
        // Each mature MF owner completes checked flush and close before the
        // next exact target starts on this same original bounded worker.
        receipts.push(run_probe(*target, direction, cancel)?);
    }
    let mut receipts = receipts.into_iter();
    let mut primary = receipts
        .next()
        .ok_or_else(|| io::Error::other("empty CPU probe set"))?;
    primary.additional_formats = receipts.map(|receipt| receipt.format).collect();
    Ok(primary)
}
#[cfg(windows)]
fn run_probe(
    target: VideoConfig,
    direction: MediaDirection,
    cancel: &AtomicBool,
) -> io::Result<ProbeResult> {
    let receipt = match direction {
        MediaDirection::Encode => nestlink_media_codec::probe_cpu_encode(target, cancel)?,
        MediaDirection::Decode => nestlink_media_codec::probe_cpu_decode(target, cancel)?,
    };
    let c = receipt.config();
    let s = receipt.sps();
    let g = receipt.geometry();
    let owner = receipt.owner();
    if (c.width, c.height, c.fps, c.bitrate_kbps)
        != (target.width, target.height, target.fps, target.bitrate_kbps)
        || s.profile_idc != 66
        || !receipt.owner_closed()
        || !receipt.checked_flush()
        || receipt.outputs() < 16
        || owner.hardware_output
        || owner.adapter_luid.is_some()
        || owner.driver_version.is_some()
    {
        return Err(io::Error::other(
            "CPU direction receipt differs from exact product target/backend",
        ));
    }
    let format = VideoFormat::h264_observed(
        s.level_idc,
        s.constraints,
        Geometry {
            coded_width: g.coded_width,
            coded_height: g.coded_height,
            crop: g.crop,
        },
        c.width,
        c.height,
        FrameRate::new(c.fps, 1).map_err(io::Error::other)?,
        c.bitrate_kbps,
    )
    .map_err(io::Error::other)?;
    Ok(ProbeResult {
        format,
        additional_formats: Vec::new(),
        resource_id: format_uuid(owner.resource_id),
    })
}
#[cfg(windows)]
fn format_uuid(b: [u8; 16]) -> String {
    let h = b.iter().map(|v| format!("{v:02x}")).collect::<String>();
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}
#[cfg(not(windows))]
fn run_probe(
    _target: VideoConfig,
    _direction: MediaDirection,
    _cancel: &AtomicBool,
) -> io::Result<ProbeResult> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "actual CPU media direction target probe unavailable on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_cpu_target_rejects_unsupported_geometry_rate_and_bitrate() {
        let valid = VideoConfig {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_kbps: 8000,
        };
        assert!(NativeMediaProvider::cpu_software(valid).is_ok());
        for bad in [
            VideoConfig {
                width: 1919,
                ..valid
            },
            VideoConfig { height: 0, ..valid },
            VideoConfig { fps: 121, ..valid },
            VideoConfig {
                bitrate_kbps: 1,
                ..valid
            },
            VideoConfig {
                bitrate_kbps: 100001,
                ..valid
            },
        ] {
            assert!(NativeMediaProvider::cpu_software(bad).is_err());
        }
    }
    #[test]
    fn adaptive_cpu_targets_are_bounded_exact_budgets_below_the_product_ceiling() -> io::Result<()>
    {
        let target = VideoConfig {
            width: 1920,
            height: 1080,
            fps: 60,
            bitrate_kbps: 8000,
        };
        let provider = NativeMediaProvider::cpu_software_adaptive(target)?;
        assert_eq!(provider.targets.len(), 3);
        let budgets: Vec<_> = provider
            .targets
            .iter()
            .map(|value| {
                assert_eq!((value.width, value.height), (target.width, target.height));
                (value.fps, value.bitrate_kbps)
            })
            .collect();
        assert_eq!(budgets, [(60, 8000), (45, 6000), (30, 4000)]);
        let minimum = NativeMediaProvider::cpu_software_adaptive(VideoConfig {
            fps: 1,
            bitrate_kbps: 64,
            ..target
        })?;
        assert_eq!(minimum.targets.len(), 1);
        Ok(())
    }
    // Synthetic results test registry transitions only. They are not evidence of
    // native checked close; cpu_direction_probe's Windows regressions supply that.
    fn receipt() -> io::Result<ProbeResult> {
        Ok(ProbeResult {
            format: VideoFormat::legacy_h264(
                31,
                640,
                480,
                nestlink_protocol::media_format::FrameRate::new(30, 1).map_err(io::Error::other)?,
                4000,
            )
            .map_err(io::Error::other)?,
            additional_formats: Vec::new(),
            resource_id: nestlink_auth::random_id(),
        })
    }
    fn wait_finished(slot: &ProbeSlot) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(1);
        while matches!(slot,ProbeSlot::Running(job) if !job.worker.is_finished()) {
            if Instant::now() >= deadline {
                return Err(io::Error::other("fixture worker did not finish"));
            }
            thread::sleep(Duration::from_millis(1));
        }
        Ok(())
    }
    fn fence() -> crate::sdk_call::DispatchFence {
        crate::sdk_call::DispatchFence {
            generation: Arc::new(AtomicU64::new(1)),
            expected: 1,
            closing: Arc::new(AtomicBool::new(false)),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }
    #[test]
    fn cancelled_error_and_panicked_probe_join_never_authorize_slot_reuse() -> io::Result<()> {
        for panic in [false, true] {
            let cancel = Arc::new(AtomicBool::new(true));
            let worker = thread::spawn(move || {
                if panic {
                    panic!("synthetic worker panic");
                }
                Err(io::Error::other("synthetic unknown cleanup"))
            });
            let mut slot = ProbeSlot::Running(ProbeJob {
                id: 1,
                cancel,
                worker,
                prewarm: None,
            });
            wait_finished(&slot)?;
            reap_abandoned(&mut slot);
            assert!(matches!(slot, ProbeSlot::Poisoned));
            reap_abandoned(&mut slot);
            assert!(matches!(slot, ProbeSlot::Poisoned));
        }
        Ok(())
    }
    #[test]
    fn successful_abandoned_probe_releases_only_after_actual_join() -> io::Result<()> {
        let cancel = Arc::new(AtomicBool::new(true));
        let (finish, wait) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            wait.recv().map_err(io::Error::other)?;
            receipt()
        });
        let mut slot = ProbeSlot::Running(ProbeJob {
            id: 1,
            cancel: cancel.clone(),
            worker,
            prewarm: None,
        });
        reap_abandoned(&mut slot);
        assert!(matches!(slot, ProbeSlot::Running(_)));
        finish.send(()).map_err(io::Error::other)?;
        wait_finished(&slot)?;
        cancel.store(false, Ordering::Release);
        reap_abandoned(&mut slot);
        assert!(matches!(slot, ProbeSlot::Running(_)));
        cancel.store(true, Ordering::Release);
        reap_abandoned(&mut slot);
        assert!(matches!(slot, ProbeSlot::Idle));
        Ok(())
    }
    #[test]
    fn cache_boundary_expiry_device_and_direction_never_extend_original_receipt() -> io::Result<()>
    {
        let device = nestlink_auth::random_id();
        let local = make_announcement(1, &device, MediaDirection::Encode, receipt()?)?;
        let expiry = local.expires_at_unix_ms;
        let state = ProviderState {
            encode: Some(local.clone()),
            ..Default::default()
        };
        for remaining in [60_001, 60_000, 1] {
            let selected = cached(&state, &device, MediaDirection::Encode, expiry - remaining)
                .ok_or_else(|| io::Error::other("valid cache rejected"))?;
            assert_eq!(selected, local);
            assert_eq!(
                prewarm_needed(Some(&selected), expiry - remaining),
                remaining <= 60_000
            );
        }
        assert!(cached(&state, &device, MediaDirection::Encode, expiry).is_none());
        assert!(
            cached(
                &state,
                &nestlink_auth::random_id(),
                MediaDirection::Encode,
                expiry - 1
            )
            .is_none()
        );
        assert!(cached(&state, &device, MediaDirection::Decode, expiry - 1).is_none());
        Ok(())
    }
    #[test]
    fn prewarm_completion_requires_current_dispatch_and_retains_single_pending_worker()
    -> io::Result<()> {
        for scenario in 0..5 {
            let state = Arc::new(Mutex::new(ProviderState::default()));
            let fence = fence();
            let (finish, wait) = std::sync::mpsc::channel();
            let worker = thread::spawn(move || {
                wait.recv().map_err(io::Error::other)?;
                receipt()
            });
            let mut slot = ProbeSlot::Running(ProbeJob {
                id: 2,
                cancel: Arc::new(AtomicBool::new(false)),
                worker,
                prewarm: Some(Prewarm {
                    state: Arc::downgrade(&state),
                    device_id: nestlink_auth::random_id(),
                    direction: MediaDirection::Encode,
                    fence: fence.clone(),
                    start: if scenario == 4 {
                        Instant::now() - Duration::from_secs(31)
                    } else {
                        Instant::now()
                    },
                }),
            });
            for _ in 0..3 {
                reap_abandoned(&mut slot);
                assert!(matches!(&slot,ProbeSlot::Running(job) if job.id==2));
            }
            match scenario {
                1 => fence.generation.store(2, Ordering::Release),
                2 => fence.closing.store(true, Ordering::Release),
                3 => fence.cancelled.store(true, Ordering::Release),
                _ => {}
            }
            finish.send(()).map_err(io::Error::other)?;
            wait_finished(&slot)?;
            reap_abandoned(&mut slot);
            assert!(matches!(slot, ProbeSlot::Idle));
            assert_eq!(
                state
                    .lock()
                    .map_err(|_| io::Error::other("fixture state poisoned"))?
                    .encode
                    .is_some(),
                scenario == 0
            );
        }
        Ok(())
    }
    #[test]
    fn generation_exhaustion_never_saturates_or_reuses_identifier() {
        assert_eq!(checked_next_id(7, 5), Some(8));
        assert_eq!(checked_next_id(7, 10), Some(10));
        assert_eq!(checked_next_id(i64::MAX as u64, 1), None);
        assert_eq!(checked_next_id(u64::MAX, 1), None);
        assert_eq!(checked_next_id(0, u64::MAX), None);
    }
    #[test]
    fn dropping_probe_waiter_marks_owner_for_quarantine_and_actual_join() {
        let cancel = Arc::new(AtomicBool::new(false));
        {
            let _waiter = ProbeRequest(cancel.clone());
            assert!(!cancel.load(Ordering::Acquire));
        }
        assert!(cancel.load(Ordering::Acquire));
    }
}
