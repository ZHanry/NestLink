//! One finite target per provider; actual CPU direction evidence only.
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
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct NativeMediaProvider {
    target: VideoConfig,
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
    resource_id: String,
}
struct ProbeJob {
    id: u64,
    cancel: Arc<AtomicBool>,
    worker: thread::JoinHandle<io::Result<ProbeResult>>,
}
fn reap_abandoned(slot: &mut Option<ProbeJob>) {
    if slot
        .as_ref()
        .is_some_and(|job| job.cancel.load(Ordering::Acquire) && job.worker.is_finished())
        && let Some(job) = slot.take()
    {
        let _ = job.worker.join();
    }
}
struct ProbeRequest(Arc<AtomicBool>);
impl Drop for ProbeRequest {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}
fn slot() -> &'static Mutex<Option<ProbeJob>> {
    static SLOT: OnceLock<Mutex<Option<ProbeJob>>> = OnceLock::new();
    SLOT.get_or_init(|| Mutex::new(None))
}
fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)
}
fn next_id() -> io::Result<u64> {
    static ID: AtomicU64 = AtomicU64::new(0);
    let wall = now()?;
    ID.fetch_update(Ordering::AcqRel, Ordering::Acquire, |old| {
        Some(wall.max(old.saturating_add(1)))
    })
    .map(|old| wall.max(old.saturating_add(1)))
    .map_err(|_| io::Error::other("probe generation unavailable"))
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
            state: Arc::new(Mutex::new(ProviderState::default())),
        })
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
            if guard.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "previous CPU probe owner still active or quarantined",
                ));
            }
            let target = self.target;
            let worker_cancel = cancel.clone();
            let worker = thread::Builder::new()
                .name("nestlink-media-direction-probe".into())
                .spawn(move || run_probe(target, direction, &worker_cancel))?;
            *guard = Some(ProbeJob {
                id,
                cancel: cancel.clone(),
                worker,
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
                if guard
                    .as_ref()
                    .is_some_and(|j| j.id == id && j.worker.is_finished())
                {
                    let job = guard
                        .take()
                        .ok_or_else(|| io::Error::other("probe owner lost"))?;
                    break job
                        .worker
                        .join()
                        .map_err(|_| io::Error::other("CPU probe worker panicked"))??;
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        let announcement = MediaAnnouncement {
            version: 2,
            device_id: device_id.into(),
            direction,
            revision: id,
            expires_at_unix_ms: now()?.saturating_add(240_000),
            probe: ProbeIdentity {
                generation: id,
                resource_id: receipt.resource_id,
                backend: "cpu-software".into(),
                adapter_luid: None,
                driver_version: None,
            },
            formats: vec![receipt.format.encode().map_err(io::Error::other)?],
        };
        announcement.validate(now()?).map_err(io::Error::other)?;
        Ok(announcement)
    }
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
    fn cancelled_probe_slot_stays_reserved_until_actual_worker_join() -> io::Result<()> {
        let cancel = Arc::new(AtomicBool::new(false));
        let (finish, wait) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let _ = wait.recv();
            Err(io::Error::other("synthetic test worker"))
        });
        let mut job = Some(ProbeJob {
            id: 1,
            cancel: cancel.clone(),
            worker,
        });
        cancel.store(true, Ordering::Release);
        reap_abandoned(&mut job);
        assert!(job.is_some());
        finish.send(()).map_err(io::Error::other)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while job.as_ref().is_some_and(|j| !j.worker.is_finished()) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(1));
        }
        // A completed non-abandoned result still belongs to its waiting caller.
        cancel.store(false, Ordering::Release);
        reap_abandoned(&mut job);
        assert!(job.is_some());
        cancel.store(true, Ordering::Release);
        reap_abandoned(&mut job);
        assert!(job.is_none());
        Ok(())
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
