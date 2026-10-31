//! Dedicated, bounded local video channel. The ordinary JSON IPC framing is
//! never used for pixels; one authenticated TLS connection switches to a
//! binary-only stream after a session-bound OpenNativeVideo request.
use crate::wire::{Command, Reply, Request, Response};
use nestlink_app_core::{CoreHandle, NativeSessionStatus, VideoLayout};
use nestlink_local_ipc::{
    Error as LocalError, LocalStream, VIDEO_CHUNK_BYTES, VIDEO_HEADER_BYTES, VIDEO_PAYLOAD_BYTES,
};
use std::{path::Path, time::Duration};
use tokio::time::Instant;
use zeroize::Zeroizing;

const VIDEO_MAGIC: &[u8; 8] = b"NLVID001";
const KIND_LAYOUT: u8 = 1;
const KIND_FRAME: u8 = 2;
const KIND_CLOSED: u8 = 3;
const PIXEL_BGRA8: u8 = 1;
const MAX_DIMENSION: u32 = 8192;
const STREAM_POLL: Duration = Duration::from_millis(8);
const AUTHORIZATION_POLL: Duration = Duration::from_millis(50);
const FRAME_SEND_BUDGET: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeVideoBinding {
    pub runtime_id: String,
    pub ui_generation: u64,
    pub request_id: String,
    pub connection_generation: u64,
    pub source: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeVideoLayout {
    pub binding: NativeVideoBinding,
    pub layout_epoch: u64,
    pub width: u32,
    pub height: u32,
}

pub struct NativeVideoFrame {
    pub codec: u8,
    pub hardware_decode: bool,
    pub binding: NativeVideoBinding,
    pub layout_epoch: u64,
    pub sequence: u64,
    pub pts_90khz: u64,
    pub width: u32,
    pub height: u32,
    pub pixels: Zeroizing<Vec<u8>>,
}

pub enum NativeVideoMessage {
    Layout(NativeVideoLayout),
    Frame(NativeVideoFrame),
    Closed(NativeVideoBinding),
}

#[derive(Debug, Clone, Copy)]
struct Header {
    codec: u8,
    hardware_decode: bool,
    kind: u8,
    binding: HeaderBinding,
    layout_epoch: u64,
    sequence: u64,
    pts_90khz: u64,
    width: u32,
    height: u32,
    payload_bytes: u32,
}

#[derive(Debug, Clone, Copy)]
struct HeaderFields {
    codec: u8,
    hardware_decode: bool,
    kind: u8,
    layout_epoch: u64,
    sequence: u64,
    pts_90khz: u64,
    width: u32,
    height: u32,
    payload_bytes: u32,
}

#[derive(Debug, Clone, Copy)]
struct HeaderBinding {
    runtime_id: [u8; 36],
    request_id: [u8; 36],
    ui_generation: u64,
    connection_generation: u64,
    source: u32,
}

pub struct VideoClient {
    connection: LocalStream,
    binding: NativeVideoBinding,
    layout: Option<(u64, u32, u32)>,
    sequence: u64,
    pts_90khz: u64,
    closed: bool,
}

impl VideoClient {
    pub async fn open(
        directory: &Path,
        ui_generation: u64,
        request_id: String,
        connection_generation: u64,
        source: u32,
    ) -> Result<Self, crate::Error> {
        let mut connection = LocalStream::connect(directory).await?;
        let runtime_id = connection.runtime_id().to_owned();
        let request = Request {
            version: nestlink_local_ipc::VERSION,
            runtime_id: runtime_id.clone(),
            sequence: 1,
            expected_generation: ui_generation,
            command: Command::OpenNativeVideo {
                request_id: request_id.clone(),
                connection_generation,
                source,
            },
        };
        connection.send(&request).await?;
        let response: Response = connection.receive().await?;
        if response.version != nestlink_local_ipc::VERSION
            || response.sequence != request.sequence
            || response.runtime_id != runtime_id
            || response.snapshot.generation != ui_generation
            || !response
                .snapshot
                .native_session
                .data
                .as_ref()
                .is_some_and(|session| {
                    session.status == NativeSessionStatus::Connected
                        && session.request_id == request_id
                        && session.connection_generation == connection_generation
                })
        {
            return Err(crate::Error::Protocol);
        }
        if !matches!(
            response.result,
            Reply::VideoStreamOpened {
                connection_generation: opened_generation,
                source: opened_source,
            } if opened_generation == connection_generation && opened_source == source
        ) {
            return Err(crate::Error::Protocol);
        }
        let binding = NativeVideoBinding {
            runtime_id,
            ui_generation,
            request_id,
            connection_generation,
            source,
        };
        Ok(Self {
            connection,
            binding,
            layout: None,
            sequence: 0,
            pts_90khz: 0,
            closed: false,
        })
    }

    pub fn binding(&self) -> &NativeVideoBinding {
        &self.binding
    }

    pub async fn receive(&mut self) -> Result<NativeVideoMessage, crate::Error> {
        if self.closed {
            return Err(crate::Error::Protocol);
        }
        let (bytes, body_payload_bytes) = self.connection.receive_video_header().await?;
        let header = decode_header(&bytes)?;
        validate_stream_header(
            header,
            &self.binding,
            body_payload_bytes,
            self.layout,
            self.sequence,
            self.pts_90khz,
        )?;
        match header.kind {
            KIND_LAYOUT => {
                self.layout = Some((header.layout_epoch, header.width, header.height));
                Ok(NativeVideoMessage::Layout(NativeVideoLayout {
                    binding: self.binding.clone(),
                    layout_epoch: header.layout_epoch,
                    width: header.width,
                    height: header.height,
                }))
            }
            KIND_FRAME => {
                let pixels = self.connection.receive_video_payload().await?;
                self.sequence = header.sequence;
                self.pts_90khz = header.pts_90khz;
                Ok(NativeVideoMessage::Frame(NativeVideoFrame {
                    codec: header.codec,
                    hardware_decode: header.hardware_decode,
                    binding: self.binding.clone(),
                    layout_epoch: header.layout_epoch,
                    sequence: header.sequence,
                    pts_90khz: header.pts_90khz,
                    width: header.width,
                    height: header.height,
                    pixels,
                }))
            }
            KIND_CLOSED => {
                self.closed = true;
                Ok(NativeVideoMessage::Closed(self.binding.clone()))
            }
            _ => Err(crate::Error::Protocol),
        }
    }
}

fn validate_stream_header(
    header: Header,
    binding: &NativeVideoBinding,
    body_payload_bytes: usize,
    layout: Option<(u64, u32, u32)>,
    sequence: u64,
    pts_90khz: u64,
) -> Result<(), crate::Error> {
    if !header_matches_binding(header, binding)
        || body_payload_bytes > VIDEO_PAYLOAD_BYTES
        || header.payload_bytes as usize != body_payload_bytes
    {
        return Err(crate::Error::Protocol);
    }
    match header.kind {
        KIND_LAYOUT => {
            if body_payload_bytes != 0
                || header.sequence != 0
                || header.pts_90khz != 0
                || !valid_geometry(header.width, header.height)
                || header.layout_epoch == 0
                || header.layout_epoch > i64::MAX as u64
                || layout.is_some_and(|(epoch, _, _)| header.layout_epoch <= epoch)
            {
                return Err(crate::Error::Protocol);
            }
        }
        KIND_FRAME => {
            let expected_payload =
                pixel_bytes(header.width, header.height).ok_or(crate::Error::Protocol)?;
            if !valid_geometry(header.width, header.height)
                || body_payload_bytes != expected_payload
                || header.layout_epoch == 0
                || header.layout_epoch > i64::MAX as u64
                || header.sequence == 0
                || header.sequence > i64::MAX as u64
                || header.sequence <= sequence
                || header.pts_90khz > i64::MAX as u64
                || (sequence > 0 && header.pts_90khz <= pts_90khz)
                || layout != Some((header.layout_epoch, header.width, header.height))
            {
                return Err(crate::Error::Protocol);
            }
        }
        KIND_CLOSED => {
            let has_expected_layout = match layout {
                Some((epoch, width, height)) => {
                    (header.layout_epoch, header.width, header.height) == (epoch, width, height)
                }
                None => (header.layout_epoch, header.width, header.height) == (0, 0, 0),
            };
            if body_payload_bytes != 0
                || header.payload_bytes != 0
                || header.sequence != 0
                || header.pts_90khz != 0
                || !has_expected_layout
            {
                return Err(crate::Error::Protocol);
            }
        }
        _ => return Err(crate::Error::Protocol),
    }
    Ok(())
}

pub(crate) fn video_binding_is_live(core: &CoreHandle, binding: &NativeVideoBinding) -> bool {
    let snapshot = core.snapshot();
    snapshot.generation == binding.ui_generation
        && snapshot
            .native_session
            .data
            .as_ref()
            .is_some_and(|session| {
                session.status == NativeSessionStatus::Connected
                    && session.request_id == binding.request_id
                    && session.connection_generation == binding.connection_generation
            })
        && core
            .native_displays(&nestlink_app_core::NativeSessionBinding {
                request_id: binding.request_id.clone(),
                connection_generation: binding.connection_generation,
            })
            .is_ok_and(|state| {
                !state.is_host
                    && state.pending.is_none()
                    && state
                        .selected
                        .as_ref()
                        .is_some_and(|selection| selection.source == binding.source)
            })
}

pub(crate) fn authorized_layout(
    core: &CoreHandle,
    binding: &NativeVideoBinding,
) -> Result<Option<NativeVideoLayout>, crate::Error> {
    if !video_binding_is_live(core, binding) {
        return Err(crate::Error::Protocol);
    }
    let layout = core
        .native_video_layout(binding.source)
        .map_err(|_| crate::Error::Protocol)?;
    if layout
        .as_ref()
        .is_some_and(|layout| !valid_layout(layout, binding))
    {
        return Err(crate::Error::Protocol);
    }
    Ok(layout.map(|layout| NativeVideoLayout {
        binding: binding.clone(),
        layout_epoch: layout.epoch.layout,
        width: layout.width,
        height: layout.height,
    }))
}

pub(crate) fn valid_layout(layout: &VideoLayout, binding: &NativeVideoBinding) -> bool {
    layout.source == binding.source
        && layout.epoch.connection == binding.connection_generation
        && layout.epoch.layout > 0
        && layout.epoch.layout <= i64::MAX as u64
        && valid_geometry(layout.width, layout.height)
}

pub(crate) async fn serve_video_stream(
    mut connection: LocalStream,
    core: CoreHandle,
    binding: NativeVideoBinding,
) -> Result<(), crate::Error> {
    let mut updates = core.observe();
    let mut poll = tokio::time::interval(STREAM_POLL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut authorize = tokio::time::interval(AUTHORIZATION_POLL);
    authorize.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_layout: Option<(u64, u32, u32)> = None;
    let session_binding = nestlink_app_core::NativeSessionBinding {
        request_id: binding.request_id.clone(),
        connection_generation: binding.connection_generation,
    };
    let selection = core
        .native_displays(&session_binding)
        .ok()
        .filter(|state| state.pending.is_none())
        .and_then(|state| state.selected)
        .filter(|selection| selection.source == binding.source)
        .ok_or(crate::Error::Protocol)?;

    loop {
        if !video_binding_is_live(&core, &binding) {
            send_closed(&mut connection, &binding, last_layout).await;
            return Ok(());
        }
        let layout = match authorized_layout(&core, &binding) {
            Ok(layout) => layout,
            Err(_) => {
                send_closed(&mut connection, &binding, last_layout).await;
                return Ok(());
            }
        };
        if let Some(layout) = &layout {
            if layout.layout_epoch != selection.layout_epoch
                || layout.layout_epoch > i64::MAX as u64
                || !valid_geometry(layout.width, layout.height)
            {
                return Err(crate::Error::Protocol);
            }
            let current = (layout.layout_epoch, layout.width, layout.height);
            if last_layout != Some(current) {
                let header = encode_header(
                    &binding,
                    HeaderFields {
                        codec: 0,
                        hardware_decode: false,
                        kind: KIND_LAYOUT,
                        layout_epoch: layout.layout_epoch,
                        sequence: 0,
                        pts_90khz: 0,
                        width: layout.width,
                        height: layout.height,
                        payload_bytes: 0,
                    },
                )?;
                connection.send_video_header(&header, 0).await?;
                last_layout = Some(current);
            }
        }

        match core.poll_native_video_for_selection(&session_binding, &selection) {
            Ok(Some(frame)) => {
                let expected_layout = last_layout;
                let frame_layout = (frame.epoch.layout, frame.width, frame.height);
                let expected_bytes = pixel_bytes(frame.width, frame.height);
                if frame.source != binding.source
                    || frame.epoch.connection != binding.connection_generation
                    || expected_layout != Some(frame_layout)
                    || expected_bytes != Some(frame.pixels.len())
                    || frame.sequence == 0
                    || frame.sequence > i64::MAX as u64
                    || frame.pts_90khz > i64::MAX as u64
                {
                    send_closed(&mut connection, &binding, last_layout).await;
                    return Ok(());
                }
                let header = encode_header(
                    &binding,
                    HeaderFields {
                        codec: frame.codec,
                        hardware_decode: frame.hardware_decode,
                        kind: KIND_FRAME,
                        layout_epoch: frame.epoch.layout,
                        sequence: frame.sequence,
                        pts_90khz: frame.pts_90khz,
                        width: frame.width,
                        height: frame.height,
                        payload_bytes: u32::try_from(frame.pixels.len())
                            .map_err(|_| crate::Error::Protocol)?,
                    },
                )?;
                send_frame_monitored(
                    &mut connection,
                    &core,
                    &mut updates,
                    &mut authorize,
                    FrameTransfer {
                        binding: &binding,
                        expected_layout: last_layout,
                        header: &header,
                        pixels: &frame.pixels,
                    },
                )
                .await?;
            }
            Ok(None) => {}
            Err(_) => {
                send_closed(&mut connection, &binding, last_layout).await;
                return Ok(());
            }
        }

        tokio::select! {
            biased;
            changed = updates.changed() => {
                if changed.is_err() || !video_binding_is_live(&core, &binding) {
                    send_closed(&mut connection, &binding, last_layout).await;
                    return Ok(());
                }
            }
            _ = authorize.tick() => {
                if authorized_layout(&core, &binding).is_err() {
                    send_closed(&mut connection, &binding, last_layout).await;
                    return Ok(());
                }
            }
            _ = poll.tick() => {}
        }
    }
}

struct FrameTransfer<'a> {
    binding: &'a NativeVideoBinding,
    expected_layout: Option<(u64, u32, u32)>,
    header: &'a [u8; VIDEO_HEADER_BYTES],
    pixels: &'a [u8],
}

async fn send_frame_monitored(
    connection: &mut LocalStream,
    core: &CoreHandle,
    updates: &mut tokio::sync::watch::Receiver<std::sync::Arc<nestlink_app_core::Snapshot>>,
    authorize: &mut tokio::time::Interval,
    frame: FrameTransfer<'_>,
) -> Result<(), crate::Error> {
    let deadline = Instant::now() + FRAME_SEND_BUDGET;
    let FrameTransfer {
        binding,
        expected_layout,
        header,
        pixels,
    } = frame;
    connection.send_video_header(header, pixels.len()).await?;
    for chunk in pixels.chunks(VIDEO_CHUNK_BYTES) {
        if !frame_authority_is_live(core, binding, expected_layout) {
            return Err(crate::Error::Protocol);
        }
        let sending = connection.send_video_payload_chunk(chunk);
        tokio::pin!(sending);
        loop {
            tokio::select! {
                biased;
                changed = updates.changed() => {
                    if changed.is_err() || !frame_authority_is_live(core, binding, expected_layout) {
                        return Err(crate::Error::Protocol);
                    }
                }
                _ = authorize.tick() => {
                    if !frame_authority_is_live(core, binding, expected_layout) {
                        return Err(crate::Error::Protocol);
                    }
                }
                result = &mut sending => {
                    result?;
                    break;
                }
                _ = tokio::time::sleep_until(deadline) => return Err(crate::Error::Transport(LocalError::Timeout)),
            }
        }
    }
    Ok(())
}

fn frame_authority_is_live(
    core: &CoreHandle,
    binding: &NativeVideoBinding,
    expected_layout: Option<(u64, u32, u32)>,
) -> bool {
    if !video_binding_is_live(core, binding) {
        return false;
    }
    authorized_layout(core, binding)
        .ok()
        .flatten()
        .is_some_and(|layout| {
            expected_layout == Some((layout.layout_epoch, layout.width, layout.height))
        })
}

async fn send_closed(
    connection: &mut LocalStream,
    binding: &NativeVideoBinding,
    layout: Option<(u64, u32, u32)>,
) {
    let (epoch, width, height) = layout.unwrap_or((0, 0, 0));
    if let Ok(header) = encode_header(
        binding,
        HeaderFields {
            codec: 0,
            hardware_decode: false,
            kind: KIND_CLOSED,
            layout_epoch: epoch,
            sequence: 0,
            pts_90khz: 0,
            width,
            height,
            payload_bytes: 0,
        },
    ) {
        let _ = connection.send_video_header(&header, 0).await;
    }
}

fn encode_header(
    binding: &NativeVideoBinding,
    fields: HeaderFields,
) -> Result<[u8; VIDEO_HEADER_BYTES], crate::Error> {
    if !valid_id(&binding.runtime_id)
        || !valid_id(&binding.request_id)
        || binding.ui_generation == 0
        || binding.ui_generation > i64::MAX as u64
        || binding.connection_generation == 0
        || binding.connection_generation > i64::MAX as u64
    {
        return Err(crate::Error::Protocol);
    }
    let mut bytes = [0_u8; VIDEO_HEADER_BYTES];
    bytes[0..8].copy_from_slice(VIDEO_MAGIC);
    bytes[8] = fields.kind;
    bytes[9] = PIXEL_BGRA8;
    bytes[10] = fields.codec;
    bytes[11] = fields.hardware_decode.into();
    bytes[12..48].copy_from_slice(binding.runtime_id.as_bytes());
    bytes[48..84].copy_from_slice(binding.request_id.as_bytes());
    bytes[84..92].copy_from_slice(&binding.ui_generation.to_be_bytes());
    bytes[92..100].copy_from_slice(&binding.connection_generation.to_be_bytes());
    bytes[100..108].copy_from_slice(&fields.layout_epoch.to_be_bytes());
    bytes[108..112].copy_from_slice(&binding.source.to_be_bytes());
    bytes[112..120].copy_from_slice(&fields.sequence.to_be_bytes());
    bytes[120..128].copy_from_slice(&fields.pts_90khz.to_be_bytes());
    bytes[128..132].copy_from_slice(&fields.width.to_be_bytes());
    bytes[132..136].copy_from_slice(&fields.height.to_be_bytes());
    bytes[136..140].copy_from_slice(&fields.payload_bytes.to_be_bytes());
    Ok(bytes)
}

fn decode_header(bytes: &[u8; VIDEO_HEADER_BYTES]) -> Result<Header, crate::Error> {
    if &bytes[0..8] != VIDEO_MAGIC
        || bytes[9] != PIXEL_BGRA8
        || bytes[10] > 1
        || bytes[11] > 1
        || (bytes[10] == 0 && bytes[11] != 0)
        || (bytes[8] != KIND_FRAME && (bytes[10] != 0 || bytes[11] != 0))
    {
        return Err(crate::Error::Protocol);
    }
    let runtime_id = std::str::from_utf8(&bytes[12..48]).map_err(|_| crate::Error::Protocol)?;
    let request_id = std::str::from_utf8(&bytes[48..84]).map_err(|_| crate::Error::Protocol)?;
    if !valid_id(runtime_id) || !valid_id(request_id) {
        return Err(crate::Error::Protocol);
    }
    Ok(Header {
        codec: bytes[10],
        hardware_decode: bytes[11] == 1,
        kind: bytes[8],
        binding: HeaderBinding {
            runtime_id: bytes[12..48]
                .try_into()
                .map_err(|_| crate::Error::Protocol)?,
            request_id: bytes[48..84]
                .try_into()
                .map_err(|_| crate::Error::Protocol)?,
            ui_generation: read_u64(&bytes[84..92])?,
            connection_generation: read_u64(&bytes[92..100])?,
            source: read_u32(&bytes[108..112])?,
        },
        layout_epoch: read_u64(&bytes[100..108])?,
        sequence: read_u64(&bytes[112..120])?,
        pts_90khz: read_u64(&bytes[120..128])?,
        width: read_u32(&bytes[128..132])?,
        height: read_u32(&bytes[132..136])?,
        payload_bytes: read_u32(&bytes[136..140])?,
    })
}

fn header_matches_binding(header: Header, binding: &NativeVideoBinding) -> bool {
    header.binding.runtime_id.as_slice() == binding.runtime_id.as_bytes()
        && header.binding.request_id.as_slice() == binding.request_id.as_bytes()
        && header.binding.ui_generation == binding.ui_generation
        && header.binding.connection_generation == binding.connection_generation
        && header.binding.source == binding.source
}

fn read_u64(bytes: &[u8]) -> Result<u64, crate::Error> {
    let bytes: [u8; 8] = bytes.try_into().map_err(|_| crate::Error::Protocol)?;
    Ok(u64::from_be_bytes(bytes))
}

fn read_u32(bytes: &[u8]) -> Result<u32, crate::Error> {
    let bytes: [u8; 4] = bytes.try_into().map_err(|_| crate::Error::Protocol)?;
    Ok(u32::from_be_bytes(bytes))
}

fn pixel_bytes(width: u32, height: u32) -> Option<usize> {
    let bytes = u64::from(width)
        .checked_mul(u64::from(height))?
        .checked_mul(4)?;
    usize::try_from(bytes)
        .ok()
        .filter(|bytes| *bytes <= VIDEO_PAYLOAD_BYTES)
}

fn valid_geometry(width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width <= MAX_DIMENSION
        && height <= MAX_DIMENSION
        && pixel_bytes(width, height).is_some()
}

fn valid_id(value: &str) -> bool {
    nestlink_protocol::valid_id(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Request, Response};
    use nestlink_app_core::{NativeSessionView, Section, Snapshot};
    use nestlink_local_ipc::LocalServer;
    use std::sync::Arc;

    fn binding() -> NativeVideoBinding {
        NativeVideoBinding {
            runtime_id: "00000000-0000-4000-8000-000000000001".into(),
            ui_generation: 7,
            request_id: "00000000-0000-4000-8000-000000000002".into(),
            connection_generation: 9,
            source: 0,
        }
    }

    fn frame_header(binding: &NativeVideoBinding) -> Header {
        let encoded = encode_header(
            binding,
            HeaderFields {
                codec: 0,
                hardware_decode: false,
                kind: KIND_FRAME,
                layout_epoch: 2,
                sequence: 3,
                pts_90khz: 90,
                width: 640,
                height: 480,
                payload_bytes: 640 * 480 * 4,
            },
        )
        .unwrap_or([0; VIDEO_HEADER_BYTES]);
        decode_header(&encoded).unwrap_or(Header {
            codec: 0,
            hardware_decode: false,
            kind: 0,
            binding: HeaderBinding {
                runtime_id: [0; 36],
                request_id: [0; 36],
                ui_generation: 0,
                connection_generation: 0,
                source: 0,
            },
            layout_epoch: 0,
            sequence: 0,
            pts_90khz: 0,
            width: 0,
            height: 0,
            payload_bytes: 0,
        })
    }

    fn connected_snapshot(
        ui_generation: u64,
        request_id: &str,
        connection_generation: u64,
    ) -> Arc<Snapshot> {
        let snapshot = Snapshot {
            generation: ui_generation,
            native_session: Section {
                data: Some(Arc::new(NativeSessionView {
                    request_id: request_id.into(),
                    connection_generation,
                    lease_sequence: 1,
                    status: NativeSessionStatus::Connected,
                    host_view_authorized: false,
                    path: None,
                    quality: None,
                    stop_reason: None,
                    stop_effects: None,
                    cleanup: None,
                    failure: None,
                })),
                ..Section::default()
            },
            ..Snapshot::default()
        };
        Arc::new(snapshot)
    }

    #[test]
    fn video_header_round_trips_the_full_local_binding_and_limits() {
        let binding = binding();
        let encoded = encode_header(
            &binding,
            HeaderFields {
                codec: 0,
                hardware_decode: false,
                kind: KIND_FRAME,
                layout_epoch: 2,
                sequence: 3,
                pts_90khz: 90,
                width: 640,
                height: 480,
                payload_bytes: 640 * 480 * 4,
            },
        )
        .unwrap_or([0; VIDEO_HEADER_BYTES]);
        let decoded = decode_header(&encoded);
        assert!(decoded.is_ok());
        let decoded = decoded.unwrap_or(Header {
            codec: 0,
            hardware_decode: false,
            kind: 0,
            binding: HeaderBinding {
                runtime_id: [0; 36],
                request_id: [0; 36],
                ui_generation: 0,
                connection_generation: 0,
                source: 1,
            },
            layout_epoch: 0,
            sequence: 0,
            pts_90khz: 0,
            width: 0,
            height: 0,
            payload_bytes: 0,
        });
        assert_eq!(decoded.kind, KIND_FRAME);
        assert!(header_matches_binding(decoded, &binding));
        assert_eq!(decoded.layout_epoch, 2);
        assert_eq!(decoded.payload_bytes as usize, 640 * 480 * 4);
        assert_eq!(pixel_bytes(8192, 2048), Some(VIDEO_PAYLOAD_BYTES));
        assert_eq!(pixel_bytes(8192, 8192), None);
    }

    #[test]
    fn video_header_rejects_noncanonical_identity_and_geometry() {
        let mut binding = binding();
        binding.request_id = "not-a-request-id".into();
        assert!(
            encode_header(
                &binding,
                HeaderFields {
                    codec: 0,
                    hardware_decode: false,
                    kind: KIND_LAYOUT,
                    layout_epoch: 1,
                    sequence: 0,
                    pts_90khz: 0,
                    width: 640,
                    height: 480,
                    payload_bytes: 0,
                },
            )
            .is_err()
        );
        assert!(!valid_geometry(8192, 8192));
        assert!(valid_geometry(8192, 2048));
    }

    #[test]
    fn stream_header_rejects_bad_geometry_and_payload_budgets_before_allocation() {
        let binding = binding();
        let mut bad_geometry = frame_header(&binding);
        bad_geometry.width = 0;
        assert!(
            validate_stream_header(
                bad_geometry,
                &binding,
                640 * 480 * 4,
                Some((2, 640, 480)),
                2,
                80,
            )
            .is_err()
        );

        let mut over_budget = frame_header(&binding);
        over_budget.payload_bytes = (VIDEO_PAYLOAD_BYTES + 1) as u32;
        assert!(
            validate_stream_header(
                over_budget,
                &binding,
                VIDEO_PAYLOAD_BYTES + 1,
                Some((2, 640, 480)),
                2,
                80,
            )
            .is_err()
        );

        let mut over_budget_claim = frame_header(&binding);
        over_budget_claim.payload_bytes = (VIDEO_PAYLOAD_BYTES + 1) as u32;
        assert!(
            validate_stream_header(over_budget_claim, &binding, 0, Some((2, 640, 480)), 2, 80,)
                .is_err()
        );

        let mut impossible_dimensions = frame_header(&binding);
        impossible_dimensions.width = u32::MAX;
        impossible_dimensions.height = u32::MAX;
        impossible_dimensions.payload_bytes = 0;
        assert!(
            validate_stream_header(
                impossible_dimensions,
                &binding,
                0,
                Some((2, u32::MAX, u32::MAX)),
                2,
                80,
            )
            .is_err()
        );
    }

    #[test]
    fn stream_header_binds_runtime_generation_request_connection_and_source() {
        let binding = binding();
        let header = frame_header(&binding);
        for mutate in [0_u8, 1, 2, 3, 4] {
            let mut wrong = binding.clone();
            match mutate {
                0 => wrong.runtime_id = "00000000-0000-4000-8000-000000000003".into(),
                1 => wrong.ui_generation += 1,
                2 => wrong.request_id = "00000000-0000-4000-8000-000000000003".into(),
                3 => wrong.connection_generation += 1,
                _ => wrong.source = 1,
            }
            assert!(
                validate_stream_header(header, &wrong, 640 * 480 * 4, Some((2, 640, 480)), 2, 80,)
                    .is_err()
            );
        }
    }

    #[test]
    fn old_layout_frames_and_nonmonotonic_frames_are_rejected() {
        let binding = binding();
        let header = frame_header(&binding);
        assert!(
            validate_stream_header(header, &binding, 640 * 480 * 4, Some((3, 640, 480)), 2, 80,)
                .is_err()
        );
        assert!(
            validate_stream_header(header, &binding, 640 * 480 * 4, Some((2, 640, 480)), 3, 80,)
                .is_err()
        );
        assert!(
            validate_stream_header(header, &binding, 640 * 480 * 4, Some((2, 640, 480)), 2, 90,)
                .is_err()
        );
    }

    #[test]
    fn layout_headers_must_advance_and_closed_headers_must_match_the_bound_layout() {
        let binding = binding();
        let encoded = encode_header(
            &binding,
            HeaderFields {
                codec: 0,
                hardware_decode: false,
                kind: KIND_LAYOUT,
                layout_epoch: 4,
                sequence: 0,
                pts_90khz: 0,
                width: 800,
                height: 600,
                payload_bytes: 0,
            },
        )
        .unwrap_or([0; VIDEO_HEADER_BYTES]);
        let layout = decode_header(&encoded).unwrap_or_else(|_| frame_header(&binding));
        assert!(validate_stream_header(layout, &binding, 0, Some((3, 640, 480)), 0, 0).is_ok());
        assert!(validate_stream_header(layout, &binding, 0, Some((4, 800, 600)), 0, 0).is_err());

        let closed_bytes = encode_header(
            &binding,
            HeaderFields {
                codec: 0,
                hardware_decode: false,
                kind: KIND_CLOSED,
                layout_epoch: 4,
                sequence: 0,
                pts_90khz: 0,
                width: 800,
                height: 600,
                payload_bytes: 0,
            },
        )
        .unwrap_or([0; VIDEO_HEADER_BYTES]);
        let closed = decode_header(&closed_bytes).unwrap_or_else(|_| frame_header(&binding));
        assert!(validate_stream_header(closed, &binding, 0, Some((4, 800, 600)), 0, 0).is_ok());
        assert!(validate_stream_header(closed, &binding, 0, Some((3, 800, 600)), 0, 0).is_err());
    }

    #[tokio::test]
    async fn video_stream_authorization_fails_closed_without_a_connected_view_session()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut owner = nestlink_app_core::AppCore::start(nestlink_app_core::Limits::default())?;
        let core = owner.handle();
        let binding = binding();
        assert!(!video_binding_is_live(&core, &binding));
        assert!(authorized_layout(&core, &binding).is_err());
        let _ = owner.shutdown(Duration::from_millis(100)).await;
        Ok(())
    }

    #[tokio::test]
    async fn video_client_opens_and_receives_a_binary_frame_over_mutual_local_tls()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join("state");
        let daemon = LocalServer::bind(&directory).await?;
        let runtime_id = daemon.runtime_id().to_owned();
        let request_id = "00000000-0000-4000-8000-000000000002".to_owned();
        let ui_generation = 7;
        let connection_generation = 9;
        let client_directory = directory.clone();
        let client_request_id = request_id.clone();
        let client = async move {
            let mut client = VideoClient::open(
                &client_directory,
                ui_generation,
                client_request_id,
                connection_generation,
                0,
            )
            .await?;
            let layout = client.receive().await?;
            assert!(matches!(
                layout,
                NativeVideoMessage::Layout(NativeVideoLayout {
                    layout_epoch: 2,
                    width: 2,
                    height: 1,
                    ..
                })
            ));
            let frame = client.receive().await?;
            match frame {
                NativeVideoMessage::Frame(frame) => {
                    assert_eq!(frame.layout_epoch, 2);
                    assert_eq!(frame.sequence, 1);
                    assert_eq!(frame.pts_90khz, 90);
                    assert_eq!(frame.width, 2);
                    assert_eq!(frame.height, 1);
                    assert_eq!(
                        frame.pixels.as_slice(),
                        &[0x10, 0x20, 0x30, 0xff, 0x40, 0x50, 0x60, 0xff],
                    );
                }
                _ => return Err("client received a non-frame message".into()),
            }
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };
        let server = async {
            let mut stream = daemon.accept().await?.authenticate().await?;
            let request: Request = stream.receive().await?;
            assert_eq!(request.runtime_id, runtime_id);
            assert_eq!(request.sequence, 1);
            assert_eq!(request.expected_generation, ui_generation);
            assert!(matches!(
                request.command,
                Command::OpenNativeVideo {
                    connection_generation: 9,
                    source: 0,
                    ..
                }
            ));
            stream
                .send(&Response {
                    version: nestlink_local_ipc::VERSION,
                    runtime_id: runtime_id.clone(),
                    sequence: request.sequence,
                    snapshot: connected_snapshot(ui_generation, &request_id, connection_generation),
                    result: Reply::VideoStreamOpened {
                        connection_generation,
                        source: 0,
                    },
                })
                .await?;

            let binding = NativeVideoBinding {
                runtime_id: runtime_id.clone(),
                ui_generation,
                request_id: request_id.clone(),
                connection_generation,
                source: 0,
            };
            let layout = encode_header(
                &binding,
                HeaderFields {
                    codec: 0,
                    hardware_decode: false,
                    kind: KIND_LAYOUT,
                    layout_epoch: 2,
                    sequence: 0,
                    pts_90khz: 0,
                    width: 2,
                    height: 1,
                    payload_bytes: 0,
                },
            )?;
            stream.send_video_header(&layout, 0).await?;
            let frame = encode_header(
                &binding,
                HeaderFields {
                    codec: 0,
                    hardware_decode: false,
                    kind: KIND_FRAME,
                    layout_epoch: 2,
                    sequence: 1,
                    pts_90khz: 90,
                    width: 2,
                    height: 1,
                    payload_bytes: 8,
                },
            )?;
            stream.send_video_header(&frame, 8).await?;
            stream
                .send_video_payload_chunk(&[0x10, 0x20, 0x30, 0xff, 0x40, 0x50, 0x60, 0xff])
                .await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (client, server) = tokio::join!(client, server);
        client?;
        server?;
        Ok(())
    }
}
