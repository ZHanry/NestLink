//! Bounded root-window ZPixmap reads. Application View authority remains in
//! VideoController; this source only enforces local desktop and format facts.
use crate::{
    denied,
    x11_session::{X11Session, X11SessionState},
    x11_transport::{Conn, IO_BUDGET, MESSAGE_BYTES, connect_until},
};
use nestlink_remote::{
    input::InputLayout,
    video::{Display, RAW_FRAME_BYTES, RawFrame},
};
use std::{
    collections::BTreeSet,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use x11rb::{
    connection::Connection,
    protocol::{
        Event,
        randr::{self, ConnectionExt as _},
        screensaver::ConnectionExt as _,
        xfixes::{ConnectionExt as _, GetCursorImageReply},
        xproto::{self, ConnectionExt as _},
    },
};

const AGGREGATE: usize = 128 * 1024 * 1024;
const CURSOR_SIDE: u16 = 256;

// XFixes GetCursorImage uses numeric 0xAARRGGBB with premultiplied
// components, independently from the root image's byte order and RGB masks.
// Reference: x11proto-dev 2023.2 fixesproto.txt, GetCursorImage.
fn blend_cursor(
    cursor: &GetCursorImageReply,
    origin: [i32; 2],
    frame: &mut RawFrame,
    until: Instant,
) -> io::Result<()> {
    frame.validate()?;
    let count = usize::from(cursor.width)
        .checked_mul(usize::from(cursor.height))
        .filter(|n| *n <= (MESSAGE_BYTES - 32) / 4)
        .ok_or_else(|| denied("X11 cursor pixel budget exceeded"))?;
    if cursor.width == 0
        || cursor.height == 0
        || cursor.width > CURSOR_SIDE
        || cursor.height > CURSOR_SIDE
        || cursor.xhot >= cursor.width
        || cursor.yhot >= cursor.height
        || cursor.cursor_image.len() != count
        || usize::try_from(cursor.length).map_err(error)? != count
    {
        return Err(denied("X11 cursor geometry/payload is invalid"));
    }
    // Validate even clipped pixels; malformed alpha must not become valid
    // merely because the pointer is currently outside this monitor.
    for (index, pixel) in cursor.cursor_image.iter().enumerate() {
        if index % 256 == 0 {
            budget(until)?;
        }
        let alpha = pixel >> 24;
        if [*pixel & 255, (*pixel >> 8) & 255, (*pixel >> 16) & 255]
            .iter()
            .any(|c| *c > alpha)
        {
            return Err(denied("X11 cursor color is not premultiplied alpha"));
        }
    }
    let left = i64::from(cursor.x) - i64::from(cursor.xhot) - i64::from(origin[0]);
    let top = i64::from(cursor.y) - i64::from(cursor.yhot) - i64::from(origin[1]);
    let x0 = left.max(0);
    let y0 = top.max(0);
    let x1 = (left + i64::from(cursor.width)).min(i64::from(frame.width));
    let y1 = (top + i64::from(cursor.height)).min(i64::from(frame.height));
    for y in y0..y1 {
        budget(until)?;
        for x in x0..x1 {
            let src = ((y - top) as usize * usize::from(cursor.width)) + (x - left) as usize;
            let dst = (y as usize * frame.width as usize + x as usize) * 4;
            let pixel = cursor.cursor_image[src];
            let alpha = pixel >> 24;
            for (channel, shift) in [0, 8, 16].into_iter().enumerate() {
                let source = (pixel >> shift) & 255;
                frame.pixels[dst + channel] = (source
                    + (u32::from(frame.pixels[dst + channel]) * (255 - alpha) + 127) / 255)
                    as u8;
            }
            frame.pixels[dst + 3] = 255;
        }
    }
    budget(until)
}
fn error(e: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::other(e)
}
fn budget(until: Instant) -> io::Result<()> {
    if Instant::now() >= until {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "X11 capture deadline expired",
        ))
    } else {
        Ok(())
    }
}
#[derive(Clone, PartialEq, Eq)]
struct Monitor {
    id: u32,
    rect: [i32; 4],
    millimeters: [u32; 2],
    outputs: Vec<u32>,
    primary: bool,
}
#[derive(PartialEq, Eq)]
struct Crtc {
    id: u32,
    rect: [i32; 4],
    mode: u32,
    rotation: u16,
    outputs: Vec<u32>,
    transform: [i32; 9],
    filter: Vec<u8>,
    params: Vec<i32>,
}
#[derive(PartialEq, Eq)]
struct Desktop {
    bounds: [u16; 2],
    timestamp: u32,
    config_timestamp: u32,
    monitors: Vec<Monitor>,
    crtcs: Vec<Crtc>,
}
#[derive(Clone, Copy)]
struct PixelFormat {
    depth: u8,
    visual: u32,
    bpp: u8,
    pad: u8,
    little: bool,
    masks: [u32; 3],
}
impl PixelFormat {
    fn new(
        depth: u8,
        visual: u32,
        bpp: u8,
        pad: u8,
        little: bool,
        masks: [u32; 3],
    ) -> io::Result<Self> {
        if !matches!(bpp, 8 | 16 | 24 | 32)
            || depth == 0
            || depth > bpp
            || !matches!(pad, 8 | 16 | 32)
            || masks.contains(&0)
            || masks[0] & masks[1] != 0
            || masks[0] & masks[2] != 0
            || masks[1] & masks[2] != 0
        {
            return Err(denied("X11 TrueColor pixel format is invalid"));
        }
        let allowed = (1u64 << bpp) - 1;
        for mask in masks {
            let bits = mask >> mask.trailing_zeros();
            if u64::from(mask) > allowed || bits & bits.wrapping_add(1) != 0 {
                return Err(denied(
                    "X11 color masks must be contiguous and inside each pixel",
                ));
            }
        }
        if masks.iter().map(|v| v.count_ones()).sum::<u32>() > u32::from(depth) {
            return Err(denied("X11 color masks exceed root depth"));
        }
        Ok(Self {
            depth,
            visual,
            bpp,
            pad,
            little,
            masks,
        })
    }
    fn stride(self, width: u32) -> io::Result<usize> {
        let bits = usize::try_from(width)
            .map_err(error)?
            .checked_mul(usize::from(self.bpp))
            .and_then(|v| v.checked_add(usize::from(self.pad) - 1))
            .ok_or_else(|| denied("X11 image stride overflow"))?;
        Ok((bits / usize::from(self.pad)) * (usize::from(self.pad) / 8))
    }
    fn decode(
        self,
        width: u32,
        height: u32,
        data: &[u8],
        output: &mut Vec<u8>,
        until: Instant,
    ) -> io::Result<()> {
        let stride = self.stride(width)?;
        let payload = stride
            .checked_mul(height as usize)
            .ok_or_else(|| denied("X11 image size overflow"))?;
        let padded = payload
            .checked_add(3)
            .map(|v| v & !3)
            .ok_or_else(|| denied("X11 image padding overflow"))?;
        if width == 0
            || height == 0
            || width > 8192
            || height > 8192
            || padded != data.len()
            || padded > MESSAGE_BYTES - 32
        {
            return Err(denied(
                "X11 image payload does not match the bounded geometry",
            ));
        }
        let output_bytes = (width as usize)
            .checked_mul(height as usize)
            .and_then(|v| v.checked_mul(4))
            .filter(|bytes| {
                output
                    .len()
                    .checked_add(*bytes)
                    .is_some_and(|n| n <= RAW_FRAME_BYTES)
            })
            .ok_or_else(|| denied("X11 decoded frame exceeds budget"))?;
        output.try_reserve(output_bytes).map_err(error)?;
        let bytes = usize::from(self.bpp / 8);
        for row in data[..payload].chunks_exact(stride) {
            budget(until)?;
            for pixel in row[..width as usize * bytes].chunks_exact(bytes) {
                let value = if self.little {
                    pixel
                        .iter()
                        .rev()
                        .fold(0u32, |v, b| (v << 8) | u32::from(*b))
                } else {
                    pixel.iter().fold(0u32, |v, b| (v << 8) | u32::from(*b))
                };
                let channel = |mask: u32| {
                    let shift = mask.trailing_zeros();
                    let maximum = u64::from(mask >> shift);
                    ((u64::from((value & mask) >> shift) * 255 + maximum / 2) / maximum) as u8
                };
                output.extend_from_slice(&[
                    channel(self.masks[2]),
                    channel(self.masks[1]),
                    channel(self.masks[0]),
                    255,
                ]);
            }
        }
        Ok(())
    }
}
fn desktop(conn: &Conn, root: u32) -> io::Result<Desktop> {
    let geometry = conn
        .get_geometry(root)
        .map_err(error)?
        .reply()
        .map_err(error)?;
    if geometry.width == 0
        || geometry.height == 0
        || geometry.width > 32768
        || geometry.height > 32768
    {
        return Err(denied("X11 root geometry exceeds capture budget"));
    }
    if conn
        .screensaver_query_info(root)
        .map_err(error)?
        .reply()
        .map_err(error)?
        .state
        == 1
    {
        return Err(denied("X11 screen saver is active"));
    }
    let resources = conn
        .randr_get_screen_resources_current(root)
        .map_err(error)?
        .reply()
        .map_err(error)?;
    if resources.crtcs.len() > 64 || resources.outputs.len() > 64 || resources.modes.len() > 4096 {
        return Err(denied("X11 display resource budget exceeded"));
    }
    let monitors = conn
        .randr_get_monitors(root, true)
        .map_err(error)?
        .reply()
        .map_err(error)?
        .monitors;
    if monitors.is_empty() || monitors.len() > 64 {
        return Err(denied("X11 monitor inventory unavailable"));
    }
    let mut ids = BTreeSet::new();
    let mut total = 0usize;
    let mut inventory = Vec::with_capacity(monitors.len());
    for mut monitor in monitors {
        let [x, y, w, h] = [
            i32::from(monitor.x),
            i32::from(monitor.y),
            i32::from(monitor.width),
            i32::from(monitor.height),
        ];
        if monitor.name == 0
            || !ids.insert(monitor.name)
            || monitor.outputs.len() > 64
            || w == 0
            || h == 0
            || w > 8192
            || h > 8192
            || x < 0
            || y < 0
            || x + w > i32::from(geometry.width)
            || y + h > i32::from(geometry.height)
        {
            return Err(denied(
                "X11 monitor lies outside the root or exceeds its budget",
            ));
        }
        let bytes = (w as usize)
            .checked_mul(h as usize)
            .and_then(|v| v.checked_mul(4))
            .filter(|v| *v <= RAW_FRAME_BYTES)
            .ok_or_else(|| denied("X11 monitor pixel budget exceeded"))?;
        total = total
            .checked_add(bytes)
            .filter(|v| *v <= AGGREGATE)
            .ok_or_else(|| denied("X11 aggregate pixel budget exceeded"))?;
        monitor.outputs.sort_unstable();
        inventory.push(Monitor {
            id: monitor.name,
            rect: [x, y, w, h],
            millimeters: [monitor.width_in_millimeters, monitor.height_in_millimeters],
            outputs: monitor.outputs,
            primary: monitor.primary,
        });
    }
    inventory.sort_by_key(|monitor| monitor.id);
    let mut crtcs = Vec::new();
    for id in resources.crtcs {
        let mut crtc = conn
            .randr_get_crtc_info(id, resources.config_timestamp)
            .map_err(error)?
            .reply()
            .map_err(error)?;
        if crtc.status != randr::SetConfig::SUCCESS || crtc.outputs.len() > 64 {
            return Err(denied("X11 CRTC facts unavailable"));
        }
        let transform = conn
            .randr_get_crtc_transform(id)
            .map_err(error)?
            .reply()
            .map_err(error)?;
        if transform.current_filter_name.len() > 256 || transform.current_params.len() > 64 {
            return Err(denied("X11 CRTC transform budget exceeded"));
        }
        let t = transform.current_transform;
        crtc.outputs.sort_unstable();
        crtcs.push(Crtc {
            id,
            rect: [
                i32::from(crtc.x),
                i32::from(crtc.y),
                i32::from(crtc.width),
                i32::from(crtc.height),
            ],
            mode: crtc.mode,
            rotation: crtc.rotation.into(),
            outputs: crtc.outputs,
            transform: [
                t.matrix11, t.matrix12, t.matrix13, t.matrix21, t.matrix22, t.matrix23, t.matrix31,
                t.matrix32, t.matrix33,
            ],
            filter: transform.current_filter_name,
            params: transform.current_params,
        });
    }
    crtcs.sort_by_key(|crtc| crtc.id);
    Ok(Desktop {
        bounds: [geometry.width, geometry.height],
        timestamp: resources.timestamp,
        config_timestamp: resources.config_timestamp,
        monitors: inventory,
        crtcs,
    })
}

/// Read-only terminal and desktop-session facts for the capture queue owner.
#[derive(Clone)]
pub struct X11CaptureControl {
    terminal: Arc<AtomicBool>,
    session: Option<X11SessionState>,
}
impl X11CaptureControl {
    /// Read-only revocation facts for a queue owner; cannot authorize capture.
    pub fn is_active(&self) -> bool {
        !self.terminal.load(Ordering::SeqCst)
            && self.session.as_ref().is_none_or(X11SessionState::is_active)
    }
}
/// A Send, independently connected local X11 capture source. It cannot issue
/// business permissions, reconnect a stopped session, or bypass logind.
pub struct X11CaptureSource {
    session: Option<X11Session>,
    conn: Conn,
    root: u32,
    format: PixelFormat,
    original: Desktop,
    displays: Vec<Display>,
    control: X11CaptureControl,
}
impl X11CaptureSource {
    /// PID comes from this GUI or authenticated local IPC, never the network.
    pub fn open_for_desktop(display: &str, local_gui_pid: u32) -> io::Result<Self> {
        let session = X11Session::open(local_gui_pid, display)?;
        Self::open_bound(display, Some(session))
    }
    #[cfg(test)]
    pub(crate) fn open_without_session(display: &str) -> io::Result<Self> {
        Self::open_bound(display, None)
    }
    fn open_bound(display: &str, session: Option<X11Session>) -> io::Result<Self> {
        let parsed = x11rb_protocol::parse_display::parse_display(Some(display)).map_err(error)?;
        if display.len() > 32
            || !display.starts_with(':')
            || !parsed.host.is_empty()
            || parsed.protocol.is_some()
        {
            return Err(denied(
                "X11 capture requires an explicit local Unix display",
            ));
        }
        let until = Instant::now() + IO_BUDGET;
        let (conn, _) = connect_until(parsed.display, usize::from(parsed.screen), until)?;
        let version = conn
            .randr_query_version(1, 5)
            .map_err(error)?
            .reply()
            .map_err(error)?;
        if (version.major_version, version.minor_version) < (1, 5) {
            return Err(denied("RandR 1.5 monitor inventory is required"));
        }
        let fixes = conn
            .xfixes_query_version(1, 0)
            .map_err(error)?
            .reply()
            .map_err(error)?;
        if fixes.major_version < 1 {
            return Err(denied("XFixes cursor images are required for X11 capture"));
        }
        let root = conn
            .setup()
            .roots
            .get(usize::from(parsed.screen))
            .ok_or_else(|| denied("X11 root is absent"))?;
        let root_id = root.root;
        let visual = root
            .allowed_depths
            .iter()
            .find(|d| d.depth == root.root_depth)
            .and_then(|d| d.visuals.iter().find(|v| v.visual_id == root.root_visual))
            .ok_or_else(|| denied("X11 root visual is absent"))?;
        if visual.class != xproto::VisualClass::TRUE_COLOR {
            return Err(denied("X11 capture requires a TrueColor root visual"));
        }
        let layout = conn
            .setup()
            .pixmap_formats
            .iter()
            .find(|format| format.depth == root.root_depth)
            .ok_or_else(|| denied("X11 root pixmap format is absent"))?;
        let little = match conn.setup().image_byte_order {
            xproto::ImageOrder::LSB_FIRST => true,
            xproto::ImageOrder::MSB_FIRST => false,
            _ => return Err(denied("X11 image byte order is invalid")),
        };
        let format = PixelFormat::new(
            root.root_depth,
            root.root_visual,
            layout.bits_per_pixel,
            layout.scanline_pad,
            little,
            [visual.red_mask, visual.green_mask, visual.blue_mask],
        )?;
        conn.randr_select_input(
            root_id,
            randr::NotifyMask::SCREEN_CHANGE
                | randr::NotifyMask::CRTC_CHANGE
                | randr::NotifyMask::OUTPUT_CHANGE
                | randr::NotifyMask::OUTPUT_PROPERTY
                | randr::NotifyMask::RESOURCE_CHANGE,
        )
        .map_err(error)?
        .check()
        .map_err(error)?;
        let original = desktop(&conn, root_id)?;
        let displays = original
            .monitors
            .iter()
            .map(|m| Display {
                source: m.id,
                logical: InputLayout {
                    left: m.rect[0],
                    top: m.rect[1],
                    width: m.rect[2] as u32,
                    height: m.rect[3] as u32,
                },
            })
            .collect();
        let control = X11CaptureControl {
            terminal: Arc::new(AtomicBool::new(false)),
            session: session.as_ref().map(X11Session::state),
        };
        let mut source = Self {
            session,
            conn,
            root: root_id,
            format,
            original,
            displays,
            control,
        };
        source.check_until(until)?;
        Ok(source)
    }
    pub fn displays(&self) -> &[Display] {
        &self.displays
    }
    pub fn control(&self) -> X11CaptureControl {
        self.control.clone()
    }
    fn fail<T>(&mut self, result: io::Result<T>) -> io::Result<T> {
        if result.is_err() {
            let _ = self.close();
        }
        result
    }
    fn changed(&self) -> io::Result<()> {
        for _ in 0..128 {
            match self.conn.poll_for_event().map_err(error)? {
                None => return Ok(()),
                Some(
                    Event::RandrNotify(_) | Event::RandrScreenChangeNotify(_) | Event::Error(_),
                ) => {
                    return Err(denied("X11 display configuration changed"));
                }
                Some(_) => {}
            }
        }
        Err(denied("X11 capture event budget exceeded"))
    }
    fn check_inner(&self, until: Instant) -> io::Result<()> {
        if !self.control.is_active() {
            return Err(denied("X11 capture source is terminal"));
        }
        budget(until)?;
        if let Some(session) = &self.session {
            session.check_until(until)?;
        }
        self.conn.stream().begin_until(until)?;
        self.changed()?;
        if desktop(&self.conn, self.root)? != self.original {
            return Err(denied("X11 capture desktop facts changed"));
        }
        self.changed()?;
        if self
            .session
            .as_ref()
            .is_some_and(|session| !session.is_active())
            || !self.control.is_active()
        {
            return Err(denied("X11 desktop consent ended during the display check"));
        }
        budget(until)
    }
    pub fn check_until(&mut self, until: Instant) -> io::Result<()> {
        let result = self.check_inner(until.min(Instant::now() + IO_BUDGET));
        self.fail(result)
    }
    pub fn capture_until(&mut self, source_id: u32, until: Instant) -> io::Result<RawFrame> {
        let until = until.min(Instant::now() + IO_BUDGET);
        let result = (|| {
            self.check_inner(until)?;
            let monitor = self
                .original
                .monitors
                .iter()
                .find(|m| m.id == source_id)
                .ok_or_else(|| denied("X11 capture source was not in the approved inventory"))?;
            let [x, y, width, height] = monitor.rect;
            let captured_at = Instant::now();
            let stride = self.format.stride(width as u32)?;
            let rows = (MESSAGE_BYTES - 32) / stride;
            if rows == 0 {
                return Err(denied("X11 capture row exceeds reply budget"));
            }
            let mut pixels = Vec::new();
            pixels
                .try_reserve_exact(width as usize * height as usize * 4)
                .map_err(error)?;
            let mut offset = 0usize;
            while offset < height as usize {
                budget(until)?;
                if !self.control.is_active() {
                    return Err(denied("X11 desktop consent ended during frame capture"));
                }
                self.conn.stream().begin_until(until)?;
                self.changed()?;
                let count = rows.min(height as usize - offset);
                let reply = self
                    .conn
                    .get_image(
                        xproto::ImageFormat::Z_PIXMAP,
                        self.root,
                        i16::try_from(x).map_err(error)?,
                        i16::try_from(y + offset as i32).map_err(error)?,
                        width as u16,
                        count as u16,
                        u32::MAX,
                    )
                    .map_err(error)?
                    .reply()
                    .map_err(error)?;
                if reply.depth != self.format.depth || reply.visual != self.format.visual {
                    return Err(denied("X11 image visual/depth changed"));
                }
                self.format
                    .decode(width as u32, count as u32, &reply.data, &mut pixels, until)?;
                offset += count;
            }
            let mut frame = RawFrame {
                source: source_id,
                width: width as u32,
                height: height as u32,
                captured_at,
                pixels,
            };
            self.conn.stream().begin_until(until)?;
            let before = self
                .conn
                .query_pointer(self.root)
                .map_err(error)?
                .reply()
                .map_err(error)?;
            if before.same_screen && before.root == self.root {
                let cursor = self
                    .conn
                    .xfixes_get_cursor_image()
                    .map_err(error)?
                    .reply()
                    .map_err(error)?;
                let after = self
                    .conn
                    .query_pointer(self.root)
                    .map_err(error)?
                    .reply()
                    .map_err(error)?;
                if after.same_screen && after.root == self.root {
                    blend_cursor(&cursor, [x, y], &mut frame, until)?;
                }
            }
            self.check_inner(until)?;
            frame.validate()?;
            if !self.control.is_active() {
                return Err(denied("X11 desktop consent ended before frame publication"));
            }
            Ok(frame)
        })();
        self.fail(result)
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.control.terminal.store(true, Ordering::SeqCst);
        self.conn.stream().terminate();
        self.session.take();
        Ok(())
    }
}
impl Drop for X11CaptureSource {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn decode(format: PixelFormat, w: u32, h: u32, bytes: &[u8]) -> io::Result<Vec<u8>> {
        let mut pixels = Vec::new();
        format.decode(w, h, bytes, &mut pixels, Instant::now() + IO_BUDGET)?;
        Ok(pixels)
    }
    #[test]
    fn truecolor_endian_masks_stride_and_bounds_are_validated() -> io::Result<()> {
        fn send<T: Send + 'static>() {}
        send::<X11CaptureSource>();
        for little in [true, false] {
            let f = PixelFormat::new(16, 1, 16, 32, little, [0xf800, 0x07e0, 0x001f])?;
            let data = if little {
                [0x00, 0xf8, 99, 99, 0xe0, 0x07, 99, 99]
            } else {
                [0xf8, 0x00, 99, 99, 0x07, 0xe0, 99, 99]
            };
            assert_eq!(decode(f, 1, 2, &data)?, [0, 0, 255, 255, 0, 255, 0, 255]);
            assert!(decode(f, 1, 2, &data[..7]).is_err());
        }
        let f = PixelFormat::new(24, 1, 24, 32, true, [0xff0000, 0xff00, 0xff])?;
        assert_eq!(decode(f, 1, 1, &[3, 2, 1, 99])?, [3, 2, 1, 255]);
        let f = PixelFormat::new(24, 1, 24, 8, false, [0xff0000, 0xff00, 0xff])?;
        // Protocol tail padding is independent from the scanline padding.
        assert_eq!(decode(f, 1, 1, &[1, 2, 3, 99])?, [3, 2, 1, 255]);
        assert!(decode(f, 1, 1, &[1, 2, 3, 99, 0, 0, 0, 0]).is_err());
        let f = PixelFormat::new(8, 1, 8, 8, true, [0xe0, 0x1c, 0x03])?;
        assert_eq!(decode(f, 1, 1, &[255, 0, 0, 0])?, [255, 255, 255, 255]);
        let f = PixelFormat::new(24, 1, 32, 32, true, [0xff0000, 0xff00, 0xff])?;
        assert_eq!(decode(f, 1, 1, &[3, 2, 1, 42])?, [3, 2, 1, 255]);
        let f = PixelFormat::new(30, 1, 32, 32, false, [0x3ff00000, 0xffc00, 0x3ff])?;
        assert_eq!(
            decode(f, 1, 1, &0x3ff00000u32.to_be_bytes())?,
            [0, 0, 255, 255]
        );
        assert!(PixelFormat::new(24, 1, 32, 32, true, [0xff0000, 0xff00, 0xff01]).is_err());
        assert!(PixelFormat::new(24, 1, 32, 32, true, [0xf50000, 0xff00, 0xff]).is_err());
        assert!(decode(f, 8192, 8192, &[]).is_err());
        assert!(decode(f, 0, 1, &[]).is_err());
        Ok(())
    }
    #[test]
    fn cursor_hotspot_negative_origin_clipping_and_premultiplied_alpha() -> io::Result<()> {
        let frame = || RawFrame {
            source: 1,
            width: 2,
            height: 2,
            captured_at: Instant::now(),
            pixels: [0, 255, 0, 255].repeat(4),
        };
        let mut cursor = GetCursorImageReply {
            x: -319,
            y: -199,
            width: 2,
            height: 2,
            xhot: 1,
            yhot: 1,
            length: 4,
            cursor_image: vec![0xff0000ff, 0x80800000, 0, 0xffffff00],
            ..Default::default()
        };
        let mut target = frame();
        blend_cursor(
            &cursor,
            [-320, -200],
            &mut target,
            Instant::now() + IO_BUDGET,
        )?;
        assert_eq!(
            target.pixels,
            [
                255, 0, 0, 255, 0, 127, 128, 255, 0, 255, 0, 255, 0, 255, 255, 255
            ]
        );
        cursor.x = 0;
        cursor.y = 0;
        let mut target = frame();
        blend_cursor(&cursor, [0, 0], &mut target, Instant::now() + IO_BUDGET)?;
        assert_eq!(
            target.pixels,
            [
                0, 255, 255, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255, 0, 255
            ]
        );
        let mut target = frame();
        blend_cursor(
            &cursor,
            [i32::MAX, i32::MIN],
            &mut target,
            Instant::now() + IO_BUDGET,
        )?;
        assert_eq!(target.pixels, frame().pixels);
        cursor.cursor_image[0] = 0x00800000;
        assert!(blend_cursor(&cursor, [0, 0], &mut target, Instant::now() + IO_BUDGET).is_err());
        cursor.cursor_image[0] = 0;
        cursor.xhot = cursor.width;
        assert!(blend_cursor(&cursor, [0, 0], &mut target, Instant::now() + IO_BUDGET).is_err());
        cursor.xhot = 0;
        cursor.length = 3;
        assert!(blend_cursor(&cursor, [0, 0], &mut target, Instant::now() + IO_BUDGET).is_err());
        cursor.length = 4;
        assert!(blend_cursor(&cursor, [0, 0], &mut target, Instant::now()).is_err());
        Ok(())
    }
}
