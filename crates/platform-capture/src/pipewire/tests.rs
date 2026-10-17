use super::*;
use nestlink_remote::input::InputLayout;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    process::{Child, Command, Stdio},
};
type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
fn description(kind: u32, width: u32, height: u32, format: u32, stride: i32) -> FrameDescription {
    FrameDescription {
        kind,
        node: 42,
        width,
        height,
        format,
        stride,
        crop_width: width,
        crop_height: height,
        ..Default::default()
    }
}
fn shared(nodes: &[u32]) -> io::Result<Shared> {
    // SAFETY: successful eventfd gets exactly one Rust owner below.
    let cancel = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
    if cancel < 0 {
        return Err(io::Error::last_os_error());
    }
    let started = Instant::now();
    Ok(Shared {
        stopped: AtomicBool::new(false),
        cancel: unsafe { OwnedFd::from_raw_fd(cancel) },
        frames: Mutex::new(Frames {
            queue: VecDeque::new(),
            bytes: 0,
            formats: BTreeMap::new(),
            views: BTreeMap::new(),
            seen: BTreeSet::new(),
        }),
        ended: Mutex::new(WorkerEnd::default()),
        done: Condvar::new(),
        nodes: nodes.iter().copied().collect(),
        started,
        heartbeat: Mutex::new(started),
        active: Box::new(|| true),
        portal: None,
    })
}
fn deliver(shared: &Shared, frame: &FrameDescription, pixels: &[u8]) -> i32 {
    // SAFETY: both borrowed values remain valid during the synchronous callback.
    unsafe {
        receive(
            (shared as *const Shared).cast_mut().cast(),
            frame,
            pixels.as_ptr(),
            pixels.len(),
        )
    }
}

#[test]
fn consent_cancellation_at_every_callback_boundary_keeps_successful_cleanup() -> Result {
    for kind in 0..=3 {
        let mut state = shared(&[42])?;
        state.active = Box::new(|| false);
        let state = Arc::new(state);
        let mut frame = description(kind, 1, 1, 2, 4);
        if kind == 3 {
            frame.stride = 0;
        }
        let data: &[u8] = if kind == 2 { &[1, 2, 3, 255] } else { &[] };
        assert_eq!(deliver(&state, &frame, data), 1, "callback kind {kind}");
        state.finish(Ok(()));
        let mut capture = PortalCapture {
            shared: state.clone(),
            displays: Vec::new(),
            worker: None,
            cleanup_deadline: None,
        };
        capture.reset()?;
        assert!(capture.poll_frame().is_err());
    }

    // Consent ends after pixel conversion and its progress check, just before
    // the final queue lock check. That boundary must also cancel normally.
    let mut state = shared(&[42])?;
    state.receive(description(1, 1, 1, 2, 0), &[])?;
    let checks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let observed = checks.clone();
    state.active = Box::new(move || observed.fetch_add(1, Ordering::SeqCst) < 2);
    assert_eq!(
        deliver(&state, &description(2, 1, 1, 2, 4), &[1, 2, 3, 255]),
        1
    );
    assert_eq!(checks.load(Ordering::SeqCst), 3);
    assert!(
        state
            .frames
            .lock()
            .map_err(|_| "poisoned")?
            .queue
            .is_empty()
    );
    state.finish(Ok(()));
    assert_eq!(state.ended.lock().map_err(|_| "poisoned")?.failure, None);
    Ok(())
}

#[test]
fn callback_failures_and_observed_timeouts_survive_a_successful_cancel_callback() -> Result {
    let state = shared(&[42])?;
    assert_eq!(
        deliver(&state, &description(1, 0, 1, 2, 0), &[]),
        -libc::EINVAL
    );
    assert_eq!(deliver(&state, &FrameDescription::default(), &[]), 1);
    // The C cancellation event may win the next iteration, but it cannot
    // overwrite a failure already observed by Rust.
    state.finish(Ok(()));
    let mut capture = PortalCapture {
        shared: Arc::new(state),
        displays: Vec::new(),
        worker: None,
        cleanup_deadline: None,
    };
    assert_eq!(
        capture.reset().err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidData)
    );

    for polling_detects_timeout in [false, true] {
        let state = shared(&[42])?;
        *state.heartbeat.lock().map_err(|_| "poisoned")? =
            Instant::now() - HEARTBEAT - Duration::from_millis(1);
        if polling_detects_timeout {
            assert_eq!(
                state.check().err().map(|e| e.kind()),
                Some(io::ErrorKind::TimedOut)
            );
        }
        assert_eq!(
            deliver(&state, &FrameDescription::default(), &[]),
            if polling_detects_timeout {
                1
            } else {
                -libc::ETIMEDOUT
            }
        );
        state.finish(Ok(()));
        let mut capture = PortalCapture {
            shared: Arc::new(state),
            displays: Vec::new(),
            worker: None,
            cleanup_deadline: None,
        };
        assert_eq!(
            capture.reset().err().map(|e| e.kind()),
            Some(io::ErrorKind::TimedOut)
        );
    }
    // A native source-loss errno remains a failure even after ordinary stop.
    let state = shared(&[42])?;
    state.stop();
    state.finish(Err(io::Error::from_raw_os_error(libc::ESTALE)));
    assert_eq!(
        state.ended.lock().map_err(|_| "poisoned")?.failure,
        Some(io::ErrorKind::StaleNetworkFileHandle)
    );
    Ok(())
}

#[test]
fn c_bridge_callback_status_has_the_same_meaning_for_format_pixels_and_heartbeat() -> Result {
    let directory = tempfile::Builder::new()
        .prefix("nestlink-pw-cancel-")
        .tempdir()?;
    fs::write(
        directory.path().join("bridge.c"),
        include_str!("../pipewire.c"),
    )?;
    let source = directory.path().join("probe.c");
    fs::write(
        &source,
        r#"
#include "bridge.c"
#include <assert.h>
static int status;
static unsigned int calls;
static uint32_t expected_kind;
static int observe(void *user, const struct nl_frame *frame, const uint8_t *pixels, size_t length) {
    (void)user;
    assert(frame->kind == expected_kind);
    assert((frame->kind == 2) == (pixels != NULL && length == 8));
    ++calls;
    return status;
}
int main(void) {
    pw_init(NULL, NULL);
    const int statuses[] = { 1, -EINVAL, -ETIMEDOUT, -ENOMEM };
    for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); ++i) {
        status = statuses[i];
        for (uint32_t kind = 0; kind <= 3; ++kind) {
            expected_kind = kind;
            struct nl_capture capture = { .callback = observe, .count = 1, .result = -EIO };
            capture.main = pw_main_loop_new(NULL);
            assert(capture.main);
            struct nl_stream *stream = &capture.streams[0];
            *stream = (struct nl_stream) { .owner = &capture, .node = 42, .have_format = true,
                .link_verified = true, .format = 2, .bytes_per_pixel = 4 };
            stream->info.size = SPA_RECTANGLE(2, 1);
            const unsigned int before = calls;
            if (kind == 0) {
                nl_tick(&capture, 1);
            } else if (kind == 1) {
                uint8_t memory[512];
                struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(memory, sizeof(memory));
                const struct spa_rectangle size = SPA_RECTANGLE(2, 1);
                const struct spa_pod *format = spa_pod_builder_add_object(&builder,
                    SPA_TYPE_OBJECT_Format, SPA_PARAM_Format,
                    SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video),
                    SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
                    SPA_FORMAT_VIDEO_format, SPA_POD_Id(SPA_VIDEO_FORMAT_BGRA),
                    SPA_FORMAT_VIDEO_size, SPA_POD_Rectangle(&size));
                nl_format(stream, SPA_PARAM_Format, format);
            } else {
                uint8_t pixels[8] = { 1, 2, 3, 255, 4, 5, 6, 255 };
                struct spa_chunk chunk = { .size = 8, .stride = 8,
                    .flags = kind == 3 ? SPA_CHUNK_FLAG_EMPTY : 0 };
                struct spa_data plane = { .type = SPA_DATA_MemPtr, .flags = SPA_DATA_FLAG_READABLE,
                    .maxsize = 8, .chunk = &chunk, .data = pixels };
                const struct spa_buffer buffer = { .n_datas = 1, .datas = &plane };
                assert(nl_buffer(stream, &buffer) == (status < 0 ? status : 0));
            }
            assert(calls == before + 1);
            assert(capture.closing && capture.result == (status < 0 ? status : 0));
            // Neither a queued cancel nor a later heartbeat replaces the result.
            nl_cancel(&capture, -1, 0);
            nl_tick(&capture, 1);
            assert(calls == before + 1 && capture.result == (status < 0 ? status : 0));
            pw_main_loop_destroy(capture.main);
        }
    }
    struct nl_capture lost = { .count = 1, .result = -EIO };
    lost.main = pw_main_loop_new(NULL);
    assert(lost.main);
    lost.streams[0].node = 42;
    nl_global_remove(&lost, 42);
    assert(lost.closing && lost.result == -ESTALE);
    pw_main_loop_destroy(lost.main);
    pw_deinit();
    return 0;
}
"#,
    )?;
    let mut flags = Command::new("pkg-config");
    flags.args(["--cflags", "--libs", "libpipewire-0.3"]);
    let flags = run_owned(directory.path(), flags, Duration::from_secs(2))?;
    assert!(
        flags.status.success(),
        "{}",
        String::from_utf8_lossy(&flags.stderr)
    );
    let binary = directory.path().join("probe");
    let mut compiler = Command::new("cc");
    compiler
        .args([
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
        ])
        .arg(source)
        .arg("-o")
        .arg(&binary)
        .args(std::str::from_utf8(&flags.stdout)?.split_whitespace());
    let compiled = run_owned(directory.path(), compiler, Duration::from_secs(15))?;
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output = run_owned(
        directory.path(),
        Command::new(binary),
        Duration::from_secs(2),
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn c_bridge_empty_and_gap_replace_old_pixels_with_opaque_black() -> Result {
    // Compile the actual production C bridge into a separate test process.
    // Its internal buffer path is exercised without exporting a bypass API.
    let directory = tempfile::Builder::new()
        .prefix("nestlink-pw-bridge-")
        .tempdir()?;
    fs::write(
        directory.path().join("bridge.c"),
        include_str!("../pipewire.c"),
    )?;
    let source = directory.path().join("probe.c");
    fs::write(
        &source,
        r#"
#include "bridge.c"
#include <assert.h>
#include <stdio.h>
static unsigned int calls;
static int observe(void *user, const struct nl_frame *frame,
                   const uint8_t *pixels, size_t length) {
    (void)user;
    assert(frame->kind == 3 && frame->node == 42 && frame->width == 2 && frame->height == 1);
    assert(frame->format >= 1 && frame->format <= 6 && frame->stride == 0 && pixels == NULL && length == 0);
    assert(frame->first_row == 0 && frame->crop_x == 0 && frame->crop_y == 0);
    assert(frame->crop_width == 2 && frame->crop_height == 1 && frame->transform == 0);
    printf("%u %u %u %u %u\n", frame->kind, frame->node, frame->width, frame->height, frame->format);
    ++calls;
    return 0;
}
int main(void) {
    struct nl_capture capture = { .callback = observe };
    assert(nl_link_count(&capture, 70, 42) == 0);
    capture.links[0] = (struct nl_link) { .id = 101, .input = 70, .output = 42, .present = true };
    assert(nl_link_count(&capture, 70, 42) == 1);
    assert(nl_link_count(&capture, 70, 43) == -ESTALE);
    capture.links[1] = (struct nl_link) { .id = 102, .input = 70, .output = 42, .present = true };
    assert(nl_link_count(&capture, 70, 42) == -ESTALE);
    memset(capture.links, 0, sizeof(capture.links));
    struct nl_stream stream = { .owner = &capture, .node = 42, .have_format = true, .link_verified = true };
    stream.info.size = SPA_RECTANGLE(2, 1);
    struct spa_chunk chunk = {0};
    struct spa_data plane = { .type = SPA_DATA_MemFd, .flags = SPA_DATA_FLAG_READABLE,
                             .maxsize = 8, .chunk = &chunk };
    struct spa_meta_header header = {0};
    struct spa_meta metadata = { .type = SPA_META_Header, .size = sizeof(header), .data = &header };
    struct spa_buffer buffer = { .n_datas = 1, .datas = &plane, .n_metas = 1, .metas = &metadata };
    for (uint32_t format = 1; format <= 6; ++format) {
        stream.format = format;
        stream.bytes_per_pixel = format <= 4 ? 4 : 3;
        /* No mapped pixel pointer and no row stride: neutral flags are enough. */
        chunk.flags = SPA_CHUNK_FLAG_EMPTY;
        header.flags = 0;
        assert(nl_buffer(&stream, &buffer) == 0);
        chunk.flags = 0;
        header.flags = SPA_META_HEADER_FLAG_GAP;
        assert(nl_buffer(&stream, &buffer) == 0);
    }
    assert(calls == 12);
    stream.link_verified = false;
    assert(nl_buffer(&stream, &buffer) == 0 && calls == 12);
    stream.link_verified = true;
    /* Absent/corrupted data does not synthesize an update or read a pointer. */
    header.flags = 0;
    assert(nl_buffer(&stream, &buffer) == 0 && calls == 12);
    chunk.flags = SPA_CHUNK_FLAG_EMPTY | SPA_CHUNK_FLAG_CORRUPTED;
    assert(nl_buffer(&stream, &buffer) == 0 && calls == 12);
    chunk.flags = SPA_CHUNK_FLAG_EMPTY;
    header.flags = SPA_META_HEADER_FLAG_CORRUPTED | SPA_META_HEADER_FLAG_GAP;
    assert(nl_buffer(&stream, &buffer) == 0 && calls == 12);
    /* A real nonempty frame still must have a mapped payload and valid stride. */
    chunk.flags = 0;
    chunk.size = 6;
    header.flags = 0;
    assert(nl_buffer(&stream, &buffer) == -EINVAL && calls == 12);
    return 0;
}
"#,
    )?;
    let mut flags = Command::new("pkg-config");
    flags.args(["--cflags", "--libs", "libpipewire-0.3"]);
    let flags = run_owned(directory.path(), flags, Duration::from_secs(2))?;
    assert!(
        flags.status.success(),
        "{}",
        String::from_utf8_lossy(&flags.stderr)
    );
    let binary = directory.path().join("probe");
    let mut compiler = Command::new("cc");
    compiler
        .args([
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .args(std::str::from_utf8(&flags.stdout)?.split_whitespace());
    let compiled = run_owned(directory.path(), compiler, Duration::from_secs(15))?;
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output = run_owned(
        directory.path(),
        Command::new(&binary),
        Duration::from_secs(2),
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let events: Vec<_> = std::str::from_utf8(&output.stdout)?.lines().collect();
    assert_eq!(events.len(), 12);
    for line in events {
        let fields = line
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(fields.len(), 5);
        let shared = shared(&[42])?;
        shared.receive(description(1, 2, 1, fields[4], 0), &[])?;
        shared.receive(description(2, 2, 1, fields[4], 8), &[255; 8])?;
        // Forward the event produced by C through the same Rust ABI callback.
        assert_eq!(
            deliver(
                &shared,
                &description(fields[0], fields[2], fields[3], fields[4], 0),
                &[]
            ),
            0
        );
        let frames = shared.frames.lock().map_err(|_| "poisoned")?;
        assert_eq!(frames.queue.len(), 1);
        assert_eq!(frames.bytes, 8);
        assert_eq!(frames.queue[0].pixels, [0, 0, 0, 255, 0, 0, 0, 255]);
    }
    Ok(())
}

#[test]
fn packed_pixels_preserve_padding_channel_order_and_reject_short_planes() -> Result {
    let data = [10, 20, 30, 40, 99, 99, 99, 99, 50, 60, 70, 80];
    assert_eq!(
        packed_bgra(description(2, 1, 2, 1, 8), &data)?,
        [10, 20, 30, 255, 50, 60, 70, 255]
    );
    assert_eq!(
        packed_bgra(description(2, 1, 2, 2, 8), &data)?,
        [10, 20, 30, 40, 50, 60, 70, 80]
    );
    assert_eq!(
        packed_bgra(description(2, 1, 2, 3, 8), &data)?,
        [30, 20, 10, 255, 70, 60, 50, 255]
    );
    assert_eq!(
        packed_bgra(description(2, 1, 2, 4, 8), &data)?,
        [30, 20, 10, 40, 70, 60, 50, 80]
    );
    assert_eq!(
        packed_bgra(description(2, 1, 2, 5, 8), &data)?,
        [30, 20, 10, 255, 70, 60, 50, 255]
    );
    assert_eq!(
        packed_bgra(description(2, 1, 2, 6, 8), &data)?,
        [10, 20, 30, 255, 50, 60, 70, 255]
    );
    for (w, h, s, d) in [
        (1, 2, 8, &data[..11]),
        (2, 1, 4, &data[..]),
        (1, 2, -4, &data[..]),
        (8192, 8192, 32768, &data[..]),
    ] {
        assert!(packed_bgra(description(2, w, h, 2, s), d).is_err());
    }
    Ok(())
}
#[test]
fn c_bridge_signed_rows_crop_and_all_buffer_transforms_preserve_pixel_positions() -> Result {
    let directory = tempfile::Builder::new()
        .prefix("nestlink-pw-layout-")
        .tempdir()?;
    fs::write(
        directory.path().join("bridge.c"),
        include_str!("../pipewire.c"),
    )?;
    let source = directory.path().join("probe.c");
    fs::write(
        &source,
        r#"
#include "bridge.c"
#include <assert.h>
#include <stdio.h>
_Static_assert(sizeof(struct nl_frame) == 48, "frame ABI");
_Static_assert(sizeof(struct nl_target) == 16 && offsetof(struct nl_target, node) == 0
    && offsetof(struct nl_target, reserved) == 4 && offsetof(struct nl_target, serial) == 8, "target ABI");
static unsigned int calls;
static bool inspect_full_crop;
static int observe(void *user, const struct nl_frame *frame, const uint8_t *pixels, size_t length) {
    (void)user;
    assert(frame->kind == 2 && length == 56);
    if (inspect_full_crop) {
        assert(frame->crop_x == 0 && frame->crop_y == 0);
        assert(frame->crop_width == 4 && frame->crop_height == 3 && frame->transform == 0);
        ++calls;
        return 0;
    }
    uint32_t count = length;
    assert(fwrite(frame, sizeof(*frame), 1, stdout) == 1);
    assert(fwrite(&count, sizeof(count), 1, stdout) == 1);
    assert(fwrite(pixels, length, 1, stdout) == 1);
    ++calls;
    return 0;
}
int main(void) {
    struct pw_properties *props = pw_properties_new(NULL, NULL);
    assert(props);
    uint32_t target_id;
    struct nl_target target = { .node = 42, .serial = UINT64_MAX };
    assert(nl_target_properties(props, &target, &target_id) == 0 && target_id == PW_ID_ANY);
    assert(!strcmp(pw_properties_get(props, PW_KEY_TARGET_OBJECT), "18446744073709551615"));
    target.serial = UINT64_C(4294967296);
    assert(nl_target_properties(props, &target, &target_id) == 0 && target_id == PW_ID_ANY);
    assert(!strcmp(pw_properties_get(props, PW_KEY_TARGET_OBJECT), "4294967296"));
    target.reserved = 1;
    assert(nl_target_properties(props, &target, &target_id) == -EINVAL);
    pw_properties_free(props);
    props = pw_properties_new(NULL, NULL);
    assert(props);
    target = (struct nl_target) { .node = 42 };
    assert(nl_target_properties(props, &target, &target_id) == 0 && target_id == 42);
    assert(pw_properties_get(props, PW_KEY_TARGET_OBJECT) == NULL);
    pw_properties_free(props);
    struct nl_capture capture = { .callback = observe };
    struct nl_stream stream = { .owner = &capture, .node = 42, .have_format = true, .link_verified = true,
                               .format = 2, .bytes_per_pixel = 4 };
    stream.info.size = SPA_RECTANGLE(4, 3);
    uint8_t memory[64];
    struct spa_chunk chunk = { .offset = 4, .size = 56, .stride = 20 };
    struct spa_data plane = { .type = SPA_DATA_MemPtr, .flags = SPA_DATA_FLAG_READABLE,
                             .data = memory, .maxsize = sizeof(memory), .chunk = &chunk };
    struct spa_meta_header header = {0};
    struct spa_meta_region crop = { .region = SPA_REGION(1, 0, 2, 3) };
    struct spa_meta_videotransform transform = {0};
    /* Metadata is deliberately unaligned, as the bridge promises scalar copies. */
    uint8_t crop_storage[sizeof(crop) + 1];
    memcpy(crop_storage + 1, &crop, sizeof(crop));
    struct spa_meta metas[4] = {
        { .type = SPA_META_Header, .size = sizeof(header), .data = &header },
        { .type = SPA_META_VideoCrop, .size = sizeof(crop), .data = crop_storage + 1 },
        { .type = SPA_META_VideoTransform, .size = sizeof(transform), .data = &transform },
    };
    struct spa_buffer buffer = { .n_datas = 1, .datas = &plane, .n_metas = 3, .metas = metas };
    for (unsigned int negative = 0; negative < 2; ++negative) {
        memset(memory, 199, sizeof(memory));
        for (unsigned int y = 0; y < 3; ++y) for (unsigned int x = 0; x < 4; ++x) {
            unsigned int row = negative ? 2 - y : y;
            uint8_t *p = memory + 4 + row * 20 + x * 4;
            p[0] = y * 4 + x + 1; p[1] = 21; p[2] = 31; p[3] = 255;
        }
        /* Offset is modulo maxsize; oversized chunk sizes are clamped per SPA. */
        chunk.offset = (negative ? 44 : 4) + sizeof(memory);
        chunk.size = UINT32_MAX;
        chunk.stride = negative ? -20 : 20;
        plane.type = negative ? SPA_DATA_MemFd : SPA_DATA_MemPtr;
        for (uint32_t t = 0; t < 8; ++t) {
            transform.transform = t;
            assert(nl_buffer(&stream, &buffer) == 0);
        }
    }
    assert(calls == 16);
    /* Negative first-row underflow, short rows, insufficient bytes and wrap. */
    transform.transform = 0;
    chunk.offset = 4; chunk.size = 56; chunk.stride = -20;
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    chunk.offset = 44; chunk.stride = INT32_MIN;
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    chunk.stride = -12;
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    chunk.stride = -20; chunk.size = 55;
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    chunk.stride = 20; chunk.size = 56; chunk.offset = 9;
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    chunk.offset = 4;
    transform.transform = 8;
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    transform.transform = 0;
    crop.region.position.x = -1;
    memcpy(crop_storage + 1, &crop, sizeof(crop));
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    crop.region.position.x = 3;
    memcpy(crop_storage + 1, &crop, sizeof(crop));
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    crop.region.position.x = 1; crop.region.size.height = 4;
    memcpy(crop_storage + 1, &crop, sizeof(crop));
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    crop.region.size.height = 3;
    memcpy(crop_storage + 1, &crop, sizeof(crop));
    for (unsigned int i = 0; i < 3; ++i) {
        uint32_t size = metas[i].size;
        metas[i].size = size - 1;
        assert(nl_buffer(&stream, &buffer) == -EINVAL);
        metas[i].size = size;
        void *data = metas[i].data; metas[i].data = NULL;
        assert(nl_buffer(&stream, &buffer) == -EINVAL);
        metas[i].data = data;
        metas[3] = metas[i]; buffer.n_metas = 4;
        assert(nl_buffer(&stream, &buffer) == -EINVAL);
        buffer.n_metas = 3;
    }
    assert(calls == 16);
    /* A zero-extent region is inactive per SPA, as is absent metadata. */
    inspect_full_crop = true;
    crop.region.size.width = 0;
    memcpy(crop_storage + 1, &crop, sizeof(crop));
    assert(nl_buffer(&stream, &buffer) == 0);
    buffer.n_metas = 0;
    assert(nl_buffer(&stream, &buffer) == 0);
    assert(calls == 18);
    crop.region.size.width = 2;
    memcpy(crop_storage + 1, &crop, sizeof(crop));
    buffer.n_metas = 3;
    plane.type = SPA_DATA_DmaBuf;
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    plane.type = SPA_DATA_MemFd;
    plane.flags = 0;
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    plane.flags = SPA_DATA_FLAG_READABLE;
    plane.maxsize = NL_LIMIT + 1;
    assert(nl_buffer(&stream, &buffer) == -EINVAL);
    return 0;
}
"#,
    )?;
    let mut flags = Command::new("pkg-config");
    flags.args(["--cflags", "--libs", "libpipewire-0.3"]);
    let flags = run_owned(directory.path(), flags, Duration::from_secs(2))?;
    assert!(
        flags.status.success(),
        "{}",
        String::from_utf8_lossy(&flags.stderr)
    );
    let binary = directory.path().join("probe");
    let mut compiler = Command::new("cc");
    compiler
        .args([
            "-std=gnu11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-fsanitize=address,undefined",
        ])
        .arg(source)
        .arg("-o")
        .arg(&binary)
        .args(std::str::from_utf8(&flags.stdout)?.split_whitespace());
    let compiled = run_owned(directory.path(), compiler, Duration::from_secs(15))?;
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let output = run_owned(
        directory.path(),
        Command::new(binary),
        Duration::from_secs(2),
    )?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(size_of::<FrameDescription>(), 48);
    assert_eq!(size_of::<CaptureTarget>(), 16);
    assert_eq!(std::mem::offset_of!(CaptureTarget, node), 0);
    assert_eq!(std::mem::offset_of!(CaptureTarget, reserved), 4);
    assert_eq!(std::mem::offset_of!(CaptureTarget, serial), 8);
    assert_eq!(output.stdout.len(), 16 * (48 + 4 + 56));
    // Handwritten non-square expectations distinguish rotation direction and
    // reflection order; crop removes the first/last raw pixel of every row.
    let expected = [
        [2, 3, 6, 7, 10, 11],
        [10, 6, 2, 11, 7, 3],
        [11, 10, 7, 6, 3, 2],
        [3, 7, 11, 2, 6, 10],
        [3, 2, 7, 6, 11, 10],
        [2, 6, 10, 3, 7, 11],
        [10, 11, 6, 7, 2, 3],
        [11, 7, 3, 10, 6, 2],
    ];
    for (index, event) in output.stdout.chunks_exact(108).enumerate() {
        let scalars: Vec<u32> = event[..52]
            .chunks_exact(4)
            .map(|value| u32::from_ne_bytes([value[0], value[1], value[2], value[3]]))
            .collect();
        let frame = FrameDescription {
            kind: scalars[0],
            node: scalars[1],
            width: scalars[2],
            height: scalars[3],
            format: scalars[4],
            stride: scalars[5] as i32,
            first_row: scalars[6],
            crop_x: scalars[7],
            crop_y: scalars[8],
            crop_width: scalars[9],
            crop_height: scalars[10],
            transform: scalars[11],
        };
        assert_eq!(scalars[12], 56);
        assert_eq!(frame.first_row, if index < 8 { 0 } else { 40 });
        assert_eq!(frame.stride, if index < 8 { 20 } else { -20 });
        let shared = shared(&[42])?;
        assert_eq!(deliver(&shared, &description(1, 4, 3, 2, 0), &[]), 0);
        assert_eq!(deliver(&shared, &frame, &event[52..]), 0);
        let frames = shared.frames.lock().map_err(|_| "poisoned")?;
        let received = frames.queue.front().ok_or("missing frame")?;
        received.validate()?;
        assert_eq!(
            (received.width, received.height),
            if index % 2 == 0 { (2, 3) } else { (3, 2) }
        );
        let positions: Vec<_> = received.pixels.chunks_exact(4).map(|p| p[0]).collect();
        assert_eq!(positions, expected[index % 8]);
        assert!(
            received
                .pixels
                .chunks_exact(4)
                .all(|p| p[1..] == [21, 31, 255])
        );
    }
    Ok(())
}

#[test]
fn layout_changes_end_session_and_cropping_never_relaxes_raw_budget() -> Result {
    for (x, transform) in [(1, 0), (0, 2)] {
        let shared = shared(&[42])?;
        assert_eq!(deliver(&shared, &description(1, 3, 2, 2, 0), &[]), 0);
        let mut frame = description(2, 3, 2, 2, 12);
        frame.crop_width = 2;
        assert_eq!(deliver(&shared, &frame, &[255; 24]), 0);
        frame.crop_x = x;
        frame.transform = transform;
        assert_eq!(deliver(&shared, &frame, &[255; 24]), -libc::EINVAL);
        assert!(shared.stopped.load(Ordering::SeqCst));
        assert!(
            shared
                .frames
                .lock()
                .map_err(|_| "poisoned")?
                .queue
                .is_empty()
        );
        assert_eq!(deliver(&shared, &FrameDescription::default(), &[]), 1);
    }
    let shared = shared(&[42, 43, 44])?;
    for node in [42, 43, 44] {
        let mut frame = description(1, 4096, 4096, 2, 0);
        frame.node = node;
        frame.crop_width = 1;
        frame.crop_height = 1;
        assert_eq!(
            deliver(&shared, &frame, &[]),
            if node == 44 { -libc::ENOMEM } else { 0 }
        );
    }
    assert!(shared.stopped.load(Ordering::SeqCst));
    assert!(packed_bgra(description(2, 8192, 8192, 2, 32768), &[255; 4]).is_err());
    Ok(())
}

#[test]
fn negative_padding_can_change_without_changing_layout_and_neutral_uses_final_dimensions() -> Result
{
    let shared = shared(&[42])?;
    assert_eq!(deliver(&shared, &description(1, 2, 3, 2, 0), &[]), 0);
    let mut frame = description(2, 2, 3, 2, 8);
    frame.transform = 1;
    assert_eq!(deliver(&shared, &frame, &[255; 24]), 0);
    frame.stride = -12;
    frame.first_row = 24;
    assert_eq!(deliver(&shared, &frame, &[255; 32]), 0);
    frame.kind = 3;
    frame.stride = 0;
    frame.first_row = 0;
    assert_eq!(deliver(&shared, &frame, &[]), 0);
    let frames = shared.frames.lock().map_err(|_| "poisoned")?;
    assert_eq!(frames.queue.len(), 1);
    let received = &frames.queue[0];
    assert_eq!((received.width, received.height), (3, 2));
    assert_eq!(received.pixels, [0, 0, 0, 255].repeat(6));
    Ok(())
}

#[test]
fn replacement_preserves_monitor_turn_and_repeated_reset_has_one_deadline() -> Result {
    let shared = Arc::new(shared(&[42, 43])?);
    for node in [42, 43] {
        let mut format = description(1, 1, 1, 2, 0);
        format.node = node;
        assert_eq!(deliver(&shared, &format, &[]), 0);
        format.kind = 2;
        format.stride = 4;
        assert_eq!(deliver(&shared, &format, &[1, 2, 3, 255]), 0);
    }
    let mut capture = PortalCapture {
        shared: shared.clone(),
        displays: Vec::new(),
        worker: None,
        cleanup_deadline: None,
    };
    assert_eq!(
        deliver(&shared, &description(2, 1, 1, 2, 4), &[4, 5, 6, 255]),
        0
    );
    let first = capture.poll_frame()?.ok_or("missing first source")?;
    assert_eq!(first.source, 42);
    assert_eq!(first.pixels, [4, 5, 6, 255]);
    assert_eq!(
        deliver(&shared, &description(2, 1, 1, 2, 4), &[7, 8, 9, 255]),
        0
    );
    assert_eq!(
        capture.poll_frame()?.ok_or("missing second source")?.source,
        43
    );
    assert_eq!(
        capture.reset().err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    let deadline = capture.cleanup_deadline;
    let started = Instant::now();
    assert_eq!(
        capture.reset().err().map(|e| e.kind()),
        Some(io::ErrorKind::TimedOut)
    );
    assert_eq!(capture.cleanup_deadline, deadline);
    assert!(
        started.elapsed() < CLEANUP / 2,
        "second reset renewed the cleanup budget"
    );
    assert!(
        shared
            .frames
            .lock()
            .map_err(|_| "poisoned")?
            .queue
            .is_empty()
    );
    assert!(capture.poll_frame().is_err());
    Ok(())
}

#[test]
fn consent_loss_between_poll_check_and_queue_lock_discards_pending_pixels() -> Result {
    use std::sync::atomic::AtomicUsize;
    let mut state = shared(&[42])?;
    let armed = Arc::new(AtomicBool::new(false));
    let checks = Arc::new(AtomicUsize::new(0));
    let observed_arm = armed.clone();
    let observed_checks = checks.clone();
    state.active = Box::new(move || {
        !observed_arm.load(Ordering::SeqCst) || observed_checks.fetch_add(1, Ordering::SeqCst) == 0
    });
    let shared = Arc::new(state);
    assert_eq!(deliver(&shared, &description(1, 1, 1, 2, 0), &[]), 0);
    assert_eq!(
        deliver(&shared, &description(2, 1, 1, 2, 4), &[1, 2, 3, 255]),
        0
    );
    let mut capture = PortalCapture {
        shared: shared.clone(),
        displays: Vec::new(),
        worker: None,
        cleanup_deadline: None,
    };
    // The first active read in check succeeds; consent ends before the second
    // read under the queue lock. No worker or consumer pre-check can hide it.
    armed.store(true, Ordering::SeqCst);
    assert_eq!(
        capture.poll_frame().err().map(|e| e.kind()),
        Some(io::ErrorKind::PermissionDenied)
    );
    assert_eq!(checks.load(Ordering::SeqCst), 2);
    assert!(shared.stopped.load(Ordering::SeqCst));
    let frames = shared.frames.lock().map_err(|_| "poisoned")?;
    assert!(frames.queue.is_empty());
    assert_eq!(frames.bytes, 0);
    drop(frames);
    armed.store(false, Ordering::SeqCst);
    assert!(capture.poll_frame().is_err());
    shared.finish(Ok(()));
    capture.reset()?;
    Ok(())
}

struct Daemon {
    directory: tempfile::TempDir,
    child: Child,
}
impl Daemon {
    fn new() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("nestlink-pw-owned-")
            .tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        let config = directory.path().join("capture.conf");
        fs::write(&config, include_str!("../../tests/pipewire-owned.conf"))?;
        let log = fs::File::create(directory.path().join("daemon.log"))?;
        let child = Command::new("pipewire")
            .arg("--config")
            .arg(&config)
            .env("XDG_RUNTIME_DIR", directory.path())
            .env("PIPEWIRE_RUNTIME_DIR", directory.path())
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log))
            .spawn()?;
        let mut owned = Self { directory, child };
        let started = Instant::now();
        while !owned.socket().exists() {
            if owned.child.try_wait()?.is_some() || started.elapsed() > Duration::from_secs(3) {
                return Err(format!(
                    "owned PipeWire failed: {}",
                    fs::read_to_string(owned.directory.path().join("daemon.log"))?
                )
                .into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(owned)
    }
    fn socket(&self) -> std::path::PathBuf {
        self.directory.path().join("nestlink-capture-fixture")
    }
    fn command(&self, binary: &str) -> Command {
        let mut command = Command::new(binary);
        command
            .env("XDG_RUNTIME_DIR", self.directory.path())
            .env("PIPEWIRE_RUNTIME_DIR", self.directory.path())
            .env("PIPEWIRE_REMOTE", "nestlink-capture-fixture");
        command
    }
    fn source(&self) -> Result<CaptureTarget> {
        self.source_named("nestlink-owned-video")
    }
    fn source_named(&self, name: &str) -> Result<CaptureTarget> {
        let output = self.run(self.command("pw-dump"))?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }
        let objects: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        objects
            .as_array()
            .ok_or("invalid dump")?
            .iter()
            .find_map(|v| {
                if v["info"]["props"]["node.name"] != name {
                    return None;
                }
                Some(CaptureTarget {
                    node: u32::try_from(v["id"].as_u64()?).ok()?,
                    reserved: 0,
                    serial: v["info"]["props"]["object.serial"].as_u64()?,
                })
            })
            .ok_or_else(|| "owned source missing".into())
    }
    fn ports_for(&self, consumer_target: u64, output_node: u32) -> Result<Option<(u32, u32)>> {
        let output = self.run(self.command("pw-dump"))?;
        let objects: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        let objects = objects.as_array().ok_or("invalid dump")?;
        let consumer = objects.iter().find_map(|v| {
            let target = &v["info"]["props"]["target.object"];
            (v["info"]["props"]["node.name"] == "nestlink-portal-capture"
                && (target.as_u64() == Some(consumer_target)
                    || target.as_str() == Some(consumer_target.to_string().as_str())))
            .then(|| v["id"].as_u64())
            .flatten()
        });
        let Some(consumer) = consumer else {
            return Ok(None);
        };
        let port = |node: u64, direction: &str| {
            objects.iter().find_map(|v| {
                (v["type"] == "PipeWire:Interface:Port"
                    && v["info"]["props"]["node.id"].as_u64() == Some(node)
                    && v["info"]["props"]["port.direction"] == direction)
                    .then(|| v["id"].as_u64())
                    .flatten()
                    .and_then(|n| u32::try_from(n).ok())
            })
        };
        Ok(port(u64::from(output_node), "out").zip(port(consumer, "in")))
    }
    fn link_target(&self, consumer_target: u64, output_node: u32) -> Result {
        let started = Instant::now();
        loop {
            if let Some((output, input)) = self.ports_for(consumer_target, output_node)? {
                let mut command = self.command("pw-link");
                command.args([output.to_string(), input.to_string()]);
                let linked = self.run(command)?;
                if linked.status.success() {
                    return Ok(());
                }
                if started.elapsed() > Duration::from_secs(2) {
                    return Err(format!(
                        "owned graph link failed: {}",
                        String::from_utf8_lossy(&linked.stderr)
                    )
                    .into());
                }
            }
            if started.elapsed() > Duration::from_secs(2) {
                return Err("owned graph ports missing".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
    fn link(&self) -> Result {
        let started = Instant::now();
        loop {
            let mut command = self.command("pw-link");
            command.args([
                "nestlink-owned-video:capture_1",
                "nestlink-portal-capture:input_1",
            ]);
            let output = self.run(command)?;
            if output.status.success() {
                return Ok(());
            }
            if started.elapsed() > Duration::from_secs(3) {
                let mut inventory = self.command("pw-link");
                inventory.args(["-I", "-o", "-i"]);
                let ports = self.run(inventory)?;
                return Err(format!(
                    "fixture link failed: {}; ports: {}",
                    String::from_utf8_lossy(&output.stderr),
                    String::from_utf8_lossy(&ports.stdout)
                )
                .into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
    fn run(&self, command: Command) -> Result<std::process::Output> {
        run_owned(self.directory.path(), command, Duration::from_secs(2))
    }
}
fn run_owned(
    directory: &std::path::Path,
    mut command: Command,
    budget: Duration,
) -> Result<std::process::Output> {
    let stdout = tempfile::NamedTempFile::new_in(directory)?;
    let stderr = tempfile::NamedTempFile::new_in(directory)?;
    let mut child = command
        .stdout(Stdio::from(stdout.reopen()?))
        .stderr(Stdio::from(stderr.reopen()?))
        .spawn()?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if started.elapsed() > budget
            || stdout.as_file().metadata()?.len() > 4 * 1024 * 1024
            || stderr.as_file().metadata()?.len() > 65536
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err("owned PipeWire tool exceeded time/output budget".into());
        }
        thread::sleep(Duration::from_millis(5));
    };
    if stdout.as_file().metadata()?.len() > 4 * 1024 * 1024
        || stderr.as_file().metadata()?.len() > 65536
    {
        return Err("owned PipeWire tool exceeded output budget".into());
    }
    Ok(std::process::Output {
        status,
        stdout: fs::read(stdout.path())?,
        stderr: fs::read(stderr.path())?,
    })
}
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
#[test]
fn actual_owned_pipewire_pixels_revocation_and_source_loss_are_terminal() -> Result {
    for (cause, bind_serial) in [
        ("revoked", false),
        ("server", false),
        ("link", false),
        ("source", false),
        ("revoked", true),
        ("server", true),
        ("link", true),
        ("source", true),
    ] {
        let mut daemon = Daemon::new()?;
        let mut target = daemon.source()?;
        let source = target.node;
        if !bind_serial {
            target.serial = 0;
        }
        let active = Arc::new(AtomicBool::new(true));
        let observed = active.clone();
        let fd: OwnedFd = UnixStream::connect(daemon.socket())?.into();
        let mut capture = PortalCapture::start(
            fd,
            vec![Display {
                source,
                logical: InputLayout {
                    left: -320,
                    top: 0,
                    width: 320,
                    height: 240,
                },
            }],
            vec![target],
            Box::new(move || observed.load(Ordering::SeqCst)),
            None,
        )?;
        daemon.link()?;
        let started = Instant::now();
        let frame = loop {
            if let Some(frame) = capture.poll_frame()? {
                break frame;
            }
            if started.elapsed() >= Duration::from_secs(4) {
                let dump = daemon.run(daemon.command("pw-dump"))?;
                return Err(format!(
                    "owned source supplied no pixels; {}",
                    String::from_utf8_lossy(&dump.stdout)
                )
                .into());
            }
            thread::sleep(Duration::from_millis(5));
        };
        frame.validate()?;
        assert_eq!(frame.source, source);
        if bind_serial {
            let dump = daemon.run(daemon.command("pw-dump"))?;
            let objects: serde_json::Value = serde_json::from_slice(&dump.stdout)?;
            let consumer = objects
                .as_array()
                .ok_or("invalid dump")?
                .iter()
                .find(|v| v["info"]["props"]["node.name"] == "nestlink-portal-capture")
                .ok_or("missing consumer")?;
            let requested = &consumer["info"]["props"]["target.object"];
            assert!(
                requested.as_u64() == Some(target.serial)
                    || requested.as_str() == Some(target.serial.to_string().as_str())
            );
        }
        assert!(frame.width > 0 && frame.height > 0);
        assert!(
            frame
                .pixels
                .chunks_exact(4)
                .any(|p| p[0] != 0 || p[1] != 0 || p[2] != 0)
        );
        if cause == "server" {
            daemon.child.kill()?;
            daemon.child.wait()?;
        } else if cause == "revoked" {
            active.store(false, Ordering::SeqCst);
        } else {
            let output = if cause == "link" {
                let mut command = daemon.command("pw-link");
                command.args([
                    "-d",
                    "nestlink-owned-video:capture_1",
                    "nestlink-portal-capture:input_1",
                ]);
                daemon.run(command)?
            } else {
                let mut command = daemon.command("pw-cli");
                command.args(["destroy", &source.to_string()]);
                daemon.run(command)?
            };
            assert!(
                output.status.success(),
                "{cause}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                daemon.child.try_wait()?.is_none(),
                "owned daemon must survive {cause} loss"
            );
        }
        let started = Instant::now();
        while capture.check().is_ok() && started.elapsed() < Duration::from_secs(1) {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(
            capture.check().is_err(),
            "capture remained active after {cause} loss"
        );
        assert!(capture.poll_frame().is_err());
        if cause == "source" && bind_serial {
            let mut command = daemon.command("pw-cli");
            command.args(["create-node", "spa-node-factory",
                "{ factory.name = videotestsrc node.name = nestlink-owned-video media.class = Video/Source node.driver = true object.linger = true }"]);
            let created = daemon.run(command)?;
            assert!(
                created.status.success(),
                "{}",
                String::from_utf8_lossy(&created.stderr)
            );
            let replacement = daemon.source()?;
            assert_ne!(replacement.serial, target.serial);
            assert!(capture.check().is_err());
            assert!(
                capture.poll_frame().is_err(),
                "replacement revived the old grant"
            );
        }
        let reset = capture.reset();
        assert!(
            !reset
                .as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::TimedOut),
            "{cause} cleanup exceeded its budget"
        );
        if cause != "server" {
            if cause == "revoked" {
                reset?;
            }
            let dump = daemon.run(daemon.command("pw-dump"))?;
            let objects: serde_json::Value = serde_json::from_slice(&dump.stdout)?;
            assert!(
                !objects
                    .as_array()
                    .ok_or("invalid dump")?
                    .iter()
                    .any(|v| v["info"]["props"]["node.name"] == "nestlink-portal-capture")
            );
        }
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(
            capture
                .shared
                .frames
                .lock()
                .map_err(|_| "poisoned")?
                .queue
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn wrong_serial_never_falls_back_to_valid_node_and_targets_must_match_grant() -> Result {
    let daemon = Daemon::new()?;
    let target = daemon.source()?;
    let display = Display {
        source: target.node,
        logical: InputLayout {
            left: 0,
            top: 0,
            width: 320,
            height: 240,
        },
    };
    for serial in [target.serial + (1u64 << 32), u64::MAX] {
        let fd = UnixStream::connect(daemon.socket())?.into();
        let mut capture = PortalCapture::start(
            fd,
            vec![display],
            vec![CaptureTarget { serial, ..target }],
            Box::new(|| true),
            None,
        )?;
        let started = Instant::now();
        loop {
            match capture.poll_frame() {
                Err(_) => break,
                Ok(Some(_)) => return Err("wrong serial delivered a valid node's pixels".into()),
                Ok(None) => {}
            }
            if started.elapsed() > Duration::from_secs(1) {
                return Err("wrong serial did not terminate after registry verification".into());
            }
            // This private daemon has no session manager; even an explicit
            // link to the numerically correct node must not bypass the serial.
            let mut link = daemon.command("pw-link");
            link.args([
                "nestlink-owned-video:capture_1",
                "nestlink-portal-capture:input_1",
            ]);
            let _ = daemon.run(link)?;
        }
        let reset = capture.reset();
        assert!(
            !reset
                .as_ref()
                .is_err_and(|e| e.kind() == io::ErrorKind::TimedOut)
        );
        assert!(capture.poll_frame().is_err());
        assert!(
            capture
                .shared
                .frames
                .lock()
                .map_err(|_| "poisoned")?
                .queue
                .is_empty()
        );
        assert_eq!(
            daemon.source()?.serial,
            target.serial,
            "authorized test source must remain alive"
        );
    }
    for targets in [
        vec![],
        vec![CaptureTarget {
            node: target.node + 1,
            ..target
        }],
        vec![target, target],
        vec![CaptureTarget {
            reserved: 1,
            ..target
        }],
    ] {
        let fd = UnixStream::connect(daemon.socket())?.into();
        assert!(PortalCapture::start(fd, vec![display], targets, Box::new(|| true), None).is_err());
    }
    Ok(())
}

#[test]
fn actual_link_from_a_second_source_never_uses_the_first_sources_identity() -> Result {
    let daemon = Daemon::new()?;
    let first = daemon.source()?;
    let mut command = daemon.command("pw-cli");
    command.args(["create-node", "spa-node-factory",
        "{ factory.name = videotestsrc node.name = nestlink-second-video media.class = Video/Source node.driver = true object.linger = true }"]);
    let created = daemon.run(command)?;
    assert!(
        created.status.success(),
        "{}",
        String::from_utf8_lossy(&created.stderr)
    );
    let fd = UnixStream::connect(daemon.socket())?.into();
    let mut capture = PortalCapture::start(
        fd,
        vec![Display {
            source: first.node,
            logical: InputLayout {
                left: 0,
                top: 0,
                width: 320,
                height: 240,
            },
        }],
        vec![first],
        Box::new(|| true),
        None,
    )?;
    let started = Instant::now();
    loop {
        let mut command = daemon.command("pw-link");
        command.args([
            "nestlink-second-video:capture_1",
            "nestlink-portal-capture:input_1",
        ]);
        if daemon.run(command)?.status.success() {
            break;
        }
        if started.elapsed() > Duration::from_secs(2) {
            return Err("second source link unavailable".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    let started = Instant::now();
    loop {
        match capture.poll_frame() {
            Err(_) => break,
            Ok(Some(_)) => {
                return Err(
                    "second source pixels were mislabeled as the first authorized source".into(),
                );
            }
            Ok(None) => {}
        }
        if started.elapsed() > Duration::from_secs(1) {
            return Err("mismatched link did not terminate".into());
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        capture
            .shared
            .frames
            .lock()
            .map_err(|_| "poisoned")?
            .queue
            .is_empty()
    );
    Ok(())
}

#[test]
fn two_approved_sources_cannot_cross_link_or_add_another_edge_to_a_consumer() -> Result {
    for extra_after_valid in [false, true] {
        let daemon = Daemon::new()?;
        let first = daemon.source()?;
        let mut command = daemon.command("pw-cli");
        command.args(["create-node", "spa-node-factory",
            "{ factory.name = videotestsrc node.name = nestlink-second-video media.class = Video/Source node.driver = true object.linger = true }"]);
        let created = daemon.run(command)?;
        assert!(
            created.status.success(),
            "{}",
            String::from_utf8_lossy(&created.stderr)
        );
        let second = daemon.source_named("nestlink-second-video")?;
        let displays = [first, second]
            .into_iter()
            .enumerate()
            .map(|(index, target)| Display {
                source: target.node,
                logical: InputLayout {
                    left: index as i32 * 320,
                    top: 0,
                    width: 320,
                    height: 240,
                },
            })
            .collect();
        let fd = UnixStream::connect(daemon.socket())?.into();
        let mut capture =
            PortalCapture::start(fd, displays, vec![first, second], Box::new(|| true), None)?;
        if extra_after_valid {
            daemon.link_target(first.serial, first.node)?;
            daemon.link_target(second.serial, second.node)?;
            let mut seen = BTreeSet::new();
            let started = Instant::now();
            while seen.len() < 2 {
                if let Some(frame) = capture.poll_frame()? {
                    seen.insert(frame.source);
                }
                if started.elapsed() > Duration::from_secs(2) {
                    return Err("approved sources supplied no frames".into());
                }
                thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(seen, BTreeSet::from([first.node, second.node]));
        }
        // Both output nodes are authorized, but each has its own coordinates.
        // A source may therefore never be substituted for the other consumer.
        daemon.link_target(first.serial, second.node)?;
        let started = Instant::now();
        while capture.check().is_ok() {
            if !extra_after_valid {
                match capture.poll_frame() {
                    Ok(Some(_)) => return Err("approved sources were cross-labeled".into()),
                    Err(_) => break,
                    Ok(None) => {}
                }
            }
            if started.elapsed() > Duration::from_secs(1) {
                return Err("cross/duplicate edge did not end capture".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        assert!(capture.poll_frame().is_err());
        assert!(
            capture
                .shared
                .frames
                .lock()
                .map_err(|_| "poisoned")?
                .queue
                .is_empty()
        );
        assert_eq!(daemon.source()?.serial, first.serial);
        assert_eq!(
            daemon.source_named("nestlink-second-video")?.serial,
            second.serial
        );
    }
    Ok(())
}
