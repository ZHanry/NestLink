/* Apache-2.0; independent, narrow system-ABI bridge. Business state is Rust. */
#include <pipewire/pipewire.h>
#include <spa/param/video/raw-utils.h>
#include <spa/param/format-utils.h>
#include <spa/param/buffers.h>
#include <spa/buffer/meta.h>
#include <spa/utils/string.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#define NL_LIMIT (64u * 1024u * 1024u)
#define NL_STREAMS 64
#define NL_LINKS 4096 /* Bounded registry facts, about 64 KiB, never pixel storage. */
/* kind 0: heartbeat, 1: format, 2: frame, 3: neutral black frame.
 * Buffer pointers live only in callback; kind 3 has no borrowed pixel payload. */
struct nl_frame {
    uint32_t kind, node, width, height, format;
    int32_t stride;
    uint32_t first_row, crop_x, crop_y, crop_width, crop_height, transform;
};
/* Callback result: 0 continues, positive cancels normally, negative fails
 * with -errno. This contract is identical for format, pixels and heartbeat. */
typedef int (*nl_callback)(void *, const struct nl_frame *, const uint8_t *, size_t);
struct nl_target { uint32_t node, reserved; uint64_t serial; };
struct nl_link { uint32_t id, input, output; bool present; };
struct nl_capture;
struct nl_stream {
    struct nl_capture *owner;
    struct pw_stream *stream;
    struct spa_hook hook;
    struct spa_video_info_raw info;
    uint32_t node;
    uint32_t format;
    uint32_t bytes_per_pixel;
    uint64_t serial;
    bool serial_verified;
    bool link_verified;
    struct pw_buffer *pending;
    int pending_sync;
    bool have_format;
    bool connected;
};
struct nl_capture {
    struct pw_main_loop *main;
    struct pw_context *context;
    struct pw_core *core;
    struct spa_hook core_hook;
    struct pw_registry *registry;
    struct spa_hook registry_hook;
    int registry_sync;
    struct spa_source *cancel;
    struct spa_source *timer;
    struct nl_stream streams[NL_STREAMS];
    struct nl_link links[NL_LINKS];
    nl_callback callback;
    void *user;
    uint32_t count;
    int result;
    bool closing;
};
static void nl_end(struct nl_capture *c, int result) {
    if (!c->closing) {
        c->closing = true;
        c->result = result;
        pw_main_loop_quit(c->main);
    }
}
static int nl_deliver(struct nl_capture *c, const struct nl_frame *frame,
                      const uint8_t *pixels, size_t length) {
    if (c->closing) return 0;
    int result = c->callback(c->user, frame, pixels, length);
    if (result) nl_end(c, result < 0 ? result : 0);
    return result < 0 ? result : 0;
}
static void nl_cancel(void *data, int fd, uint32_t mask) {
    (void)fd; (void)mask;
    nl_end(data, 0);
}
static void nl_tick(void *data, uint64_t expirations) {
    (void)expirations;
    struct nl_capture *c = data;
    const struct nl_frame frame = {0};
    nl_deliver(c, &frame, NULL, 0);
}
static void nl_error(void *data, uint32_t id, int seq, int res, const char *message) {
    (void)id; (void)seq; (void)message;
    nl_end(data, res < 0 ? res : -EIO);
}
static int nl_buffer(struct nl_stream *s, const struct spa_buffer *buffer);
static int nl_link_count(const struct nl_capture *c, uint32_t input, uint32_t output) {
    int count = 0;
    for (uint32_t j = 0; j < NL_LINKS; ++j) {
        const struct nl_link *link = &c->links[j];
        if (!link->present || link->input != input) continue;
        if (++count > 1 || link->output != output) return -ESTALE;
    }
    return count;
}
static void nl_links(struct nl_capture *c) {
    if (c->closing) return;
    for (uint32_t i = 0; i < c->count; ++i) {
        struct nl_stream *s = &c->streams[i];
        uint32_t node = s->stream ? pw_stream_get_node_id(s->stream) : SPA_ID_INVALID;
        if (node == SPA_ID_INVALID) continue;
        int count = nl_link_count(c, node, s->node);
        if (count < 0) { nl_end(c, count); return; }
        if (!count && s->link_verified) { nl_end(c, -ESTALE); return; }
        s->link_verified = count == 1;
    }
}
static bool nl_node_property(const struct spa_dict *props, const char *key, uint32_t *node) {
    const char *text = props ? spa_dict_lookup(props, key) : NULL;
    return text && *text >= '0' && *text <= '9' && spa_atou32(text, node, 10) && *node != SPA_ID_INVALID;
}
static void nl_global(void *data, uint32_t id, uint32_t permissions, const char *type,
                      uint32_t version, const struct spa_dict *props) {
    (void)permissions; (void)version;
    struct nl_capture *c = data;
    if (c->closing) return;
    for (uint32_t i = 0; i < c->count; ++i) {
        struct nl_stream *s = &c->streams[i];
        if (!s->serial || s->node != id) continue;
        const char *text = props ? spa_dict_lookup(props, PW_KEY_OBJECT_SERIAL) : NULL;
        uint64_t serial = 0;
        if (!type || strcmp(type, PW_TYPE_INTERFACE_Node) || !text || *text < '0' || *text > '9'
            || !spa_atou64(text, &serial, 10) || serial != s->serial) {
            nl_end(c, -ESTALE); return;
        }
        s->serial_verified = true;
    }
    if (type && !strcmp(type, PW_TYPE_INTERFACE_Link)) {
        uint32_t input, output;
        if (!nl_node_property(props, PW_KEY_LINK_INPUT_NODE, &input)
            || !nl_node_property(props, PW_KEY_LINK_OUTPUT_NODE, &output)) { nl_end(c, -EINVAL); return; }
        struct nl_link *slot = NULL;
        for (uint32_t i = 0; i < NL_LINKS; ++i) {
            if (c->links[i].present && c->links[i].id == id) { nl_end(c, -ESTALE); return; }
            if (!c->links[i].present && !slot) slot = &c->links[i];
        }
        if (!slot) { nl_end(c, -ENOSPC); return; }
        *slot = (struct nl_link) { .id = id, .input = input, .output = output, .present = true };
    }
    nl_links(c);
}
static void nl_global_remove(void *data, uint32_t id) {
    struct nl_capture *c = data;
    for (uint32_t i = 0; i < c->count; ++i) {
        if (c->streams[i].node == id) {
            nl_end(c, -ESTALE); return;
        }
    }
    for (uint32_t i = 0; i < NL_LINKS; ++i) if (c->links[i].present && c->links[i].id == id) {
        c->links[i].present = false;
    }
    nl_links(c);
}
static void nl_done(void *data, uint32_t id, int seq) {
    struct nl_capture *c = data;
    if (c->closing || id != PW_ID_CORE) return;
    nl_links(c);
    if (c->closing) return;
    for (uint32_t i = 0; i < c->count; ++i) {
        struct nl_stream *s = &c->streams[i];
        if (seq == c->registry_sync && s->serial && !s->serial_verified) {
            nl_end(c, -ENOENT); return;
        }
        if (s->pending && seq == s->pending_sync) {
            struct pw_buffer *pending = s->pending;
            s->pending = NULL;
            int failure = nl_buffer(s, pending->buffer);
            pw_stream_queue_buffer(s->stream, pending);
            if (failure) { nl_end(c, failure); return; }
        }
    }
}
static void nl_state(void *data, enum pw_stream_state old,
                     enum pw_stream_state state, const char *message) {
    (void)old; (void)message;
    struct nl_stream *s = data;
    if (state == PW_STREAM_STATE_ERROR || (state == PW_STREAM_STATE_UNCONNECTED && s->connected)) {
        nl_end(s->owner, -EPIPE);
    } else if (state >= PW_STREAM_STATE_PAUSED) {
        s->connected = true;
        nl_links(s->owner);
    }
}
static struct nl_frame nl_description(const struct nl_stream *s, uint32_t kind) {
    return (struct nl_frame) { .kind = kind, .node = s->node,
        .width = s->info.size.width, .height = s->info.size.height, .format = s->format,
        .crop_width = s->info.size.width, .crop_height = s->info.size.height };
}
static void nl_format(void *data, uint32_t id, const struct spa_pod *param) {
    struct nl_stream *s = data;
    if (id != SPA_PARAM_Format || s->owner->closing) return;
    uint32_t type = 0, subtype = 0;
    struct spa_video_info_raw info = {0};
    if (!param || spa_format_parse(param, &type, &subtype) < 0 || type != SPA_MEDIA_TYPE_video
        || subtype != SPA_MEDIA_SUBTYPE_raw || spa_format_video_raw_parse(param, &info) < 0
        || info.size.width == 0 || info.size.height == 0 || info.size.width > 8192
        || info.size.height > 8192 || (uint64_t)info.size.width * info.size.height * 4 > NL_LIMIT
        || info.flags & SPA_VIDEO_FLAG_MODIFIER || info.interlace_mode != SPA_VIDEO_INTERLACE_MODE_PROGRESSIVE
        || (info.pixel_aspect_ratio.denom && info.pixel_aspect_ratio.num != info.pixel_aspect_ratio.denom)) {
        nl_end(s->owner, -EINVAL); return;
    }
    uint32_t format;
    switch (info.format) {
        case SPA_VIDEO_FORMAT_BGRx: format = 1; break;
        case SPA_VIDEO_FORMAT_BGRA: format = 2; break;
        case SPA_VIDEO_FORMAT_RGBx: format = 3; break;
        case SPA_VIDEO_FORMAT_RGBA: format = 4; break;
        case SPA_VIDEO_FORMAT_RGB: format = 5; break;
        case SPA_VIDEO_FORMAT_BGR: format = 6; break;
        default: nl_end(s->owner, -ENOTSUP); return;
    }
    if (s->have_format && (s->format != format || s->info.size.width != info.size.width
        || s->info.size.height != info.size.height)) { nl_end(s->owner, -ESTALE); return; }
    s->info = info; s->format = format; s->bytes_per_pixel = format <= 4 ? 4 : 3; s->have_format = true;
    const struct nl_frame frame = nl_description(s, 1);
    if (nl_deliver(s->owner, &frame, NULL, 0) || s->owner->closing) return;
    uint8_t memory[1024];
    struct spa_pod_builder b = SPA_POD_BUILDER_INIT(memory, sizeof(memory));
    const struct spa_pod *parameters[4];
    parameters[0] = spa_pod_builder_add_object(&b, SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
        SPA_PARAM_BUFFERS_buffers, SPA_POD_CHOICE_RANGE_Int(3, 2, 4),
        SPA_PARAM_BUFFERS_blocks, SPA_POD_Int(1),
        SPA_PARAM_BUFFERS_size, SPA_POD_Int((int)(info.size.width * info.size.height * s->bytes_per_pixel)),
        SPA_PARAM_BUFFERS_stride, SPA_POD_Int((int)(info.size.width * s->bytes_per_pixel)),
        SPA_PARAM_BUFFERS_dataType, SPA_POD_CHOICE_FLAGS_Int((1 << SPA_DATA_MemPtr) | (1 << SPA_DATA_MemFd)));
    parameters[1] = spa_pod_builder_add_object(&b, SPA_TYPE_OBJECT_ParamMeta, SPA_PARAM_Meta,
        SPA_PARAM_META_type, SPA_POD_Id(SPA_META_Header),
        SPA_PARAM_META_size, SPA_POD_Int(sizeof(struct spa_meta_header)));
    parameters[2] = spa_pod_builder_add_object(&b, SPA_TYPE_OBJECT_ParamMeta, SPA_PARAM_Meta,
        SPA_PARAM_META_type, SPA_POD_Id(SPA_META_VideoCrop),
        SPA_PARAM_META_size, SPA_POD_Int(sizeof(struct spa_meta_region)));
    parameters[3] = spa_pod_builder_add_object(&b, SPA_TYPE_OBJECT_ParamMeta, SPA_PARAM_Meta,
        SPA_PARAM_META_type, SPA_POD_Id(SPA_META_VideoTransform),
        SPA_PARAM_META_size, SPA_POD_Int(sizeof(struct spa_meta_videotransform)));
    if (pw_stream_update_params(s->stream, parameters, 4) < 0) nl_end(s->owner, -EIO);
}
/* Metadata is optional, but a present truncated/duplicate object is not absent.
 * Copy scalar structs rather than assuming the producer's pointer alignment. */
static int nl_metadata(const struct spa_buffer *buffer, uint32_t type, void *out, size_t size) {
    bool found = false;
    for (uint32_t i = 0; i < buffer->n_metas; ++i) {
        const struct spa_meta *meta = &buffer->metas[i];
        if (meta->type != type) continue;
        if (found || !meta->data || meta->size < size) return -EINVAL;
        memcpy(out, meta->data, size);
        found = true;
    }
    return 0;
}
/* The buffer stays dequeued across this call. Validate all objects before
 * reading pixels; EMPTY/GAP describes black, not an absent update. */
static int nl_buffer(struct nl_stream *s, const struct spa_buffer *buffer) {
    if (s->owner->closing) return 0;
    /* target.object is a session-manager request. The portal's exact node and
     * serial must also exist in this granted remote before any pixels escape. */
    if (!s->link_verified || (s->serial && !s->serial_verified)) return 0;
    if (!s->have_format || !buffer || buffer->n_datas != 1 || !buffer->datas || buffer->n_metas > 64
        || (buffer->n_metas && !buffer->metas)) return -EINVAL;
    const struct spa_data *plane = &buffer->datas[0];
    if ((plane->type != SPA_DATA_MemPtr && plane->type != SPA_DATA_MemFd) || !plane->chunk
        || !(plane->flags & SPA_DATA_FLAG_READABLE) || plane->maxsize == 0 || plane->maxsize > NL_LIMIT)
        return -EINVAL;
    struct spa_meta_header header = {0};
    struct spa_meta_region crop = {0};
    struct spa_meta_videotransform transform = {0};
    if (nl_metadata(buffer, SPA_META_Header, &header, sizeof(header))
        || nl_metadata(buffer, SPA_META_VideoCrop, &crop, sizeof(crop))
        || nl_metadata(buffer, SPA_META_VideoTransform, &transform, sizeof(transform))) return -EINVAL;
    if (plane->chunk->flags & SPA_CHUNK_FLAG_CORRUPTED
        || header.flags & SPA_META_HEADER_FLAG_CORRUPTED) return 0;
    struct nl_frame frame = nl_description(s, 2);
    /* SPA defines a zero-extent region as inactive; otherwise it must fit the
     * untransformed buffer. Cropping precedes undoing the buffer transform. */
    if (spa_meta_region_is_valid(&crop)) {
        if (crop.region.position.x < 0 || crop.region.position.y < 0
            || (uint64_t)crop.region.position.x + crop.region.size.width > frame.width
            || (uint64_t)crop.region.position.y + crop.region.size.height > frame.height) return -EINVAL;
        frame.crop_x = crop.region.position.x;
        frame.crop_y = crop.region.position.y;
        frame.crop_width = crop.region.size.width;
        frame.crop_height = crop.region.size.height;
    }
    if (transform.transform > SPA_META_TRANSFORMATION_Flipped270) return -EINVAL;
    frame.transform = transform.transform;
    if (plane->chunk->flags & SPA_CHUNK_FLAG_EMPTY || header.flags & SPA_META_HEADER_FLAG_GAP) {
        frame.kind = 3;
        return nl_deliver(s->owner, &frame, NULL, 0);
    }
    if (plane->chunk->size == 0) return 0;
    int64_t stride = plane->chunk->stride;
    uint64_t step = stride < 0 ? -stride : stride;
    uint64_t row = (uint64_t)frame.width * s->bytes_per_pixel;
    uint64_t distance = (uint64_t)(frame.height - 1) * step;
    uint64_t need = distance + row;
    uint32_t offset = plane->chunk->offset % plane->maxsize;
    uint32_t available = SPA_MIN(plane->chunk->size, plane->maxsize);
    int64_t low = (int64_t)offset - (stride < 0 ? (int64_t)distance : 0);
    if (!plane->data || step < row || need > available || need > NL_LIMIT || low < 0
        || (uint64_t)low + need > plane->maxsize) return -EINVAL;
    /* offset names the first displayed row, including for negative strides.
     * Borrow the lowest-addressed contiguous span; never wrap a video plane. */
    frame.first_row = stride < 0 ? distance : 0;
    frame.stride = plane->chunk->stride;
    return nl_deliver(s->owner, &frame, (const uint8_t *)plane->data + low, (size_t)need);
}
static void nl_process(void *data) {
    struct nl_stream *s = data;
    struct pw_buffer *current = NULL, *next;
    /* Bound draining even if the source keeps filling; favor the latest frame. */
    for (unsigned int i = 0; i < 4 && (next = pw_stream_dequeue_buffer(s->stream)); ++i) {
        if (current) pw_stream_queue_buffer(s->stream, current);
        current = next;
    }
    if (!current) return;
    nl_links(s->owner);
    if (s->owner->closing || !s->link_verified || (s->serial && !s->serial_verified)) {
        pw_stream_queue_buffer(s->stream, current);
        return;
    }
    if (s->pending) pw_stream_queue_buffer(s->stream, s->pending);
    s->pending = current;
    /* Buffer wakeups and registry messages use different transports. Wait for
     * a server round trip after dequeue before trusting the observed link.
     * Any intervening wrong/duplicate/removed edge terminates before publish. */
    s->pending_sync = pw_core_sync(s->owner->core, PW_ID_CORE, 0);
    if (s->pending_sync < 0) nl_end(s->owner, s->pending_sync);
}
static const struct pw_core_events core_events = { PW_VERSION_CORE_EVENTS, .error = nl_error, .done = nl_done };
static const struct pw_registry_events registry_events = {
    PW_VERSION_REGISTRY_EVENTS, .global = nl_global, .global_remove = nl_global_remove
};
static const struct pw_stream_events stream_events = {
    PW_VERSION_STREAM_EVENTS, .state_changed = nl_state, .param_changed = nl_format, .process = nl_process
};
void nl_pw_init(void) { pw_init(NULL, NULL); }
static int nl_target_properties(struct pw_properties *props, const struct nl_target *target, uint32_t *id) {
    if (!target->node || target->node == SPA_ID_INVALID || target->reserved) return -EINVAL;
    *id = target->node;
    if (target->serial) {
        if (pw_properties_setf(props, PW_KEY_TARGET_OBJECT, "%" PRIu64, target->serial) < 0) return -ENOMEM;
        *id = PW_ID_ANY;
    }
    return 0;
}
/* Takes fd on all paths. cancel_fd, targets and user remain borrowed until return. */
int nl_pw_capture(int fd, int cancel_fd, const struct nl_target *targets, uint32_t count, nl_callback callback, void *user) {
    struct nl_capture c = { .callback = callback, .user = user, .count = count, .result = -EIO };
    if (fd < 0 || cancel_fd < 0 || count == 0 || count > NL_STREAMS || !callback || !targets) {
        if (fd >= 0) close(fd);
        return -EINVAL;
    }
    for (uint32_t i = 0; i < count; ++i) {
        if (!targets[i].node || targets[i].node == SPA_ID_INVALID || targets[i].reserved) { close(fd); return -EINVAL; }
        for (uint32_t j = 0; j < i; ++j) {
            if (targets[i].node == targets[j].node || (targets[i].serial && targets[i].serial == targets[j].serial)) {
                close(fd); return -EINVAL;
            }
        }
        c.streams[i].owner = &c; c.streams[i].node = targets[i].node; c.streams[i].serial = targets[i].serial;
    }
    c.main = pw_main_loop_new(NULL);
    if (!c.main) goto cleanup;
    struct pw_loop *loop = pw_main_loop_get_loop(c.main);
    c.cancel = pw_loop_add_io(loop, cancel_fd, SPA_IO_IN | SPA_IO_ERR | SPA_IO_HUP, false, nl_cancel, &c);
    c.timer = pw_loop_add_timer(loop, nl_tick, &c);
    if (!c.cancel || !c.timer) goto cleanup;
    struct timespec interval = { .tv_nsec = 50000000 };
    if (pw_loop_update_timer(loop, c.timer, &interval, &interval, false) < 0) goto cleanup;
    c.context = pw_context_new(loop, NULL, 0);
    if (!c.context) goto cleanup;
    c.core = pw_context_connect_fd(c.context, fd, NULL, 0);
    fd = -1; /* connect_fd consumes it on error as well. */
    if (!c.core) goto cleanup;
    pw_core_add_listener(c.core, &c.core_hook, &core_events, &c);
    c.registry = pw_core_get_registry(c.core, PW_VERSION_REGISTRY, 0);
    if (!c.registry) goto cleanup;
    if (pw_registry_add_listener(c.registry, &c.registry_hook, &registry_events, &c) < 0) goto cleanup;
    c.registry_sync = pw_core_sync(c.core, PW_ID_CORE, 0);
    if (c.registry_sync < 0) goto cleanup;
    for (uint32_t i = 0; i < count; ++i) {
        struct nl_stream *s = &c.streams[i];
        struct pw_properties *props = pw_properties_new(PW_KEY_MEDIA_TYPE, "Video", PW_KEY_MEDIA_CATEGORY, "Capture",
            PW_KEY_MEDIA_ROLE, "Screen", PW_KEY_NODE_NAME, "nestlink-portal-capture", NULL);
        if (!props) goto cleanup;
        uint32_t target_id;
        if (nl_target_properties(props, &targets[i], &target_id) < 0) { pw_properties_free(props); goto cleanup; }
        s->stream = pw_stream_new(c.core, "NestLink approved monitor", props);
        if (!s->stream) goto cleanup;
        pw_stream_add_listener(s->stream, &s->hook, &stream_events, s);
        uint8_t memory[512];
        struct spa_pod_builder b = SPA_POD_BUILDER_INIT(memory, sizeof(memory));
        const struct spa_pod *format = spa_pod_builder_add_object(&b, SPA_TYPE_OBJECT_Format, SPA_PARAM_EnumFormat,
            SPA_FORMAT_mediaType, SPA_POD_Id(SPA_MEDIA_TYPE_video),
            SPA_FORMAT_mediaSubtype, SPA_POD_Id(SPA_MEDIA_SUBTYPE_raw),
            SPA_FORMAT_VIDEO_format, SPA_POD_CHOICE_ENUM_Id(6, SPA_VIDEO_FORMAT_BGRx, SPA_VIDEO_FORMAT_BGRA,
                SPA_VIDEO_FORMAT_RGBx, SPA_VIDEO_FORMAT_RGBA, SPA_VIDEO_FORMAT_RGB, SPA_VIDEO_FORMAT_BGR));
        if (pw_stream_connect(s->stream, PW_DIRECTION_INPUT, target_id,
            PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_DONT_RECONNECT,
            &format, 1) < 0) goto cleanup;
    }
    const struct nl_frame heartbeat = {0};
    nl_deliver(&c, &heartbeat, NULL, 0);
    if (c.closing) goto cleanup;
    pw_main_loop_run(c.main);
cleanup:
    c.closing = true;
    for (uint32_t i = 0; i < count; ++i) if (c.streams[i].stream) {
        if (c.streams[i].pending) pw_stream_queue_buffer(c.streams[i].stream, c.streams[i].pending);
        spa_hook_remove(&c.streams[i].hook);
        pw_stream_destroy(c.streams[i].stream);
    }
    if (c.registry) { spa_hook_remove(&c.registry_hook); pw_proxy_destroy((struct pw_proxy *)c.registry); }
    if (c.core) { spa_hook_remove(&c.core_hook); pw_core_disconnect(c.core); }
    if (c.context) pw_context_destroy(c.context);
    if (c.main) {
        struct pw_loop *loop = pw_main_loop_get_loop(c.main);
        if (c.cancel) pw_loop_destroy_source(loop, c.cancel);
        if (c.timer) pw_loop_destroy_source(loop, c.timer);
        pw_main_loop_destroy(c.main);
    }
    if (fd >= 0) close(fd);
    return c.result;
}
