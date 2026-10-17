/* Apache-2.0. Independent PipeWire ABI adapter, written from system contracts.
 * Only local graph facts and PCM live here. Business authorization is Rust. */
#include "pipewire_audio.h"
#include <pipewire/pipewire.h>
#include <spa/param/audio/raw-utils.h>
#include <spa/param/format-utils.h>
#include <spa/param/buffers.h>
#include <spa/buffer/meta.h>
#include <spa/utils/string.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#define NL_AUDIO_SINKS 64
#define NL_AUDIO_LINKS 4096
#define NL_AUDIO_FRAMES 1920u
#define NL_AUDIO_NATIVE_QUEUE 2880u /* <=60ms; Rust playback holds <=40ms. */
#define NL_AUDIO_TEXT 1024u
struct nl_sink { uint32_t id; uint64_t serial; char name[NL_AUDIO_TEXT], description[NL_AUDIO_TEXT]; };
struct nl_link { uint32_t id, input, output; bool present; };
struct nl_audio {
    struct pw_main_loop *main;
    struct pw_context *context;
    struct pw_core *core;
    struct pw_registry *registry;
    struct pw_node *node;
    struct pw_stream *stream;
    struct spa_hook core_hook, registry_hook, node_hook, stream_hook;
    struct spa_source *timer, *cancel;
    struct nl_sink sinks[NL_AUDIO_SINKS];
    struct nl_link links[NL_AUDIO_LINKS];
    uint32_t sink_count, cookie, channels;
    int registry_sync, pending_sync;
    struct pw_buffer *pending;
    struct pw_time pending_time;
    struct spa_fraction graph_rate;
    uint64_t expected;
    bool clock_seen;
    bool have_cookie, registry_done, target_seen, node_seen;
    bool format_seen, links_seen, connected, armed, closing, enumerate, capture;
    bool core_listening, registry_listening, node_listening;
    int result;
    const struct nl_audio_target *target;
    nl_audio_endpoint_fn endpoint;
    nl_audio_control_fn control;
    nl_audio_capture_fn read;
    nl_audio_play_fn write;
    void *user;
};
static void nl_end(struct nl_audio *a, int result) {
    if (!a->closing) {
        a->result = result;
        a->closing = true;
        if (a->main) pw_main_loop_quit(a->main);
    }
}
static bool nl_u64(const struct spa_dict *p, const char *key, uint64_t *value) {
    const char *s = p ? spa_dict_lookup(p, key) : NULL;
    return s && *s >= '0' && *s <= '9' && spa_atou64(s, value, 10);
}
static bool nl_id(const struct spa_dict *p, const char *key, uint32_t *value) {
    uint64_t id;
    if (!nl_u64(p, key, &id) || id == 0 || id >= SPA_ID_INVALID) return false;
    *value = (uint32_t)id;
    return true;
}
static bool nl_text(const char *s) { return s && *s && strnlen(s, NL_AUDIO_TEXT) < NL_AUDIO_TEXT; }
static int nl_graph_links(const struct nl_link *links, uint32_t own, uint32_t target,
                           bool capture, bool previously_seen) {
    if (own == SPA_ID_INVALID) return 0;
    unsigned count = 0;
    for (unsigned i = 0; i < NL_AUDIO_LINKS; ++i) {
        const struct nl_link *l = &links[i];
        if (!l->present) continue;
        bool relevant = capture ? l->input == own : l->output == own;
        if (!relevant) continue;
        uint32_t actual = capture ? l->output : l->input;
        if (actual != target || ++count > 64) return -ESTALE;
    }
    if (!count && previously_seen) return -ESTALE;
    return count ? 1 : 0;
}
static int nl_link_facts(struct nl_audio *a) {
    uint32_t own = a->stream ? pw_stream_get_node_id(a->stream) : SPA_ID_INVALID;
    int count = nl_graph_links(a->links, own, a->target->node, a->capture, a->links_seen);
    if (count) a->links_seen = true;
    return count;
}
static bool nl_ready(struct nl_audio *a) {
    return a->have_cookie && a->registry_done && a->target_seen && a->node_seen
        && a->connected && a->links_seen;
}
static int nl_progress(struct nl_audio *a) {
    return (nl_ready(a) ? 1 : 0) | (a->have_cookie ? 2 : 0) | (a->registry_done ? 4 : 0)
        | (a->target_seen ? 8 : 0) | (a->node_seen ? 16 : 0) | (a->format_seen ? 32 : 0)
        | (a->links_seen ? 64 : 0) | (a->connected ? 128 : 0);
}
static int nl_control(struct nl_audio *a, bool timer) {
    if (a->closing) return 2;
    int links = a->enumerate ? 0 : nl_link_facts(a);
    if (links < 0) { nl_end(a, links); return 2; }
    int result = a->control(a->user, timer, a->enumerate ? 0 : nl_progress(a));
    if (result < 0 || result == 2) {
        nl_end(a, result < 0 ? result : 0);
        return 2;
    }
    if (result > 2) { nl_end(a, -EINVAL); return 2; }
    if (result == 1 && !a->enumerate && nl_ready(a) && !a->armed) {
        int res = pw_stream_set_active(a->stream, true);
        if (res < 0) { nl_end(a, res); return 2; }
        a->armed = true;
        /* Stop may have arrived during the native call. Recheck before any PCM. */
        result = a->control(a->user, 0, nl_progress(a));
        if (result < 0 || result == 2) { nl_end(a, result < 0 ? result : 0); return 2; }
    }
    return result;
}
static void nl_tick(void *data, uint64_t expirations) {
    (void)expirations;
    nl_control(data, true);
}
static void nl_cancel(void *data, int fd, uint32_t mask) {
    (void)fd; (void)mask;
    nl_end(data, 0);
}
static void nl_error(void *data, uint32_t id, int seq, int res, const char *message) {
    (void)id; (void)seq; (void)message;
    nl_end(data, res < 0 ? res : -EIO);
}
static void nl_core_info(void *data, const struct pw_core_info *info) {
    struct nl_audio *a = data;
    if (!info || (a->have_cookie && info->cookie != a->cookie)
        || (!a->enumerate && info->cookie != a->target->cookie)) {
        nl_end(a, -ESTALE); return;
    }
    a->have_cookie = true;
    a->cookie = info->cookie;
}
static void nl_node_info(void *data, const struct pw_node_info *info) {
    struct nl_audio *a = data;
    if (!info || info->id != a->target->node || info->state == PW_NODE_STATE_ERROR) {
        nl_end(a, -ESTALE); return;
    }
    if (!a->node_seen || (info->change_mask & PW_NODE_CHANGE_MASK_PROPS)) {
        const char *name = info->props ? spa_dict_lookup(info->props, PW_KEY_NODE_NAME) : NULL;
        const char *kind = info->props ? spa_dict_lookup(info->props, PW_KEY_MEDIA_CLASS) : NULL;
        uint64_t serial;
        if (!nl_text(name) || strcmp(name, a->target->name) || !kind || strcmp(kind, "Audio/Sink")
            || !nl_u64(info->props, PW_KEY_OBJECT_SERIAL, &serial) || serial != a->target->serial) {
            nl_end(a, -ESTALE); return;
        }
    }
    a->node_seen = true;
}
static const struct pw_node_events node_events = { PW_VERSION_NODE_EVENTS, .info = nl_node_info };
static void nl_global(void *data, uint32_t id, uint32_t permissions, const char *type,
                      uint32_t version, const struct spa_dict *props) {
    (void)version;
    struct nl_audio *a = data;
    if (a->closing || !type) return;
    if (!strcmp(type, PW_TYPE_INTERFACE_Node)) {
        const char *kind = props ? spa_dict_lookup(props, PW_KEY_MEDIA_CLASS) : NULL;
        const char *name = props ? spa_dict_lookup(props, PW_KEY_NODE_NAME) : NULL;
        const char *description = props ? spa_dict_lookup(props, PW_KEY_NODE_DESCRIPTION) : NULL;
        uint64_t serial;
        bool valid = id && id != SPA_ID_INVALID && kind && !strcmp(kind, "Audio/Sink")
            && nl_text(name) && nl_u64(props, PW_KEY_OBJECT_SERIAL, &serial) && serial;
        if (a->enumerate && valid) {
            if (a->sink_count >= NL_AUDIO_SINKS || (description && !nl_text(description))) {
                nl_end(a, -ENOSPC); return;
            }
            struct nl_sink *s = &a->sinks[a->sink_count++];
            s->id = id; s->serial = serial;
            strcpy(s->name, name); strcpy(s->description, description ? description : name);
        }
        if (!a->enumerate && id == a->target->node) {
            if (!valid || serial != a->target->serial || strcmp(name, a->target->name)
                || (permissions & (PW_PERM_R | PW_PERM_X)) != (PW_PERM_R | PW_PERM_X)
                || a->target_seen) { nl_end(a, -ESTALE); return; }
            a->target_seen = true;
            a->node = pw_registry_bind(a->registry, id, PW_TYPE_INTERFACE_Node, PW_VERSION_NODE, 0);
            if (!a->node || pw_node_add_listener(a->node, &a->node_hook, &node_events, a) < 0) {
                nl_end(a, -EIO); return;
            }
            a->node_listening = true;
        }
    }
    if (!a->enumerate && !strcmp(type, PW_TYPE_INTERFACE_Link)) {
        uint32_t input, output;
        if (!nl_id(props, PW_KEY_LINK_INPUT_NODE, &input) || !nl_id(props, PW_KEY_LINK_OUTPUT_NODE, &output)) {
            nl_end(a, -EINVAL); return;
        }
        struct nl_link *slot = NULL;
        for (unsigned i = 0; i < NL_AUDIO_LINKS; ++i) {
            if (a->links[i].present && a->links[i].id == id) { nl_end(a, -ESTALE); return; }
            if (!a->links[i].present && !slot) slot = &a->links[i];
        }
        if (!slot) { nl_end(a, -ENOSPC); return; }
        *slot = (struct nl_link){ .id = id, .input = input, .output = output, .present = true };
        int result = nl_link_facts(a);
        if (result < 0) nl_end(a, result);
    }
}
static void nl_global_remove(void *data, uint32_t id) {
    struct nl_audio *a = data;
    if (a->enumerate) { nl_end(a, -ESTALE); return; }
    if (id == a->target->node) { nl_end(a, -ESTALE); return; }
    uint32_t own = a->stream ? pw_stream_get_node_id(a->stream) : SPA_ID_INVALID;
    for (unsigned i = 0; i < NL_AUDIO_LINKS; ++i) {
        struct nl_link *l = &a->links[i];
        if (!l->present || l->id != id) continue;
        if ((a->capture ? l->input : l->output) == own && a->links_seen) {
            nl_end(a, -ESTALE); return;
        }
        l->present = false;
    }
}
/* Validate raw ABI sizes before any memcpy. Pure entry point also used by the
 * sanitizer corpus. Chunk offset never wraps and mapped memory is borrowed. */
static int nl_audio_view(const struct spa_buffer *buffer, uint32_t channels, bool capture,
                         int16_t **samples, uint32_t *frames, bool *silence) {
    if (!buffer || channels < 1 || channels > 2 || buffer->n_datas != 1 || !buffer->datas) return -EINVAL;
    const struct spa_data *d = &buffer->datas[0];
    uint32_t stride = channels * sizeof(int16_t);
    if (!d->chunk || !d->data || d->maxsize > 65536 || d->maxsize < stride
        || !(d->flags & (capture ? SPA_DATA_FLAG_READABLE : SPA_DATA_FLAG_WRITABLE))
        || (uintptr_t)d->data % _Alignof(int16_t) || d->chunk->flags & ~(SPA_CHUNK_FLAG_CORRUPTED | SPA_CHUNK_FLAG_EMPTY)
        || d->chunk->flags & SPA_CHUNK_FLAG_CORRUPTED) return -EINVAL;
    uint32_t offset = capture ? d->chunk->offset : 0;
    uint32_t bytes = capture ? d->chunk->size : d->maxsize;
    if (offset % stride || offset > d->maxsize || bytes > d->maxsize - offset
        || bytes % stride || (capture && d->chunk->stride != (int32_t)stride)) return -EINVAL;
    *frames = bytes / stride;
    if (!*frames || (capture && *frames > NL_AUDIO_FRAMES)) return -EOVERFLOW;
    *samples = (int16_t *)((uint8_t *)d->data + offset);
    *silence = capture && (d->chunk->flags & SPA_CHUNK_FLAG_EMPTY);
    return 0;
}
static int nl_capture_buffer(struct nl_audio *a, struct pw_buffer *b) {
    int16_t *samples; uint32_t frames; bool silence;
    int result = nl_audio_view(b->buffer, a->channels, true, &samples, &frames, &silence);
    if (result < 0) return result;
    const struct spa_meta_header *header = spa_buffer_find_meta_data(b->buffer, SPA_META_Header, sizeof(*header));
    bool discontinuity = header && (header->flags & SPA_META_HEADER_FLAG_DISCONT);
    if (header && header->flags & ~(SPA_META_HEADER_FLAG_DISCONT | SPA_META_HEADER_FLAG_GAP)) return -EINVAL;
    silence |= header && (header->flags & SPA_META_HEADER_FLAG_GAP);
    struct pw_time t = a->pending_time;
    uint64_t now = pw_stream_get_nsec(a->stream);
    if (!b->time || b->time > now || now - b->time > 100000000 || t.now <= 0
        || (uint64_t)t.now < b->time || !t.rate.num || !t.rate.denom
        || t.rate.num > 1000000 || t.rate.denom > 1000000) return -ESTALE;
    /* A graph tick is not always a 48kHz sample. Convert the real driver clock
     * with 128-bit arithmetic; resampler rounding of <=2 samples preserves the
     * already-observed PCM clock. Larger gaps discard partial chunks in Rust. */
    __uint128_t scaled = (__uint128_t)t.ticks * t.rate.num * 48000 / t.rate.denom;
    __uint128_t older = (__uint128_t)((uint64_t)t.now - b->time) * 48000 / 1000000000;
    if (scaled < older || scaled - older > INT64_MAX) return -EOVERFLOW;
    uint64_t position = (uint64_t)(scaled - older);
    if (a->clock_seen) {
        if (t.rate.num != a->graph_rate.num || t.rate.denom != a->graph_rate.denom) return -ESTALE;
        uint64_t difference = position > a->expected ? position - a->expected : a->expected - position;
        if (difference <= 2 && !discontinuity) position = a->expected;
        else if (position < a->expected) return -ESTALE;
    }
    a->clock_seen = true; a->graph_rate = t.rate;
    if (position > (uint64_t)INT64_MAX - frames) return -EOVERFLOW;
    a->expected = position + frames;
    struct nl_audio_packet packet = { position, now - b->time, frames, discontinuity,
        t.rate.num, t.rate.denom };
    int16_t zeros[NL_AUDIO_FRAMES * 2] = {0};
    return a->read(a->user, &packet, silence ? zeros : samples);
}
static struct nl_audio_play_timing nl_play_timing(const struct pw_time *t) {
    struct nl_audio_play_timing result = {0, (uint32_t)(t->queued + t->buffered), 0};
    if (t->delay >= 0 && t->rate.num && t->rate.denom && t->rate.num <= 1000000 && t->rate.denom <= 1000000) {
        __uint128_t ns = (__uint128_t)t->delay * t->rate.num * 1000000000 / t->rate.denom;
        if (ns <= 250000000) { result.latency_ns = (uint64_t)ns; result.latency_known = 1; }
    }
    return result;
}
static int nl_play_buffer(struct nl_audio *a, struct pw_buffer *b) {
    int16_t *samples; uint32_t capacity; bool silence;
    int result = nl_audio_view(b->buffer, a->channels, false, &samples, &capacity, &silence);
    if (result < 0) return result;
    uint64_t requested = b->requested ? b->requested : 960;
    if (requested > capacity || requested > NL_AUDIO_FRAMES) return -EOVERFLOW;
    struct pw_time t;
    if (pw_stream_get_time_n(a->stream, &t, sizeof(t)) < 0
        || t.queued > NL_AUDIO_NATIVE_QUEUE || t.buffered > NL_AUDIO_NATIVE_QUEUE
        || t.queued + t.buffered + requested > NL_AUDIO_NATIVE_QUEUE) return -ENOBUFS;
    struct nl_audio_play_timing timing = nl_play_timing(&t);
    result = a->write(a->user, samples, (uint32_t)requested, &timing);
    if (result < 0) return result;
    b->buffer->datas[0].chunk->offset = 0;
    b->buffer->datas[0].chunk->stride = (int32_t)(a->channels * sizeof(int16_t));
    b->buffer->datas[0].chunk->size = (uint32_t)requested * a->channels * sizeof(int16_t);
    b->buffer->datas[0].chunk->flags = 0;
    b->size = requested;
    return 0;
}
static void nl_process(void *data) {
    struct nl_audio *a = data;
    if (nl_control(a, false) == 2 || !a->armed || !nl_ready(a) || !a->format_seen || a->pending) return;
    struct pw_buffer *b = pw_stream_dequeue_buffer(a->stream);
    if (!b) return;
    a->pending = b;
    if (pw_stream_get_time_n(a->stream, &a->pending_time, sizeof(a->pending_time)) < 0) {
        nl_end(a, -EIO); return;
    }
    /* Flush registry facts before touching PCM: target.object is a request,
     * not proof that a session manager actually linked the chosen sink. */
    a->pending_sync = pw_core_sync(a->core, PW_ID_CORE, 0);
    if (a->pending_sync < 0) nl_end(a, a->pending_sync);
}
static void nl_done(void *data, uint32_t id, int seq) {
    struct nl_audio *a = data;
    if (a->closing || id != PW_ID_CORE) return;
    if (seq == a->registry_sync) {
        if (!a->have_cookie) { nl_end(a, -ENODATA); return; }
        a->registry_done = true;
        if (a->enumerate) {
            for (unsigned i = 0; i < a->sink_count && !a->closing; ++i) {
                const struct nl_sink *s = &a->sinks[i];
                int res = a->endpoint(a->user, s->id, a->cookie, s->serial, s->name, s->description);
                if (res) { nl_end(a, res < 0 ? res : -EINVAL); return; }
            }
            nl_end(a, 0); return;
        }
        if (!a->target_seen) { nl_end(a, -ENOENT); return; }
    }
    if (a->pending && seq == a->pending_sync) {
        struct pw_buffer *b = a->pending;
        a->pending = NULL;
        int result = 0;
        if (nl_control(a, false) == 2 || !nl_ready(a) || !a->format_seen || !a->armed) {
            /* Return borrowed capture memory only. An unfilled playback buffer
             * may contain samples from a previous cycle and must never queue. */
            if (a->capture) pw_stream_queue_buffer(a->stream, b);
            return;
        }
        result = a->capture ? nl_capture_buffer(a, b) : nl_play_buffer(a, b);
        int queued = pw_stream_queue_buffer(a->stream, b);
        if (result < 0 || queued < 0) nl_end(a, result < 0 ? result : queued);
    }
}
static void nl_state(void *data, enum pw_stream_state old, enum pw_stream_state state, const char *message) {
    (void)old; (void)message;
    struct nl_audio *a = data;
    if (state == PW_STREAM_STATE_ERROR || (state == PW_STREAM_STATE_UNCONNECTED && a->connected))
        nl_end(a, -EPIPE);
    else if (state >= PW_STREAM_STATE_PAUSED) a->connected = true;
}
static void nl_format(void *data, uint32_t id, const struct spa_pod *param) {
    struct nl_audio *a = data;
    if (id != SPA_PARAM_Format || a->closing) return;
    if (!param) { if (a->format_seen) nl_end(a, -ESTALE); return; }
    struct spa_audio_info_raw info = {0};
    if (spa_format_audio_raw_parse(param, &info) < 0 || info.format != SPA_AUDIO_FORMAT_S16
        || info.rate != 48000 || info.channels != a->channels) { nl_end(a, -ENOTSUP); return; }
    if (a->format_seen) return;
    a->format_seen = true;
    uint8_t memory[1024];
    struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(memory, sizeof(memory));
    const struct spa_pod *params[2];
    params[0] = spa_pod_builder_add_object(&builder, SPA_TYPE_OBJECT_ParamBuffers, SPA_PARAM_Buffers,
        SPA_PARAM_BUFFERS_buffers, SPA_POD_CHOICE_RANGE_Int(2, 2, 2),
        SPA_PARAM_BUFFERS_blocks, SPA_POD_Int(1),
        SPA_PARAM_BUFFERS_size, SPA_POD_CHOICE_RANGE_Int(960 * a->channels * 2, 64 * a->channels * 2, NL_AUDIO_FRAMES * a->channels * 2),
        SPA_PARAM_BUFFERS_stride, SPA_POD_Int(a->channels * 2));
    params[1] = spa_pod_builder_add_object(&builder, SPA_TYPE_OBJECT_ParamMeta, SPA_PARAM_Meta,
        SPA_PARAM_META_type, SPA_POD_Id(SPA_META_Header), SPA_PARAM_META_size, SPA_POD_Int(sizeof(struct spa_meta_header)));
    int res = pw_stream_update_params(a->stream, params, 2);
    if (res < 0) nl_end(a, res);
}
static const struct pw_core_events core_events = {
    PW_VERSION_CORE_EVENTS, .info = nl_core_info, .done = nl_done, .error = nl_error
};
static const struct pw_registry_events registry_events = {
    PW_VERSION_REGISTRY_EVENTS, .global = nl_global, .global_remove = nl_global_remove
};
static const struct pw_stream_events stream_events = {
    PW_VERSION_STREAM_EVENTS, .state_changed = nl_state, .param_changed = nl_format, .process = nl_process
};
void nl_pw_audio_init(void) { pw_init(NULL, NULL); }
static void nl_cleanup_error(int *first, int result) { if (result < 0 && !*first) *first = result; }
static int nl_run(struct nl_audio *a, int fd, int cancel_fd, int *cleanup) {
    *cleanup = 0;
    a->result = -EIO;
    a->main = pw_main_loop_new(NULL);
    if (!a->main) goto cleanup;
    struct pw_loop *loop = pw_main_loop_get_loop(a->main);
    a->timer = pw_loop_add_timer(loop, nl_tick, a);
    a->cancel = pw_loop_add_io(loop, cancel_fd, SPA_IO_IN | SPA_IO_ERR | SPA_IO_HUP, false, nl_cancel, a);
    if (!a->timer || !a->cancel) goto cleanup;
    struct timespec interval = { .tv_nsec = 5000000 };
    if (pw_loop_update_timer(loop, a->timer, &interval, &interval, false) < 0) goto cleanup;
    a->context = pw_context_new(loop, NULL, 0);
    if (!a->context) goto cleanup;
    a->core = pw_context_connect_fd(a->context, fd, NULL, 0);
    fd = -1; /* connect_fd consumes even on error. */
    if (!a->core) goto cleanup;
    if (pw_core_add_listener(a->core, &a->core_hook, &core_events, a) < 0) goto cleanup;
    a->core_listening = true;
    a->registry = pw_core_get_registry(a->core, PW_VERSION_REGISTRY, 0);
    if (!a->registry || pw_registry_add_listener(a->registry, &a->registry_hook, &registry_events, a) < 0) goto cleanup;
    a->registry_listening = true;
    a->registry_sync = pw_core_sync(a->core, PW_ID_CORE, 0);
    if (a->registry_sync < 0) goto cleanup;
    if (!a->enumerate) {
        struct pw_properties *props = pw_properties_new(
            PW_KEY_MEDIA_TYPE, "Audio", PW_KEY_MEDIA_CATEGORY, a->capture ? "Capture" : "Playback",
            PW_KEY_MEDIA_ROLE, "Communication", PW_KEY_NODE_NAME, a->capture ? "nestlink-system-audio-capture" : "nestlink-system-audio-playback",
            PW_KEY_STREAM_CAPTURE_SINK, a->capture ? "true" : "false",
            PW_KEY_NODE_DONT_RECONNECT, "true", "node.dont-move", "true",
            "adapter.auto-port-config", "{ mode = dsp monitor = false position = preserve }",
            PW_KEY_NODE_LATENCY, "960/48000", PW_KEY_NODE_MAX_LATENCY, "1920/48000", PW_KEY_NODE_RATE, "1/48000", NULL);
        if (!props) goto cleanup;
        if (pw_properties_setf(props, PW_KEY_TARGET_OBJECT, "%" PRIu64, a->target->serial) < 0) {
            pw_properties_free(props); goto cleanup;
        }
        a->stream = pw_stream_new(a->core, "NestLink selected system audio", props);
        if (!a->stream) goto cleanup;
        pw_stream_add_listener(a->stream, &a->stream_hook, &stream_events, a);
        uint8_t memory[512];
        struct spa_pod_builder builder = SPA_POD_BUILDER_INIT(memory, sizeof(memory));
        struct spa_audio_info_raw info = { .format = SPA_AUDIO_FORMAT_S16, .rate = 48000, .channels = a->channels };
        info.position[0] = a->channels == 1 ? SPA_AUDIO_CHANNEL_MONO : SPA_AUDIO_CHANNEL_FL;
        info.position[1] = SPA_AUDIO_CHANNEL_FR;
        const struct spa_pod *format = spa_format_audio_raw_build(&builder, SPA_PARAM_EnumFormat, &info);
        int res = pw_stream_connect(a->stream, a->capture ? PW_DIRECTION_INPUT : PW_DIRECTION_OUTPUT, PW_ID_ANY,
            PW_STREAM_FLAG_AUTOCONNECT | PW_STREAM_FLAG_INACTIVE | PW_STREAM_FLAG_MAP_BUFFERS | PW_STREAM_FLAG_DONT_RECONNECT,
            &format, 1);
        if (res < 0) { a->result = res; goto cleanup; }
    }
    nl_control(a, true);
    if (!a->closing) pw_main_loop_run(a->main);
cleanup:
    a->closing = true;
    if (a->stream) {
        if (a->pending) {
            /* Return capture memory, but never queue unsent playback PCM. */
            if (a->capture) nl_cleanup_error(cleanup, pw_stream_queue_buffer(a->stream, a->pending));
            a->pending = NULL;
        }
        nl_cleanup_error(cleanup, pw_stream_set_active(a->stream, false));
        nl_cleanup_error(cleanup, pw_stream_flush(a->stream, false));
        nl_cleanup_error(cleanup, pw_stream_disconnect(a->stream));
        spa_hook_remove(&a->stream_hook); pw_stream_destroy(a->stream);
    }
    if (a->node) { if (a->node_listening) spa_hook_remove(&a->node_hook); pw_proxy_destroy((struct pw_proxy *)a->node); }
    if (a->registry) { if (a->registry_listening) spa_hook_remove(&a->registry_hook); pw_proxy_destroy((struct pw_proxy *)a->registry); }
    if (a->core) { if (a->core_listening) spa_hook_remove(&a->core_hook); nl_cleanup_error(cleanup, pw_core_disconnect(a->core)); }
    if (a->context) pw_context_destroy(a->context);
    if (a->main) {
        struct pw_loop *loop = pw_main_loop_get_loop(a->main);
        if (a->cancel) pw_loop_destroy_source(loop, a->cancel);
        if (a->timer) pw_loop_destroy_source(loop, a->timer);
        pw_main_loop_destroy(a->main);
    }
    if (fd >= 0) close(fd);
    return a->result;
}
int nl_pw_audio_enumerate(int fd, int cancel, nl_audio_endpoint_fn endpoint,
                         nl_audio_control_fn control, void *user, uint32_t *cookie) {
    if (fd < 0 || cancel < 0 || !endpoint || !control || !user || !cookie) {
        if (fd >= 0) close(fd);
        return -EINVAL;
    }
    struct nl_audio a = { .enumerate = true, .endpoint = endpoint, .control = control, .user = user };
    int cleanup, result = nl_run(&a, fd, cancel, &cleanup);
    *cookie = a.cookie;
    return result < 0 ? result : cleanup;
}
int nl_pw_audio_run(int fd, int cancel, const struct nl_audio_target *target,
                    uint32_t channels, int capture, nl_audio_control_fn control,
                    nl_audio_capture_fn read, nl_audio_play_fn write, void *user, int *cleanup) {
    if (fd < 0 || cancel < 0 || !target || !target->node || target->node == SPA_ID_INVALID
        || !target->serial || !nl_text(target->name) || channels < 1 || channels > 2
        || (capture != 0 && capture != 1) || !control || !user || !cleanup
        || (capture ? !read : !write)) {
        if (fd >= 0) close(fd);
        if (cleanup) *cleanup = 0;
        return -EINVAL;
    }
    struct nl_audio a = { .target = target, .channels = channels, .capture = capture,
        .control = control, .read = read, .write = write, .user = user };
    return nl_run(&a, fd, cancel, cleanup);
}
