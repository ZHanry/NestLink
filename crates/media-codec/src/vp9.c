/* Thin boundary around the fixed libvpx/libyuv public APIs. No VP9 parser. */
#include <vpx/vp8cx.h>
#include <vpx/vp8dx.h>
#include <vpx/vpx_decoder.h>
#include <vpx/vpx_encoder.h>
#include <libyuv/convert_argb.h>
#include <libyuv/convert_from_argb.h>
#include <libyuv/planar_functions.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NL_RAW_LIMIT (64u * 1024u * 1024u)
#define NL_PACKET_LIMIT (8u * 1024u * 1024u)
#define NL_FRAME_LIMIT ((INT64_MAX - 10000000) / 10000000)
enum { NL_OK, NL_INVALID, NL_MEMORY, NL_CODEC, NL_OUTPUT };
typedef int (*nl_video_packet)(void *, const uint8_t *, size_t, uint64_t, uint32_t);
struct nl_vp9_encoder {
    vpx_codec_ctx_t codec;
    vpx_image_t image;
    uint8_t *rgb;
    uint32_t width, height;
    int64_t last_pts, frame_index;
    int have_pts;
};
struct nl_vp9_decoder {
    vpx_codec_ctx_t codec;
    uint8_t *rgb;
    uint32_t width, height;
};
static void wipe(void *data, size_t bytes) {
    volatile uint8_t *at = data;
    while (bytes--) *at++ = 0;
}
static int geometry(uint32_t width, uint32_t height) {
    return width >= 16 && height >= 16 && width <= 8192 && height <= 8192
        && (uint64_t)width * height * 4 <= NL_RAW_LIMIT;
}
/* Public library parsing precedes decoder allocation for every independent
 * keyframe. Hidden/inter/reference frames are not part of this exact mode. */
int nl_vp9_peek(const uint8_t *packet, size_t length, uint32_t width, uint32_t height) {
    if (!packet || !length || length > NL_PACKET_LIMIT || !geometry(width, height)) return NL_INVALID;
    vpx_codec_stream_info_t info = { .sz = sizeof(info) };
    if (vpx_codec_peek_stream_info(vpx_codec_vp9_dx(), packet, (unsigned int)length, &info)
        || !info.is_kf || info.w != width || info.h != height) return NL_INVALID;
    return NL_OK;
}
int nl_vp9_encoder_create(uint32_t width, uint32_t height, uint32_t fps, uint32_t kbps, void **out) {
    if (!out) return NL_INVALID;
    *out = NULL;
    if (!geometry(width, height) || !fps || fps > 144 || kbps < 64 || kbps > 100000) return NL_INVALID;
    if (vpx_codec_version() != ((1 << 16) | (16 << 8))) return NL_CODEC;
    struct nl_vp9_encoder *s = calloc(1, sizeof(*s));
    if (!s) return NL_MEMORY;
    vpx_codec_enc_cfg_t cfg;
    if (vpx_codec_enc_config_default(vpx_codec_vp9_cx(), &cfg, 0)) { free(s); return NL_CODEC; }
    cfg.g_w = width; cfg.g_h = height; cfg.g_threads = 2;
    cfg.g_profile = 1; cfg.g_bit_depth = VPX_BITS_8; cfg.g_input_bit_depth = 8;
    cfg.g_timebase.num = 1; cfg.g_timebase.den = (int)fps;
    cfg.g_pass = VPX_RC_ONE_PASS; cfg.g_lag_in_frames = 0;
    cfg.g_error_resilient = 0;
    cfg.rc_end_usage = VPX_CBR; cfg.rc_target_bitrate = kbps;
    cfg.rc_dropframe_thresh = 0; cfg.rc_resize_allowed = 0;
    cfg.rc_min_quantizer = 0; cfg.rc_max_quantizer = 32;
    cfg.kf_mode = VPX_KF_DISABLED; cfg.kf_min_dist = 0; cfg.kf_max_dist = 0;
    if (vpx_codec_enc_init(&s->codec, vpx_codec_vp9_cx(), &cfg, 0)) { free(s); return NL_CODEC; }
    if (vpx_codec_control(&s->codec, VP8E_SET_CPUUSED, 8)
        || vpx_codec_control(&s->codec, VP8E_SET_ENABLEAUTOALTREF, 0)
        || vpx_codec_control(&s->codec, VP9E_SET_FRAME_PARALLEL_DECODING, 0u)
        || vpx_codec_control(&s->codec, VP9E_SET_TILE_COLUMNS, 0)
        || vpx_codec_control(&s->codec, VP9E_SET_TILE_ROWS, 0)
        || vpx_codec_control(&s->codec, VP9E_SET_TUNE_CONTENT, VP9E_CONTENT_SCREEN)
        || vpx_codec_control(&s->codec, VP9E_SET_COLOR_SPACE, VPX_CS_SRGB)
        || vpx_codec_control(&s->codec, VP9E_SET_COLOR_RANGE, VPX_CR_FULL_RANGE)
        || !vpx_img_alloc(&s->image, VPX_IMG_FMT_I444, width, height, 1)) {
        vpx_codec_destroy(&s->codec); free(s); return NL_CODEC;
    }
    s->rgb = malloc((size_t)width * height * 3);
    if (!s->rgb) { vpx_img_free(&s->image); vpx_codec_destroy(&s->codec); free(s); return NL_MEMORY; }
    s->image.cs = VPX_CS_SRGB; s->image.range = VPX_CR_FULL_RANGE;
    s->width = width; s->height = height;
    *out = s; return NL_OK;
}
int nl_vp9_encode(void *opaque, const uint8_t *bgra, size_t length, uint64_t pts,
    nl_video_packet callback, void *user) {
    struct nl_vp9_encoder *s = opaque;
    if (!s || !bgra || !callback || length != (size_t)s->width * s->height * 4
        || pts > INT64_MAX || (s->have_pts && pts <= (uint64_t)s->last_pts)
        || s->frame_index >= NL_FRAME_LIMIT) return NL_INVALID;
    if (ARGBToRAW(bgra, (int)s->width * 4, s->rgb, (int)s->width * 3, (int)s->width, (int)s->height)) return NL_OUTPUT;
    /* VP9 sRGB uses G/B/R in its Y/U/V storage; all three planes are full size. */
    SplitRGBPlane(s->rgb, (int)s->width * 3, s->image.planes[2], s->image.stride[2],
        s->image.planes[0], s->image.stride[0], s->image.planes[1], s->image.stride[1],
        (int)s->width, (int)s->height);
    const int64_t frame_index = s->frame_index;
    if (vpx_codec_encode(&s->codec, &s->image, frame_index, 1, VPX_EFLAG_FORCE_KF, VPX_DL_REALTIME)) return NL_CODEC;
    s->last_pts = (int64_t)pts; s->have_pts = 1; ++s->frame_index;
    vpx_codec_iter_t iterator = NULL;
    const vpx_codec_cx_pkt_t *packet;
    unsigned int frames = 0;
    while ((packet = vpx_codec_get_cx_data(&s->codec, &iterator))) {
        if (packet->kind != VPX_CODEC_CX_FRAME_PKT) continue;
        if (++frames != 1 || !packet->data.frame.buf || !packet->data.frame.sz
            || packet->data.frame.sz > NL_PACKET_LIMIT || packet->data.frame.pts != frame_index
            || (packet->data.frame.flags & (VPX_FRAME_IS_FRAGMENT | VPX_FRAME_IS_INVISIBLE))
            || !(packet->data.frame.flags & VPX_FRAME_IS_KEY)
            || nl_vp9_peek(packet->data.frame.buf, packet->data.frame.sz, s->width, s->height)) return NL_OUTPUT;
        if (callback(user, packet->data.frame.buf, packet->data.frame.sz, pts, 1)) return NL_OUTPUT;
    }
    return frames == 1 ? NL_OK : NL_OUTPUT;
}
int nl_vp9_encoder_close(void *opaque) {
    struct nl_vp9_encoder *s = opaque;
    if (!s) return NL_INVALID;
    if (vpx_codec_destroy(&s->codec)) return NL_CODEC;
    wipe(s->rgb, (size_t)s->width * s->height * 3); free(s->rgb);
    for (unsigned int plane = 0; plane < 3; ++plane)
        for (uint32_t row = 0; row < s->height; ++row)
            wipe(s->image.planes[plane] + (size_t)row * s->image.stride[plane], s->width);
    vpx_img_free(&s->image); free(s); return NL_OK;
}
int nl_vp9_decoder_create(uint32_t width, uint32_t height, void **out) {
    if (!out) return NL_INVALID;
    *out = NULL;
    if (!geometry(width, height)) return NL_INVALID;
    if (vpx_codec_version() != ((1 << 16) | (16 << 8))) return NL_CODEC;
    struct nl_vp9_decoder *s = calloc(1, sizeof(*s));
    if (!s) return NL_MEMORY;
    vpx_codec_dec_cfg_t cfg = { .threads = 2, .w = width, .h = height };
    if (vpx_codec_dec_init(&s->codec, vpx_codec_vp9_dx(), &cfg, 0)) { free(s); return NL_CODEC; }
    s->rgb = malloc((size_t)width * height * 3);
    if (!s->rgb) { vpx_codec_destroy(&s->codec); free(s); return NL_MEMORY; }
    s->width = width; s->height = height; *out = s; return NL_OK;
}
int nl_vp9_decode(void *opaque, const uint8_t *packet, size_t length, uint8_t *bgra, size_t bytes) {
    struct nl_vp9_decoder *s = opaque;
    if (!s || !bgra || bytes != (size_t)s->width * s->height * 4
        || nl_vp9_peek(packet, length, s->width, s->height)) return NL_INVALID;
    if (vpx_codec_decode(&s->codec, packet, (unsigned int)length, NULL, 0)) return NL_CODEC;
    int corrupted = 0;
    if (vpx_codec_control(&s->codec, VP8D_GET_FRAME_CORRUPTED, &corrupted) || corrupted) return NL_CODEC;
    vpx_codec_iter_t iterator = NULL;
    vpx_image_t *image = vpx_codec_get_frame(&s->codec, &iterator);
    if (!image || image->fmt != VPX_IMG_FMT_I444 || image->bit_depth != 8
        || image->x_chroma_shift || image->y_chroma_shift
        || image->cs != VPX_CS_SRGB || image->range != VPX_CR_FULL_RANGE
        || image->d_w != s->width || image->d_h != s->height) return NL_OUTPUT;
    for (unsigned int plane = 0; plane < 3; ++plane)
        if (!image->planes[plane] || image->stride[plane] < (int)s->width) return NL_OUTPUT;
    MergeRGBPlane(image->planes[2], image->stride[2], image->planes[0], image->stride[0],
        image->planes[1], image->stride[1], s->rgb, (int)s->width * 3, (int)s->width, (int)s->height);
    if (RAWToARGB(s->rgb, (int)s->width * 3, bgra, (int)s->width * 4, (int)s->width, (int)s->height)) return NL_OUTPUT;
    if (vpx_codec_get_frame(&s->codec, &iterator)) return NL_OUTPUT;
    return NL_OK;
}
int nl_vp9_decoder_close(void *opaque) {
    struct nl_vp9_decoder *s = opaque;
    if (!s) return NL_INVALID;
    if (vpx_codec_destroy(&s->codec)) return NL_CODEC;
    wipe(s->rgb, (size_t)s->width * s->height * 3); free(s->rgb); free(s); return NL_OK;
}
