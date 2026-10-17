/* Apache-2.0. First-party boundary around the public libvpx API. */
#include <vpx/vp8cx.h>
#include <vpx/vp8dx.h>
#include <vpx/vpx_decoder.h>
#include <vpx/vpx_encoder.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NL_RAW_LIMIT (64u * 1024u * 1024u)
#define NL_PACKET_LIMIT (8u * 1024u * 1024u)
/* libvpx rescales time to 10,000,000 ticks/second. Reserve room for
 * duration and rounding; this bound is over 2,000 years even at 120 fps. */
#define NL_FRAME_LIMIT ((INT64_MAX - 10000000) / 10000000)
/* Stable bridge errors; no libvpx structure or versioned ABI reaches Rust. */
enum { NL_OK, NL_INVALID, NL_MEMORY, NL_CODEC, NL_OUTPUT };
typedef int (*nl_vp8_packet)(void *, const uint8_t *, size_t, uint64_t, uint32_t);
struct nl_vp8_encoder {
    vpx_codec_ctx_t codec;
    vpx_codec_enc_cfg_t config;
    vpx_image_t image;
    uint32_t width, height;
    int64_t last_pts, frame_index;
    int have_pts;
};
struct nl_vp8_decoder {
    vpx_codec_ctx_t codec;
    uint32_t width, height;
    int have_keyframe;
};
static int nl_geometry(uint32_t width, uint32_t height) {
    return width && height && width <= 8192 && height <= 8192
        && (uint64_t)width * height * 4 <= NL_RAW_LIMIT;
}
static size_t nl_i420_size(uint32_t width, uint32_t height) {
    return (size_t)width * height + 2 * (size_t)((width + 1) / 2) * ((height + 1) / 2);
}
int nl_vp8_encoder_create(uint32_t width, uint32_t height, uint32_t fps,
                          uint32_t bitrate_kbps, void **out) {
    if (!out) return NL_INVALID;
    *out = NULL;
    if (!nl_geometry(width, height) || !fps || fps > 120 || bitrate_kbps < 64 || bitrate_kbps > 100000)
        return NL_INVALID;
    if (vpx_codec_version() != ((1 << 16) | (16 << 8))) return NL_CODEC;
    struct nl_vp8_encoder *encoder = calloc(1, sizeof(*encoder));
    if (!encoder) return NL_MEMORY;
    vpx_codec_enc_cfg_t config;
    if (vpx_codec_enc_config_default(vpx_codec_vp8_cx(), &config, 0)) { free(encoder); return NL_CODEC; }
    config.g_w = width; config.g_h = height; config.g_threads = 2;
    config.g_timebase.num = 1; config.g_timebase.den = (int)fps;
    config.g_pass = VPX_RC_ONE_PASS; config.g_lag_in_frames = 0;
    config.g_error_resilient = VPX_ERROR_RESILIENT_DEFAULT;
    config.rc_end_usage = VPX_CBR; config.rc_target_bitrate = bitrate_kbps;
    config.rc_dropframe_thresh = 0; config.rc_resize_allowed = 0;
    config.kf_mode = VPX_KF_AUTO; config.kf_min_dist = 0; config.kf_max_dist = fps * 2;
    if (vpx_codec_enc_init(&encoder->codec, vpx_codec_vp8_cx(), &config, 0)) { free(encoder); return NL_CODEC; }
    if (vpx_codec_control(&encoder->codec, VP8E_SET_CPUUSED, 8)
        || vpx_codec_control(&encoder->codec, VP8E_SET_ENABLEAUTOALTREF, 0)
        || vpx_codec_control(&encoder->codec, VP8E_SET_SCREEN_CONTENT_MODE, 1u)) {
        vpx_codec_destroy(&encoder->codec); free(encoder); return NL_CODEC;
    }
    if (!vpx_img_alloc(&encoder->image, VPX_IMG_FMT_I420, width, height, 1)) {
        vpx_codec_destroy(&encoder->codec); free(encoder); return NL_MEMORY;
    }
    encoder->image.cs = VPX_CS_BT_601;
    encoder->image.range = VPX_CR_STUDIO_RANGE;
    encoder->width = width; encoder->height = height;
    encoder->config = config;
    *out = encoder;
    return NL_OK;
}
int nl_vp8_encoder_set_bitrate(void *handle, uint32_t bitrate_kbps) {
    struct nl_vp8_encoder *encoder = handle;
    if (!encoder || bitrate_kbps < 64 || bitrate_kbps > 100000) return NL_INVALID;
    if (encoder->config.rc_target_bitrate == bitrate_kbps) return NL_OK;
    vpx_codec_enc_cfg_t config = encoder->config;
    config.rc_target_bitrate = bitrate_kbps;
    if (vpx_codec_enc_config_set(&encoder->codec, &config)) return NL_CODEC;
    encoder->config = config;
    return NL_OK;
}
void nl_vp8_encoder_destroy(void *handle) {
    struct nl_vp8_encoder *encoder = handle;
    if (!encoder) return;
    vpx_img_free(&encoder->image);
    vpx_codec_destroy(&encoder->codec);
    free(encoder);
}
int nl_vp8_encode(void *handle, const uint8_t *i420, size_t length,
                  uint64_t pts, uint32_t force_keyframe, nl_vp8_packet callback, void *user) {
    struct nl_vp8_encoder *encoder = handle;
    if (!encoder || !i420 || !callback || force_keyframe > 1 || pts > INT64_MAX
        || (encoder->have_pts && pts <= (uint64_t)encoder->last_pts)
        || encoder->frame_index >= NL_FRAME_LIMIT
        || length != nl_i420_size(encoder->width, encoder->height)) return NL_INVALID;
    size_t offset = 0;
    for (unsigned int plane = 0; plane < 3; ++plane) {
        uint32_t width = plane ? (encoder->width + 1) / 2 : encoder->width;
        uint32_t height = plane ? (encoder->height + 1) / 2 : encoder->height;
        for (uint32_t row = 0; row < height; ++row) {
            memcpy(encoder->image.planes[plane] + (size_t)row * encoder->image.stride[plane], i420 + offset, width);
            offset += width;
        }
    }
    /* External 90 kHz presentation timestamps may have a large origin or gap.
     * Keep them as transport metadata; this fixed-fps profile uses a bounded
     * frame clock so libvpx's internal rescaling cannot overflow. */
    int64_t frame_index = encoder->frame_index;
    if (vpx_codec_encode(&encoder->codec, &encoder->image, frame_index, 1,
                         force_keyframe ? VPX_EFLAG_FORCE_KF : 0, VPX_DL_REALTIME)) return NL_CODEC;
    encoder->last_pts = (int64_t)pts; encoder->have_pts = 1; ++encoder->frame_index;
    vpx_codec_iter_t iterator = NULL;
    const vpx_codec_cx_pkt_t *packet;
    unsigned int frames = 0;
    while ((packet = vpx_codec_get_cx_data(&encoder->codec, &iterator))) {
        if (packet->kind != VPX_CODEC_CX_FRAME_PKT) continue;
        if (++frames != 1 || !packet->data.frame.buf || !packet->data.frame.sz
            || packet->data.frame.sz > NL_PACKET_LIMIT || packet->data.frame.pts != frame_index
            || (packet->data.frame.flags & VPX_FRAME_IS_FRAGMENT)) return NL_OUTPUT;
        /* libvpx only guarantees this pointer until the next vpx_codec_* call.
         * The synchronous Rust callback must copy before iteration continues. */
        if (callback(user, packet->data.frame.buf, packet->data.frame.sz, pts,
                     (packet->data.frame.flags & VPX_FRAME_IS_KEY) != 0)) return NL_OUTPUT;
    }
    /* This profile disables frame dropping, lookahead and hidden altref frames. */
    return frames == 1 ? NL_OK : NL_OUTPUT;
}
int nl_vp8_decoder_create(uint32_t width, uint32_t height, void **out) {
    if (!out) return NL_INVALID;
    *out = NULL;
    if (!nl_geometry(width, height)) return NL_INVALID;
    if (vpx_codec_version() != ((1 << 16) | (16 << 8))) return NL_CODEC;
    struct nl_vp8_decoder *decoder = calloc(1, sizeof(*decoder));
    if (!decoder) return NL_MEMORY;
    vpx_codec_dec_cfg_t config = { .threads = 2, .w = width, .h = height };
    if (vpx_codec_dec_init(&decoder->codec, vpx_codec_vp8_dx(), &config, 0)) { free(decoder); return NL_CODEC; }
    decoder->width = width; decoder->height = height;
    *out = decoder;
    return NL_OK;
}
void nl_vp8_decoder_destroy(void *handle) {
    struct nl_vp8_decoder *decoder = handle;
    if (!decoder) return;
    vpx_codec_destroy(&decoder->codec);
    free(decoder);
}
int nl_vp8_decode(void *handle, const uint8_t *packet, size_t length,
                  uint8_t *i420, size_t output_length) {
    struct nl_vp8_decoder *decoder = handle;
    if (!decoder || !packet || length < 3 || length > NL_PACKET_LIMIT || !i420
        || output_length != nl_i420_size(decoder->width, decoder->height)
        || !(packet[0] & 0x10)) return NL_INVALID;
    int keyframe = !(packet[0] & 1);
    size_t header = keyframe ? 10 : 3;
    size_t first_partition = ((size_t)packet[0] | (size_t)packet[1] << 8
                              | (size_t)packet[2] << 16) >> 5;
    if (length <= header || !first_partition || first_partition > length - header)
        return NL_INVALID;
    if (!keyframe && !decoder->have_keyframe) return NL_INVALID;
    if (keyframe) {
        if (length < 10 || (packet[7] & 0xc0) || (packet[9] & 0xc0)) return NL_INVALID;
        vpx_codec_stream_info_t info = { .sz = sizeof(info) };
        /* Validate keyframe geometry before libvpx can allocate reference
         * buffers. Interframes cannot change VP8 dimensions. */
        if (vpx_codec_peek_stream_info(vpx_codec_vp8_dx(), packet, (unsigned int)length, &info)
            || !info.is_kf || !nl_geometry(info.w, info.h)
            || info.w != decoder->width || info.h != decoder->height) return NL_INVALID;
    }
    if (vpx_codec_decode(&decoder->codec, packet, (unsigned int)length, NULL, 0)) return NL_CODEC;
    int corrupted = 0;
    if (vpx_codec_control(&decoder->codec, VP8D_GET_FRAME_CORRUPTED, &corrupted)
        || corrupted) return NL_CODEC;
    vpx_codec_iter_t iterator = NULL;
    vpx_image_t *image = vpx_codec_get_frame(&decoder->codec, &iterator);
    if (!image || image->fmt != VPX_IMG_FMT_I420 || image->bit_depth != 8
        || image->d_w != decoder->width || image->d_h != decoder->height) return NL_OUTPUT;
    size_t offset = 0;
    for (unsigned int plane = 0; plane < 3; ++plane) {
        uint32_t width = plane ? (decoder->width + 1) / 2 : decoder->width;
        uint32_t height = plane ? (decoder->height + 1) / 2 : decoder->height;
        if (!image->planes[plane] || image->stride[plane] < (int)width) return NL_OUTPUT;
        for (uint32_t row = 0; row < height; ++row) {
            memcpy(i420 + offset, image->planes[plane] + (size_t)row * image->stride[plane], width);
            offset += width;
        }
    }
    if (vpx_codec_get_frame(&decoder->codec, &iterator)) return NL_OUTPUT;
    decoder->have_keyframe = 1;
    return NL_OK;
}
