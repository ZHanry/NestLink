/* First-party narrow wrapper around the public Opus 1.6.1 API. */
#include <opus/opus.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NL_OPUS_RATE 48000
#define NL_OPUS_SAMPLES 960
#define NL_OPUS_PACKET 1275

_Static_assert(sizeof(opus_int16) == sizeof(int16_t), "Opus PCM ABI mismatch");

struct nl_opus_encoder {
    OpusEncoder *codec;
    uint32_t channels;
};
struct nl_opus_decoder {
    OpusDecoder *codec;
    uint32_t channels;
};

static int nl_opus_channels(uint32_t channels) {
    return channels == 1 || channels == 2;
}
static int nl_opus_version(void) {
    const char *version = opus_get_version_string();
    return version != NULL && strcmp(version, "libopus 1.6.1") == 0;
}

/* Validate the complete framing before the decoder sees untrusted bytes.
 * Opus can otherwise transparently resample channels or decode up to 120 ms.
 * This transport has one negotiated channel count and exactly 20 ms per packet.
 */
static int nl_opus_packet(const uint8_t *packet, uint32_t bytes,
                          uint32_t channels) {
    if (packet == NULL || bytes == 0 || bytes > NL_OPUS_PACKET ||
        !nl_opus_channels(channels))
        return OPUS_INVALID_PACKET;
    if (opus_packet_get_nb_channels(packet) != (int)channels ||
        opus_packet_get_nb_samples(packet, (opus_int32)bytes, NL_OPUS_RATE) !=
            NL_OPUS_SAMPLES)
        return OPUS_INVALID_PACKET;
    opus_int16 sizes[48];
    const unsigned char *frames[48];
    unsigned char toc;
    int payload_offset;
    int count = opus_packet_parse(packet, (opus_int32)bytes, &toc, frames,
                                  sizes, &payload_offset);
    if (count <= 0)
        return OPUS_INVALID_PACKET;
    for (int i = 0; i < count; ++i) {
        /* A zero-byte coded frame asks Opus to conceal loss. That operation
         * is available only through our explicit conceal_loss entry point. */
        if (sizes[i] <= 0)
            return OPUS_INVALID_PACKET;
    }
    return OPUS_OK;
}

int32_t nl_opus_encoder_new(uint32_t channels, uint32_t bitrate, void **out) {
    if (out == NULL)
        return OPUS_BAD_ARG;
    *out = NULL;
    if (!nl_opus_channels(channels) || bitrate < 6000 || bitrate > 256000)
        return OPUS_BAD_ARG;
    if (!nl_opus_version())
        return OPUS_UNIMPLEMENTED;
    int error = OPUS_OK;
    OpusEncoder *codec = opus_encoder_create(NL_OPUS_RATE, (int)channels,
                                             OPUS_APPLICATION_AUDIO, &error);
    if (codec == NULL)
        return error == OPUS_OK ? OPUS_ALLOC_FAIL : error;
    /* Fixed channel identity must match the negotiated stream even at low
     * bitrate. FEC and DTX are deliberately absent from this initial API. */
    if ((error = opus_encoder_ctl(codec, OPUS_SET_BITRATE((opus_int32)bitrate))) != OPUS_OK ||
        (error = opus_encoder_ctl(codec, OPUS_SET_FORCE_CHANNELS((int)channels))) != OPUS_OK ||
        (error = opus_encoder_ctl(codec, OPUS_SET_VBR(1))) != OPUS_OK ||
        (error = opus_encoder_ctl(codec, OPUS_SET_COMPLEXITY(5))) != OPUS_OK ||
        (error = opus_encoder_ctl(codec, OPUS_SET_DTX(0))) != OPUS_OK ||
        (error = opus_encoder_ctl(codec, OPUS_SET_INBAND_FEC(0))) != OPUS_OK ||
        (error = opus_encoder_ctl(codec, OPUS_SET_PACKET_LOSS_PERC(0))) != OPUS_OK) {
        opus_encoder_destroy(codec);
        return error;
    }
    struct nl_opus_encoder *encoder = malloc(sizeof(*encoder));
    if (encoder == NULL) {
        opus_encoder_destroy(codec);
        return OPUS_ALLOC_FAIL;
    }
    encoder->codec = codec;
    encoder->channels = channels;
    *out = encoder;
    return OPUS_OK;
}

void nl_opus_encoder_free(void *opaque) {
    struct nl_opus_encoder *encoder = opaque;
    if (encoder != NULL) {
        opus_encoder_destroy(encoder->codec);
        free(encoder);
    }
}

int32_t nl_opus_encode(void *opaque, const int16_t *pcm, uint32_t samples,
                       uint8_t *packet, uint32_t capacity) {
    struct nl_opus_encoder *encoder = opaque;
    if (encoder == NULL || pcm == NULL || packet == NULL ||
        samples != NL_OPUS_SAMPLES * encoder->channels ||
        capacity != NL_OPUS_PACKET)
        return OPUS_BAD_ARG;
    opus_int32 bytes = opus_encode(encoder->codec, pcm, NL_OPUS_SAMPLES,
                                   packet, (opus_int32)capacity);
    if (bytes < 0)
        return bytes;
    if (nl_opus_packet(packet, (uint32_t)bytes, encoder->channels) != OPUS_OK)
        return OPUS_INTERNAL_ERROR;
    return bytes;
}

int32_t nl_opus_encoder_reset(void *opaque) {
    struct nl_opus_encoder *encoder = opaque;
    if (encoder == NULL)
        return OPUS_BAD_ARG;
    return opus_encoder_ctl(encoder->codec, OPUS_RESET_STATE);
}

int32_t nl_opus_decoder_new(uint32_t channels, void **out) {
    if (out == NULL)
        return OPUS_BAD_ARG;
    *out = NULL;
    if (!nl_opus_channels(channels))
        return OPUS_BAD_ARG;
    if (!nl_opus_version())
        return OPUS_UNIMPLEMENTED;
    int error = OPUS_OK;
    OpusDecoder *codec = opus_decoder_create(NL_OPUS_RATE, (int)channels, &error);
    if (codec == NULL)
        return error == OPUS_OK ? OPUS_ALLOC_FAIL : error;
    struct nl_opus_decoder *decoder = malloc(sizeof(*decoder));
    if (decoder == NULL) {
        opus_decoder_destroy(codec);
        return OPUS_ALLOC_FAIL;
    }
    decoder->codec = codec;
    decoder->channels = channels;
    *out = decoder;
    return OPUS_OK;
}

void nl_opus_decoder_free(void *opaque) {
    struct nl_opus_decoder *decoder = opaque;
    if (decoder != NULL) {
        opus_decoder_destroy(decoder->codec);
        free(decoder);
    }
}

int32_t nl_opus_decode(void *opaque, const uint8_t *packet, uint32_t bytes,
                       int16_t *pcm, uint32_t samples) {
    struct nl_opus_decoder *decoder = opaque;
    if (decoder == NULL || pcm == NULL ||
        samples != NL_OPUS_SAMPLES * decoder->channels)
        return OPUS_BAD_ARG;
    int error = nl_opus_packet(packet, bytes, decoder->channels);
    if (error != OPUS_OK)
        return error;
    /* A nonempty valid payload always decodes normally; never request FEC or
     * accidentally reinterpret an empty network packet as loss concealment. */
    int decoded = opus_decode(decoder->codec, packet, (opus_int32)bytes, pcm,
                               NL_OPUS_SAMPLES, 0);
    if (decoded < 0)
        return decoded;
    return decoded == NL_OPUS_SAMPLES ? decoded : OPUS_INTERNAL_ERROR;
}

int32_t nl_opus_validate_packet(const uint8_t *packet, uint32_t bytes, uint32_t channels) {
    if (!nl_opus_channels(channels))
        return OPUS_BAD_ARG;
    return nl_opus_packet(packet, bytes, channels);
}

int32_t nl_opus_conceal(void *opaque, int16_t *pcm, uint32_t samples) {
    struct nl_opus_decoder *decoder = opaque;
    if (decoder == NULL || pcm == NULL ||
        samples != NL_OPUS_SAMPLES * decoder->channels)
        return OPUS_BAD_ARG;
    int decoded = opus_decode(decoder->codec, NULL, 0, pcm, NL_OPUS_SAMPLES, 0);
    if (decoded < 0)
        return decoded;
    return decoded == NL_OPUS_SAMPLES ? decoded : OPUS_INTERNAL_ERROR;
}

int32_t nl_opus_decoder_reset(void *opaque) {
    struct nl_opus_decoder *decoder = opaque;
    if (decoder == NULL)
        return OPUS_BAD_ARG;
    return opus_decoder_ctl(decoder->codec, OPUS_RESET_STATE);
}
