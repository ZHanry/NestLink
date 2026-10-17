/* Apache-2.0. Narrow first-party ABI; no application permission decisions. */
#ifndef NL_PIPEWIRE_AUDIO_H
#define NL_PIPEWIRE_AUDIO_H
#include <stdint.h>
#include <stddef.h>
struct nl_audio_target {
    uint32_t node, cookie;
    uint64_t serial;
    const char *name;
};
struct nl_audio_packet {
    uint64_t position, age_ns;
    uint32_t frames, discontinuity, graph_rate_num, graph_rate_denom;
};
typedef int (*nl_audio_endpoint_fn)(void *, uint32_t, uint32_t, uint64_t,
                                  const char *, const char *);
/* timer=1 is the sole worker heartbeat. Progress bits: 1 ready, 2 core cookie,
 * 4 registry sync, 8 target serial, 16 node properties, 32 negotiated format,
 * 64 actual links, 128 connected. Inactive streams may negotiate PCM only after
 * activation; PCM is forbidden until bit 32. Callback result 0 stays inactive,
 * 1 arms a ready stream, 2 cancels, negative returns -errno. */
typedef int (*nl_audio_control_fn)(void *, int timer, int ready);
typedef int (*nl_audio_capture_fn)(void *, const struct nl_audio_packet *, const int16_t *);
struct nl_audio_play_timing { uint64_t latency_ns; uint32_t queued_frames, latency_known; };
typedef int (*nl_audio_play_fn)(void *, int16_t *, uint32_t frames, const struct nl_audio_play_timing *);
void nl_pw_audio_init(void);
/* Each entry point consumes fd on every return path; all other values are
 * borrowed synchronously. The callbacks run on this calling thread. */
int nl_pw_audio_enumerate(int fd, int cancel, nl_audio_endpoint_fn,
                         nl_audio_control_fn, void *, uint32_t *cookie);
int nl_pw_audio_run(int fd, int cancel, const struct nl_audio_target *,
                    uint32_t channels, int capture, nl_audio_control_fn,
                    nl_audio_capture_fn, nl_audio_play_fn, void *, int *cleanup);
#endif
