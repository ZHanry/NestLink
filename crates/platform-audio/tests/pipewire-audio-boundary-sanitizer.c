/* First-party adversarial corpus for the exact production ABI validators.
 * The system libpipewire itself is dynamically linked, not instrumented. */
#include "../src/pipewire_audio.c"
#include <assert.h>
#include <stdio.h>

static uint32_t random_value(uint32_t *state) {
    *state ^= *state << 13; *state ^= *state >> 17; *state ^= *state << 5;
    return *state;
}
int main(void) {
    struct pw_time clock = { .rate = { 1, 48000 }, .delay = 480, .queued = 480, .buffered = 960 };
    struct nl_audio_play_timing timing = nl_play_timing(&clock);
    assert(timing.latency_known && timing.latency_ns == 10000000 && timing.queued_frames == 1440);
    clock.rate.denom = 44100; clock.delay = 441;
    timing = nl_play_timing(&clock); assert(timing.latency_known && timing.latency_ns == 10000000);
    clock.delay = -1; timing = nl_play_timing(&clock); assert(!timing.latency_known);
    clock.delay = 480; clock.rate.denom = 0; timing = nl_play_timing(&clock); assert(!timing.latency_known);

    int16_t storage[32768] = {0};
    struct spa_chunk chunk = { .offset = 0, .size = 960 * 4, .stride = 4, .flags = 0 };
    struct spa_data data = { .type = SPA_DATA_MemPtr, .flags = SPA_DATA_FLAG_READWRITE,
        .data = storage, .maxsize = sizeof(storage), .chunk = &chunk };
    struct spa_buffer buffer = { .n_datas = 1, .datas = &data };
    int16_t *samples; uint32_t frames; bool silence;
    assert(nl_audio_view(&buffer, 2, true, &samples, &frames, &silence) == 0);
    assert(samples == storage && frames == 960 && !silence);
    chunk.offset = 16; chunk.flags = SPA_CHUNK_FLAG_EMPTY;
    assert(nl_audio_view(&buffer, 2, true, &samples, &frames, &silence) == 0);
    assert(samples == storage + 8 && silence);
    chunk.flags = SPA_CHUNK_FLAG_CORRUPTED;
    assert(nl_audio_view(&buffer, 2, true, &samples, &frames, &silence) < 0);
    data.flags = SPA_DATA_FLAG_READABLE;
    assert(nl_audio_view(&buffer, 2, false, &samples, &frames, &silence) < 0);
    data.flags = SPA_DATA_FLAG_READWRITE;
    uint32_t state = 0x97a316b5;
    for (unsigned i = 0; i < 100000; ++i) {
        uint32_t channels = random_value(&state) % 5;
        chunk.offset = random_value(&state);
        chunk.size = random_value(&state);
        chunk.stride = (int32_t)random_value(&state);
        chunk.flags = random_value(&state);
        data.maxsize = random_value(&state);
        buffer.n_datas = random_value(&state) % 4;
        if (i % 3 == 0) {
            channels = 1 + random_value(&state) % 2;
            chunk.offset = (random_value(&state) % 100) * channels * 2;
            chunk.size = (random_value(&state) % 2200) * channels * 2;
            chunk.stride = (int32_t)(channels * 2);
            chunk.flags = (i % 2) ? SPA_CHUNK_FLAG_EMPTY : 0;
            data.maxsize = sizeof(storage); buffer.n_datas = 1;
        }
        int result = nl_audio_view(&buffer, channels, true, &samples, &frames, &silence);
        if (result == 0) {
            assert(frames > 0 && frames <= NL_AUDIO_FRAMES);
            assert((uintptr_t)samples >= (uintptr_t)storage);
            assert((uintptr_t)samples + frames * channels * 2 <= (uintptr_t)storage + sizeof(storage));
            volatile int16_t first = samples[0], last = samples[frames * channels - 1];
            (void)first; (void)last;
        }
    }
    struct nl_link links[NL_AUDIO_LINKS] = {0};
    links[0] = (struct nl_link){ .id = 1, .input = 90, .output = 55, .present = true };
    links[1] = (struct nl_link){ .id = 2, .input = 90, .output = 55, .present = true };
    assert(nl_graph_links(links, 90, 55, true, false) == 1);
    assert(nl_graph_links(links, 55, 90, false, false) == 1);
    links[1].output = 56;
    assert(nl_graph_links(links, 90, 55, true, false) == -ESTALE);
    links[0].present = false; links[1].present = false;
    assert(nl_graph_links(links, 90, 55, true, true) == -ESTALE);
    assert(nl_graph_links(links, 90, 55, true, false) == 0);
    const struct spa_dict_item items[] = { { PW_KEY_OBJECT_SERIAL, "18446744073709551615" }, { PW_KEY_LINK_INPUT_NODE, "4294967296" } };
    const struct spa_dict properties = SPA_DICT_INIT_ARRAY(items);
    uint64_t serial; uint32_t node;
    assert(nl_u64(&properties, PW_KEY_OBJECT_SERIAL, &serial) && serial == UINT64_MAX);
    assert(!nl_id(&properties, PW_KEY_LINK_INPUT_NODE, &node));
    puts("PipeWire audio production validators: 100000 PCM cases, permissions, channel/offset/stride bounds, silence, links and uint64 serial passed");
    return 0;
}
