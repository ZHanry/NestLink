#pragma once
#include <cstdint>
// Independent HDR ring semantic version. Legacy SDR remains reserved=0.
constexpr uint32_t NL_SHARED_HDR10_VERSION=5;
struct NlSharedRingDescriptor {
    uint8_t ring_id[16]{};
    uint64_t adapter_luid=0;
    uint64_t handles[3]{};
    uint8_t resource_ids[3][16]{};
    uint32_t width=0,height=0;
    uint64_t bytes=0;
    uint32_t bit_depth=0,reserved=0;
};
struct NlSharedFrame {
    uint64_t token=0,pts=0,acquire_key=0,release_key=0,expires_qpc=0;
    uint32_t slot=0,reserved=0;
};
static_assert(sizeof(NlSharedRingDescriptor)==120,"shared ring ABI");
static_assert(sizeof(NlSharedFrame)==48,"shared frame ABI");
