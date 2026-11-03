// Thin owner-confined adapter to the official MIT AMF interfaces. Runtime bytes
// come only from the installed AMD driver. No SDK helper, codec or fallback is
// embedded here. Original HEVC admission remains in Rust above this boundary.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d11.h>
#include <d3d10.h>
#include <dxgi.h>
#include <wrl/client.h>
#include <AMF/core/Factory.h>
#include <AMF/components/VideoEncoderHEVC.h>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <deque>
#include <memory>
#include <new>
#include <initializer_list>
#include <utility>
#include "owner_observation.h"

namespace {
using Microsoft::WRL::ComPtr;
constexpr size_t packet_limit = 8 * 1024 * 1024;
constexpr uint64_t raw_limit = 64 * 1024 * 1024;
constexpr uint64_t pool_limit = 128 * 1024 * 1024;
// A failed close cannot authorize another owner against unknown driver state.
std::atomic<bool> quarantined{false};

HRESULT checked(AMF_RESULT value, const char* stage) noexcept {
    if (value == AMF_OK) return S_OK;
    std::fprintf(stderr, "amf stage=%s result=%d\n", stage, static_cast<int>(value));
    std::fflush(stderr);
    return HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED);
}

struct ReleaseState {
    std::array<std::atomic<bool>, 4> busy{};
    ReleaseState() noexcept {
        for (auto& value : busy) value.store(false, std::memory_order_relaxed);
    }
};
class Released final : public amf::AMFSurfaceObserver {
    std::shared_ptr<ReleaseState> state;
    size_t index;
public:
    Released(std::shared_ptr<ReleaseState> value, size_t slot) noexcept
        : state(std::move(value)), index(slot) {}
    void AMF_STD_CALL OnSurfaceDataRelease(amf::AMFSurface*) override {
        // May run on an AMF thread. No D3D/context/owner access here.
        state->busy[index].store(false, std::memory_order_release);
    }
};

struct Encoder {
    DWORD thread = GetCurrentThreadId();
    bool com = false, failed = false, draining = false, drain_sent = false, eof = false;
    bool actual_output = false, id_initialized = false, init_attempted = false, initialized = false;
    GUID id{};
    uint32_t width = 0, height = 0, fps = 0, depth = 0;
    HMODULE module = nullptr;
    uint64_t runtime = 0;
    amf::AMFFactory* factory = nullptr; // Factory has no Release interface.
    amf::AMFContextPtr amf_context;
    amf::AMFComponentPtr component;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<ID3D11Query> pending_copy;
    ComPtr<ID3D11Texture2D> pending_source;
    std::array<ComPtr<ID3D11Texture2D>, 4> slots;
    std::shared_ptr<ReleaseState> released;
    std::array<std::unique_ptr<Released>, 4> observers;
    std::deque<uint64_t> pending;
    std::array<std::pair<const wchar_t*, amf::AMFVariant>, 32> configured;
    size_t configured_count = 0;
    bool has_input = false;
    uint64_t last_input = 0;
    uint64_t accepted = 0, outputs = 0, pool_full = 0, copy_pending = 0;
};

HRESULT current(Encoder& state) noexcept {
    if (state.thread != GetCurrentThreadId() || state.failed) return E_UNEXPECTED;
    return state.device->GetDeviceRemovedReason();
}

HRESULT close_native(Encoder& state) noexcept {
    if (state.thread != GetCurrentThreadId()) return E_UNEXPECTED;
    // Releasing D3D references does not prove an earlier timed-out copy has
    // completed. Keep its EVENT and all owners until the GPU confirms it. This
    // is one non-flushing observation, not another wait/copy budget.
    if (state.pending_copy) {
        const HRESULT hr = state.context->GetData(state.pending_copy.Get(), nullptr, 0,
            D3D11_ASYNC_GETDATA_DONOTFLUSH);
        if (hr == S_FALSE) return E_PENDING;
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        state.pending_copy.Reset();
        state.pending_source.Reset();
    }
    // Flush is an explicit discard on cancellation/error, not evidence that EOS
    // completed. Functional probes separately require EOF and exact accounting.
    if (state.component) {
        if (state.initialized) {
            const HRESULT hr = checked(state.component->Flush(), "close-flush");
            if (FAILED(hr)) return hr;
        }
        if (state.init_attempted) {
            const HRESULT hr = checked(state.component->Terminate(), "close-terminate");
            if (FAILED(hr)) return hr;
        }
        state.component = nullptr;
    }
    if (state.released) {
        for (const auto& busy : state.released->busy) {
            if (busy.load(std::memory_order_acquire)) return E_PENDING;
        }
    }
    if (state.amf_context) {
        const HRESULT hr = checked(state.amf_context->Terminate(), "close-context");
        if (FAILED(hr)) return hr;
        state.amf_context = nullptr;
    }
    state.factory = nullptr;
    state.context.Reset();
    for (auto& texture : state.slots) texture.Reset();
    state.device.Reset();
    if (state.module) {
        if (!FreeLibrary(state.module)) return HRESULT_FROM_WIN32(GetLastError());
        state.module = nullptr;
    }
    if (state.com) { CoUninitialize(); state.com = false; }
    return S_OK;
}

HRESULT abandon(std::unique_ptr<Encoder>& state, HRESULT original) noexcept {
    const HRESULT closed = close_native(*state);
    if (FAILED(closed)) {
        quarantined.store(true, std::memory_order_release);
        // Keep module, callbacks, textures and COM refs alive after failed close.
        (void)state.release();
        std::fprintf(stderr, "amf startup-close-unknown hr=0x%08lx original=0x%08lx\n",
            static_cast<unsigned long>(closed), static_cast<unsigned long>(original));
    }
    return original;
}

HRESULT load_runtime(Encoder& state) noexcept {
    wchar_t path[MAX_PATH]{};
    const UINT count = GetSystemDirectoryW(path, MAX_PATH);
    if (!count || count >= MAX_PATH - 16) return E_UNEXPECTED;
    const wchar_t suffix[] = L"\\amfrt64.dll";
    std::memcpy(path + count, suffix, sizeof(suffix));
    state.module = LoadLibraryExW(path, nullptr,
        LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!state.module) return HRESULT_FROM_WIN32(GetLastError());
    wchar_t actual[MAX_PATH]{};
    const DWORD written = GetModuleFileNameW(state.module, actual, MAX_PATH);
    if (!written || written >= MAX_PATH || _wcsicmp(path, actual) != 0) return E_ACCESSDENIED;
    const FARPROC query_address = GetProcAddress(state.module, AMF_QUERY_VERSION_FUNCTION_NAME);
    const FARPROC init_address = GetProcAddress(state.module, AMF_INIT_FUNCTION_NAME);
    AMFQueryVersion_Fn query = nullptr;
    AMFInit_Fn init = nullptr;
    static_assert(sizeof(query) == sizeof(query_address), "Windows function pointer size");
    static_assert(sizeof(init) == sizeof(init_address), "Windows function pointer size");
    std::memcpy(&query, &query_address, sizeof(query));
    std::memcpy(&init, &init_address, sizeof(init));
    if (!query || !init) return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
    HRESULT hr = checked(query(&state.runtime), "query-version");
    if (FAILED(hr)) return hr;
    if (AMF_GET_MAJOR_VERSION(state.runtime) != 1) return E_NOTIMPL;
    // Official API reference initializes with the queried installed version.
    // Optional properties are checked individually; headers do not prove driver support.
    hr = checked(init(state.runtime, &state.factory), "init-runtime");
    std::fprintf(stderr, "amf runtime path=\"%ls\" headers=0x%016llx runtime=0x%016llx hr=0x%08lx\n",
        actual, static_cast<unsigned long long>(AMF_FULL_VERSION),
        static_cast<unsigned long long>(state.runtime), static_cast<unsigned long>(hr));
    std::fflush(stderr);
    return SUCCEEDED(hr) && !state.factory ? E_UNEXPECTED : hr;
}

bool equivalent(const amf::AMFVariant& a, const amf::AMFVariant& b) noexcept {
    if (a.type != b.type) return false;
    switch (a.type) {
    case amf::AMF_VARIANT_BOOL: return a.boolValue == b.boolValue;
    case amf::AMF_VARIANT_INT64: return a.int64Value == b.int64Value;
    case amf::AMF_VARIANT_SIZE: return a.sizeValue.width == b.sizeValue.width && a.sizeValue.height == b.sizeValue.height;
    case amf::AMF_VARIANT_RATE: return a.rateValue.num == b.rateValue.num && a.rateValue.den == b.rateValue.den;
    default: return false;
    }
}

bool valid_property_name(const wchar_t* name) noexcept {
    if (!name) return false;
    size_t length = 0;
    while (length < 256 && name[length]) ++length;
    return length > 0 && length < 256;
}

bool legacy_optional_property(const wchar_t* name) noexcept {
    // The earlier explicit input/output 709 profile is required before the
    // separate matrix/range controls. Only these absent extensions or disabled
    // optional features may be omitted; no core format/rate/color property may.
    for (const wchar_t* optional : {AMF_VIDEO_ENCODER_HEVC_INPUT_MATRIX_COEFF,
        AMF_VIDEO_ENCODER_HEVC_OUTPUT_MATRIX_COEFF, AMF_VIDEO_ENCODER_HEVC_INPUT_FULL_RANGE_COLOR,
        AMF_VIDEO_ENCODER_HEVC_ENABLE_SMART_ACCESS_VIDEO, AMF_VIDEO_ENCODER_HEVC_QUERY_TIMEOUT}) {
        if (std::wcscmp(name, optional) == 0) return true;
    }
    return false;
}

template<class Storage>
HRESULT describe_property(Storage* storage, const wchar_t* name, bool optional_equivalent,
    const amf::AMFPropertyInfo** info) noexcept {
    if (!storage || !info || !valid_property_name(name)) return E_INVALIDARG;
    *info = nullptr;
    if (optional_equivalent && !legacy_optional_property(name)) return E_INVALIDARG;
    const AMF_RESULT described = storage->GetPropertyInfo(name, info);
    std::fprintf(stderr, "amf property=\"%ls\" stage=property-info result=%d optional_equivalent=%u descriptor_present=%u\n",
        name, static_cast<int>(described), optional_equivalent ? 1u : 0u, *info ? 1u : 0u);
    std::fflush(stderr);
    if (described == AMF_OK) {
        return *info && valid_property_name((*info)->name) && std::wcscmp((*info)->name, name) == 0 ? S_OK : E_UNEXPECTED;
    }
    if (!optional_equivalent || *info || (described != AMF_NOT_FOUND && described != AMF_INVALID_ARG)) {
        return checked(described, "property-info");
    }
    // The observed older runtime returned INVALID_ARG at the first newer
    // optional descriptor lookup; the reference specifies NOT_FOUND for an
    // absent name. Neither result alone proves absence. Require the entire
    // stable registered descriptor inventory to omit this exact optional name.
    const amf_size count = storage->GetPropertiesInfoCount();
    std::fprintf(stderr, "amf property=\"%ls\" stage=property-inventory count=%zu\n", name, static_cast<size_t>(count));
    if (count == 0 || count > 512) return E_UNEXPECTED;
    std::array<const wchar_t*, 512> names{};
    for (amf_size index = 0; index < count; ++index) {
        const amf::AMFPropertyInfo* entry = nullptr;
        const AMF_RESULT result = storage->GetPropertyInfo(index, &entry);
        if (result != AMF_OK || !entry || !valid_property_name(entry->name)) {
            std::fprintf(stderr, "amf property=\"%ls\" stage=property-inventory index=%zu result=%d descriptor_valid=0\n",
                name, static_cast<size_t>(index), static_cast<int>(result));
            return result == AMF_OK ? E_UNEXPECTED : checked(result, "property-inventory");
        }
        if (std::wcscmp(entry->name, name) == 0) return E_UNEXPECTED;
        for (amf_size previous = 0; previous < index; ++previous) {
            if (std::wcscmp(names[previous], entry->name) == 0) return E_UNEXPECTED;
        }
        names[index] = entry->name;
    }
    if (storage->GetPropertiesInfoCount() != count || storage->HasProperty(name)) return E_UNEXPECTED;
    std::fprintf(stderr, "amf property=\"%ls\" unavailable_in_installed_runtime=1 complete_inventory_absence_verified=1 original_sps_validation_required=1\n", name);
    std::fflush(stderr);
    return S_FALSE;
}

HRESULT property(Encoder& state, const wchar_t* name, const amf::AMFVariant& requested,
    bool optional_equivalent = false) noexcept {
    const amf::AMFPropertyInfo* info = nullptr;
    const HRESULT described = describe_property(static_cast<amf::AMFComponent*>(state.component), name, optional_equivalent, &info);
    if (described == S_FALSE) return S_OK;
    if (FAILED(described)) return described;
    amf::AMFVariant validated;
    AMF_RESULT result = state.component->ValidateProperty(name, requested, &validated);
    // Validation must not clamp/coerce a different semantic value into success.
    if (result == AMF_OK && !equivalent(requested, validated)) result = AMF_INVALID_ARG;
    if (result == AMF_OK) result = state.component->SetProperty(name, validated);
    amf::AMFVariant actual;
    if (result == AMF_OK) result = state.component->GetProperty(name, &actual);
    if (result == AMF_OK && !equivalent(validated, actual)) result = AMF_INVALID_ARG;
    std::fprintf(stderr, "amf property=\"%ls\" declared_type=%d requested_type=%d requested_scalar=%lld read_type=%d read_scalar=%lld result=%d\n",
        name, static_cast<int>(info->type), static_cast<int>(requested.type),
        static_cast<long long>(requested.type == amf::AMF_VARIANT_INT64 ? requested.int64Value : requested.type == amf::AMF_VARIANT_BOOL ? requested.boolValue : -1),
        static_cast<int>(actual.type), static_cast<long long>(actual.type == amf::AMF_VARIANT_INT64 ? actual.int64Value : actual.type == amf::AMF_VARIANT_BOOL ? actual.boolValue : -1), static_cast<int>(result));
    std::fflush(stderr);
    if (result == AMF_OK) {
        if (state.configured_count >= state.configured.size()) return E_UNEXPECTED;
        state.configured[state.configured_count++] = {name, actual};
    }
    return checked(result, "property-set-readback");
}

HRESULT verify_initialized_configuration(Encoder& state) noexcept {
    for (size_t i = 0; i < state.configured_count; ++i) {
        const auto& entry = state.configured[i];
        amf::AMFVariant actual;
        AMF_RESULT result = state.component->GetProperty(entry.first, &actual);
        if (result == AMF_OK && !equivalent(entry.second, actual)) result = AMF_INVALID_ARG;
        std::fprintf(stderr, "amf initialized_property=\"%ls\" result=%d\n", entry.first, static_cast<int>(result));
        const HRESULT hr = checked(result, "post-init-property-readback");
        if (FAILED(hr)) return hr;
    }
    return S_OK;
}

HRESULT range_value(const amf::AMFPropertyInfo& info, amf::AMFVariant& value) noexcept {
    if (info.type == amf::AMF_VARIANT_BOOL) { value = false; return S_OK; }
    // Both layouts are present in published AMD headers. Select by the actual
    // declared range, never by a driver-name/version guess or the newest enum.
    if (info.type != amf::AMF_VARIANT_INT64 || info.minValue.type != amf::AMF_VARIANT_INT64 || info.maxValue.type != amf::AMF_VARIANT_INT64)
        return E_NOTIMPL;
    const amf_int64 min = info.minValue.int64Value, max = info.maxValue.int64Value;
    if (min == 1 && max == 2) { value = amf_int64(2); return S_OK; }
    if (min == 0 && max == 1) { value = amf_int64(0); return S_OK; }
    return E_NOTIMPL;
}

HRESULT limited_range(Encoder& state) noexcept {
    const amf::AMFPropertyInfo* info = nullptr;
    HRESULT hr = describe_property(static_cast<amf::AMFComponent*>(state.component),
        AMF_VIDEO_ENCODER_HEVC_OUTPUT_FULL_RANGE_COLOR, false, &info);
    if (FAILED(hr)) return hr;
    amf::AMFVariant value;
    hr = range_value(*info, value);
    return FAILED(hr) ? hr : property(state, AMF_VIDEO_ENCODER_HEVC_OUTPUT_FULL_RANGE_COLOR, value);
}

HRESULT capabilities(Encoder& state) noexcept {
    amf::AMFCapsPtr caps;
    HRESULT hr = checked(state.component->GetCaps(&caps), "get-caps");
    if (FAILED(hr) || !caps) return FAILED(hr) ? hr : E_UNEXPECTED;
    if (caps->GetAccelerationType() != amf::AMF_ACCEL_HARDWARE) return DXGI_ERROR_UNSUPPORTED;
    amf::AMFIOCapsPtr input;
    hr = checked(caps->GetInputCaps(&input), "input-caps");
    if (FAILED(hr) || !input) return FAILED(hr) ? hr : E_UNEXPECTED;
    amf_int32 min_width = 0, max_width = 0, min_height = 0, max_height = 0;
    input->GetWidthRange(&min_width, &max_width);
    input->GetHeightRange(&min_height, &max_height);
    const auto format = state.depth == 10 ? amf::AMF_SURFACE_P010 : amf::AMF_SURFACE_NV12;
    bool found_format = false, found_memory = false;
    const amf_int32 formats = input->GetNumOfFormats(), memories = input->GetNumOfMemoryTypes();
    if (formats < 0 || formats > 128 || memories < 0 || memories > 32) return E_UNEXPECTED;
    for (amf_int32 index = 0; index < formats; ++index) {
        amf::AMF_SURFACE_FORMAT actual = amf::AMF_SURFACE_UNKNOWN;
        amf_bool native = false;
        hr = checked(input->GetFormatAt(index, &actual, &native), "input-format");
        if (FAILED(hr)) return hr;
        if (actual == format && native) found_format = true;
    }
    for (amf_int32 index = 0; index < memories; ++index) {
        amf::AMF_MEMORY_TYPE actual = amf::AMF_MEMORY_UNKNOWN;
        amf_bool native = false;
        hr = checked(input->GetMemoryTypeAt(index, &actual, &native), "input-memory");
        if (FAILED(hr)) return hr;
        if (actual == amf::AMF_MEMORY_DX11 && native) found_memory = true;
    }
    std::fprintf(stderr, "amf hardware-caps native_format=%u native_dx11=%u width_min=%d width_max=%d height_min=%d height_max=%d vertical_memory_alignment=%d\n",
        found_format ? 1u : 0u, found_memory ? 1u : 0u, min_width, max_width, min_height, max_height, input->GetVertAlign());
    std::fflush(stderr);
    return found_format && found_memory && static_cast<amf_int32>(state.width) >= min_width && static_cast<amf_int32>(state.width) <= max_width
        && static_cast<amf_int32>(state.height) >= min_height && static_cast<amf_int32>(state.height) <= max_height ? S_OK : DXGI_ERROR_UNSUPPORTED;
}

HRESULT configure(Encoder& state, uint32_t kbps) noexcept {
    HRESULT hr = property(state, AMF_VIDEO_ENCODER_HEVC_USAGE, amf::AMFVariant(amf_int64(AMF_VIDEO_ENCODER_HEVC_USAGE_ULTRA_LOW_LATENCY)));
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_FRAMESIZE, amf::AMFVariant(AMFConstructSize(static_cast<amf_int32>(state.width), static_cast<amf_int32>(state.height))));
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_FRAMERATE, amf::AMFVariant(AMFConstructRate(state.fps, 1)));
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_PROFILE, amf::AMFVariant(amf_int64(state.depth == 10 ? AMF_VIDEO_ENCODER_HEVC_PROFILE_MAIN_10 : AMF_VIDEO_ENCODER_HEVC_PROFILE_MAIN)));
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_TIER, amf::AMFVariant(amf_int64(AMF_VIDEO_ENCODER_HEVC_TIER_MAIN)));
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_COLOR_BIT_DEPTH, amf::AMFVariant(amf_int64(state.depth)));
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_RATE_CONTROL_METHOD, amf::AMFVariant(amf_int64(AMF_VIDEO_ENCODER_HEVC_RATE_CONTROL_METHOD_CBR)));
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_TARGET_BITRATE, amf::AMFVariant(amf_int64(kbps) * 1000));
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_GOP_SIZE, amf::AMFVariant(amf_int64(1)));
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_RATE_CONTROL_SKIP_FRAME_ENABLE, amf::AMFVariant(false));
    if (FAILED(hr)) return hr;
    for (const wchar_t* name : {AMF_VIDEO_ENCODER_HEVC_INPUT_COLOR_PROFILE, AMF_VIDEO_ENCODER_HEVC_OUTPUT_COLOR_PROFILE}) {
        hr = property(state, name, amf::AMFVariant(amf_int64(AMF_VIDEO_CONVERTER_COLOR_PROFILE_709)));
        if (FAILED(hr)) return hr;
    }
    for (const wchar_t* name : {AMF_VIDEO_ENCODER_HEVC_INPUT_TRANSFER_CHARACTERISTIC, AMF_VIDEO_ENCODER_HEVC_OUTPUT_TRANSFER_CHARACTERISTIC,
        AMF_VIDEO_ENCODER_HEVC_INPUT_COLOR_PRIMARIES, AMF_VIDEO_ENCODER_HEVC_OUTPUT_COLOR_PRIMARIES}) {
        hr = property(state, name, amf::AMFVariant(amf_int64(1)));
        if (FAILED(hr)) return hr;
    }
    for (const wchar_t* name : {AMF_VIDEO_ENCODER_HEVC_INPUT_MATRIX_COEFF, AMF_VIDEO_ENCODER_HEVC_OUTPUT_MATRIX_COEFF}) {
        hr = property(state, name, amf::AMFVariant(amf_int64(1)), true);
        if (FAILED(hr)) return hr;
    }
    hr = property(state, AMF_VIDEO_ENCODER_HEVC_INPUT_FULL_RANGE_COLOR, amf::AMFVariant(false), true);
    if (SUCCEEDED(hr)) hr = limited_range(state);
    // Unknown old-runtime properties are not invented. Absence means the
    // feature did not exist; if it is exposed it must be disabled/read back.
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_ENABLE_SMART_ACCESS_VIDEO, amf::AMFVariant(false), true);
    if (SUCCEEDED(hr)) hr = property(state, AMF_VIDEO_ENCODER_HEVC_QUERY_TIMEOUT, amf::AMFVariant(amf_int64(0)), true);
    return hr;
}

HRESULT open_native(Encoder& state, ID3D11Device* supplied, uint32_t kbps) {
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return hr;
    state.com = true;
    state.device = supplied;
    supplied->GetImmediateContext(&state.context);
    ComPtr<ID3D10Multithread> protection;
    hr = state.context.As(&protection);
    if (FAILED(hr)) return hr;
    protection->SetMultithreadProtected(TRUE);
    ComPtr<IDXGIDevice> dxgi;
    ComPtr<IDXGIAdapter> adapter;
    DXGI_ADAPTER_DESC desc{};
    hr = supplied->QueryInterface(IID_PPV_ARGS(&dxgi));
    if (SUCCEEDED(hr)) hr = dxgi->GetAdapter(&adapter);
    if (SUCCEEDED(hr)) hr = adapter->GetDesc(&desc);
    if (FAILED(hr) || desc.VendorId != 0x1002) return FAILED(hr) ? hr : DXGI_ERROR_UNSUPPORTED;
    NlOwnerObservation original{};
    hr = nl_observe_owner(supplied, false, state.id, state.id_initialized, &original);
    if (FAILED(hr) || (original.flags & 3) != 3) return FAILED(hr) ? hr : E_UNEXPECTED;
    std::fprintf(stderr, "amf source adapter=0x%016llx driver=0x%016llx vendor=0x%04x device=0x%04x depth=%u geometry=%ux%u\n",
        static_cast<unsigned long long>(original.adapter_luid), static_cast<unsigned long long>(original.driver_version), desc.VendorId, desc.DeviceId, state.depth, state.width, state.height);
    hr = load_runtime(state);
    if (FAILED(hr)) return hr;
    hr = checked(state.factory->CreateContext(&state.amf_context), "create-context");
    if (FAILED(hr) || !state.amf_context) return FAILED(hr) ? hr : E_UNEXPECTED;
    hr = checked(state.amf_context->InitDX11(supplied, amf::AMF_DX11_0), "init-supplied-dx11");
    if (FAILED(hr)) return hr;
    auto* actual = static_cast<ID3D11Device*>(state.amf_context->GetDX11Device(amf::AMF_DX11_0));
    if (!actual) return E_UNEXPECTED;
    ComPtr<IUnknown> supplied_identity, actual_identity;
    hr = supplied->QueryInterface(IID_PPV_ARGS(&supplied_identity));
    if (SUCCEEDED(hr)) hr = actual->QueryInterface(IID_PPV_ARGS(&actual_identity));
    if (FAILED(hr) || supplied_identity.Get() != actual_identity.Get()) return FAILED(hr) ? hr : DXGI_ERROR_UNSUPPORTED;
    hr = checked(state.factory->CreateComponent(state.amf_context, AMFVideoEncoder_HEVC, &state.component), "create-hardware-hevc");
    if (FAILED(hr) || !state.component) return FAILED(hr) ? hr : E_UNEXPECTED;
    hr = capabilities(state);
    if (SUCCEEDED(hr)) hr = configure(state, kbps);
    if (FAILED(hr)) return hr;
    state.released = std::make_shared<ReleaseState>();
    D3D11_TEXTURE2D_DESC texture{};
    texture.Width = state.width; texture.Height = state.height;
    texture.MipLevels = 1; texture.ArraySize = 1;
    texture.Format = state.depth == 10 ? DXGI_FORMAT_P010 : DXGI_FORMAT_NV12;
    texture.SampleDesc.Count = 1; texture.Usage = D3D11_USAGE_DEFAULT;
    texture.BindFlags = D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE;
    for (size_t i = 0; i < state.slots.size(); ++i) {
        hr = supplied->CreateTexture2D(&texture, nullptr, &state.slots[i]);
        if (FAILED(hr)) return hr;
        state.observers[i] = std::make_unique<Released>(state.released, i);
    }
    state.init_attempted = true;
    hr = checked(state.component->Init(state.depth == 10 ? amf::AMF_SURFACE_P010 : amf::AMF_SURFACE_NV12,
        static_cast<amf_int32>(state.width), static_cast<amf_int32>(state.height)), "init-exact-encoder");
    if (SUCCEEDED(hr)) {
        state.initialized = true;
        hr = verify_initialized_configuration(state);
    }
    return hr;
}

HRESULT send_drain(Encoder& state) noexcept {
    if (!state.draining || state.drain_sent) return S_OK;
    const AMF_RESULT result = state.component->Drain();
    if (result == AMF_INPUT_FULL) return S_OK;
    const HRESULT hr = checked(result, "drain");
    if (SUCCEEDED(hr)) state.drain_sent = true;
    return hr;
}

HRESULT output(Encoder& state, uint8_t* destination, size_t capacity, size_t* length, uint64_t* pts) {
    HRESULT hr = send_drain(state);
    if (FAILED(hr)) return hr;
    if (state.eof) return S_OK;
    amf::AMFDataPtr data;
    const AMF_RESULT result = state.component->QueryOutput(&data);
    if (result == AMF_EOF) {
        if (data || !state.draining || !state.drain_sent || !state.pending.empty()) return E_UNEXPECTED;
        state.eof = true;
        return S_OK;
    }
    if (result == AMF_REPEAT) return data ? E_UNEXPECTED : S_OK;
    if (result == AMF_OK && !data) return S_OK;
    hr = checked(result, "query-output");
    if (FAILED(hr)) return hr;
    amf::AMFBufferPtr buffer(data);
    if (!buffer || buffer->GetMemoryType() != amf::AMF_MEMORY_HOST || !buffer->GetNative() || buffer->GetSize() == 0 || buffer->GetSize() > capacity || buffer->GetSize() > packet_limit || state.pending.empty()) return E_UNEXPECTED;
    const uint64_t expected = state.pending.front();
    const amf_pts actual = buffer->GetPts();
    if (actual < 0 || static_cast<uint64_t>(actual) != expected * 1000 / 9) return E_UNEXPECTED;
    *length = static_cast<size_t>(buffer->GetSize());
    *pts = expected;
    std::memcpy(destination, buffer->GetNative(), *length);
    SecureZeroMemory(buffer->GetNative(), *length);
    state.pending.pop_front();
    ++state.outputs;
    state.actual_output = true;
    return S_OK;
}

HRESULT input(Encoder& state, ID3D11Texture2D* source, uint64_t pts, bool keyframe, bool* accepted) {
    if (state.draining || (state.has_input && pts <= state.last_input)) return E_INVALIDARG;
    if (state.pending_copy) return E_UNEXPECTED;
    if (state.pending.size() >= 16) return S_OK;
    D3D11_TEXTURE2D_DESC desc{};
    source->GetDesc(&desc);
    ComPtr<ID3D11Device> device;
    source->GetDevice(&device);
    if (device.Get() != state.device.Get() || desc.Width != state.width || desc.Height != state.height
        || desc.Format != (state.depth == 10 ? DXGI_FORMAT_P010 : DXGI_FORMAT_NV12) || desc.MipLevels != 1
        || desc.ArraySize != 1 || desc.SampleDesc.Count != 1) return DXGI_ERROR_UNSUPPORTED;
    size_t slot = state.slots.size();
    for (size_t i = 0; i < state.slots.size(); ++i) {
        bool free = false;
        if (state.released->busy[i].compare_exchange_strong(free, true, std::memory_order_acq_rel)) { slot = i; break; }
    }
    if (slot == state.slots.size()) { ++state.pool_full; return S_OK; }
    amf::AMFSurfacePtr surface;
    AMF_RESULT result = state.amf_context->CreateSurfaceFromDX11Native(state.slots[slot].Get(), &surface, state.observers[slot].get());
    if (result != AMF_OK || !surface) {
        if (!surface) state.released->busy[slot].store(false, std::memory_order_release);
        return checked(result == AMF_OK ? AMF_FAIL : result, "wrap-original-device-slot");
    }
    D3D11_QUERY_DESC query_desc{D3D11_QUERY_EVENT, 0};
    ComPtr<ID3D11Query> query;
    HRESULT hr = state.device->CreateQuery(&query_desc, &query);
    if (FAILED(hr)) return hr;
    state.pending_copy = query;
    state.pending_source = source;
    state.context->CopyResource(state.slots[slot].Get(), source);
    state.context->End(query.Get()); state.context->Flush();
    const ULONGLONG deadline = GetTickCount64() + 16;
    do { hr = state.context->GetData(query.Get(), nullptr, 0, 0); if (hr == S_FALSE) Sleep(0); }
    while (hr == S_FALSE && GetTickCount64() < deadline);
    // An incomplete copy must not release and reuse its slot as another input.
    // Retire this owner instead of acknowledging an unaccepted retryable frame.
    if (hr == S_FALSE) { ++state.copy_pending; return HRESULT_FROM_WIN32(ERROR_TIMEOUT); }
    if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
    state.pending_copy.Reset();
    state.pending_source.Reset();
    surface->SetPts(static_cast<amf_pts>(pts * 1000 / 9));
    surface->SetDuration(AMF_SECOND / state.fps);
    if (keyframe) {
        result = surface->SetProperty(AMF_VIDEO_ENCODER_HEVC_FORCE_PICTURE_TYPE, amf_int64(AMF_VIDEO_ENCODER_HEVC_PICTURE_TYPE_IDR));
        if (result == AMF_OK) result = surface->SetProperty(AMF_VIDEO_ENCODER_HEVC_INSERT_HEADER, true);
        hr = checked(result, "force-idr-and-original-headers");
        if (FAILED(hr)) return hr;
    }
    result = state.component->SubmitInput(surface);
    if (result == AMF_INPUT_FULL) return S_OK;
    hr = checked(result, "submit-input");
    if (FAILED(hr)) return hr;
    state.pending.push_back(pts);
    state.has_input = true; state.last_input = pts;
    ++state.accepted;
    *accepted = true;
    // The runtime retains accepted surfaces. The observer releases this slot,
    // independent of output order; this local reference must not pin the pool.
    return S_OK;
}
} // namespace

extern "C" int32_t nl_amf_open(void* device, uint32_t width, uint32_t height,
    uint32_t fps, uint32_t kbps, uint32_t depth, void** result) noexcept {
    if (!result) return E_POINTER;
    *result = nullptr;
    if (!device || !width || !height || ((width | height) & 1) || width > 8192 || height > 8192
        || fps == 0 || fps > 144 || kbps < 64 || kbps > 100000 || (depth != 8 && depth != 10)
        || uint64_t(width) * height * (depth == 10 ? 8u : 4u) > raw_limit
        || uint64_t(width) * height * 6 * (depth == 10 ? 2u : 1u) > pool_limit) return E_INVALIDARG;
    if (quarantined.load(std::memory_order_acquire)) return E_UNEXPECTED;
    std::unique_ptr<Encoder> state(new (std::nothrow) Encoder());
    if (!state) return E_OUTOFMEMORY;
    state->width = width; state->height = height; state->fps = fps; state->depth = depth;
    try {
        const HRESULT hr = open_native(*state, static_cast<ID3D11Device*>(device), kbps);
        if (FAILED(hr)) return abandon(state, hr);
        *result = state.release();
        return S_OK;
    } catch (const std::bad_alloc&) { return abandon(state, E_OUTOFMEMORY); }
    catch (...) { return abandon(state, E_FAIL); }
}

extern "C" int32_t nl_amf_process(void* handle, void* texture, uint64_t pts, uint32_t keyframe,
    uint8_t* destination, size_t capacity, size_t* length, uint64_t* output_pts) noexcept {
    auto* state = static_cast<Encoder*>(handle);
    if (!state || !destination || !length || !output_pts || capacity == 0 || capacity > packet_limit || pts > INT64_MAX / 1000 || keyframe > 1) return E_INVALIDARG;
    *length = 0; *output_pts = 0;
    HRESULT hr = current(*state);
    if (FAILED(hr)) return hr;
    try {
        bool accepted = false;
        hr = output(*state, destination, capacity, length, output_pts);
        if (SUCCEEDED(hr) && texture) hr = input(*state, static_cast<ID3D11Texture2D*>(texture), pts, keyframe != 0, &accepted);
        if (FAILED(hr)) { state->failed = true; return hr; }
        return accepted ? (*length ? 0 : 1) : (*length ? 2 : 3);
    } catch (...) { state->failed = true; return E_OUTOFMEMORY; }
}

extern "C" int32_t nl_amf_drain(void* handle) noexcept {
    auto* state = static_cast<Encoder*>(handle);
    if (!state) return E_POINTER;
    const HRESULT hr = current(*state);
    if (FAILED(hr) || state->draining) return FAILED(hr) ? hr : E_UNEXPECTED;
    state->draining = true;
    const HRESULT result = send_drain(*state);
    if (FAILED(result)) state->failed = true;
    return result;
}

extern "C" int32_t nl_amf_observation(void* handle, NlOwnerObservation* out,
    uint64_t* runtime, uint32_t* flags) noexcept {
    auto* state = static_cast<Encoder*>(handle);
    if (!state || !out || !runtime || !flags) return E_POINTER;
    const HRESULT hr = current(*state);
    if (FAILED(hr)) return hr;
    *runtime = state->runtime;
    *flags = 1u | (state->draining ? 2u : 0u) | (state->eof ? 4u : 0u);
    return nl_observe_owner(state->device.Get(), state->actual_output, state->id, state->id_initialized, out);
}

extern "C" int32_t nl_amf_close(void* handle) noexcept {
    auto* state = static_cast<Encoder*>(handle);
    if (!state) return E_POINTER;
    const HRESULT hr = close_native(*state);
    std::fprintf(stderr, "amf close hr=0x%08lx accepted=%llu outputs=%llu pending=%zu pool_full=%llu copy_pending=%llu eof=%u copy_query_retained=%u\n",
        static_cast<unsigned long>(hr), static_cast<unsigned long long>(state->accepted), static_cast<unsigned long long>(state->outputs), state->pending.size(),
        static_cast<unsigned long long>(state->pool_full), static_cast<unsigned long long>(state->copy_pending), state->eof ? 1u : 0u, state->pending_copy ? 1u : 0u);
    std::fflush(stderr);
    if (FAILED(hr)) { quarantined.store(true, std::memory_order_release); return hr; }
    delete state;
    return S_OK;
}

// Scalar API-shape and callback bookkeeping regression only. This does not
// load AMF, create a GPU, submit pixels or qualify an encoder.
extern "C" uint32_t nl_amf_boundary_contract() noexcept {
    try {
        uint32_t passed = 0;
        amf::AMFPropertyInfo info;
        amf::AMFVariant value;
        info.type = amf::AMF_VARIANT_BOOL;
        if (range_value(info, value) == S_OK && value.type == amf::AMF_VARIANT_BOOL && !value.boolValue) passed |= 1;
        info.type = amf::AMF_VARIANT_INT64;
        info.minValue = amf::AMFVariant(amf_int64(1)); info.maxValue = amf::AMFVariant(amf_int64(2));
        if (range_value(info, value) == S_OK && value.type == amf::AMF_VARIANT_INT64 && value.int64Value == 2) passed |= 2;
        info.minValue = amf::AMFVariant(amf_int64(0)); info.maxValue = amf::AMFVariant(amf_int64(1));
        if (range_value(info, value) == S_OK && value.type == amf::AMF_VARIANT_INT64 && value.int64Value == 0) passed |= 4;
        info.maxValue = amf::AMFVariant(amf_int64(2));
        if (FAILED(range_value(info, value))) passed |= 8;
        info.minValue.type = amf::AMF_VARIANT_EMPTY;
        if (FAILED(range_value(info, value))) passed |= 16;
        auto release = std::make_shared<ReleaseState>();
        release->busy[0].store(true); release->busy[1].store(true);
        Released observer(release, 1); observer.OnSurfaceDataRelease(nullptr);
        if (release->busy[0].load() && !release->busy[1].load()) passed |= 32;
        void* handle = reinterpret_cast<void*>(uintptr_t(1));
        if (FAILED(nl_amf_open(nullptr, 1920, 1080, 60, 8000, 8, &handle)) && handle == nullptr) passed |= 64;
        return passed;
    } catch (...) { return 0; }
}

// Exercise the same descriptor decision as production without loading a
// runtime/device. A named lookup error must not hide an existing or unknown
// required property, malformed inventory or contradictory HasProperty result.
extern "C" uint32_t nl_amf_optional_property_contract() noexcept {
    struct Inventory {
        amf::AMFPropertyInfo entries[2];
        AMF_RESULT named = AMF_INVALID_ARG;
        amf_size count = 2;
        unsigned count_reads = 0;
        bool changing_count = false, named_pointer = false, index_error = false;
        bool null_entry = false, has_property = false;
        Inventory() noexcept {
            entries[0].name = AMF_VIDEO_ENCODER_HEVC_INPUT_COLOR_PROFILE;
            entries[1].name = AMF_VIDEO_ENCODER_HEVC_OUTPUT_COLOR_PROFILE;
        }
        AMF_RESULT GetPropertyInfo(const wchar_t*, const amf::AMFPropertyInfo** info) noexcept {
            *info = named_pointer ? &entries[0] : nullptr;
            return named;
        }
        AMF_RESULT GetPropertyInfo(amf_size index, const amf::AMFPropertyInfo** info) noexcept {
            if (index_error || index >= 2) return AMF_FAIL;
            *info = null_entry ? nullptr : &entries[index];
            return AMF_OK;
        }
        amf_size GetPropertiesInfoCount() noexcept {
            return count + ((changing_count && count_reads++ != 0) ? 1 : 0);
        }
        bool HasProperty(const wchar_t*) const noexcept { return has_property; }
    };
    try {
        uint32_t passed = 0;
        const wchar_t* optional = AMF_VIDEO_ENCODER_HEVC_INPUT_MATRIX_COEFF;
        auto inspect = [](Inventory& inventory, const wchar_t* name, bool allowed) noexcept {
            const amf::AMFPropertyInfo* info = nullptr;
            return describe_property(&inventory, name, allowed, &info);
        };
        Inventory invalid_arg;
        if (inspect(invalid_arg, optional, true) == S_FALSE) passed |= 1;
        Inventory not_found;
        not_found.named = AMF_NOT_FOUND;
        if (inspect(not_found, optional, true) == S_FALSE) passed |= 2;
        if (FAILED(inspect(invalid_arg, AMF_VIDEO_ENCODER_HEVC_PROFILE, false))) passed |= 4;
        if (FAILED(inspect(not_found, AMF_VIDEO_ENCODER_HEVC_PROFILE, false))) passed |= 8;
        if (FAILED(inspect(invalid_arg, AMF_VIDEO_ENCODER_HEVC_PROFILE, true))) passed |= 16;
        Inventory present;
        present.entries[1].name = optional;
        if (FAILED(inspect(present, optional, true))) passed |= 32;
        Inventory index_error;
        index_error.index_error = true;
        if (FAILED(inspect(index_error, optional, true))) passed |= 64;
        Inventory null_entry;
        null_entry.null_entry = true;
        if (FAILED(inspect(null_entry, optional, true))) passed |= 128;
        Inventory no_name;
        no_name.entries[1].name = nullptr;
        if (FAILED(inspect(no_name, optional, true))) passed |= 256;
        Inventory duplicate;
        duplicate.entries[1].name = duplicate.entries[0].name;
        if (FAILED(inspect(duplicate, optional, true))) passed |= 512;
        Inventory empty;
        empty.count = 0;
        if (FAILED(inspect(empty, optional, true))) passed |= 1024;
        Inventory excessive;
        excessive.count = 513;
        if (FAILED(inspect(excessive, optional, true))) passed |= 2048;
        Inventory changing;
        changing.changing_count = true;
        if (FAILED(inspect(changing, optional, true))) passed |= 4096;
        Inventory contradictory;
        contradictory.has_property = true;
        if (FAILED(inspect(contradictory, optional, true))) passed |= 8192;
        Inventory unknown_error;
        unknown_error.named = AMF_FAIL;
        if (FAILED(inspect(unknown_error, optional, true))) passed |= 16384;
        Inventory valid;
        valid.named = AMF_OK; valid.named_pointer = true;
        if (inspect(valid, valid.entries[0].name, false) == S_OK) passed |= 32768;
        Inventory missing_descriptor;
        missing_descriptor.named = AMF_OK;
        if (FAILED(inspect(missing_descriptor, optional, true))) passed |= 65536;
        if (FAILED(inspect(valid, optional, true))) passed |= 131072;
        valid.named = AMF_NOT_FOUND;
        if (FAILED(inspect(valid, optional, true))) passed |= 262144;
        return passed;
    } catch (...) { return 0; }
}
