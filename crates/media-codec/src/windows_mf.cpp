// First-party bounded Media Foundation bridge; HEVC diagnostic extension draft.
// Worker-thread ownership,
// COM pointers stay on the original worker. Shared NT handles target only the
// retained OS process capability supplied by the native pinned TLS owner.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <codecapi.h>
#include <icodecapi.h>
#include <d3d11.h>
#include <wrl/client.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <memory>
#include <new>
#include <array>
#include <atomic>
#if defined(NESTLINK_DEBUG_WIPE_TIMING)
#include <chrono>
#endif
#include <d3d10.h>
#include <dxgi1_2.h>
#include "owner_observation.h"
using Microsoft::WRL::ComPtr;
#include "shared_decode_surface.h"
namespace {
constexpr size_t raw_limit = 64 * 1024 * 1024;
constexpr size_t packet_limit = 8 * 1024 * 1024;
constexpr UINT32 adapter_luid_bytes = sizeof(LUID);
uint64_t adapter_luid_bits(const LUID& luid) noexcept {
    return static_cast<uint64_t>(static_cast<uint32_t>(luid.HighPart)) << 32 | luid.LowPart;
}
bool same_adapter_luid(const LUID& left, const LUID& right) noexcept {
    return left.HighPart == right.HighPart && left.LowPart == right.LowPart;
}
// MFT_ENUM_ADAPTER_LUID is a LUID blob, not a UINT64 attribute. Use this exact
// reader for the enumeration request, activation identity and metadata tests.
HRESULT read_adapter_luid(IMFAttributes* attributes, LUID* result, UINT32* blob_bytes) noexcept {
    if (!attributes || !result || !blob_bytes) return E_POINTER;
    *result = LUID{}; *blob_bytes = 0;
    HRESULT hr = attributes->GetBlobSize(MFT_ENUM_ADAPTER_LUID, blob_bytes);
    if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
    if (*blob_bytes != adapter_luid_bytes) return E_INVALIDARG;
    LUID value{}; UINT32 received = 0;
    hr = attributes->GetBlob(MFT_ENUM_ADAPTER_LUID, reinterpret_cast<UINT8*>(&value),
        adapter_luid_bytes, &received);
    *blob_bytes = received;
    if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
    if (received != adapter_luid_bytes) return E_UNEXPECTED;
    *result = value;
    return S_OK;
}
HRESULT match_adapter_luid(IMFAttributes* attributes, const LUID& requested,
    LUID* actual, UINT32* blob_bytes) noexcept {
    const HRESULT hr = read_adapter_luid(attributes, actual, blob_bytes);
    if (hr != S_OK) return hr;
    return same_adapter_luid(*actual, requested) ? S_OK : DXGI_ERROR_UNSUPPORTED;
}
HRESULT set_adapter_request(IMFAttributes* attributes, const LUID& requested) noexcept {
    if (!attributes) return E_POINTER;
    HRESULT hr = attributes->SetBlob(MFT_ENUM_ADAPTER_LUID,
        reinterpret_cast<const UINT8*>(&requested), adapter_luid_bytes);
    if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
    LUID actual{}; UINT32 bytes = 0;
    return match_adapter_luid(attributes, requested, &actual, &bytes);
}
struct AdapterEnumerationBinding {
    bool scoped_enum2 = false;
    HRESULT request = E_UNEXPECTED, enumeration = E_UNEXPECTED;
};
struct AdapterSelectionBinding {
    HRESULT result;
    const char* basis;
};
// MFTEnum2 returns transforms matching its input adapter search criterion. Its
// activation objects need not repeat that input attribute. Only an absent
// optional attribute can use that successful exact scope; an explicit conflict
// or malformed attribute still fails the unchanged strict blob matcher.
AdapterSelectionBinding select_adapter_binding(const AdapterEnumerationBinding& enumeration,
    HRESULT activation_match) noexcept {
    if (enumeration.enumeration != S_OK)
        return {FAILED(enumeration.enumeration) ? enumeration.enumeration : E_UNEXPECTED, "rejected"};
    if (enumeration.scoped_enum2 && enumeration.request != S_OK)
        return {FAILED(enumeration.request) ? enumeration.request : E_UNEXPECTED, "rejected"};
    if (activation_match == S_OK) return {S_OK, "activation_luid_blob"};
    if (enumeration.scoped_enum2 && activation_match == MF_E_ATTRIBUTENOTFOUND)
        return {S_OK, "mft_enum2_exact_adapter_scope"};
    return {FAILED(activation_match) ? activation_match : E_UNEXPECTED, "rejected"};
}
void log_activation_identity(IMFActivate* activation, bool encoder, bool hevc,
    UINT32 index, const char* phase, HRESULT operation, bool binding_required,
    HRESULT binding, const LUID& actual, UINT32 blob_bytes, const AdapterSelectionBinding& selection) noexcept {
    WCHAR name[160]{}; GUID clsid{}; WCHAR clsid_text[40]{};
    const HRESULT name_hr = activation->GetString(MFT_FRIENDLY_NAME_Attribute, name, 160, nullptr);
    const HRESULT clsid_hr = activation->GetGUID(MFT_TRANSFORM_CLSID_Attribute, &clsid);
    const bool clsid_known = clsid_hr == S_OK && StringFromGUID2(clsid, clsid_text, 40) != 0;
    std::fprintf(stderr,
        "mf activation: codec=%s direction=%s owner_thread=%lu index=%u phase=%s hr=0x%08lx binding_required=%u "
        "adapter_binding_hr=0x%08lx adapter_blob_bytes=%u activation_adapter_known=%u activation_adapter=0x%016llx "
        "selection_binding_hr=0x%08lx selection_binding_basis=%s "
        "name_hr=0x%08lx name=\"%.159ls\" clsid_hr=0x%08lx clsid=\"%ls\"\n",
        hevc ? "hevc" : "h264", encoder ? "encode" : "decode",
        static_cast<unsigned long>(GetCurrentThreadId()), index, phase,
        static_cast<unsigned long>(operation), binding_required ? 1u : 0u,
        static_cast<unsigned long>(binding), blob_bytes,
        binding == S_OK || binding == DXGI_ERROR_UNSUPPORTED ? 1u : 0u,
        static_cast<unsigned long long>(adapter_luid_bits(actual)),
        static_cast<unsigned long>(selection.result), selection.basis,
        static_cast<unsigned long>(name_hr), name_hr == S_OK ? name : L"unknown",
        static_cast<unsigned long>(clsid_hr), clsid_known ? clsid_text : L"unknown");
    std::fflush(stderr);
}
struct BufferedOutput {
    std::unique_ptr<uint8_t[]> bytes;
    size_t length = 0, capacity = 0;
    uint64_t pts = 0;
#if defined(NESTLINK_DEBUG_WIPE_TIMING)
    unsigned diagnostic_wipes = 0;
#endif
    void reset() noexcept {
        if (bytes) {
#if defined(NESTLINK_DEBUG_WIPE_TIMING)
            const bool observe = diagnostic_wipes < 4;
            const auto started = observe ? std::chrono::steady_clock::now() : std::chrono::steady_clock::time_point{};
#endif
            SecureZeroMemory(bytes.get(), capacity);
#if defined(NESTLINK_DEBUG_WIPE_TIMING)
            if (observe) {
                const auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
                    std::chrono::steady_clock::now() - started).count();
                ++diagnostic_wipes;
                std::fprintf(stderr, "mf output wipe: slot_wipe=%u capacity=%zu length=%zu elapsed_us=%lld\n",
                    diagnostic_wipes, capacity, length, static_cast<long long>(elapsed));
            }
#endif
        }
        bytes.reset(); length = 0; capacity = 0; pts = 0;
    }
    ~BufferedOutput() { reset(); }
};
// Callback owns only release flags; no GPU/context operation occurs on MF threads.
struct GpuRelease { std::array<std::atomic<bool>, 4> busy{}; };
class SampleReleased final : public IMFAsyncCallback {
    std::atomic<ULONG> refs{1};
    std::shared_ptr<GpuRelease> release;
    size_t slot;
public:
    SampleReleased(std::shared_ptr<GpuRelease> state, size_t index) noexcept : release(state), slot(index) {}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** out) override {
        if (!out) return E_POINTER;
        *out = nullptr;
        if (iid == __uuidof(IUnknown) || iid == __uuidof(IMFAsyncCallback)) {
            *out = static_cast<IMFAsyncCallback*>(this); AddRef(); return S_OK;
        }
        return E_NOINTERFACE;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++refs; }
    ULONG STDMETHODCALLTYPE Release() override { auto n = --refs; if (!n) delete this; return n; }
    HRESULT STDMETHODCALLTYPE GetParameters(DWORD*, DWORD*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Invoke(IMFAsyncResult*) override {
        release->busy[slot].store(false, std::memory_order_release); return S_OK;
    }
};
struct Codec {
    GUID observation_id{}; bool observation_initialized=false;
    ComPtr<IMFTransform> transform;
    ComPtr<IMFMediaEventGenerator> events;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IMFDXGIDeviceManager> manager;
    uint32_t width = 0, height = 0, fps = 0, level = 0;
    bool gpu_input = false, hevc = false, main10 = false, hdr10 = false, drain_started = false, drain_complete = false;
    uint32_t gpu_calls=0, gpu_accepted=0, gpu_pool_blocked=0, gpu_outputs=0, gpu_need_input=0, gpu_copy_pending=0;
    std::array<ComPtr<ID3D11Texture2D>, 4> gpu_slots;
    std::shared_ptr<GpuRelease> gpu_release;
    std::unique_ptr<SharedDecodeRing> shared_output;

    std::array<BufferedOutput, 2> ready;
    size_t ready_head = 0, ready_size = 0, ready_bytes = 0;
    uint32_t output_height = 0, output_pitch = 0;
    bool encoder = false, hardware = false, hardware_used = false, com = false, mf = false;
    DWORD thread = GetCurrentThreadId();
    unsigned input_events = 0, output_events = 0;
    ~Codec() {
        if (transform) {
            transform->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
            transform->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
        for (auto& entry : ready) entry.reset();
        shared_output.reset();
        events.Reset(); transform.Reset();
        for (auto& texture : gpu_slots) texture.Reset();
        gpu_release.reset(); manager.Reset(); context.Reset(); device.Reset();
        if (mf) MFShutdown();
        if (com) CoUninitialize();
    }
};
HRESULT set_codec_value(IMFTransform* transform, const GUID& key, ULONG value, bool boolean = false) {
    ComPtr<ICodecAPI> api;
    HRESULT hr = transform->QueryInterface(IID_PPV_ARGS(&api));
    if (FAILED(hr)) return hr;
    VARIANT variant{};
    variant.vt = static_cast<VARTYPE>(boolean ? VT_BOOL : VT_UI4);
    if (boolean) variant.boolVal = value ? VARIANT_TRUE : VARIANT_FALSE;
    else variant.ulVal = value;
    return api->SetValue(&key, &variant);
}
HRESULT media_type(Codec& state, bool compressed, uint32_t kbps, IMFMediaType** result) {
    ComPtr<IMFMediaType> type;
    HRESULT hr = MFCreateMediaType(&type);
    if (FAILED(hr)) return hr;
    hr = type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    if (SUCCEEDED(hr)) hr = type->SetGUID(MF_MT_SUBTYPE, compressed ? (state.hevc ? MFVideoFormat_HEVC : MFVideoFormat_H264) : (state.main10 ? MFVideoFormat_P010 : MFVideoFormat_NV12));
    if (SUCCEEDED(hr)) hr = type->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    if (SUCCEEDED(hr)) hr = MFSetAttributeSize(type.Get(), MF_MT_FRAME_SIZE, state.width, state.height);
    if (SUCCEEDED(hr)) hr = MFSetAttributeRatio(type.Get(), MF_MT_FRAME_RATE, state.fps, 1);
    if (SUCCEEDED(hr)) hr = MFSetAttributeRatio(type.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
    if (SUCCEEDED(hr)) hr = type->SetUINT32(MF_MT_YUV_MATRIX, state.hdr10 ? MFVideoTransferMatrix_BT2020_10 : MFVideoTransferMatrix_BT709);
    if (SUCCEEDED(hr)) hr = type->SetUINT32(MF_MT_VIDEO_PRIMARIES, state.hdr10 ? MFVideoPrimaries_BT2020 : MFVideoPrimaries_BT709);
    if (SUCCEEDED(hr)) hr = type->SetUINT32(MF_MT_TRANSFER_FUNCTION, state.hdr10 ? MFVideoTransFunc_2084 : MFVideoTransFunc_709);
    if (SUCCEEDED(hr)) hr = type->SetUINT32(MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235);
    if (SUCCEEDED(hr) && compressed && state.hevc) hr = type->SetUINT32(MF_MT_MPEG2_PROFILE, state.main10 ? 2u : 1u);
    if (compressed && state.encoder) {
        if (SUCCEEDED(hr)) hr = type->SetUINT32(MF_MT_AVG_BITRATE, kbps * 1000);
        if (SUCCEEDED(hr)) hr = type->SetUINT32(MF_MT_MPEG2_PROFILE, state.hevc ? (state.main10 ? 2u : 1u) : 66u);
        if (SUCCEEDED(hr) && state.level) hr = type->SetUINT32(MF_MT_MPEG2_LEVEL, state.level);
    }
    if (FAILED(hr)) return hr;
    *result = type.Detach();
    return S_OK;
}
HRESULT hevc_sdr(IMFMediaType* type, bool negotiate) {
    const GUID* keys[] = {&MF_MT_YUV_MATRIX, &MF_MT_VIDEO_PRIMARIES, &MF_MT_TRANSFER_FUNCTION, &MF_MT_VIDEO_NOMINAL_RANGE};
    const UINT32 expected[] = {MFVideoTransferMatrix_BT709, MFVideoPrimaries_BT709, MFVideoTransFunc_709, MFNominalRange_16_235};
    for (size_t i=0;i<4;++i) {
        UINT32 value=0; HRESULT hr=type->GetUINT32(*keys[i],&value);
        if (hr==MF_E_ATTRIBUTENOTFOUND && negotiate) hr=type->SetUINT32(*keys[i],expected[i]);
        else if (SUCCEEDED(hr) && value!=expected[i]) return MF_E_INVALIDMEDIATYPE;
        if (FAILED(hr)) return hr;
    }
    return S_OK;
}
HRESULT hevc_color(IMFMediaType* type, bool negotiate, bool hdr10) {
    if (!hdr10) return hevc_sdr(type, negotiate);
    const GUID* keys[] = {&MF_MT_YUV_MATRIX, &MF_MT_VIDEO_PRIMARIES, &MF_MT_TRANSFER_FUNCTION, &MF_MT_VIDEO_NOMINAL_RANGE};
    const UINT32 expected[] = {MFVideoTransferMatrix_BT2020_10, MFVideoPrimaries_BT2020, MFVideoTransFunc_2084, MFNominalRange_16_235};
    for (size_t i=0;i<4;++i) {
        UINT32 value=0; HRESULT hr=type->GetUINT32(*keys[i],&value);
        if (hr==MF_E_ATTRIBUTENOTFOUND && negotiate) hr=type->SetUINT32(*keys[i],expected[i]);
        else if (hr==S_OK && value!=expected[i]) return MF_E_INVALIDMEDIATYPE;
        if (hr!=S_OK) return FAILED(hr)?hr:E_UNEXPECTED;
    }
    return S_OK;
}
struct CodecColorReceipt {
    HRESULT supported=E_PENDING,set=E_PENDING,read=E_PENDING;
    VARTYPE actual_type=VT_EMPTY;
    ULONG actual=0;
};
// IsSupported explicitly permits S_FALSE or E_NOTIMPL for an absent property.
// SetValue's S_FALSE means read-only, so it must never be treated as a set.
// A supported property must round-trip the documented VT_UI4 enum exactly.
template<class Supported,class Set,class Get>
HRESULT codec_color_property(ULONG expected,Supported supported,Set set,Get get,CodecColorReceipt& receipt) {
    receipt.supported=supported();
    if(receipt.supported==S_FALSE || receipt.supported==E_NOTIMPL)return S_OK;
    if(receipt.supported!=S_OK)return FAILED(receipt.supported)?receipt.supported:E_UNEXPECTED;
    VARIANT requested{};requested.vt=VT_UI4;requested.ulVal=expected;
    receipt.set=set(&requested);
    if(receipt.set!=S_OK)return FAILED(receipt.set)?receipt.set:E_UNEXPECTED;
    VARIANT actual{};
    receipt.read=get(&actual);receipt.actual_type=actual.vt;
    if(actual.vt==VT_UI4)receipt.actual=actual.ulVal;
    const bool matches=actual.vt==VT_UI4 && actual.ulVal==expected;
    const HRESULT cleared=VariantClear(&actual);
    if(receipt.read!=S_OK)return FAILED(receipt.read)?receipt.read:E_UNEXPECTED;
    if(FAILED(cleared))return cleared;
    return matches?S_OK:MF_E_INVALIDMEDIATYPE;
}
HRESULT hevc_encoder_color(IMFTransform* transform) {
    ComPtr<ICodecAPI> api;
    HRESULT hr=transform->QueryInterface(IID_PPV_ARGS(&api));
    std::fprintf(stderr,"hevc_mf_color_codecapi hr=0x%08lx\n",static_cast<unsigned long>(hr));
    std::fflush(stderr);
    if(hr==E_NOINTERFACE)return S_OK; // MF types and the original actual SPS check still apply.
    if(FAILED(hr))return hr;
    if(hr!=S_OK || !api)return E_UNEXPECTED;
    // These are codecapi.h enum values, not H.265 VUI code points. In particular
    // Windows BT.709 primaries=2 and transfer=5 map to VUI code point 1.
    struct Property {const GUID* key;const char* name;ULONG expected;};
    const Property properties[]={
        {&CODECAPI_AVEncVideoInputColorPrimaries,"input.primaries",eAVEncVideoColorPrimaries_BT709},
        {&CODECAPI_AVEncVideoOutputColorPrimaries,"output.primaries",eAVEncVideoColorPrimaries_BT709},
        {&CODECAPI_AVEncVideoInputColorTransferFunction,"input.transfer",eAVEncVideoColorTransferFunction_22_709},
        {&CODECAPI_AVEncVideoOutputColorTransferFunction,"output.transfer",eAVEncVideoColorTransferFunction_22_709},
        {&CODECAPI_AVEncVideoInputColorTransferMatrix,"input.matrix",eAVEncVideoColorTransferMatrix_BT709},
        {&CODECAPI_AVEncVideoOutputColorTransferMatrix,"output.matrix",eAVEncVideoColorTransferMatrix_BT709},
        {&CODECAPI_AVEncVideoInputColorNominalRange,"input.range",eAVEncVideoColorNominalRange_16_235},
        {&CODECAPI_AVEncVideoOutputColorNominalRange,"output.range",eAVEncVideoColorNominalRange_16_235},
    };
    for(const auto& property:properties) {
        CodecColorReceipt receipt{};
        hr=codec_color_property(property.expected,[&](){return api->IsSupported(property.key);},
            [&](VARIANT* value){return api->SetValue(property.key,value);},
            [&](VARIANT* value){return api->GetValue(property.key,value);},receipt);
        std::fprintf(stderr,"hevc_mf_color_property name=%s expected=%lu supported=0x%08lx set=0x%08lx read=0x%08lx actual_vt=%u actual=%lu result=0x%08lx\n",
            property.name,property.expected,static_cast<unsigned long>(receipt.supported),
            static_cast<unsigned long>(receipt.set),static_cast<unsigned long>(receipt.read),
            static_cast<unsigned>(receipt.actual_type),receipt.actual,static_cast<unsigned long>(hr));
        std::fflush(stderr);
        if(FAILED(hr))return hr;
    }
    return S_OK;
}
HRESULT hevc_current_types(Codec& state) {
    const GUID* keys[]={&MF_MT_YUV_MATRIX,&MF_MT_VIDEO_PRIMARIES,&MF_MT_TRANSFER_FUNCTION,&MF_MT_VIDEO_NOMINAL_RANGE};
    const char* names[]={"matrix","primaries","transfer","range"};
    for(unsigned output=0;output<2;++output) {
        ComPtr<IMFMediaType> actual;
        HRESULT hr=output?state.transform->GetOutputCurrentType(0,&actual):state.transform->GetInputCurrentType(0,&actual);
        if(FAILED(hr))return hr;
        for(size_t i=0;i<4;++i) {
            UINT32 value=0;hr=actual->GetUINT32(*keys[i],&value);
            std::fprintf(stderr,"hevc_mf_current_type encoder=%u output=%u attribute=%s hr=0x%08lx value=%u\n",
                state.encoder?1u:0u,output,names[i],static_cast<unsigned long>(hr),value);
        }
        std::fflush(stderr);
        hr=hevc_color(actual.Get(),false,state.hdr10);if(FAILED(hr))return hr;
    }
    return S_OK;
}
void hevc_configure_result(Codec& state,const char* stage,HRESULT hr) {
    if(!state.hevc)return;
    std::fprintf(stderr,"hevc_mf_configure encoder=%u stage=%s hr=0x%08lx\n",
        state.encoder?1u:0u,stage,static_cast<unsigned long>(hr));
    std::fflush(stderr);
}
HRESULT configure(Codec& state, IMFTransform* transform, uint32_t kbps) {
    state.transform = transform;
    ComPtr<IMFAttributes> attributes;
    if (SUCCEEDED(transform->GetAttributes(&attributes))) {
        const HRESULT low_latency=attributes->SetUINT32(MF_LOW_LATENCY, TRUE);
        if(FAILED(low_latency))return low_latency;
        UINT32 asynchronous = FALSE;
        if (SUCCEEDED(attributes->GetUINT32(MF_TRANSFORM_ASYNC, &asynchronous)) && asynchronous) {
            HRESULT hr = attributes->SetUINT32(MF_TRANSFORM_ASYNC_UNLOCK, TRUE);
            if (FAILED(hr)) return hr;
            hr = transform->QueryInterface(IID_PPV_ARGS(&state.events));
            if (FAILED(hr)) return hr;
        }
        UINT32 d3d = FALSE;
        if (state.hardware && SUCCEEDED(attributes->GetUINT32(MF_SA_D3D11_AWARE, &d3d)) && d3d) {
            D3D_FEATURE_LEVEL level{};
            HRESULT hr = S_OK;
            if (!state.device) hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
                nullptr, 0, D3D11_SDK_VERSION, &state.device, &level, &state.context);
            if (SUCCEEDED(hr)) {
                UINT token = 0;
                hr = MFCreateDXGIDeviceManager(&token, &state.manager);
                if (SUCCEEDED(hr)) hr = state.manager->ResetDevice(state.device.Get(), token);
                if (SUCCEEDED(hr)) hr = transform->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER,
                    reinterpret_cast<ULONG_PTR>(state.manager.Get()));
            }
            if (FAILED(hr) && state.hardware) return hr;
        }
        if (state.hardware && (!state.encoder || state.gpu_input) && !state.manager) return MF_E_UNSUPPORTED_D3D_TYPE;
    }
    if (state.gpu_input && !state.manager) return MF_E_UNSUPPORTED_D3D_TYPE;
    // Optional properties vary by vendor. Successful stream creation and a real
    // probe decide availability; an adapter's marketing name never does.
    set_codec_value(transform, CODECAPI_AVLowLatencyMode, 1, true);
    if (state.encoder) {
        set_codec_value(transform, CODECAPI_AVEncCommonRealTime, 1, true);
        set_codec_value(transform, CODECAPI_AVEncMPVDefaultBPictureCount, 0);
        set_codec_value(transform, CODECAPI_AVEncCommonMeanBitRate, kbps * 1000);
    }
    ComPtr<IMFMediaType> compressed, raw;
    HRESULT hr = media_type(state, true, kbps, &compressed);
    if (FAILED(hr)) return hr;
    hr = media_type(state, false, kbps, &raw);
    if (FAILED(hr)) return hr;
    if (state.encoder) {
        hr = transform->SetOutputType(0, compressed.Get(), 0);
        hevc_configure_result(state,"set_compressed_output",hr);
        if (SUCCEEDED(hr)) {
            hr = transform->SetInputType(0, raw.Get(), 0);
            hevc_configure_result(state,"set_raw_input",hr);
        }
    } else {
        hr = transform->SetInputType(0, compressed.Get(), 0);
        hevc_configure_result(state,"set_compressed_input",hr);
        if (SUCCEEDED(hr)) {
            hr = transform->SetOutputType(0, raw.Get(), 0);
            hevc_configure_result(state,"set_raw_output",hr);
        }
    }
    if (FAILED(hr)) return hr;
    if (state.hevc) {
        // codecapi.h's legacy color enums do not define PQ/BT2020. Independent
        // HDR uses MF's explicit color types plus mandatory actual SPS proof;
        // never invent CodecAPI enum values or apply the SDR property list.
        if(state.encoder && !state.hdr10) {hr=hevc_encoder_color(transform);if(FAILED(hr))return hr;}
        hr=hevc_current_types(state);if(FAILED(hr))return hr;
        ComPtr<IMFMediaType> actual_raw;
        hr = state.encoder ? transform->GetInputCurrentType(0,&actual_raw) : transform->GetOutputCurrentType(0,&actual_raw);
        GUID subtype{};
        if (SUCCEEDED(hr)) hr=actual_raw->GetGUID(MF_MT_SUBTYPE,&subtype);
        if (SUCCEEDED(hr) && subtype!=(state.main10 ? MFVideoFormat_P010 : MFVideoFormat_NV12)) hr=MF_E_INVALIDMEDIATYPE;
        if (SUCCEEDED(hr)) hr=hevc_color(actual_raw.Get(),false,state.hdr10);
        if (FAILED(hr)) return hr;
    }
    hr = transform->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    hevc_configure_result(state,"begin_streaming",hr);
    if (SUCCEEDED(hr)) {
        hr = transform->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
        hevc_configure_result(state,"start_of_stream",hr);
    }
    return hr;
}
HRESULT poll_events(Codec& state) {
    if (!state.events) return S_OK;
    for (unsigned count = 0; count < 64; ++count) {
        ComPtr<IMFMediaEvent> event;
        HRESULT hr = state.events->GetEvent(MF_EVENT_FLAG_NO_WAIT, &event);
        if (hr == MF_E_NO_EVENTS_AVAILABLE) return S_OK;
        if (FAILED(hr)) return hr;
        HRESULT status = S_OK;
        hr = event->GetStatus(&status);
        if (FAILED(hr)) return hr;
        if (FAILED(status)) return status;
        MediaEventType type{};
        hr = event->GetType(&type);
        if (FAILED(hr)) return hr;
        if (state.hevc && type == METransformDrainComplete) state.drain_complete = true;
        if (type == METransformNeedInput) ++state.input_events;
        if (type == METransformHaveOutput) ++state.output_events;
    }
    return E_UNEXPECTED;
}
HRESULT wait_event(Codec& state, bool input, DWORD milliseconds) {
    const ULONGLONG end = GetTickCount64() + milliseconds;
    do {
        HRESULT hr = poll_events(state);
        if (FAILED(hr)) return hr;
        unsigned& count = input ? state.input_events : state.output_events;
        if (count) { --count; return S_OK; }
        Sleep(1);
    } while (GetTickCount64() < end);
    return S_FALSE;
}
uint8_t clamp(int value) { return static_cast<uint8_t>(value < 0 ? 0 : value > 255 ? 255 : value); }
void to_nv12(const uint8_t* bgra, uint8_t* nv12, uint32_t width, uint32_t height) {
    const size_t plane = static_cast<size_t>(width) * height;
    for (uint32_t y = 0; y < height; ++y) for (uint32_t x = 0; x < width; ++x) {
        const uint8_t* p = bgra + (static_cast<size_t>(y) * width + x) * 4;
        nv12[static_cast<size_t>(y) * width + x] = clamp(((47*p[2] + 157*p[1] + 16*p[0] + 128) >> 8) + 16);
    }
    for (uint32_t y = 0; y < height; y += 2) for (uint32_t x = 0; x < width; x += 2) {
        int r = 0, g = 0, b = 0;
        for (uint32_t dy = 0; dy < 2; ++dy) for (uint32_t dx = 0; dx < 2; ++dx) {
            const uint8_t* p = bgra + (static_cast<size_t>(y+dy) * width + x+dx) * 4;
            r += p[2]; g += p[1]; b += p[0];
        }
        r = (r+2)/4; g = (g+2)/4; b = (b+2)/4;
        const size_t offset = plane + static_cast<size_t>(y/2) * width + x;
        nv12[offset] = clamp(((-26*r - 87*g + 112*b + 128) >> 8) + 128);
        nv12[offset+1] = clamp(((112*r - 102*g - 10*b + 128) >> 8) + 128);
    }
}
void from_nv12(const uint8_t* nv12, size_t pitch, uint32_t plane_height, uint8_t* bgra, uint32_t width, uint32_t height) {
    const uint8_t* uv = nv12 + pitch * plane_height;
    for (uint32_t y = 0; y < height; ++y) for (uint32_t x = 0; x < width; ++x) {
        const int l = static_cast<int>(nv12[y*pitch+x]) - 16;
        const int u = static_cast<int>(uv[(y/2)*pitch+(x&~1U)]) - 128;
        const int v = static_cast<int>(uv[(y/2)*pitch+(x&~1U)+1]) - 128;
        uint8_t* p = bgra + (static_cast<size_t>(y)*width+x)*4;
        p[0] = clamp((298*l + 541*u + 128) >> 8);
        p[1] = clamp((298*l - 55*u - 136*v + 128) >> 8);
        p[2] = clamp((298*l + 459*v + 128) >> 8); p[3] = 255;
    }
}
// Explicit SDR readback only. Shared P010 stays ten-bit on the GPU; converting
// it to the legacy BGRA mailbox does not claim HDR or a ten-bit display.
void from_420(const uint8_t* bytes,size_t pitch,uint32_t plane_height,uint8_t* bgra,uint32_t width,uint32_t height,bool main10) {
    if(!main10){from_nv12(bytes,pitch,plane_height,bgra,width,height);return;}
    const auto sample=[](const uint8_t* p)->int {uint16_t word=0;std::memcpy(&word,p,2);return int(word>>6);};
    const auto* uv=bytes+pitch*plane_height;
    for(uint32_t y=0;y<height;++y)for(uint32_t x=0;x<width;++x) {
        const int l=sample(bytes+y*pitch+x*2)-64;
        const int u=sample(uv+(y/2)*pitch+(x&~1U)*2)-512;
        const int v=sample(uv+(y/2)*pitch+(x&~1U)*2+2)-512;
        auto* p=bgra+(static_cast<size_t>(y)*width+x)*4;
        p[0]=clamp((298*l+541*u+512)>>10);p[1]=clamp((298*l-55*u-136*v+512)>>10);
        p[2]=clamp((298*l+459*v+512)>>10);p[3]=255;
    }
}
// Diagnostic packing only: three actual ten-bit Y/Cb/Cr samples per u32.
// HDR product presentation consumes the original shared P010 texture instead.
void hdr10_samples(const uint8_t* bytes,size_t pitch,uint32_t plane_height,uint8_t* packed,uint32_t width,uint32_t height) {
    const auto sample=[](const uint8_t* p)->uint32_t {uint16_t v=0;std::memcpy(&v,p,2);return v>>6;};
    const auto* uv=bytes+pitch*plane_height;
    for(uint32_t y=0;y<height;++y)for(uint32_t x=0;x<width;++x) {
        const uint32_t value=sample(bytes+y*pitch+x*2) | (sample(uv+(y/2)*pitch+(x&~1U)*2)<<10) |
            (sample(uv+(y/2)*pitch+(x&~1U)*2+2)<<20);
        std::memcpy(packed+(static_cast<size_t>(y)*width+x)*4,&value,4);
    }
}
HRESULT choose_decoder_output(Codec& state) {
    for (DWORD index = 0; index < 64; ++index) {
        ComPtr<IMFMediaType> type;
        HRESULT hr = state.transform->GetOutputAvailableType(0, index, &type);
        if (FAILED(hr)) return hr;
        GUID subtype{};
        if (FAILED(type->GetGUID(MF_MT_SUBTYPE, &subtype)) || subtype != (state.main10?MFVideoFormat_P010:MFVideoFormat_NV12)) continue;
        UINT32 width = 0, height = 0, pitch = 0;
        hr = MFGetAttributeSize(type.Get(), MF_MT_FRAME_SIZE, &width, &height);
        if (FAILED(hr) || width < state.width || width > state.width+255 || height < state.height || height > state.height+31)
            return MF_E_INVALIDMEDIATYPE;
        if (width != state.width || height != state.height) {
            MFVideoArea area{}; UINT32 length = 0;
            hr = type->GetBlob(MF_MT_MINIMUM_DISPLAY_APERTURE, reinterpret_cast<UINT8*>(&area), sizeof(area), &length);
            if (FAILED(hr)) hr = type->GetBlob(MF_MT_GEOMETRIC_APERTURE, reinterpret_cast<UINT8*>(&area), sizeof(area), &length);
            if (FAILED(hr) || length != sizeof(area) || area.OffsetX.value || area.OffsetX.fract ||
                area.OffsetY.value || area.OffsetY.fract || area.Area.cx != static_cast<LONG>(state.width) ||
                area.Area.cy != static_cast<LONG>(state.height)) return MF_E_INVALIDMEDIATYPE;
        }
        const UINT32 row_bytes=width*(state.main10?2u:1u);
        if (FAILED(type->GetUINT32(MF_MT_DEFAULT_STRIDE, &pitch))) pitch = row_bytes;
        if (pitch < row_bytes || pitch > row_bytes+1024 || static_cast<uint64_t>(pitch)*height*3/2 > raw_limit)
            return MF_E_INVALIDMEDIATYPE;
        if (state.hevc) { hr=hevc_color(type.Get(),true,state.hdr10); if (FAILED(hr)) return hr; }
        hr = state.transform->SetOutputType(0, type.Get(), 0);
        if (FAILED(hr)) continue;
        state.output_height = height; state.output_pitch = pitch;
        return S_OK;
    }
    return MF_E_INVALIDMEDIATYPE;
}
HRESULT output(Codec& state, uint8_t* destination, size_t capacity, size_t* length, uint64_t* pts, DWORD wait_ms) {
    *length = 0;
    if(state.shared_output) {
        const HRESULT shared=state.shared_output->room();
        if(shared!=S_OK)return shared;
    }
    if (state.events) {
        HRESULT hr = poll_events(state);
        if (FAILED(hr)) return hr;
        if (!state.output_events && !wait_ms) return S_FALSE;
        hr = wait_event(state, false, wait_ms);
        if (hr != S_OK) return hr;
    }
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        MFT_OUTPUT_STREAM_INFO info{};
        HRESULT hr = state.transform->GetOutputStreamInfo(0, &info);
        if (FAILED(hr)) return hr;
        ComPtr<IMFSample> supplied;
        if (!(info.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES))) {
            hr = MFCreateSample(&supplied);
            if (FAILED(hr)) return hr;
            const size_t requested = info.cbSize ? info.cbSize : capacity;
            if (!requested || requested > raw_limit) return E_INVALIDARG;
            ComPtr<IMFMediaBuffer> buffer;
            hr = info.cbAlignment > 1 ? MFCreateAlignedMemoryBuffer(static_cast<DWORD>(requested), info.cbAlignment-1, &buffer)
                : MFCreateMemoryBuffer(static_cast<DWORD>(requested), &buffer);
            if (SUCCEEDED(hr)) hr = supplied->AddBuffer(buffer.Get());
            if (FAILED(hr)) return hr;
        }
        MFT_OUTPUT_DATA_BUFFER data{};
        data.pSample = supplied.Get();
        DWORD status = 0;
        hr = state.transform->ProcessOutput(0, 1, &data, &status);
        if (data.pEvents) data.pEvents->Release();
        ComPtr<IMFSample> sample;
        if (data.pSample == supplied.Get()) sample = supplied;
        else sample.Attach(data.pSample);
        if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) {
            if (state.gpu_input) ++state.gpu_need_input;
            if (state.hevc && state.drain_started && !state.events) state.drain_complete = true;
            return S_FALSE;
        }
        if (hr == MF_E_TRANSFORM_STREAM_CHANGE && !state.encoder && attempt == 0) {
            hr = choose_decoder_output(state);
            if (FAILED(hr)) return hr;
            continue;
        }
        if (FAILED(hr)) return hr;
        if (!sample) return E_UNEXPECTED;
        if (state.hevc) {
            ComPtr<IMFMediaType> actual;
            hr=state.transform->GetOutputCurrentType(0,&actual);
            if (SUCCEEDED(hr)) hr=hevc_color(actual.Get(),false,state.hdr10);
            if (FAILED(hr)) return hr;
        }
        LONGLONG time = 0;
        if (FAILED(sample->GetSampleTime(&time)) || time < 0) return E_UNEXPECTED;
        *pts = static_cast<uint64_t>(time) / 1000 * 9 + (static_cast<uint64_t>(time) % 1000 * 9 + 500) / 1000;
        ComPtr<IMFMediaBuffer> buffer;
        hr = sample->ConvertToContiguousBuffer(&buffer);
        if (FAILED(hr)) return hr;
        if (!state.encoder && state.context) {
            ComPtr<IMFDXGIBuffer> gpu;
            if (SUCCEEDED(buffer.As(&gpu))) {
                ComPtr<ID3D11Texture2D> texture;
                UINT subresource = 0;
                hr = gpu->GetResource(IID_PPV_ARGS(&texture));
                if (SUCCEEDED(hr)) hr = gpu->GetSubresourceIndex(&subresource);
                if (FAILED(hr)) return hr;
                D3D11_TEXTURE2D_DESC desc{}; texture->GetDesc(&desc);
                ComPtr<ID3D11Device> actual_device;texture->GetDevice(&actual_device);
                if(actual_device.Get()!=state.device.Get() || desc.MipLevels!=1 || subresource>=desc.ArraySize)
                    return MF_E_INVALIDMEDIATYPE;
                if (desc.Width < state.width || desc.Width > state.width+255 ||
                    desc.Height < state.height || desc.Height > state.height+31 ||
                    static_cast<uint64_t>(desc.Width)*desc.Height*3/2*(state.main10?2u:1u) > raw_limit ||
                    ((desc.Width|desc.Height)&1) || desc.Format != (state.main10?DXGI_FORMAT_P010:DXGI_FORMAT_NV12))
                    return MF_E_INVALIDMEDIATYPE;
                if(state.shared_output) {
                    hr=state.shared_output->copy(texture.Get(),subresource,*pts);
                    if(hr!=S_OK)return FAILED(hr)?hr:E_UNEXPECTED;
                }
                desc.Usage = D3D11_USAGE_STAGING; desc.BindFlags = 0;
                desc.MiscFlags = 0; desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
                desc.ArraySize = 1; desc.MipLevels = 1;
                ComPtr<ID3D11Texture2D> staging;
                hr = state.device->CreateTexture2D(&desc, nullptr, &staging);
                if (FAILED(hr)) return hr;
                state.context->CopySubresourceRegion(staging.Get(), 0, 0, 0, 0, texture.Get(), subresource, nullptr);
                D3D11_MAPPED_SUBRESOURCE mapped{};
                hr = state.context->Map(staging.Get(), 0, D3D11_MAP_READ, 0, &mapped);
                if (FAILED(hr)) return hr;
                const size_t row_bytes=static_cast<size_t>(state.width)*(state.main10?2u:1u);
                if (!mapped.pData || mapped.RowPitch < row_bytes || capacity != static_cast<size_t>(state.width)*state.height*4) {
                    state.context->Unmap(staging.Get(), 0); return E_UNEXPECTED;
                }
                // UV starts after the allocated texture height, which can be
                // padded beyond the visible frame. Copy to compact NV12 first.
                const size_t plane = row_bytes*state.height;
                std::unique_ptr<uint8_t[]> compact(new (std::nothrow) uint8_t[plane*3/2]);
                if (!compact) { state.context->Unmap(staging.Get(), 0); return E_OUTOFMEMORY; }
                const auto* source = static_cast<const uint8_t*>(mapped.pData);
                for (uint32_t row = 0; row < state.height; ++row)
                    std::memcpy(compact.get()+static_cast<size_t>(row)*row_bytes, source+static_cast<size_t>(row)*mapped.RowPitch, row_bytes);
                for (uint32_t row = 0; row < state.height/2; ++row)
                    std::memcpy(compact.get()+plane+static_cast<size_t>(row)*row_bytes,
                        source+static_cast<size_t>(desc.Height+row)*mapped.RowPitch, row_bytes);
                state.context->Unmap(staging.Get(), 0);
                if(state.hdr10) hdr10_samples(compact.get(),row_bytes,state.height,destination,state.width,state.height);
                else from_420(compact.get(), row_bytes, state.height, destination, state.width, state.height,state.main10);
                SecureZeroMemory(compact.get(), plane*3/2);
                state.hardware_used = true;
                *length = capacity; return S_OK;
            }
        }
        BYTE* bytes = nullptr; DWORD maximum = 0, used = 0;
        hr = buffer->Lock(&bytes, &maximum, &used);
        if (FAILED(hr)) return hr;
        if (!bytes || used > maximum || (state.encoder ? used > capacity : used < static_cast<size_t>(state.output_pitch)*state.output_height*3/2)) {
            buffer->Unlock(); return E_UNEXPECTED;
        }
        if (state.encoder) { std::memcpy(destination, bytes, used); *length = used; state.hardware_used = state.hardware; if (state.gpu_input) ++state.gpu_outputs; }
        else {
            if(state.hdr10) hdr10_samples(bytes,state.output_pitch,state.output_height,destination,state.width,state.height);
            else from_420(bytes, state.output_pitch, state.output_height, destination, state.width, state.height,state.main10);
            *length = capacity;
        }
        buffer->Unlock(); return S_OK;
    }
    return E_UNEXPECTED;
}
} // namespace

extern thread_local bool gpu_teardown_failed;
static int32_t open_codec(ID3D11Device* supplied_device, uint32_t encoder, uint32_t hardware_only, uint32_t width,
    uint32_t height, uint32_t fps, uint32_t kbps, uint32_t level, void** result, bool hevc=false,bool main10=false,bool hdr10=false) {
    if (!result) return E_POINTER;
    *result = nullptr;
    if (supplied_device && gpu_teardown_failed) return MF_E_SHUTDOWN;
    if (!width || !height || (width|height)&1 || width > 8192 || height > 8192 ||
        static_cast<uint64_t>(width)*height*4 > raw_limit || !fps || fps > (hevc ? 144u : 120u) || kbps > 100000)
        return E_INVALIDARG;
    std::unique_ptr<Codec> state(new (std::nothrow) Codec());
    if (!state) return E_OUTOFMEMORY;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return hr;
    state->com = true;
    hr = MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET);
    if (FAILED(hr)) return hr;
    state->mf = true; state->encoder = encoder != 0; state->hardware = hardware_only != 0; state->hevc=hevc;state->main10=main10;state->hdr10=hdr10;
    state->width = width; state->height = height; state->fps = fps; state->level = level;
    state->output_height = height; state->output_pitch = width*(main10?2u:1u);
    LUID source_adapter{};
    const bool binding_required = supplied_device && state->encoder;
    if (supplied_device) {
        ComPtr<IDXGIDevice> dxgi; ComPtr<IDXGIAdapter> adapter; DXGI_ADAPTER_DESC source_desc{};
        hr = supplied_device->QueryInterface(IID_PPV_ARGS(&dxgi));
        if (hr == S_OK) hr = dxgi->GetAdapter(&adapter);
        if (hr == S_OK) hr = adapter->GetDesc(&source_desc);
        std::fprintf(stderr, "mf source device: codec=%s direction=%s owner_thread=%lu adapter_hr=0x%08lx\n",
            hevc ? "hevc" : "h264", state->encoder ? "encode" : "decode",
            static_cast<unsigned long>(state->thread), static_cast<unsigned long>(hr));
        std::fflush(stderr);
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        source_adapter = source_desc.AdapterLuid;
        LARGE_INTEGER driver{};
        const HRESULT driver_hr = adapter->CheckInterfaceSupport(__uuidof(IDXGIDevice), &driver);
        std::fprintf(stderr,
            "mf source identity: codec=%s direction=%s owner_thread=%lu adapter=0x%016llx vendor=0x%04x device=0x%04x description=\"%.127ls\" "
            "driver_hr=0x%08lx driver=0x%016llx binding_required=%u\n",
            hevc ? "hevc" : "h264", state->encoder ? "encode" : "decode", static_cast<unsigned long>(state->thread),
            static_cast<unsigned long long>(adapter_luid_bits(source_adapter)), source_desc.VendorId, source_desc.DeviceId,
            source_desc.Description, static_cast<unsigned long>(driver_hr),
            static_cast<unsigned long long>(driver_hr == S_OK ? driver.QuadPart : 0), binding_required ? 1u : 0u);
        std::fflush(stderr);
        state->gpu_input = state->encoder; state->device = supplied_device;
        supplied_device->GetImmediateContext(&state->context);
        ComPtr<ID3D10Multithread> protection;
        hr = state->context.As(&protection);
        if (FAILED(hr)) return hr;
        protection->SetMultithreadProtected(TRUE);
        if (state->encoder) {
            // Four immutable-in-flight input surfaces, including all retained MFT samples.
            if (static_cast<uint64_t>(width)*height*3/2*4*(main10?2u:1u) > 128*1024*1024) return E_OUTOFMEMORY;
            state->gpu_release = std::shared_ptr<GpuRelease>(new (std::nothrow) GpuRelease());
            if (!state->gpu_release) return E_OUTOFMEMORY;
            D3D11_TEXTURE2D_DESC desc{};
            desc.Width = width; desc.Height = height; desc.MipLevels = 1; desc.ArraySize = 1;
            desc.Format = main10?DXGI_FORMAT_P010:DXGI_FORMAT_NV12; desc.SampleDesc.Count = 1;
            desc.Usage = D3D11_USAGE_DEFAULT; desc.BindFlags = D3D11_BIND_RENDER_TARGET;
            for (auto& texture : state->gpu_slots) {
                hr = supplied_device->CreateTexture2D(&desc, nullptr, &texture);
                if (FAILED(hr)) return hr;
            }
        }
    }
    MFT_REGISTER_TYPE_INFO raw{MFMediaType_Video, main10?MFVideoFormat_P010:MFVideoFormat_NV12};
    MFT_REGISTER_TYPE_INFO compressed{MFMediaType_Video, hevc ? MFVideoFormat_HEVC : MFVideoFormat_H264};
    IMFActivate** choices = nullptr; UINT32 count = 0;
    // Prefer adapter-targeted enumeration when supported by this Windows runtime.
    // A checked MFTEnum2 adapter input scopes every returned candidate to that
    // adapter. EnumEx has no such scope and still needs an exact activation LUID.
    // A device-manager Set alone is never evidence for a foreign adapter.
    using Enum2 = HRESULT (WINAPI*)(GUID, UINT32, const MFT_REGISTER_TYPE_INFO*, const MFT_REGISTER_TYPE_INFO*, IMFAttributes*, IMFActivate***, UINT32*);
    const auto enum2_address = GetProcAddress(GetModuleHandleW(L"mfplat.dll"),"MFTEnum2");
    Enum2 enum2 = nullptr;
    static_assert(sizeof(enum2) == sizeof(enum2_address), "Windows function pointer size");
    std::memcpy(&enum2, &enum2_address, sizeof(enum2));
    AdapterEnumerationBinding enumeration_binding;
    if (binding_required && enum2) {
        enumeration_binding.scoped_enum2 = true;
        ComPtr<IMFAttributes> attributes;
        hr = MFCreateAttributes(&attributes,1);
        if (hr == S_OK) hr = set_adapter_request(attributes.Get(), source_adapter);
        enumeration_binding.request = hr;
        std::fprintf(stderr,
            "mf adapter request: codec=%s owner_thread=%lu requested_adapter=0x%016llx type=LUID_blob bytes=%u hr=0x%08lx enum=MFTEnum2\n",
            hevc ? "hevc" : "h264", static_cast<unsigned long>(state->thread),
            static_cast<unsigned long long>(adapter_luid_bits(source_adapter)), adapter_luid_bytes,
            static_cast<unsigned long>(hr));
        std::fflush(stderr);
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        hr = enum2(MFT_CATEGORY_VIDEO_ENCODER,MFT_ENUM_FLAG_SORTANDFILTER|MFT_ENUM_FLAG_HARDWARE,
            &raw,&compressed,attributes.Get(),&choices,&count);
    } else {
        if (binding_required) std::fprintf(stderr,
            "mf adapter request: codec=%s owner_thread=%lu requested_adapter=0x%016llx enum=MFTEnumEx activation_binding_required=1\n",
            hevc ? "hevc" : "h264", static_cast<unsigned long>(state->thread),
            static_cast<unsigned long long>(adapter_luid_bits(source_adapter)));
        hr = MFTEnumEx(state->encoder ? MFT_CATEGORY_VIDEO_ENCODER : MFT_CATEGORY_VIDEO_DECODER,
            MFT_ENUM_FLAG_SORTANDFILTER | (hardware_only ? MFT_ENUM_FLAG_HARDWARE : MFT_ENUM_FLAG_SYNCMFT),
            state->encoder ? &raw : &compressed, state->encoder ? &compressed : &raw, &choices, &count);
    }
    enumeration_binding.enumeration = hr;
    std::fprintf(stderr, "mf enumeration: codec=%s direction=%s owner_thread=%lu hr=0x%08lx count=%u exact_adapter_scope=%u\n",
        hevc ? "hevc" : "h264", state->encoder ? "encode" : "decode",
        static_cast<unsigned long>(state->thread), static_cast<unsigned long>(hr), count,
        enumeration_binding.scoped_enum2 && enumeration_binding.request == S_OK && hr == S_OK ? 1u : 0u);
    std::fflush(stderr);
    if (FAILED(hr)) return hr;
    // The system H.264 decoder is a synchronous MFT which becomes DXVA/D3D11
    // accelerated when given a device manager. It is not listed as a hardware
    // MFT. Actual GPU output, rather than this enumeration, confirms its mode.
    if (!count && hardware_only && !state->encoder) {
        CoTaskMemFree(choices); choices = nullptr;
        hr = MFTEnumEx(MFT_CATEGORY_VIDEO_DECODER, MFT_ENUM_FLAG_SORTANDFILTER | MFT_ENUM_FLAG_SYNCMFT,
            &compressed, &raw, &choices, &count);
        if (FAILED(hr)) return hr;
    }
    HRESULT last = MF_E_TOPO_CODEC_NOT_FOUND;
    for (UINT32 index = 0; index < count; ++index) {
        if (!state->transform) {
            LUID activation_adapter{}; UINT32 blob_bytes = 0;
            const HRESULT binding = binding_required
                ? match_adapter_luid(choices[index], source_adapter, &activation_adapter, &blob_bytes)
                : read_adapter_luid(choices[index], &activation_adapter, &blob_bytes);
            const AdapterSelectionBinding selection = binding_required
                ? select_adapter_binding(enumeration_binding, binding) : AdapterSelectionBinding{S_OK, "not_required"};
            log_activation_identity(choices[index], state->encoder, hevc, index, "candidate", S_OK,
                binding_required, binding, activation_adapter, blob_bytes, selection);
            if (selection.result != S_OK) {
                // Unscoped missing identity, malformed attributes, conflicting
                // adapters and unsuccessful scope creation remain refusals.
                last = selection.result;
                log_activation_identity(choices[index], true, hevc, index, "binding_rejected", last,
                    true, binding, activation_adapter, blob_bytes, selection);
            } else {
                ComPtr<IMFTransform> transform;
                last = choices[index]->ActivateObject(IID_PPV_ARGS(&transform));
                log_activation_identity(choices[index], state->encoder, hevc, index, "activate", last,
                    binding_required, binding, activation_adapter, blob_bytes, selection);
                if (SUCCEEDED(last)) {
                    last = configure(*state, transform.Get(), kbps);
                    log_activation_identity(choices[index], state->encoder, hevc, index,
                        SUCCEEDED(last) ? "selected" : "configuration_rejected", last,
                        binding_required, binding, activation_adapter, blob_bytes, selection);
                }
                if (FAILED(last)) { state->events.Reset(); state->transform.Reset(); state->manager.Reset(); if (!state->gpu_input) { state->context.Reset(); state->device.Reset(); } state->input_events = 0; state->output_events = 0; }
            }
        }
        choices[index]->Release();
    }
    CoTaskMemFree(choices);
    if (!state->transform) return last;
    *result = state.release(); return S_OK;
}
extern "C" int32_t nl_mf_open(uint32_t encoder, uint32_t hardware_only, uint32_t width,
    uint32_t height, uint32_t fps, uint32_t kbps, uint32_t level, void** result) noexcept {
    try { return open_codec(nullptr, encoder, hardware_only, width, height, fps, kbps, level, result); }
    catch (...) { return E_OUTOFMEMORY; }
}
extern "C" int32_t nl_mf_open_gpu(void* device, uint32_t width, uint32_t height,
    uint32_t fps, uint32_t kbps, uint32_t level, void** result) noexcept {
    if (!device) return E_INVALIDARG;
    try { return open_codec(static_cast<ID3D11Device*>(device), 1, 1, width, height, fps, kbps, level, result); }
    catch (...) { return E_OUTOFMEMORY; }
}
namespace {
// The bridge owns at most two outputs, with a combined 64 MiB budget. Drain
// before submitting input, including when a synchronous MFT says NOTACCEPTING.
HRESULT collect_output(Codec& state, size_t capacity, DWORD wait_ms) {
    if (state.ready_size >= 2 || capacity > raw_limit - state.ready_bytes) return S_FALSE;
    auto& next = state.ready[(state.ready_head + state.ready_size) % 2];
    next.bytes.reset(new (std::nothrow) uint8_t[capacity]);
    if (!next.bytes) return E_OUTOFMEMORY;
    next.capacity = capacity;
    HRESULT hr = output(state, next.bytes.get(), capacity, &next.length, &next.pts, wait_ms);
    if (hr != S_OK) { next.reset(); return hr; }
    if (!next.length || next.length > capacity) { next.reset(); return E_UNEXPECTED; }
    state.ready_bytes += capacity;
    ++state.ready_size;
    return S_OK;
}
// Shared by the live MFT pump and deterministic boundary tests. S_FALSE is
// bounded backpressure; only a negative HRESULT is fatal. No accepted sample
// can be submitted twice, including when output belongs to a previous sample.
template<class Ready, class Input, class Drain, class Room, class Pause>
HRESULT pump_input(Ready ready, Input input, Drain drain, Room room, Pause pause) {
    for (unsigned attempt = 0; attempt < 4; ++attempt) {
        HRESULT hr = ready();
        if (FAILED(hr)) return hr;
        if (hr == S_OK) {
            hr = input();
            if (SUCCEEDED(hr)) return S_OK;
            if (hr != MF_E_NOTACCEPTING) return hr;
        }
        hr = drain();
        if (FAILED(hr)) return hr;
        if (!room()) return S_FALSE;
        pause();
    }
    return S_FALSE;
}
int32_t process(Codec& state, const uint8_t* input, size_t input_length,
    uint64_t pts, uint32_t force_keyframe, uint32_t submit,
    uint8_t* destination, size_t capacity, size_t* length, uint64_t* output_pts, ID3D11Texture2D* gpu = nullptr) {
    if (state.hevc && state.drain_started && submit) return MF_E_NOTACCEPTING;
    // No input is retained across calls. A sample is retried only after
    // NOTACCEPTING, and is never submitted again once ProcessInput succeeds.
    const size_t plane = static_cast<size_t>(state.width)*state.height;
    if (submit && (state.encoder ? ((!gpu && input_length != plane*4) || capacity > packet_limit) :
        (input_length == 0 || input_length > packet_limit || capacity != plane*4))) return E_INVALIDARG;
    HRESULT hr = collect_output(state, capacity, 0);
    if (FAILED(hr)) return hr;
    bool accepted = false;
    if (gpu) ++state.gpu_calls;
    bool gpu_room = !gpu;
    if (gpu) for (const auto& busy : state.gpu_release->busy) if (!busy.load(std::memory_order_acquire)) gpu_room = true;
    if (gpu && !gpu_room) ++state.gpu_pool_blocked;
    if (submit && gpu_room && state.ready_size < 2 && capacity <= raw_limit - state.ready_bytes) {
        if (state.encoder && force_keyframe) {
            hr = set_codec_value(state.transform.Get(), CODECAPI_AVEncVideoForceKeyFrame, 1);
            if (FAILED(hr)) hr = set_codec_value(state.transform.Get(), CODECAPI_AVEncVideoForceKeyFrame, 1, true);
            if (FAILED(hr)) return hr;
        }
        ComPtr<IMFSample> sample;
        ComPtr<IMFMediaBuffer> buffer;
        const size_t size = state.encoder ? plane*3/2*(state.main10?2u:1u) : input_length;
        if (gpu) {
            D3D11_TEXTURE2D_DESC desc{}; gpu->GetDesc(&desc);
            ComPtr<ID3D11Device> input_device; gpu->GetDevice(&input_device);
            if (!state.gpu_input || input_device.Get() != state.device.Get() ||
                desc.Width != state.width || desc.Height != state.height || desc.Format != (state.main10?DXGI_FORMAT_P010:DXGI_FORMAT_NV12))
                return MF_E_UNSUPPORTED_D3D_TYPE;
            size_t slot = state.gpu_slots.size();
            for (size_t i = 0; i < state.gpu_slots.size(); ++i) {
                bool available = false;
                if (state.gpu_release->busy[i].compare_exchange_strong(available, true, std::memory_order_acq_rel)) { slot = i; break; }
            }
            if (slot == state.gpu_slots.size()) return E_UNEXPECTED;
            ComPtr<IMFTrackedSample> tracked;
            hr = MFCreateTrackedSample(&tracked);
            if (SUCCEEDED(hr)) hr = tracked.As(&sample);
            ComPtr<IMFAsyncCallback> callback;
            callback.Attach(new (std::nothrow) SampleReleased(state.gpu_release, slot));
            if (!callback) hr = E_OUTOFMEMORY;
            if (SUCCEEDED(hr)) hr = tracked->SetAllocator(callback.Get(), nullptr);
            if (FAILED(hr)) { state.gpu_release->busy[slot].store(false); return hr; }
            state.context->CopyResource(state.gpu_slots[slot].Get(), gpu);
            // MF may consume through another context. Complete our copy before handoff.
            D3D11_QUERY_DESC query_desc{D3D11_QUERY_EVENT, 0};
            ComPtr<ID3D11Query> query;
            hr = state.device->CreateQuery(&query_desc, &query);
            if (FAILED(hr)) return hr;
            state.context->End(query.Get()); state.context->Flush();
            const ULONGLONG deadline = GetTickCount64() + 16;
            do { hr = state.context->GetData(query.Get(), nullptr, 0, 0); if (hr == S_FALSE) Sleep(0); }
            while (hr == S_FALSE && GetTickCount64() < deadline);
            if (hr == S_FALSE) {
                // The bounded copy wait expired without a device error. This
                // input was never handed to MF, so preserve unaccepted status.
                // Commands on this same immediate context remain ordered; the
                // tracked callback releases the slot after the local sample dies.
                ++state.gpu_copy_pending;
                return 3;
            }
            if (FAILED(hr)) return hr;
            hr = MFCreateDXGISurfaceBuffer(__uuidof(ID3D11Texture2D), state.gpu_slots[slot].Get(), 0, FALSE, &buffer);
            if (SUCCEEDED(hr)) hr = buffer->SetCurrentLength(static_cast<DWORD>(size));
        } else {
            if (state.gpu_input) return E_INVALIDARG;
            hr = MFCreateSample(&sample);
            if (SUCCEEDED(hr)) hr = MFCreateMemoryBuffer(static_cast<DWORD>(size), &buffer);
            if (FAILED(hr)) return hr;
            BYTE* bytes = nullptr;
            hr = buffer->Lock(&bytes, nullptr, nullptr);
            if (FAILED(hr)) return hr;
            if (state.encoder) to_nv12(input, bytes, state.width, state.height);
            else std::memcpy(bytes, input, size);
            buffer->Unlock();
            hr = buffer->SetCurrentLength(static_cast<DWORD>(size));
        }
        if (SUCCEEDED(hr)) hr = sample->AddBuffer(buffer.Get());
        if (SUCCEEDED(hr)) hr = sample->SetSampleTime(static_cast<LONGLONG>(pts*1000/9));
        if (SUCCEEDED(hr)) hr = sample->SetSampleDuration(10000000/state.fps);
        if (FAILED(hr)) return hr;
        hr = pump_input(
            [&]() -> HRESULT {
                HRESULT status = poll_events(state);
                if (FAILED(status)) return status;
                return !state.events || state.input_events ? S_OK : S_FALSE;
            },
            [&]() -> HRESULT {
                if (state.events) --state.input_events;
                return state.transform->ProcessInput(0, sample.Get(), 0);
            },
            [&]() { return collect_output(state, capacity, 0); },
            [&]() { return state.ready_size < 2 && capacity <= raw_limit - state.ready_bytes; },
            []() { Sleep(1); });
        if (FAILED(hr)) return hr;
        accepted = hr == S_OK;
        if (gpu && accepted) ++state.gpu_accepted;
    }
    // A full tracked GPU pool is backpressure, not a reason to spin. Give
    // the asynchronous MFT its bounded output wait so it can release samples
    // and return an older AU before the caller retries the unaccepted input.
    if ((accepted || !submit || (gpu && !gpu_room)) && !state.ready_size) {
        hr = collect_output(state, capacity, 8);
        if (FAILED(hr)) return hr;
    }
    if (!state.ready_size) return accepted ? 1 : 3;
    auto& next = state.ready[state.ready_head];
    if (next.length > capacity) return E_UNEXPECTED;
    std::memcpy(destination, next.bytes.get(), next.length);
    *length = next.length; *output_pts = next.pts;
    state.ready_bytes -= next.capacity;
    next.reset();
    state.ready_head = (state.ready_head + 1) % 2;
    --state.ready_size;
    return accepted ? 0 : 2;
}
} // namespace
extern "C" int32_t nl_mf_process(void* opaque, const uint8_t* input, size_t input_length,
    uint64_t pts, uint32_t force_keyframe, uint32_t submit, uint8_t* destination, size_t capacity,
    size_t* length, uint64_t* output_pts) noexcept {
    auto* state = static_cast<Codec*>(opaque);
    if (!state || !input || !destination || !length || !output_pts || state->thread != GetCurrentThreadId() ||
        pts > INT64_MAX / 1000 || !capacity || capacity > raw_limit || input_length > raw_limit) return E_INVALIDARG;
    *length = 0; *output_pts = 0;
    // 0 accepted+output; 1 accepted+no output; 2 backpressure+old output;
    // 3 backpressure+no output. Negative HRESULTs alone are fatal.
    return process(*state, input, input_length, pts, force_keyframe, submit,
        destination, capacity, length, output_pts);
}
extern "C" int32_t nl_mf_process_gpu(void* opaque, void* texture, uint64_t pts,
    uint32_t force_keyframe, uint32_t submit, uint8_t* destination, size_t capacity,
    size_t* length, uint64_t* output_pts) noexcept {
    auto* state = static_cast<Codec*>(opaque);
    if (!state || !state->gpu_input || !texture || !destination || !length || !output_pts ||
        state->thread != GetCurrentThreadId() || pts > INT64_MAX / 1000 || !capacity || capacity > packet_limit) return E_INVALIDARG;
    *length = 0; *output_pts = 0;
    return process(*state, nullptr, 0, pts, force_keyframe, submit, destination, capacity, length, output_pts,
        static_cast<ID3D11Texture2D*>(texture));
}
extern "C" int32_t nl_mf_bitrate(void* opaque, uint32_t kbps) noexcept {
    auto* state = static_cast<Codec*>(opaque);
    if (!state || !state->encoder || state->thread != GetCurrentThreadId() || kbps < 64 || kbps > 100000) return E_INVALIDARG;
    return set_codec_value(state->transform.Get(), CODECAPI_AVEncCommonMeanBitRate, kbps*1000);
}
extern "C" int32_t nl_mf_enable_shared_output(void* opaque,void* process,NlSharedRingDescriptor* result) noexcept {
    auto* state=static_cast<Codec*>(opaque);
    if(!state || state->thread!=GetCurrentThreadId() || state->encoder || !state->hevc || !state->hardware ||
        !state->device || !state->context || state->shared_output || !result)return E_INVALIDARG;
    std::unique_ptr<SharedDecodeRing> ring(new(std::nothrow)SharedDecodeRing());if(!ring)return E_OUTOFMEMORY;
    const HRESULT hr=ring->initialize(state->device.Get(),state->context.Get(),static_cast<HANDLE>(process),
        state->width,state->height,state->main10?10u:8u,result,state->hdr10);
    if(FAILED(hr))return hr;
    state->shared_output=std::move(ring);return S_OK;
}
extern "C" int32_t nl_mf_shared_frame(void* opaque,uint64_t pts,NlSharedFrame* result) noexcept {
    auto* state=static_cast<Codec*>(opaque);
    if(!state || state->thread!=GetCurrentThreadId() || !result)return E_INVALIDARG;
    if(!state->shared_output)return S_FALSE;
    return state->shared_output->frame(pts,result);
}
extern "C" int32_t nl_mf_discard_shared_frame(void* opaque,uint32_t slot,uint64_t token) noexcept {
    auto* state=static_cast<Codec*>(opaque);
    if(!state || state->thread!=GetCurrentThreadId() || !state->shared_output)return E_INVALIDARG;
    return state->shared_output->discard(slot,token);
}
extern "C" int32_t nl_mf_shared_frame_status(void* opaque,uint32_t slot,uint64_t token) noexcept {
    auto* state=static_cast<Codec*>(opaque);
    if(!state || state->thread!=GetCurrentThreadId() || !state->shared_output)return E_INVALIDARG;
    return state->shared_output->status(slot,token);
}
extern "C" int32_t nl_mf_flush_decoder(void* opaque) noexcept {
    auto* state = static_cast<Codec*>(opaque);
    if (!state || state->encoder || state->thread != GetCurrentThreadId()) return E_INVALIDARG;
    HRESULT hr = S_OK;
    state->input_events = 0;
    state->output_events = 0;
    for (auto& entry : state->ready) entry.reset();
    state->ready_head = 0; state->ready_size = 0; state->ready_bytes = 0;
    if (state->events) {
        // Drain the old stream before flushing. Flush may itself publish fresh
        // NeedInput credits; draining afterwards would discard those credits.
        bool drained = false;
        for (unsigned count = 0; count < 64; ++count) {
            ComPtr<IMFMediaEvent> event;
            hr = state->events->GetEvent(MF_EVENT_FLAG_NO_WAIT, &event);
            if (hr == MF_E_NO_EVENTS_AVAILABLE) { drained = true; break; }
            if (FAILED(hr)) return hr;
        }
        if (!drained) return E_UNEXPECTED;
    }
    hr = state->transform->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
    if (FAILED(hr)) return hr;
    return state->transform->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
}
extern "C" uint32_t nl_mf_hardware_used(void* opaque) noexcept {
    auto* state = static_cast<Codec*>(opaque);
    return state && state->thread == GetCurrentThreadId() && state->hardware_used ? 1 : 0;
}
// A stuck vendor sample retains its entire state instead of freeing a texture
// that MF may still read. At most one failed GPU owner is admitted per thread.
thread_local bool gpu_teardown_failed = false;
extern "C" int32_t nl_mf_close_checked(void* opaque) noexcept {
    auto* state = static_cast<Codec*>(opaque);
    if (!state || state->thread != GetCurrentThreadId()) return E_INVALIDARG;
    if (state->gpu_input && state->gpu_release) {
        unsigned busy_slots=0;
        for (const auto& slot : state->gpu_release->busy) if (slot.load(std::memory_order_acquire)) ++busy_slots;
        std::fprintf(stderr,"host_gpu_mf_stage=close calls=%u accepted=%u pool_blocked=%u output_samples=%u output_need_input=%u copy_pending=%u busy_slots=%u asynchronous=%u input_credits=%u output_credits=%u\n",
            state->gpu_calls,state->gpu_accepted,state->gpu_pool_blocked,state->gpu_outputs,state->gpu_need_input,state->gpu_copy_pending,busy_slots,state->events?1u:0u,state->input_events,state->output_events);
        if (state->transform) {
            state->transform->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH,0);
            state->transform->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING,0);
        }
        state->events.Reset(); state->transform.Reset();
        const ULONGLONG deadline = GetTickCount64()+50;
        bool busy = true;
        do {
            busy = false;
            for (const auto& slot : state->gpu_release->busy) if (slot.load(std::memory_order_acquire)) busy = true;
            if (busy) Sleep(1);
        } while (busy && GetTickCount64()<deadline);
        if (busy) {
            gpu_teardown_failed = true;
            for (auto& entry : state->ready) entry.reset();
            // Deliberate bounded quarantine, never reused or released off owner.
            return HRESULT_FROM_WIN32(WAIT_TIMEOUT);
        }
    }
    HRESULT checked_close=S_OK;
    if(!state->gpu_input && state->transform) {
        checked_close=state->transform->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH,0);
        const HRESULT end=state->transform->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING,0);
        if(SUCCEEDED(checked_close) && FAILED(end))checked_close=end;
        state->events.Reset();state->transform.Reset();
    }
    delete state; return checked_close;
}
extern "C" void nl_mf_close(void* opaque) noexcept { (void)nl_mf_close_checked(opaque); }

// Deterministic tests of the exact pump used above, without a GPU or COM MFT.
extern "C" uint32_t nl_mf_backpressure_contract() noexcept {
    unsigned calls = 0, drains = 0;
    bool ordered = true;
    HRESULT hr = pump_input([]() { return S_OK; }, [&]() {
        ++calls;
        if (calls == 1) return MF_E_NOTACCEPTING;
        ordered = drains == 1;
        return S_OK;
    }, [&]() { ++drains; return S_OK; }, []() { return true; }, []() {});
    uint32_t result = hr == S_OK && calls == 2 && drains == 1 && ordered ? 1 : 0;
    calls = 0; drains = 0;
    hr = pump_input([]() { return S_OK; }, [&]() { ++calls; return S_OK; },
        [&]() { ++drains; return S_OK; }, []() { return true; }, []() {});
    if (hr == S_OK && calls == 1 && !drains) result |= 2;
    calls = 0;
    hr = pump_input([]() { return S_OK; }, [&]() { ++calls; return MF_E_NOTACCEPTING; },
        []() { return S_FALSE; }, []() { return true; }, []() {});
    if (hr == S_FALSE && calls == 4) result |= 4;
    calls = 0; drains = 0;
    hr = pump_input([]() { return S_FALSE; }, [&]() { ++calls; return S_OK; },
        [&]() { ++drains; return S_OK; }, []() { return false; }, []() {});
    if (hr == S_FALSE && !calls && drains == 1) result |= 8;
    return result;
}


// The actual allocator callback contains no COM/GPU owner and survives owner
// mailbox release. Exercise slot exclusivity and completion without hardware.
extern "C" uint32_t nl_mf_gpu_pool_contract() noexcept {
    try {
        auto release = std::make_shared<GpuRelease>();
        for (auto& busy : release->busy) {
            bool expected = false;
            if (!busy.compare_exchange_strong(expected,true)) return 0;
            expected = false;
            if (busy.compare_exchange_strong(expected,true)) return 0;
        }
        ComPtr<IMFAsyncCallback> callback;
        callback.Attach(new (std::nothrow) SampleReleased(release,2));
        if (!callback) return 0;
        if (FAILED(callback->Invoke(nullptr)) || release->busy[2].load() || !release->busy[1].load()) return 0;
        bool expected = false;
        if (!release->busy[2].compare_exchange_strong(expected,true)) return 0;
        auto weak = std::weak_ptr<GpuRelease>(release);
        release.reset();
        if (weak.expired() || FAILED(callback->Invoke(nullptr))) return 0;
        callback.Reset();
        return weak.expired() ? 1 : 0;
    } catch (...) { return 0; }
}

// Real IMFAttributes exercise the production request writer and identity reader.
// No device, MFT enumeration, encoder, capture or GPU resource is opened here.
extern "C" uint32_t nl_mf_adapter_binding_contract() noexcept {
    uint32_t passed = 0;
    const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(com)) return passed;
    if (FAILED(MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET))) { CoUninitialize(); return passed; }
    {
        ComPtr<IMFAttributes> attributes;
        if (MFCreateAttributes(&attributes, 1) == S_OK) {
            const LUID expected{0x89abcdefu, -1234567};
            LUID actual{}; UINT32 bytes = 0; MF_ATTRIBUTE_TYPE type{};
            if (set_adapter_request(attributes.Get(), expected) == S_OK &&
                attributes->GetItemType(MFT_ENUM_ADAPTER_LUID, &type) == S_OK && type == MF_ATTRIBUTE_BLOB &&
                match_adapter_luid(attributes.Get(), expected, &actual, &bytes) == S_OK &&
                bytes == adapter_luid_bytes && same_adapter_luid(actual, expected)) passed |= 1;
            if (attributes->DeleteAllItems() == S_OK &&
                FAILED(match_adapter_luid(attributes.Get(), expected, &actual, &bytes))) passed |= 2;
            if (attributes->SetUINT64(MFT_ENUM_ADAPTER_LUID, adapter_luid_bits(expected)) == S_OK &&
                FAILED(match_adapter_luid(attributes.Get(), expected, &actual, &bytes))) passed |= 4;
            const BYTE short_blob[sizeof(LUID) - 1]{};
            if (attributes->SetBlob(MFT_ENUM_ADAPTER_LUID, short_blob, sizeof(short_blob)) == S_OK &&
                FAILED(match_adapter_luid(attributes.Get(), expected, &actual, &bytes)) &&
                bytes == sizeof(short_blob)) passed |= 8;
            const BYTE long_blob[sizeof(LUID) + 1]{};
            if (attributes->SetBlob(MFT_ENUM_ADAPTER_LUID, long_blob, sizeof(long_blob)) == S_OK &&
                FAILED(match_adapter_luid(attributes.Get(), expected, &actual, &bytes)) &&
                bytes == sizeof(long_blob)) passed |= 16;
            LUID foreign = expected; foreign.LowPart ^= 1;
            if (set_adapter_request(attributes.Get(), foreign) == S_OK &&
                match_adapter_luid(attributes.Get(), expected, &actual, &bytes) == DXGI_ERROR_UNSUPPORTED &&
                same_adapter_luid(actual, foreign)) passed |= 32;
            foreign = expected; foreign.HighPart ^= 1;
            if (set_adapter_request(attributes.Get(), foreign) == S_OK &&
                match_adapter_luid(attributes.Get(), expected, &actual, &bytes) == DXGI_ERROR_UNSUPPORTED &&
                same_adapter_luid(actual, foreign)) passed |= 64;
            const LUID zero{};
            if (set_adapter_request(attributes.Get(), zero) == S_OK &&
                match_adapter_luid(attributes.Get(), zero, &actual, &bytes) == S_OK &&
                bytes == adapter_luid_bytes && same_adapter_luid(actual, zero)) passed |= 128;
            if (attributes->SetUINT64(MFT_ENUM_ADAPTER_LUID, adapter_luid_bits(expected)) == S_OK &&
                set_adapter_request(attributes.Get(), expected) == S_OK &&
                attributes->GetItemType(MFT_ENUM_ADAPTER_LUID, &type) == S_OK && type == MF_ATTRIBUTE_BLOB &&
                match_adapter_luid(attributes.Get(), expected, &actual, &bytes) == S_OK) passed |= 256;
        }
    }
    MFShutdown(); CoUninitialize(); return passed;
}

// Independent selection policy regression; the strict blob-reader contract
// above remains unchanged. Enum HRESULTs model the production call receipts;
// activation metadata uses real IMFAttributes and the production strict reader.
extern "C" uint32_t nl_mf_adapter_selection_contract() noexcept {
    uint32_t passed = 0;
    const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(com)) return passed;
    if (FAILED(MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET))) { CoUninitialize(); return passed; }
    {
        ComPtr<IMFAttributes> attributes;
        if (MFCreateAttributes(&attributes, 1) == S_OK) {
            const LUID expected{0x89abcdefu, -1234567};
            const AdapterEnumerationBinding scoped{true, S_OK, S_OK};
            const AdapterEnumerationBinding unscoped{false, E_UNEXPECTED, S_OK};
            LUID actual{}; UINT32 bytes = 0;
            const auto decide = [&](const AdapterEnumerationBinding& enumeration) {
                return select_adapter_binding(enumeration,
                    match_adapter_luid(attributes.Get(), expected, &actual, &bytes));
            };
            auto selected = decide(scoped);
            if (match_adapter_luid(attributes.Get(), expected, &actual, &bytes) == MF_E_ATTRIBUTENOTFOUND &&
                selected.result == S_OK && std::strcmp(selected.basis, "mft_enum2_exact_adapter_scope") == 0) passed |= 1;
            if (set_adapter_request(attributes.Get(), expected) == S_OK) {
                selected = decide(scoped);
                if (selected.result == S_OK && std::strcmp(selected.basis, "activation_luid_blob") == 0) passed |= 2;
            }
            LUID foreign = expected; foreign.HighPart ^= 1;
            if (set_adapter_request(attributes.Get(), foreign) == S_OK &&
                decide(scoped).result == DXGI_ERROR_UNSUPPORTED && decide(unscoped).result == DXGI_ERROR_UNSUPPORTED) passed |= 4;
            bool malformed = attributes->SetUINT64(MFT_ENUM_ADAPTER_LUID, adapter_luid_bits(expected)) == S_OK &&
                FAILED(decide(scoped).result);
            const BYTE short_blob[sizeof(LUID) - 1]{}, long_blob[sizeof(LUID) + 1]{};
            malformed = malformed && attributes->SetBlob(MFT_ENUM_ADAPTER_LUID, short_blob, sizeof(short_blob)) == S_OK &&
                FAILED(decide(scoped).result);
            malformed = malformed && attributes->SetBlob(MFT_ENUM_ADAPTER_LUID, long_blob, sizeof(long_blob)) == S_OK &&
                FAILED(decide(scoped).result);
            if (malformed) passed |= 8;
            if (set_adapter_request(attributes.Get(), expected) == S_OK) {
                const AdapterEnumerationBinding failed_request{true, E_ACCESSDENIED, S_OK};
                const AdapterEnumerationBinding inexact_request{true, S_FALSE, S_OK};
                const AdapterEnumerationBinding conflicting_request{true, DXGI_ERROR_UNSUPPORTED, S_OK};
                if (decide(failed_request).result == E_ACCESSDENIED && FAILED(decide(inexact_request).result) &&
                    decide(conflicting_request).result == DXGI_ERROR_UNSUPPORTED) passed |= 16;
                const AdapterEnumerationBinding failed_enum{true, S_OK, E_ACCESSDENIED};
                const AdapterEnumerationBinding inexact_enum{true, S_OK, S_FALSE};
                const AdapterEnumerationBinding failed_fallback{false, E_UNEXPECTED, E_ACCESSDENIED};
                if (decide(failed_enum).result == E_ACCESSDENIED && FAILED(decide(inexact_enum).result) &&
                    decide(failed_fallback).result == E_ACCESSDENIED) passed |= 32;
                selected = decide(unscoped);
                if (selected.result == S_OK && std::strcmp(selected.basis, "activation_luid_blob") == 0 &&
                    attributes->DeleteAllItems() == S_OK && decide(unscoped).result == MF_E_ATTRIBUTENOTFOUND) passed |= 64;
                if (decide(failed_request).result == E_ACCESSDENIED && decide(failed_enum).result == E_ACCESSDENIED &&
                    select_adapter_binding(scoped, E_ACCESSDENIED).result == E_ACCESSDENIED &&
                    FAILED(select_adapter_binding(scoped, S_FALSE).result)) passed |= 128;
            }
        }
    }
    MFShutdown(); CoUninitialize(); return passed;
}

// Same property decision path used by the real encoder, plus actual MF types.
// No decoder, GPU device, window or capture resource is opened by this test.
extern "C" uint32_t nl_hevc_color_contract() noexcept {
    uint32_t passed=0;
    const auto scenario=[](HRESULT support,HRESULT set,HRESULT get,VARTYPE type,ULONG value,unsigned& calls) {
        CodecColorReceipt receipt{};
        return codec_color_property(2,[&](){return support;},[&](VARIANT* requested){
            ++calls;return requested->vt==VT_UI4 && requested->ulVal==2?set:E_INVALIDARG;
        },[&](VARIANT* actual){
            calls+=2;actual->vt=type;
            if(type==VT_UI4)actual->ulVal=value;
            else if(type==VT_I4)actual->lVal=static_cast<LONG>(value);
            return get;
        },receipt);
    };
    unsigned calls=0;
    if(scenario(S_OK,S_OK,S_OK,VT_UI4,2,calls)==S_OK && calls==3)passed|=1;
    calls=0;
    if(scenario(S_FALSE,S_OK,S_OK,VT_UI4,2,calls)==S_OK && !calls)passed|=2;
    if(scenario(E_NOTIMPL,S_OK,S_OK,VT_UI4,2,calls)==S_OK && !calls)passed|=4;
    if(scenario(E_ACCESSDENIED,S_OK,S_OK,VT_UI4,2,calls)==E_ACCESSDENIED && !calls)passed|=8;
    calls=0;
    bool rejected=scenario(S_OK,E_INVALIDARG,S_OK,VT_UI4,2,calls)==E_INVALIDARG && calls==1;
    calls=0;
    rejected=rejected && FAILED(scenario(S_OK,S_FALSE,S_OK,VT_UI4,2,calls)) && calls==1;
    if(rejected)passed|=16;
    calls=0;
    rejected=scenario(S_OK,S_OK,E_FAIL,VT_UI4,2,calls)==E_FAIL && calls==3;
    calls=0;
    rejected=rejected && FAILED(scenario(S_OK,S_OK,S_FALSE,VT_UI4,2,calls)) && calls==3;
    if(rejected)passed|=32;
    calls=0;
    rejected=scenario(S_OK,S_OK,S_OK,VT_UI4,0,calls)==MF_E_INVALIDMEDIATYPE;
    rejected=rejected && scenario(S_OK,S_OK,S_OK,VT_I4,2,calls)==MF_E_INVALIDMEDIATYPE;
    if(rejected)passed|=64;
    const HRESULT com=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if(FAILED(com))return passed;
    if(FAILED(MFStartup(MF_VERSION,MFSTARTUP_NOSOCKET))){CoUninitialize();return passed;}
    {
        Codec state;state.hevc=true;state.encoder=true;
        state.width=1920;state.height=1080;state.fps=60;
        ComPtr<IMFMediaType> raw,compressed;
        if(SUCCEEDED(media_type(state,false,8000,&raw)) && SUCCEEDED(media_type(state,true,8000,&compressed)) &&
            SUCCEEDED(hevc_sdr(raw.Get(),false)) && SUCCEEDED(hevc_sdr(compressed.Get(),false))) {
            UINT32 primaries=0,transfer=0;
            if(SUCCEEDED(raw->GetUINT32(MF_MT_VIDEO_PRIMARIES,&primaries)) && primaries==2 &&
                SUCCEEDED(compressed->GetUINT32(MF_MT_TRANSFER_FUNCTION,&transfer)) && transfer==5 &&
                SUCCEEDED(compressed->SetUINT32(MF_MT_VIDEO_PRIMARIES,0)) &&
                hevc_sdr(compressed.Get(),false)==MF_E_INVALIDMEDIATYPE)passed|=128;
        }
    }
    MFShutdown();CoUninitialize();return passed;
}

// Explicit prototype entry points. No product VideoCodec/wire identity is changed.
extern "C" int32_t nl_hevc_open(void* device, uint32_t encoder, uint32_t hardware,
    uint32_t width,uint32_t height,uint32_t fps,uint32_t kbps,uint32_t bit_depth,void** result) noexcept {
    if ((bit_depth!=8 && bit_depth!=10) || (encoder && (!device || !hardware))) return E_INVALIDARG;
    try { return open_codec(static_cast<ID3D11Device*>(device),encoder,hardware,width,height,fps,kbps,0,result,true,bit_depth==10); }
    catch (...) { return E_OUTOFMEMORY; }
}
extern "C" int32_t nl_hevc_hdr10_open(void* device, uint32_t encoder, uint32_t hardware,
    uint32_t width,uint32_t height,uint32_t fps,uint32_t kbps,void** result) noexcept {
    if (encoder && (!device || !hardware)) return E_INVALIDARG;
    try { return open_codec(static_cast<ID3D11Device*>(device),encoder,hardware,width,height,fps,kbps,0,result,true,true,true); }
    catch (...) { return E_FAIL; }
}
// Scalar receipt from the live transform, never a vendor-name inference.
extern "C" int32_t nl_hevc_observation(void* opaque,uint64_t* luid,uint32_t* flags) noexcept {
    auto* s=static_cast<Codec*>(opaque);
    if (!s || !s->hevc || !luid || !flags || s->thread!=GetCurrentThreadId()) return E_INVALIDARG;
    *flags=(s->events?1u:0u)|(s->manager?2u:0u)|(s->hardware_used?4u:0u)|(s->gpu_input?8u:0u)|
        (s->drain_started?16u:0u)|(s->drain_complete?32u:0u);
    *luid=0;
    if (s->device) {
        ComPtr<IDXGIDevice> dxgi;ComPtr<IDXGIAdapter> adapter;DXGI_ADAPTER_DESC desc{};
        HRESULT hr=s->device.As(&dxgi);if(SUCCEEDED(hr))hr=dxgi->GetAdapter(&adapter);
        if(SUCCEEDED(hr))hr=adapter->GetDesc(&desc);if(FAILED(hr))return hr;
        *luid=static_cast<uint64_t>(static_cast<uint32_t>(desc.AdapterLuid.HighPart))<<32|desc.AdapterLuid.LowPart;
    }
    return S_OK;
}
namespace {
struct HevcDecoderDevice {
    ComPtr<ID3D11Device> device;ComPtr<ID3D11DeviceContext> context;
    DWORD thread=GetCurrentThreadId();
};
struct HevcSyntheticSource {
    ComPtr<ID3D11Device> device;ComPtr<ID3D11DeviceContext> context;ComPtr<ID3D11Texture2D> texture;
    DWORD thread=GetCurrentThreadId();
};
}
// Real decode-only D3D owner: no synthetic texture, desktop read or HWND.
extern "C" int32_t nl_hevc_decoder_device_open(uint64_t adapter_luid,void** result) noexcept {
    if(!result)return E_POINTER;*result=nullptr;
    try {
        std::unique_ptr<HevcDecoderDevice> s(new(std::nothrow) HevcDecoderDevice());if(!s)return E_OUTOFMEMORY;
        ComPtr<IDXGIFactory1> factory;HRESULT hr=CreateDXGIFactory1(IID_PPV_ARGS(&factory));if(FAILED(hr))return hr;
        ComPtr<IDXGIAdapter1> selected;
        for(UINT index=0;;++index){
            ComPtr<IDXGIAdapter1> candidate;hr=factory->EnumAdapters1(index,&candidate);
            if(hr==DXGI_ERROR_NOT_FOUND)break;if(FAILED(hr))return hr;
            DXGI_ADAPTER_DESC1 desc{};hr=candidate->GetDesc1(&desc);if(FAILED(hr))return hr;
            const uint64_t luid=(uint64_t(uint32_t(desc.AdapterLuid.HighPart))<<32)|uint32_t(desc.AdapterLuid.LowPart);
            if(luid==adapter_luid && !(desc.Flags&DXGI_ADAPTER_FLAG_SOFTWARE)){selected=candidate;break;}
        }
        if(!selected)return DXGI_ERROR_NOT_FOUND;
        hr=D3D11CreateDevice(selected.Get(),D3D_DRIVER_TYPE_UNKNOWN,nullptr,D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            nullptr,0,D3D11_SDK_VERSION,&s->device,nullptr,&s->context);if(FAILED(hr))return hr;
        *result=s.release();return S_OK;
    }catch(...){return E_OUTOFMEMORY;}
}
extern "C" int32_t nl_hevc_decoder_device_borrow(void* opaque,void** device) noexcept {
    auto* s=static_cast<HevcDecoderDevice*>(opaque);
    if(!s||!device||s->thread!=GetCurrentThreadId())return E_INVALIDARG;
    HRESULT hr=s->device->GetDeviceRemovedReason();if(FAILED(hr))return hr;
    *device=s->device.Get();return S_OK;
}
extern "C" int32_t nl_hevc_decoder_device_close(void* opaque) noexcept {
    auto* s=static_cast<HevcDecoderDevice*>(opaque);
    if(!s||s->thread!=GetCurrentThreadId())return E_INVALIDARG;
    delete s;return S_OK;
}
// Synthetic upload only: no monitor enumeration, capture API, HWND or desktop read.
extern "C" int32_t nl_hevc_synthetic_open(uint32_t width,uint32_t height,uint32_t bit_depth,void** result) noexcept {
    if(!result)return E_POINTER;*result=nullptr;
    if((bit_depth!=8 && bit_depth!=10)||!width||!height||((width|height)&1)||width>8192||height>8192 ||
        static_cast<uint64_t>(width)*height*4>raw_limit)return E_INVALIDARG;
    try {
        std::unique_ptr<HevcSyntheticSource> s(new(std::nothrow) HevcSyntheticSource());if(!s)return E_OUTOFMEMORY;
        HRESULT hr=D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            nullptr,0,D3D11_SDK_VERSION,&s->device,nullptr,&s->context);if(FAILED(hr))return hr;
        D3D11_TEXTURE2D_DESC d{};d.Width=width;d.Height=height;d.MipLevels=1;d.ArraySize=1;
        d.Format=bit_depth==10?DXGI_FORMAT_P010:DXGI_FORMAT_NV12;d.SampleDesc.Count=1;d.Usage=D3D11_USAGE_DEFAULT;d.BindFlags=D3D11_BIND_RENDER_TARGET;
        hr=s->device->CreateTexture2D(&d,nullptr,&s->texture);if(FAILED(hr))return hr;
        const size_t plane=static_cast<size_t>(width)*height;
        std::unique_ptr<uint8_t[]> bgra(new(std::nothrow) uint8_t[plane*4]);
        std::unique_ptr<uint8_t[]> nv12(new(std::nothrow) uint8_t[plane*3/2]);if(!bgra||!nv12)return E_OUTOFMEMORY;
        // Four solid quadrants expose matrix/range and channel mistakes.
        const uint8_t colors[4][4]={{32,96,192,255},{192,96,32,255},{16,16,16,255},{224,224,224,255}};
        for(uint32_t y=0;y<height;++y)for(uint32_t x=0;x<width;++x)
            std::memcpy(bgra.get()+(static_cast<size_t>(y)*width+x)*4,colors[(x>=width/2?1:0)+(y>=height/2?2:0)],4);
        to_nv12(bgra.get(),nv12.get(),width,height);
        if(bit_depth==10) {
            std::unique_ptr<uint16_t[]> p010(new(std::nothrow)uint16_t[plane*3/2]);if(!p010)return E_OUTOFMEMORY;
            // Nonzero low two sample bits exercise actual P010 storage. This
            // synthetic SDR probe is independent from the BGRA desktop source.
            for(size_t i=0;i<plane*3/2;++i)p010[i]=static_cast<uint16_t>((uint16_t(nv12[i])<<8)|((i&3u)<<6));
            s->context->UpdateSubresource(s->texture.Get(),0,nullptr,p010.get(),width*2,0);
            SecureZeroMemory(p010.get(),plane*3);
        } else s->context->UpdateSubresource(s->texture.Get(),0,nullptr,nv12.get(),width,0);
        s->context->Flush();
        SecureZeroMemory(bgra.get(),plane*4);SecureZeroMemory(nv12.get(),plane*3/2);
        *result=s.release();return S_OK;
    }catch(...){return E_OUTOFMEMORY;}
}
extern "C" int32_t nl_hevc_hdr10_synthetic_open(uint32_t width,uint32_t height,void** result) noexcept {
    const HRESULT opened=nl_hevc_synthetic_open(width,height,10,result);
    if(opened!=S_OK)return opened;
    auto* s=static_cast<HevcSyntheticSource*>(*result);
    const size_t plane=static_cast<size_t>(width)*height;
    std::unique_ptr<uint16_t[]> pixels(new(std::nothrow)uint16_t[plane*3/2]);
    if(!pixels){delete s;*result=nullptr;return E_OUTOFMEMORY;}
    const uint16_t samples[4][3]={{401,341,683},{723,653,301},{67,513,511},{923,511,515}};
    for(uint32_t y=0;y<height;++y)for(uint32_t x=0;x<width;++x) {
        const auto& color=samples[(x>=width/2?1:0)+(y>=height/2?2:0)];
        pixels[static_cast<size_t>(y)*width+x]=static_cast<uint16_t>(color[0]<<6);
        if(!(y&1) && !(x&1)) {
            const size_t uv=plane+static_cast<size_t>(y/2)*width+x;
            pixels[uv]=static_cast<uint16_t>(color[1]<<6);pixels[uv+1]=static_cast<uint16_t>(color[2]<<6);
        }
    }
    s->context->UpdateSubresource(s->texture.Get(),0,nullptr,pixels.get(),width*2,0);s->context->Flush();
    SecureZeroMemory(pixels.get(),plane*3);return S_OK;
}
extern "C" int32_t nl_hevc_synthetic_borrow(void* opaque,void** device,void** texture) noexcept {
    auto* s=static_cast<HevcSyntheticSource*>(opaque);
    if(!s||!device||!texture||s->thread!=GetCurrentThreadId())return E_INVALIDARG;
    *device=s->device.Get();*texture=s->texture.Get();return S_OK;
}
extern "C" void nl_hevc_synthetic_close(void* opaque) noexcept {
    auto* s=static_cast<HevcSyntheticSource*>(opaque);if(s&&s->thread==GetCurrentThreadId())delete s;
}

// A finite diagnostic stream ends once, then receives all already-accepted output.
// This entry point is HEVC-only; no H264 product drain/latency semantics change.
extern "C" int32_t nl_hevc_begin_drain(void* opaque) noexcept {
    auto* s=static_cast<Codec*>(opaque);
    if(!s || !s->hevc || s->thread!=GetCurrentThreadId() || s->drain_started) return MF_E_INVALIDREQUEST;
    s->drain_started=true;
    HRESULT hr=s->transform->ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM,0);
    if(SUCCEEDED(hr))hr=s->transform->ProcessMessage(MFT_MESSAGE_COMMAND_DRAIN,0);
    return hr;
}

extern "C" int32_t nl_mf_owner_observation(void* opaque,NlOwnerObservation* out) noexcept {
    auto* s=static_cast<Codec*>(opaque);
    if(!s || !out || s->thread!=GetCurrentThreadId())return E_INVALIDARG;
    return nl_observe_owner(s->device.Get(),s->hardware_used,s->observation_id,s->observation_initialized,out);
}
