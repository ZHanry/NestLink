// First-party bounded Media Foundation H.264 bridge. Worker-thread ownership,
// no shared handles or pointers cross the application IPC boundary.
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
#include <memory>
#include <new>
#include <array>
#include <atomic>
#include <d3d10.h>
#include <dxgi1_2.h>
using Microsoft::WRL::ComPtr;
namespace {
constexpr size_t raw_limit = 64 * 1024 * 1024;
constexpr size_t packet_limit = 8 * 1024 * 1024;
struct BufferedOutput {
    std::unique_ptr<uint8_t[]> bytes;
    size_t length = 0, capacity = 0;
    uint64_t pts = 0;
    void reset() noexcept {
        if (bytes) SecureZeroMemory(bytes.get(), capacity);
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
    ComPtr<IMFTransform> transform;
    ComPtr<IMFMediaEventGenerator> events;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IMFDXGIDeviceManager> manager;
    uint32_t width = 0, height = 0, fps = 0, level = 0;
    bool gpu_input = false;
    std::array<ComPtr<ID3D11Texture2D>, 4> gpu_slots;
    std::shared_ptr<GpuRelease> gpu_release;

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
    type->SetGUID(MF_MT_MAJOR_TYPE, MFMediaType_Video);
    type->SetGUID(MF_MT_SUBTYPE, compressed ? MFVideoFormat_H264 : MFVideoFormat_NV12);
    type->SetUINT32(MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    MFSetAttributeSize(type.Get(), MF_MT_FRAME_SIZE, state.width, state.height);
    MFSetAttributeRatio(type.Get(), MF_MT_FRAME_RATE, state.fps, 1);
    MFSetAttributeRatio(type.Get(), MF_MT_PIXEL_ASPECT_RATIO, 1, 1);
    type->SetUINT32(MF_MT_YUV_MATRIX, MFVideoTransferMatrix_BT709);
    type->SetUINT32(MF_MT_VIDEO_PRIMARIES, MFVideoPrimaries_BT709);
    type->SetUINT32(MF_MT_TRANSFER_FUNCTION, MFVideoTransFunc_709);
    type->SetUINT32(MF_MT_VIDEO_NOMINAL_RANGE, MFNominalRange_16_235);
    if (compressed && state.encoder) {
        type->SetUINT32(MF_MT_AVG_BITRATE, kbps * 1000);
        type->SetUINT32(MF_MT_MPEG2_PROFILE, 66); // H.264 Baseline, no B frames.
        if (state.level) type->SetUINT32(MF_MT_MPEG2_LEVEL, state.level);
    }
    *result = type.Detach();
    return S_OK;
}
HRESULT configure(Codec& state, IMFTransform* transform, uint32_t kbps) {
    state.transform = transform;
    ComPtr<IMFAttributes> attributes;
    if (SUCCEEDED(transform->GetAttributes(&attributes))) {
        attributes->SetUINT32(MF_LOW_LATENCY, TRUE);
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
        if (SUCCEEDED(hr)) hr = transform->SetInputType(0, raw.Get(), 0);
    } else {
        hr = transform->SetInputType(0, compressed.Get(), 0);
        if (SUCCEEDED(hr)) hr = transform->SetOutputType(0, raw.Get(), 0);
    }
    if (FAILED(hr)) return hr;
    hr = transform->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    if (SUCCEEDED(hr)) hr = transform->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
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
HRESULT choose_decoder_output(Codec& state) {
    for (DWORD index = 0; index < 64; ++index) {
        ComPtr<IMFMediaType> type;
        HRESULT hr = state.transform->GetOutputAvailableType(0, index, &type);
        if (FAILED(hr)) return hr;
        GUID subtype{};
        if (FAILED(type->GetGUID(MF_MT_SUBTYPE, &subtype)) || subtype != MFVideoFormat_NV12) continue;
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
        if (FAILED(type->GetUINT32(MF_MT_DEFAULT_STRIDE, &pitch))) pitch = width;
        if (pitch < width || pitch > width+512 || static_cast<uint64_t>(pitch)*height*3/2 > raw_limit)
            return MF_E_INVALIDMEDIATYPE;
        hr = state.transform->SetOutputType(0, type.Get(), 0);
        if (FAILED(hr)) continue;
        state.output_height = height; state.output_pitch = pitch;
        return S_OK;
    }
    return MF_E_INVALIDMEDIATYPE;
}
HRESULT output(Codec& state, uint8_t* destination, size_t capacity, size_t* length, uint64_t* pts, DWORD wait_ms) {
    *length = 0;
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
        if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) return S_FALSE;
        if (hr == MF_E_TRANSFORM_STREAM_CHANGE && !state.encoder && attempt == 0) {
            hr = choose_decoder_output(state);
            if (FAILED(hr)) return hr;
            continue;
        }
        if (FAILED(hr)) return hr;
        if (!sample) return E_UNEXPECTED;
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
                if (desc.Width < state.width || desc.Width > state.width+255 ||
                    desc.Height < state.height || desc.Height > state.height+31 ||
                    static_cast<uint64_t>(desc.Width)*desc.Height*3/2 > raw_limit ||
                    ((desc.Width|desc.Height)&1) || desc.Format != DXGI_FORMAT_NV12)
                    return MF_E_INVALIDMEDIATYPE;
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
                if (!mapped.pData || mapped.RowPitch < state.width || capacity != static_cast<size_t>(state.width)*state.height*4) {
                    state.context->Unmap(staging.Get(), 0); return E_UNEXPECTED;
                }
                // UV starts after the allocated texture height, which can be
                // padded beyond the visible frame. Copy to compact NV12 first.
                const size_t plane = static_cast<size_t>(state.width)*state.height;
                std::unique_ptr<uint8_t[]> compact(new (std::nothrow) uint8_t[plane*3/2]);
                if (!compact) { state.context->Unmap(staging.Get(), 0); return E_OUTOFMEMORY; }
                const auto* source = static_cast<const uint8_t*>(mapped.pData);
                for (uint32_t row = 0; row < state.height; ++row)
                    std::memcpy(compact.get()+static_cast<size_t>(row)*state.width, source+static_cast<size_t>(row)*mapped.RowPitch, state.width);
                for (uint32_t row = 0; row < state.height/2; ++row)
                    std::memcpy(compact.get()+plane+static_cast<size_t>(row)*state.width,
                        source+static_cast<size_t>(desc.Height+row)*mapped.RowPitch, state.width);
                state.context->Unmap(staging.Get(), 0);
                from_nv12(compact.get(), state.width, state.height, destination, state.width, state.height);
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
        if (state.encoder) { std::memcpy(destination, bytes, used); *length = used; state.hardware_used = state.hardware; }
        else { from_nv12(bytes, state.output_pitch, state.output_height, destination, state.width, state.height); *length = capacity; }
        buffer->Unlock(); return S_OK;
    }
    return E_UNEXPECTED;
}
} // namespace

extern thread_local bool gpu_teardown_failed;
static int32_t open_codec(ID3D11Device* supplied_device, uint32_t encoder, uint32_t hardware_only, uint32_t width,
    uint32_t height, uint32_t fps, uint32_t kbps, uint32_t level, void** result) {
    if (!result) return E_POINTER;
    *result = nullptr;
    if (supplied_device && gpu_teardown_failed) return MF_E_SHUTDOWN;
    if (!width || !height || (width|height)&1 || width > 8192 || height > 8192 ||
        static_cast<uint64_t>(width)*height*4 > raw_limit || !fps || fps > 120 || kbps > 100000)
        return E_INVALIDARG;
    std::unique_ptr<Codec> state(new (std::nothrow) Codec());
    if (!state) return E_OUTOFMEMORY;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return hr;
    state->com = true;
    hr = MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET);
    if (FAILED(hr)) return hr;
    state->mf = true; state->encoder = encoder != 0; state->hardware = hardware_only != 0;
    state->width = width; state->height = height; state->fps = fps; state->level = level;
    state->output_height = height; state->output_pitch = width;
    if (supplied_device) {
        state->gpu_input = true; state->device = supplied_device;
        supplied_device->GetImmediateContext(&state->context);
        ComPtr<ID3D10Multithread> protection;
        hr = state->context.As(&protection);
        if (FAILED(hr)) return hr;
        protection->SetMultithreadProtected(TRUE);
        // Four immutable-in-flight input surfaces, including all retained MFT samples.
        if (static_cast<uint64_t>(width)*height*3/2*4 > 128*1024*1024) return E_OUTOFMEMORY;
        state->gpu_release = std::shared_ptr<GpuRelease>(new (std::nothrow) GpuRelease());
        if (!state->gpu_release) return E_OUTOFMEMORY;
        D3D11_TEXTURE2D_DESC desc{};
        desc.Width = width; desc.Height = height; desc.MipLevels = 1; desc.ArraySize = 1;
        desc.Format = DXGI_FORMAT_NV12; desc.SampleDesc.Count = 1;
        desc.Usage = D3D11_USAGE_DEFAULT; desc.BindFlags = D3D11_BIND_RENDER_TARGET;
        for (auto& texture : state->gpu_slots) {
            hr = supplied_device->CreateTexture2D(&desc, nullptr, &texture);
            if (FAILED(hr)) return hr;
        }
    }
    MFT_REGISTER_TYPE_INFO raw{MFMediaType_Video, MFVideoFormat_NV12};
    MFT_REGISTER_TYPE_INFO compressed{MFMediaType_Video, MFVideoFormat_H264};
    IMFActivate** choices = nullptr; UINT32 count = 0;
    // Prefer adapter-targeted enumeration when supported by this Windows runtime.
    using Enum2 = HRESULT (WINAPI*)(GUID, UINT32, const MFT_REGISTER_TYPE_INFO*, const MFT_REGISTER_TYPE_INFO*, IMFAttributes*, IMFActivate***, UINT32*);
    const auto enum2_address = GetProcAddress(GetModuleHandleW(L"mfplat.dll"),"MFTEnum2");
    Enum2 enum2 = nullptr;
    static_assert(sizeof(enum2) == sizeof(enum2_address), "Windows function pointer size");
    std::memcpy(&enum2, &enum2_address, sizeof(enum2));
    if (supplied_device && enum2) {
        ComPtr<IDXGIDevice> dxgi; ComPtr<IDXGIAdapter> adapter; DXGI_ADAPTER_DESC desc{};
        hr = supplied_device->QueryInterface(IID_PPV_ARGS(&dxgi));
        if (SUCCEEDED(hr)) hr = dxgi->GetAdapter(&adapter);
        if (SUCCEEDED(hr)) hr = adapter->GetDesc(&desc);
        ComPtr<IMFAttributes> attributes;
        if (SUCCEEDED(hr)) hr = MFCreateAttributes(&attributes,1);
        const UINT64 luid = static_cast<UINT64>(static_cast<UINT32>(desc.AdapterLuid.HighPart)) << 32 | desc.AdapterLuid.LowPart;
        if (SUCCEEDED(hr)) hr = attributes->SetUINT64(MFT_ENUM_ADAPTER_LUID,luid);
        if (SUCCEEDED(hr)) hr = enum2(MFT_CATEGORY_VIDEO_ENCODER,MFT_ENUM_FLAG_SORTANDFILTER|MFT_ENUM_FLAG_HARDWARE,
            &raw,&compressed,attributes.Get(),&choices,&count);
    } else {
    hr = MFTEnumEx(state->encoder ? MFT_CATEGORY_VIDEO_ENCODER : MFT_CATEGORY_VIDEO_DECODER,
        MFT_ENUM_FLAG_SORTANDFILTER | (hardware_only ? MFT_ENUM_FLAG_HARDWARE : MFT_ENUM_FLAG_SYNCMFT),
        state->encoder ? &raw : &compressed, state->encoder ? &compressed : &raw, &choices, &count);
    }
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
            ComPtr<IMFTransform> transform;
            last = choices[index]->ActivateObject(IID_PPV_ARGS(&transform));
            if (SUCCEEDED(last)) last = configure(*state, transform.Get(), kbps);
            if (FAILED(last)) { state->events.Reset(); state->transform.Reset(); state->manager.Reset(); if (!state->gpu_input) { state->context.Reset(); state->device.Reset(); } state->input_events = 0; state->output_events = 0; }
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
    // No input is retained across calls. A sample is retried only after
    // NOTACCEPTING, and is never submitted again once ProcessInput succeeds.
    const size_t plane = static_cast<size_t>(state.width)*state.height;
    if (submit && (state.encoder ? ((!gpu && input_length != plane*4) || capacity > packet_limit) :
        (input_length == 0 || input_length > packet_limit || capacity != plane*4))) return E_INVALIDARG;
    HRESULT hr = collect_output(state, capacity, 0);
    if (FAILED(hr)) return hr;
    bool accepted = false;
    bool gpu_room = !gpu;
    if (gpu) for (const auto& busy : state.gpu_release->busy) if (!busy.load(std::memory_order_acquire)) gpu_room = true;
    if (submit && gpu_room && state.ready_size < 2 && capacity <= raw_limit - state.ready_bytes) {
        if (state.encoder && force_keyframe) {
            hr = set_codec_value(state.transform.Get(), CODECAPI_AVEncVideoForceKeyFrame, 1);
            if (FAILED(hr)) hr = set_codec_value(state.transform.Get(), CODECAPI_AVEncVideoForceKeyFrame, 1, true);
            if (FAILED(hr)) return hr;
        }
        ComPtr<IMFSample> sample;
        ComPtr<IMFMediaBuffer> buffer;
        const size_t size = state.encoder ? plane*3/2 : input_length;
        if (gpu) {
            D3D11_TEXTURE2D_DESC desc{}; gpu->GetDesc(&desc);
            ComPtr<ID3D11Device> input_device; gpu->GetDevice(&input_device);
            if (!state.gpu_input || input_device.Get() != state.device.Get() ||
                desc.Width != state.width || desc.Height != state.height || desc.Format != DXGI_FORMAT_NV12)
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
            if (hr != S_OK) return FAILED(hr) ? hr : HRESULT_FROM_WIN32(WAIT_TIMEOUT);
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
    }
    if ((accepted || !submit) && !state.ready_size) {
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
    delete state; return S_OK;
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
