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
using Microsoft::WRL::ComPtr;
namespace {
constexpr size_t raw_limit = 64 * 1024 * 1024;
constexpr size_t packet_limit = 8 * 1024 * 1024;
struct Codec {
    ComPtr<IMFTransform> transform;
    ComPtr<IMFMediaEventGenerator> events;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IMFDXGIDeviceManager> manager;
    uint32_t width = 0, height = 0, fps = 0;
    uint32_t output_height = 0, output_pitch = 0;
    bool encoder = false, hardware = false, hardware_used = false, com = false, mf = false;
    DWORD thread = GetCurrentThreadId();
    unsigned input_events = 0, output_events = 0;
    ~Codec() {
        if (transform) {
            transform->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
            transform->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        }
        events.Reset(); transform.Reset(); manager.Reset(); context.Reset(); device.Reset();
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
            HRESULT hr = D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr,
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
        if (state.hardware && !state.encoder && !state.manager) return MF_E_UNSUPPORTED_D3D_TYPE;
    }
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
HRESULT output(Codec& state, uint8_t* destination, size_t capacity, size_t* length, uint64_t* pts) {
    *length = 0;
    if (state.events) {
        HRESULT hr = wait_event(state, false, 30);
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

extern "C" int32_t nl_mf_open(uint32_t encoder, uint32_t hardware_only, uint32_t width,
    uint32_t height, uint32_t fps, uint32_t kbps, void** result) noexcept {
    if (!result) return E_POINTER;
    *result = nullptr;
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
    state->width = width; state->height = height; state->fps = fps;
    state->output_height = height; state->output_pitch = width;
    MFT_REGISTER_TYPE_INFO raw{MFMediaType_Video, MFVideoFormat_NV12};
    MFT_REGISTER_TYPE_INFO compressed{MFMediaType_Video, MFVideoFormat_H264};
    IMFActivate** choices = nullptr; UINT32 count = 0;
    hr = MFTEnumEx(state->encoder ? MFT_CATEGORY_VIDEO_ENCODER : MFT_CATEGORY_VIDEO_DECODER,
        MFT_ENUM_FLAG_SORTANDFILTER | (hardware_only ? MFT_ENUM_FLAG_HARDWARE : MFT_ENUM_FLAG_SYNCMFT),
        state->encoder ? &raw : &compressed, state->encoder ? &compressed : &raw, &choices, &count);
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
            if (FAILED(last)) { state->events.Reset(); state->transform.Reset(); state->input_events = 0; state->output_events = 0; }
        }
        choices[index]->Release();
    }
    CoTaskMemFree(choices);
    if (!state->transform) return last;
    *result = state.release(); return S_OK;
}
extern "C" int32_t nl_mf_process(void* opaque, const uint8_t* input, size_t input_length,
    uint64_t pts, uint32_t force_keyframe, uint8_t* destination, size_t capacity,
    size_t* length, uint64_t* output_pts) noexcept {
    auto* state = static_cast<Codec*>(opaque);
    if (!state || !input || !destination || !length || !output_pts || state->thread != GetCurrentThreadId() ||
        pts > INT64_MAX / 1000 || capacity > raw_limit || input_length > raw_limit) return E_INVALIDARG;
    *length = 0;
    const size_t plane = static_cast<size_t>(state->width)*state->height;
    if (state->encoder ? (input_length != plane*4 || capacity > packet_limit) :
        (input_length == 0 || input_length > packet_limit || capacity != plane*4)) return E_INVALIDARG;
    if (state->events) {
        HRESULT hr = wait_event(*state, true, 200);
        if (hr != S_OK) return hr == S_FALSE ? MF_E_NOTACCEPTING : hr;
    }
    if (state->encoder && force_keyframe) {
        // This property takes VT_UI4 on the Microsoft encoder. Some vendor
        // transforms expose VT_BOOL; check both, never silently ignore a
        // rejected recovery request.
        HRESULT force_hr = set_codec_value(state->transform.Get(), CODECAPI_AVEncVideoForceKeyFrame, 1);
        if (FAILED(force_hr)) force_hr = set_codec_value(state->transform.Get(), CODECAPI_AVEncVideoForceKeyFrame, 1, true);
        if (FAILED(force_hr)) return force_hr;
    }
    ComPtr<IMFSample> sample;
    ComPtr<IMFMediaBuffer> buffer;
    HRESULT hr = MFCreateSample(&sample);
    if (FAILED(hr)) return hr;
    const size_t size = state->encoder ? plane*3/2 : input_length;
    hr = MFCreateMemoryBuffer(static_cast<DWORD>(size), &buffer);
    if (FAILED(hr)) return hr;
    BYTE* bytes = nullptr;
    hr = buffer->Lock(&bytes, nullptr, nullptr);
    if (FAILED(hr)) return hr;
    if (state->encoder) to_nv12(input, bytes, state->width, state->height);
    else std::memcpy(bytes, input, size);
    buffer->Unlock();
    hr = buffer->SetCurrentLength(static_cast<DWORD>(size));
    if (SUCCEEDED(hr)) hr = sample->AddBuffer(buffer.Get());
    if (SUCCEEDED(hr)) hr = sample->SetSampleTime(static_cast<LONGLONG>(pts*1000/9));
    if (SUCCEEDED(hr)) hr = sample->SetSampleDuration(10000000/state->fps);
    if (FAILED(hr)) return hr;
    hr = state->transform->ProcessInput(0, sample.Get(), 0);
    if (FAILED(hr)) return hr;
    return output(*state, destination, capacity, length, output_pts);
}
extern "C" int32_t nl_mf_bitrate(void* opaque, uint32_t kbps) noexcept {
    auto* state = static_cast<Codec*>(opaque);
    if (!state || !state->encoder || state->thread != GetCurrentThreadId() || kbps < 64 || kbps > 100000) return E_INVALIDARG;
    return set_codec_value(state->transform.Get(), CODECAPI_AVEncCommonMeanBitRate, kbps*1000);
}
extern "C" uint32_t nl_mf_hardware_used(void* opaque) noexcept {
    auto* state = static_cast<Codec*>(opaque);
    return state && state->thread == GetCurrentThreadId() && state->hardware_used ? 1 : 0;
}
extern "C" void nl_mf_close(void* opaque) noexcept { delete static_cast<Codec*>(opaque); }
