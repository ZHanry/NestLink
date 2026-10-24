// Same-owner-thread DXGI -> owned BGRA -> video processor NV12.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>
#include <cstdint>
#include <memory>
#include <new>
#include <atomic>
#include <dxgi1_6.h>
#include <roapi.h>
#include <windows.graphics.capture.interop.h>
#include <windows.graphics.directx.direct3d11.interop.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Graphics.h>
#include <winrt/Windows.Graphics.DirectX.h>
#include <winrt/Windows.Graphics.Capture.h>
#include <winrt/Windows.Graphics.DirectX.Direct3D11.h>
using Microsoft::WRL::ComPtr;
struct GpuCapture {
    DWORD thread = GetCurrentThreadId();
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IDXGIOutputDuplication> duplication;
    ComPtr<ID3D11Texture2D> bgra, nv12;
    ComPtr<ID3D11VideoDevice> video;
    ComPtr<ID3D11VideoContext> processor_context;
    ComPtr<ID3D11VideoProcessorEnumerator> enumerator;
    ComPtr<ID3D11VideoProcessor> processor;
    ComPtr<ID3D11VideoProcessorInputView> input;
    ComPtr<ID3D11VideoProcessorOutputView> output;
    uint32_t width = 0, height = 0, backend = 0; // 0 unknown/synthetic, 1 DXGI, 2 WGC
    LONG left = 0, top = 0;
    LUID luid{};
    std::shared_ptr<std::atomic<bool>> closed;
    bool pointer_separate = false, retained = false, ro = false, com = false, wgc_started = false;
    winrt::Windows::Graphics::Capture::GraphicsCaptureItem item{nullptr};
    winrt::Windows::Graphics::Capture::Direct3D11CaptureFramePool pool{nullptr};
    winrt::Windows::Graphics::Capture::GraphicsCaptureSession session{nullptr};
    ~GpuCapture() {
        try { if (session) session.Close(); if (pool) pool.Close(); } catch (...) { }
        session = nullptr; pool = nullptr; item = nullptr;
        // Remaining D3D members are released before RoUninitialize below.
        output.Reset(); input.Reset(); processor.Reset(); enumerator.Reset();
        processor_context.Reset(); video.Reset(); nv12.Reset(); bgra.Reset();
        duplication.Reset(); context.Reset(); device.Reset();
        if (ro) RoUninitialize();
        if (com) CoUninitialize();
    }
};
namespace {
HRESULT create_surfaces(GpuCapture* s,uint32_t width,uint32_t height,uint32_t fps) {
    HRESULT hr = S_OK;
    D3D11_TEXTURE2D_DESC texture{};
    texture.Width = width; texture.Height = height; texture.MipLevels = 1; texture.ArraySize = 1;
    texture.Format = DXGI_FORMAT_B8G8R8A8_UNORM; texture.SampleDesc.Count = 1;
    texture.Usage = D3D11_USAGE_DEFAULT;
    texture.BindFlags = D3D11_BIND_RENDER_TARGET|D3D11_BIND_SHADER_RESOURCE;
    texture.MiscFlags = D3D11_RESOURCE_MISC_GDI_COMPATIBLE;
    hr = s->device->CreateTexture2D(&texture,nullptr,&s->bgra);
    if (FAILED(hr)) return hr;
    texture.Format = DXGI_FORMAT_NV12; texture.MiscFlags = 0;
    texture.BindFlags = D3D11_BIND_RENDER_TARGET;
    hr = s->device->CreateTexture2D(&texture,nullptr,&s->nv12);
    if (FAILED(hr)) return hr;
    hr = s->device.As(&s->video);
    if (SUCCEEDED(hr)) hr = s->context.As(&s->processor_context);
    if (FAILED(hr)) return hr;
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC content{};
    content.InputFrameFormat = D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
    content.InputFrameRate = {fps,1}; content.OutputFrameRate = {fps,1};
    content.InputWidth = width; content.InputHeight = height;
    content.OutputWidth = width; content.OutputHeight = height;
    content.Usage = D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
    hr = s->video->CreateVideoProcessorEnumerator(&content,&s->enumerator);
    UINT support = 0;
    if (SUCCEEDED(hr)) hr = s->enumerator->CheckVideoProcessorFormat(DXGI_FORMAT_B8G8R8A8_UNORM,&support);
    if (SUCCEEDED(hr) && !(support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT)) hr = DXGI_ERROR_UNSUPPORTED;
    if (SUCCEEDED(hr)) hr = s->enumerator->CheckVideoProcessorFormat(DXGI_FORMAT_NV12,&support);
    if (SUCCEEDED(hr) && !(support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT)) hr = DXGI_ERROR_UNSUPPORTED;
    if (SUCCEEDED(hr)) hr = s->video->CreateVideoProcessor(s->enumerator.Get(),0,&s->processor);
    if (FAILED(hr)) return hr;
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC iv{};
    iv.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
    hr = s->video->CreateVideoProcessorInputView(s->bgra.Get(),s->enumerator.Get(),&iv,&s->input);
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC ov{};
    ov.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
    if (SUCCEEDED(hr)) hr = s->video->CreateVideoProcessorOutputView(s->nv12.Get(),s->enumerator.Get(),&ov,&s->output);
    if (FAILED(hr)) return hr;
    RECT rect{0,0,static_cast<LONG>(width),static_cast<LONG>(height)};
    s->processor_context->VideoProcessorSetStreamSourceRect(s->processor.Get(),0,TRUE,&rect);
    s->processor_context->VideoProcessorSetStreamDestRect(s->processor.Get(),0,TRUE,&rect);
    s->processor_context->VideoProcessorSetOutputTargetRect(s->processor.Get(),TRUE,&rect);
    s->processor_context->VideoProcessorSetStreamAutoProcessingMode(s->processor.Get(),0,FALSE);
    D3D11_VIDEO_PROCESSOR_COLOR_SPACE rgb{}; rgb.RGB_Range = 0; rgb.YCbCr_Matrix = 1; rgb.Nominal_Range = 2;
    D3D11_VIDEO_PROCESSOR_COLOR_SPACE yuv{}; yuv.YCbCr_Matrix = 1; yuv.Nominal_Range = 1;
    s->processor_context->VideoProcessorSetStreamColorSpace(s->processor.Get(),0,&rgb);
    s->processor_context->VideoProcessorSetOutputColorSpace(s->processor.Get(),&yuv);
    s->width=width; s->height=height;
    return S_OK;
}
// No picker and no unapproved HWND: public monitor interop uses the same grant.
HRESULT open_wgc(GpuCapture& s, HMONITOR monitor, uint32_t width, uint32_t height) noexcept {
    HRESULT hr = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(hr)) return hr;
    s.ro = true;
    try {
        using namespace winrt::Windows::Graphics::Capture;
        if (!GraphicsCaptureSession::IsSupported()) return DXGI_ERROR_UNSUPPORTED;
        const auto factory = winrt::get_activation_factory<GraphicsCaptureItem, IGraphicsCaptureItemInterop>();
        hr = factory->CreateForMonitor(monitor, winrt::guid_of<GraphicsCaptureItem>(), winrt::put_abi(s.item));
        if (FAILED(hr)) return hr;
        s.closed = std::make_shared<std::atomic<bool>>(false);
        s.item.Closed([closed=s.closed](auto const&, auto const&) noexcept {closed->store(true);});
        const auto size = s.item.Size();
        if (size.Width != static_cast<int32_t>(width) || size.Height != static_cast<int32_t>(height)) return E_INVALIDARG;
        ComPtr<IDXGIDevice> dxgi;
        hr = s.device.As(&dxgi); if (FAILED(hr)) return hr;
        ComPtr<IInspectable> inspectable;
        hr = CreateDirect3D11DeviceFromDXGIDevice(dxgi.Get(), &inspectable);
        if (FAILED(hr)) return hr;
        auto device = winrt::Windows::Graphics::DirectX::Direct3D11::IDirect3DDevice{nullptr};
        hr = inspectable->QueryInterface(winrt::guid_of<decltype(device)>(),winrt::put_abi(device));
        if (FAILED(hr)) return hr;
        s.pool = Direct3D11CaptureFramePool::CreateFreeThreaded(device,
            winrt::Windows::Graphics::DirectX::DirectXPixelFormat::B8G8R8A8UIntNormalized,2,size);
        // Free-threaded callbacks own no frame/COM/GPU object. Owner polls frames.
        s.pool.FrameArrived([](auto const&, auto const&) noexcept {});
        s.session = s.pool.CreateCaptureSession(s.item);
        // Default system cursor capture is preserved, so never draw it twice.
        // Activation is deferred until the first authorized capture command.
        return S_OK;
    } catch (...) { return winrt::to_hresult(); }
}
HRESULT convert(GpuCapture& s) {
    D3D11_VIDEO_PROCESSOR_STREAM stream{};
    stream.Enable = TRUE; stream.pInputSurface = s.input.Get();
    return s.processor_context->VideoProcessorBlt(s.processor.Get(), s.output.Get(), 0, 1, &stream);
}
HRESULT cursor(GpuCapture& s) {
    if (!s.pointer_separate) return S_OK;
    CURSORINFO info{}; info.cbSize = sizeof(info);
    if (!GetCursorInfo(&info)) return HRESULT_FROM_WIN32(GetLastError());
    if (!(info.flags & CURSOR_SHOWING) || (info.flags & CURSOR_SUPPRESSED)) return S_OK;
    HICON icon = CopyIcon(info.hCursor);
    if (!icon) return HRESULT_FROM_WIN32(GetLastError());
    ICONINFO image{};
    if (!GetIconInfo(icon, &image)) { DestroyIcon(icon); return HRESULT_FROM_WIN32(GetLastError()); }
    BITMAP bitmap{};
    const int obtained = GetObjectW(image.hbmColor ? image.hbmColor : image.hbmMask, static_cast<int>(sizeof(bitmap)), &bitmap);
    const LONG height = image.hbmColor ? bitmap.bmHeight : bitmap.bmHeight/2;
    HRESULT hr = E_INVALIDARG;
    if (obtained == static_cast<int>(sizeof(bitmap)) && bitmap.bmWidth > 0 && bitmap.bmWidth <= 512 && height > 0 && height <= 512 &&
        image.xHotspot < static_cast<DWORD>(bitmap.bmWidth) && image.yHotspot < static_cast<DWORD>(height)) {
        ComPtr<IDXGISurface1> surface;
        hr = s.bgra.As(&surface);
        HDC dc = nullptr;
        if (SUCCEEDED(hr)) hr = surface->GetDC(FALSE, &dc);
        if (SUCCEEDED(hr)) {
            // GDI-compatible GPU surface preserves alpha and monochrome AND/XOR.
            // Driver-internal copies are unknown: no zero-copy/readback claim.
            const int x = info.ptScreenPos.x - s.left - static_cast<LONG>(image.xHotspot);
            const int y = info.ptScreenPos.y - s.top - static_cast<LONG>(image.yHotspot);
            if (!DrawIconEx(dc,x,y,icon,bitmap.bmWidth,height,0,nullptr,DI_NORMAL | DI_NOMIRROR))
                hr = HRESULT_FROM_WIN32(GetLastError());
            const HRESULT released = surface->ReleaseDC(nullptr);
            if (SUCCEEDED(hr)) hr = released;
        }
    }
    if (image.hbmColor) DeleteObject(image.hbmColor);
    if (image.hbmMask) DeleteObject(image.hbmMask);
    DestroyIcon(icon);
    return hr;
}
}
extern "C" int32_t nl_capture_gpu_open(uintptr_t monitor, uint32_t width, uint32_t height,
    uint32_t fps, void** result) noexcept {
    if (!result) return E_POINTER;
    *result = nullptr;
    // Odd/HDR/rotated outputs use the existing complete CPU path.
    if (!monitor || !width || !height || ((width|height)&1) || width > 8192 || height > 8192 ||
        static_cast<uint64_t>(width)*height*4 > 64*1024*1024 || !fps || fps > 120) return E_INVALIDARG;
    ComPtr<IDXGIFactory1> factory;
    HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(hr)) return hr;
    for (UINT ai = 0; ai < 64; ++ai) {
        ComPtr<IDXGIAdapter1> adapter;
        hr = factory->EnumAdapters1(ai,&adapter);
        if (hr == DXGI_ERROR_NOT_FOUND) break;
        if (FAILED(hr)) return hr;
        for (UINT oi = 0; oi < 64; ++oi) {
            ComPtr<IDXGIOutput> output;
            hr = adapter->EnumOutputs(oi,&output);
            if (hr == DXGI_ERROR_NOT_FOUND) break;
            if (FAILED(hr)) return hr;
            DXGI_OUTPUT_DESC desc{};
            hr = output->GetDesc(&desc);
            if (FAILED(hr)) return hr;
            if (reinterpret_cast<uintptr_t>(desc.Monitor) != monitor) continue;
            if (!desc.AttachedToDesktop || (desc.Rotation != DXGI_MODE_ROTATION_IDENTITY && desc.Rotation != DXGI_MODE_ROTATION_UNSPECIFIED) ||
                desc.DesktopCoordinates.right-desc.DesktopCoordinates.left != static_cast<LONG>(width) ||
                desc.DesktopCoordinates.bottom-desc.DesktopCoordinates.top != static_cast<LONG>(height)) return DXGI_ERROR_UNSUPPORTED;
            // HDR requires an explicit verified tone mapper; retain CPU fallback.
            ComPtr<IDXGIOutput6> output6;
            if (SUCCEEDED(output.As(&output6))) {
                DXGI_OUTPUT_DESC1 color{};
                hr = output6->GetDesc1(&color);
                if (FAILED(hr)) return hr;
                if (color.ColorSpace != DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709) return DXGI_ERROR_UNSUPPORTED;
            }
            std::unique_ptr<GpuCapture> s(new (std::nothrow) GpuCapture());
            if (!s) return E_OUTOFMEMORY;
            hr=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
            if (FAILED(hr)) return hr;
            s->com=true;
            D3D_FEATURE_LEVEL level{};
            hr = D3D11CreateDevice(adapter.Get(),D3D_DRIVER_TYPE_UNKNOWN,nullptr,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT|D3D11_CREATE_DEVICE_VIDEO_SUPPORT,nullptr,0,D3D11_SDK_VERSION,
                &s->device,&level,&s->context);
            if (FAILED(hr)) return hr;
            DXGI_ADAPTER_DESC1 adapter_desc{};
            hr = adapter->GetDesc1(&adapter_desc); if (FAILED(hr)) return hr;
            s->luid = adapter_desc.AdapterLuid;
            ComPtr<IDXGIOutput1> output1;
            hr = output.As(&output1);
            if (SUCCEEDED(hr)) hr = output1->DuplicateOutput(s->device.Get(),&s->duplication);
            if (FAILED(hr)) {
                s->duplication.Reset();
                hr = open_wgc(*s,reinterpret_cast<HMONITOR>(monitor),width,height);
                if (FAILED(hr)) return hr;
            }
            hr = create_surfaces(s.get(),width,height,fps);
            if (FAILED(hr)) return hr;
            s->backend = s->duplication ? 1u : 2u;
            s->width = width; s->height = height; s->left = desc.DesktopCoordinates.left; s->top = desc.DesktopCoordinates.top;
            *result = s.release(); return S_OK;
        }
    }
    return DXGI_ERROR_NOT_FOUND;
}
extern "C" int32_t nl_capture_gpu_device(void* opaque, void** device, uint64_t* luid) noexcept {
    auto* s = static_cast<GpuCapture*>(opaque);
    if (!s || !device || !luid || s->thread != GetCurrentThreadId()) return E_INVALIDARG;
    *device = s->device.Get();
    *luid = static_cast<uint64_t>(static_cast<uint32_t>(s->luid.HighPart)) << 32 | s->luid.LowPart;
    return S_OK;
}
// Owner-local scalar metadata only. Does not open/enumerate/capture a source.
extern "C" int32_t nl_capture_gpu_observation(void* opaque, uint32_t* backend, uint64_t* luid) noexcept {
    auto* s = static_cast<GpuCapture*>(opaque);
    if (!s || !backend || !luid || s->thread != GetCurrentThreadId()) return E_INVALIDARG;
    *backend = s->backend;
    *luid = static_cast<uint64_t>(static_cast<uint32_t>(s->luid.HighPart)) << 32 | s->luid.LowPart;
    return S_OK;
}
extern "C" int32_t nl_capture_gpu_frame(void* opaque, uint32_t repeated, void** texture) noexcept {
    auto* s = static_cast<GpuCapture*>(opaque);
    if (!s || !texture || s->thread != GetCurrentThreadId()) return E_INVALIDARG;
    *texture = nullptr;
    if (repeated) { if (!s->retained) return S_FALSE; *texture = s->nv12.Get(); return S_OK; }
    HRESULT hr = S_OK;
    if (s->pool) {
        if (s->closed && s->closed->load()) return DXGI_ERROR_ACCESS_LOST;
        try {
            if (!s->wgc_started) { s->session.StartCapture(); s->wgc_started = true; }
            auto frame = s->pool.TryGetNextFrame();
            if (!frame) return S_FALSE;
            const auto size = frame.ContentSize();
            if (size.Width != static_cast<int32_t>(s->width) || size.Height != static_cast<int32_t>(s->height)) {
                frame.Close(); return DXGI_ERROR_ACCESS_LOST;
            }
            auto access = frame.Surface().as<::Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess>();
            ComPtr<ID3D11Texture2D> acquired;
            hr = access->GetInterface(IID_PPV_ARGS(&acquired));
            if (SUCCEEDED(hr)) {
                D3D11_TEXTURE2D_DESC desc{}; acquired->GetDesc(&desc);
                ComPtr<ID3D11Device> device; acquired->GetDevice(&device);
                if (device.Get() != s->device.Get() || desc.Width != s->width || desc.Height != s->height || desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM)
                    hr = DXGI_ERROR_UNSUPPORTED;
                else s->context->CopyResource(s->bgra.Get(),acquired.Get());
            }
            frame.Close();
        } catch (...) { return winrt::to_hresult(); }
        if (FAILED(hr)) return hr;
    } else {
        if (!s->duplication) return E_INVALIDARG;
        DXGI_OUTDUPL_FRAME_INFO info{};
        ComPtr<IDXGIResource> resource;
        hr = s->duplication->AcquireNextFrame(0,&info,&resource);
        if (hr == DXGI_ERROR_WAIT_TIMEOUT) return S_FALSE;
        if (FAILED(hr)) return hr;
        ComPtr<ID3D11Texture2D> acquired;
        hr = resource.As(&acquired);
        if (SUCCEEDED(hr)) {
            D3D11_TEXTURE2D_DESC desc{}; acquired->GetDesc(&desc);
            if (desc.Width != s->width || desc.Height != s->height || desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM) hr = DXGI_ERROR_UNSUPPORTED;
            else s->context->CopyResource(s->bgra.Get(),acquired.Get());
        }
        if (info.LastMouseUpdateTime.QuadPart) s->pointer_separate = info.PointerPosition.Visible != FALSE;
        const HRESULT released = s->duplication->ReleaseFrame();
        if (FAILED(hr)) return hr;
        if (FAILED(released)) return released;
    }
    hr = cursor(*s);
    if (SUCCEEDED(hr)) hr = convert(*s);
    if (FAILED(hr)) return hr;
    s->retained = true; *texture = s->nv12.Get(); return S_OK;
}
// Synthetic upload probes the real device/conversion/encoder without desktop pixels.
extern "C" int32_t nl_capture_gpu_probe(void* opaque, const uint8_t* pixels, size_t length, void** texture) noexcept {
    auto* s = static_cast<GpuCapture*>(opaque);
    if (!s || !pixels || !texture || s->thread != GetCurrentThreadId() || length != static_cast<size_t>(s->width)*s->height*4) return E_INVALIDARG;
    s->context->UpdateSubresource(s->bgra.Get(),0,nullptr,pixels,s->width*4,0);
    const HRESULT hr = convert(*s);
    if (FAILED(hr)) return hr;
    *texture = s->nv12.Get(); return S_OK;
}
extern "C" void nl_capture_gpu_close(void* opaque) noexcept {
    auto* s = static_cast<GpuCapture*>(opaque);
    if (s && s->thread == GetCurrentThreadId()) delete s;
}

extern "C" void nl_capture_gpu_discard(void* opaque) noexcept {
    auto* s = static_cast<GpuCapture*>(opaque);
    if (s && s->thread == GetCurrentThreadId()) {
        s->retained = false;
        if (s->pool) {
            try { for (unsigned i=0;i<2;++i) {auto frame=s->pool.TryGetNextFrame();if (!frame) break;frame.Close();} }
            catch (...) {if (s->closed) s->closed->store(true);}
        }
    }
}

// No duplication or WGC object is created: this API can only encode synthetic uploads.
extern "C" int32_t nl_capture_gpu_synthetic_open(uint32_t width,uint32_t height,uint32_t fps,void** result) noexcept {
    if (!result) return E_POINTER;
    *result=nullptr;
    if (!width || !height || ((width|height)&1) || width>8192 || height>8192 ||
        static_cast<uint64_t>(width)*height*4>64*1024*1024 || !fps || fps>120) return E_INVALIDARG;
    std::unique_ptr<GpuCapture> s(new (std::nothrow) GpuCapture());
    if (!s) return E_OUTOFMEMORY;
    HRESULT hr=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if (FAILED(hr)) return hr;
    s->com=true;
    D3D_FEATURE_LEVEL level{};
    hr=D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT|D3D11_CREATE_DEVICE_VIDEO_SUPPORT,nullptr,0,D3D11_SDK_VERSION,
        &s->device,&level,&s->context);
    if (FAILED(hr)) return hr;
    ComPtr<IDXGIDevice> dxgi;ComPtr<IDXGIAdapter> adapter;DXGI_ADAPTER_DESC desc{};
    hr=s->device.As(&dxgi);
    if (SUCCEEDED(hr)) hr=dxgi->GetAdapter(&adapter);
    if (SUCCEEDED(hr)) hr=adapter->GetDesc(&desc);
    if (SUCCEEDED(hr)) hr=create_surfaces(s.get(),width,height,fps);
    if (FAILED(hr)) return hr;
    s->luid=desc.AdapterLuid;*result=s.release();return S_OK;
}
