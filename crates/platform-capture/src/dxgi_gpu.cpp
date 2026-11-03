// Same-owner-thread SDR capture -> owned RGB -> video processor NV12/P010.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d11.h>
#include <d3d11_1.h>
#include <dxgi1_2.h>
#include <wrl/client.h>
#include <cstdint>
#include <memory>
#include <new>
#include <atomic>
#include <cstdio>
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
// Owner-local observations only: neither wire authority nor content precision
// qualification. Color spaces describe the configured conversion interpretation.
struct CaptureSourceObservation {
    uint32_t configured_format = 0, observed_format = 0;
    uint32_t input_color_space = 0, output_color_space = 0;
    uint32_t display_color_space = 0, display_bits_per_color = 0;
    uint32_t flags = 0, reserved = 0;
};
static_assert(sizeof(CaptureSourceObservation) == 32, "Rust/native capture observation layout");
struct GpuCapture {
    DWORD thread = GetCurrentThreadId();
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IDXGIOutputDuplication> duplication;
    ComPtr<ID3D11Texture2D> capture_rgb, nv12;
    ComPtr<IDXGIFactory1> source_factory;
    ComPtr<IDXGIOutput6> source_output;
    DXGI_OUTPUT_DESC1 original_output{};
    DXGI_FORMAT capture_format = DXGI_FORMAT_B8G8R8A8_UNORM, observed_format = DXGI_FORMAT_UNKNOWN;
    bool high_precision_sdr = false, hdr10 = false, display_known = false, conversion_checked = false, retired = false;
    bool precise() const noexcept { return high_precision_sdr || hdr10; }
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
        processor_context.Reset(); video.Reset(); nv12.Reset(); capture_rgb.Reset();
        duplication.Reset(); context.Reset(); device.Reset();
        source_output.Reset(); source_factory.Reset();
        if (ro) RoUninitialize();
        if (com) CoUninitialize();
    }
};
namespace {
constexpr DXGI_COLOR_SPACE_TYPE fp16_input_color = DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709;
constexpr DXGI_COLOR_SPACE_TYPE p010_output_color = DXGI_COLOR_SPACE_YCBCR_STUDIO_G22_LEFT_P709;
constexpr DXGI_COLOR_SPACE_TYPE hdr10_output_color = DXGI_COLOR_SPACE_YCBCR_STUDIO_G2084_LEFT_P2020;
DXGI_FORMAT capture_format_for_depth(uint32_t bit_depth) noexcept {
    return bit_depth == 10 ? DXGI_FORMAT_R16G16B16A16_FLOAT : DXGI_FORMAT_B8G8R8A8_UNORM;
}
bool sdr_output(const DXGI_OUTPUT_DESC1& description) noexcept {
    return description.ColorSpace == DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;
}
bool hdr10_output(const DXGI_OUTPUT_DESC1& description) noexcept {
    return description.AttachedToDesktop && description.BitsPerColor >= 10 &&
        description.ColorSpace == DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020;
}
bool same_output_color(const DXGI_OUTPUT_DESC1& original, const DXGI_OUTPUT_DESC1& current) noexcept {
    if (original.Monitor != current.Monitor || original.AttachedToDesktop != current.AttachedToDesktop ||
        original.Rotation != current.Rotation || original.BitsPerColor != current.BitsPerColor ||
        original.ColorSpace != current.ColorSpace || original.DesktopCoordinates.left != current.DesktopCoordinates.left ||
        original.DesktopCoordinates.top != current.DesktopCoordinates.top ||
        original.DesktopCoordinates.right != current.DesktopCoordinates.right ||
        original.DesktopCoordinates.bottom != current.DesktopCoordinates.bottom ||
        original.MinLuminance != current.MinLuminance || original.MaxLuminance != current.MaxLuminance ||
        original.MaxFullFrameLuminance != current.MaxFullFrameLuminance) return false;
    for (unsigned component = 0; component < 2; ++component) {
        if (original.RedPrimary[component] != current.RedPrimary[component] ||
            original.GreenPrimary[component] != current.GreenPrimary[component] ||
            original.BluePrimary[component] != current.BluePrimary[component] ||
            original.WhitePoint[component] != current.WhitePoint[component]) return false;
    }
    return true;
}
HRESULT retain_source_color(bool& retired, bool factory_current, HRESULT query,
    const DXGI_OUTPUT_DESC1& original, const DXGI_OUTPUT_DESC1& current) noexcept {
    if (retired) return DXGI_ERROR_ACCESS_LOST;
    if (!factory_current || query != S_OK || !sdr_output(current) || !same_output_color(original, current)) {
        retired = true;
        return FAILED(query) ? query : DXGI_ERROR_ACCESS_LOST;
    }
    return S_OK;
}
HRESULT retain_hdr_source_color(bool& retired, bool factory_current, HRESULT query,
    const DXGI_OUTPUT_DESC1& original, const DXGI_OUTPUT_DESC1& current) noexcept {
    if(retired)return DXGI_ERROR_ACCESS_LOST;
    if(!factory_current || query!=S_OK || !hdr10_output(current) || !same_output_color(original,current)) {
        retired=true;return FAILED(query)?query:DXGI_ERROR_ACCESS_LOST;
    }
    return S_OK;
}
HRESULT check_source_current(GpuCapture& s) noexcept {
    if (!s.precise()) return S_OK; // Preserve the original eight-bit path.
    if (s.retired) return DXGI_ERROR_ACCESS_LOST;
    const bool current = s.source_factory && s.source_factory->IsCurrent() && s.source_output &&
        (!s.closed || !s.closed->load());
    DXGI_OUTPUT_DESC1 description{};
    const HRESULT query = current ? s.source_output->GetDesc1(&description) : S_OK;
    HRESULT hr = S_OK;
    if (s.hdr10) {
        hr=retain_hdr_source_color(s.retired,current,query,s.original_output,description);
    } else {
        hr = retain_source_color(s.retired, current, query, s.original_output, description);
    }
    if (FAILED(hr)) {
        s.retained = false;
        std::fprintf(stderr, "capture source retired: owner_thread=%lu hr=0x%08lx factory_current=%u color_query_hr=0x%08lx\n",
            static_cast<unsigned long>(s.thread), static_cast<unsigned long>(hr), current ? 1u : 0u,
            static_cast<unsigned long>(query));
        std::fflush(stderr);
    }
    return hr;
}
template<class Check>
HRESULT check_fp16_conversion(Check check, DXGI_COLOR_SPACE_TYPE output_color = p010_output_color) {
    BOOL supported = FALSE;
    const HRESULT hr = check(DXGI_FORMAT_R16G16B16A16_FLOAT, fp16_input_color,
        DXGI_FORMAT_P010, output_color, &supported);
    if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
    return supported ? S_OK : DXGI_ERROR_UNSUPPORTED;
}
bool exact_precision_colors(DXGI_COLOR_SPACE_TYPE input, DXGI_COLOR_SPACE_TYPE output) noexcept {
    return input == fp16_input_color && output == p010_output_color;
}
bool exact_precision_surface(const D3D11_TEXTURE2D_DESC& description, uint32_t width, uint32_t height,
    bool same_device) noexcept {
    return same_device && description.Width == width && description.Height == height &&
        description.Format == DXGI_FORMAT_R16G16B16A16_FLOAT && description.MipLevels == 1 &&
        description.ArraySize == 1 && description.SampleDesc.Count == 1 && description.SampleDesc.Quality == 0;
}
HRESULT create_surfaces(GpuCapture* s,uint32_t width,uint32_t height,uint32_t fps,uint32_t bit_depth=8) {
    HRESULT hr = S_OK;
    D3D11_TEXTURE2D_DESC texture{};
    texture.Width = width; texture.Height = height; texture.MipLevels = 1; texture.ArraySize = 1;
    texture.Format = s->capture_format; texture.SampleDesc.Count = 1;
    texture.Usage = D3D11_USAGE_DEFAULT;
    texture.BindFlags = D3D11_BIND_RENDER_TARGET|D3D11_BIND_SHADER_RESOURCE;
    texture.MiscFlags = s->precise() ? 0u : D3D11_RESOURCE_MISC_GDI_COMPATIBLE;
    hr = s->device->CreateTexture2D(&texture,nullptr,&s->capture_rgb);
    if (FAILED(hr)) return hr;
    texture.Format = bit_depth==10?DXGI_FORMAT_P010:DXGI_FORMAT_NV12; texture.MiscFlags = 0;
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
    if (SUCCEEDED(hr)) hr = s->enumerator->CheckVideoProcessorFormat(s->capture_format,&support);
    if (SUCCEEDED(hr) && !(support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT)) hr = DXGI_ERROR_UNSUPPORTED;
    if (SUCCEEDED(hr)) hr = s->enumerator->CheckVideoProcessorFormat(texture.Format,&support);
    if (SUCCEEDED(hr) && !(support & D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT)) hr = DXGI_ERROR_UNSUPPORTED;
    if (SUCCEEDED(hr)) hr = s->video->CreateVideoProcessor(s->enumerator.Get(),0,&s->processor);
    if (FAILED(hr)) return hr;
    if (s->precise()) {
        const auto expected_output_color = s->hdr10 ? hdr10_output_color : p010_output_color;
        ComPtr<ID3D11VideoProcessorEnumerator1> enumerator1;
        ComPtr<ID3D11VideoContext1> context1;
        hr = s->enumerator.As(&enumerator1);
        if (hr == S_OK) hr = s->processor_context.As(&context1);
        std::fprintf(stderr, "capture Float16 interfaces: owner_thread=%lu hr=0x%08lx\n",
            static_cast<unsigned long>(s->thread), static_cast<unsigned long>(hr));
        std::fflush(stderr);
        if (hr == S_OK) hr = check_fp16_conversion([&](DXGI_FORMAT input_format, DXGI_COLOR_SPACE_TYPE input_color,
            DXGI_FORMAT output_format, DXGI_COLOR_SPACE_TYPE output_color, BOOL* supported) {
            const HRESULT conversion_hr = enumerator1->CheckVideoProcessorFormatConversion(input_format, input_color,
                output_format, output_color, supported);
            std::fprintf(stderr,
                "capture Float16 conversion: owner_thread=%lu input_format=%u input_color_space=%u output_format=%u output_color_space=%u hr=0x%08lx supported=%u\n",
                static_cast<unsigned long>(s->thread), static_cast<unsigned>(input_format), static_cast<unsigned>(input_color),
                static_cast<unsigned>(output_format), static_cast<unsigned>(output_color),
                static_cast<unsigned long>(conversion_hr), *supported ? 1u : 0u);
            std::fflush(stderr);
            return conversion_hr;
        }, expected_output_color);
        if (hr != S_OK) return FAILED(hr) ? hr : E_UNEXPECTED;
        context1->VideoProcessorSetStreamColorSpace1(s->processor.Get(), 0, fp16_input_color);
        context1->VideoProcessorSetOutputColorSpace1(s->processor.Get(), expected_output_color);
        DXGI_COLOR_SPACE_TYPE actual_input = DXGI_COLOR_SPACE_RESERVED, actual_output = DXGI_COLOR_SPACE_RESERVED;
        context1->VideoProcessorGetStreamColorSpace1(s->processor.Get(), 0, &actual_input);
        context1->VideoProcessorGetOutputColorSpace1(s->processor.Get(), &actual_output);
        std::fprintf(stderr, "capture Float16 color readback: owner_thread=%lu input_color_space=%u output_color_space=%u\n",
            static_cast<unsigned long>(s->thread), static_cast<unsigned>(actual_input), static_cast<unsigned>(actual_output));
        std::fflush(stderr);
        if (s->hdr10 ? actual_input != fp16_input_color || actual_output != hdr10_output_color
            : !exact_precision_colors(actual_input, actual_output)) return DXGI_ERROR_UNSUPPORTED;
        s->conversion_checked = true;
    }
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC iv{};
    iv.ViewDimension = D3D11_VPIV_DIMENSION_TEXTURE2D;
    hr = s->video->CreateVideoProcessorInputView(s->capture_rgb.Get(),s->enumerator.Get(),&iv,&s->input);
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC ov{};
    ov.ViewDimension = D3D11_VPOV_DIMENSION_TEXTURE2D;
    if (SUCCEEDED(hr)) hr = s->video->CreateVideoProcessorOutputView(s->nv12.Get(),s->enumerator.Get(),&ov,&s->output);
    if (FAILED(hr)) return hr;
    RECT rect{0,0,static_cast<LONG>(width),static_cast<LONG>(height)};
    s->processor_context->VideoProcessorSetStreamSourceRect(s->processor.Get(),0,TRUE,&rect);
    s->processor_context->VideoProcessorSetStreamDestRect(s->processor.Get(),0,TRUE,&rect);
    s->processor_context->VideoProcessorSetOutputTargetRect(s->processor.Get(),TRUE,&rect);
    s->processor_context->VideoProcessorSetStreamAutoProcessingMode(s->processor.Get(),0,FALSE);
    if (!s->precise()) {
        D3D11_VIDEO_PROCESSOR_COLOR_SPACE rgb{}; rgb.RGB_Range = 0; rgb.YCbCr_Matrix = 1; rgb.Nominal_Range = 2;
        D3D11_VIDEO_PROCESSOR_COLOR_SPACE yuv{}; yuv.YCbCr_Matrix = 1; yuv.Nominal_Range = 1;
        s->processor_context->VideoProcessorSetStreamColorSpace(s->processor.Get(),0,&rgb);
        s->processor_context->VideoProcessorSetOutputColorSpace(s->processor.Get(),&yuv);
    }
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
            static_cast<winrt::Windows::Graphics::DirectX::DirectXPixelFormat>(s.capture_format),2,size);
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
        hr = s.capture_rgb.As(&surface);
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
static int32_t capture_gpu_open(uintptr_t monitor, uint32_t width, uint32_t height,
    uint32_t fps,uint32_t bit_depth, bool hdr10, void** result) noexcept {
    if (!result) return E_POINTER;
    *result = nullptr;
    if((bit_depth!=8 && bit_depth!=10) || (hdr10 && bit_depth!=10))return E_INVALIDARG;
    if (!monitor || !width || !height || ((width|height)&1) || width > 8192 || height > 8192 ||
        static_cast<uint64_t>(width)*height*(bit_depth==10?8u:4u) > 64*1024*1024 || !fps || fps > 144) return E_INVALIDARG;
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
            // P010 does not authorize HDR or imply native source content depth.
            ComPtr<IDXGIOutput6> output6;
            DXGI_OUTPUT_DESC1 display_color{}; bool display_known = false;
            if (SUCCEEDED(output.As(&output6))) {
                hr = output6->GetDesc1(&display_color);
                if (FAILED(hr)) return hr;
                display_known = hr == S_OK;
                if (hdr10 ? !hdr10_output(display_color) : !sdr_output(display_color)) return DXGI_ERROR_UNSUPPORTED;
            }
            if (bit_depth == 10 && !display_known) return DXGI_ERROR_UNSUPPORTED;
            std::unique_ptr<GpuCapture> s(new (std::nothrow) GpuCapture());
            if (!s) return E_OUTOFMEMORY;
            s->high_precision_sdr = bit_depth == 10 && !hdr10;
            s->hdr10 = hdr10;
            s->capture_format = capture_format_for_depth(bit_depth);
            s->display_known = display_known; s->original_output = display_color;
            if (s->precise()) { s->source_factory = factory; s->source_output = output6; }
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
            if (s->precise()) {
                // WGC provides the system cursor in the Float16 capture. The
                // legacy duplication/GDI path would quantize it through BGRA8.
                hr = open_wgc(*s,reinterpret_cast<HMONITOR>(monitor),width,height);
                if (FAILED(hr)) return hr;
            } else {
                ComPtr<IDXGIOutput1> output1;
                hr = output.As(&output1);
                if (SUCCEEDED(hr)) hr = output1->DuplicateOutput(s->device.Get(),&s->duplication);
                if (FAILED(hr)) {
                    s->duplication.Reset();
                    hr = open_wgc(*s,reinterpret_cast<HMONITOR>(monitor),width,height);
                    if (FAILED(hr)) return hr;
                }
            }
            hr = create_surfaces(s.get(),width,height,fps,bit_depth);
            if (FAILED(hr)) return hr;
            s->backend = s->duplication ? 1u : 2u;
            s->width = width; s->height = height; s->left = desc.DesktopCoordinates.left; s->top = desc.DesktopCoordinates.top;
            hr = check_source_current(*s);
            if (FAILED(hr)) return hr;
            *result = s.release(); return S_OK;
        }
    }
    return DXGI_ERROR_NOT_FOUND;
}
// Original entry remains strictly SDR, including the independent Main10 mode.
extern "C" int32_t nl_capture_gpu_open(uintptr_t monitor, uint32_t width, uint32_t height,
    uint32_t fps,uint32_t bit_depth, void** result) noexcept {
    return capture_gpu_open(monitor,width,height,fps,bit_depth,false,result);
}
// Independent HDR entry: actual HDR output, FP16/scRGB WGC and exact PQ/P2020
// P010 conversion are mandatory. Opening starts no desktop capture.
extern "C" int32_t nl_capture_gpu_hdr10_open(uintptr_t monitor, uint32_t width, uint32_t height,
    uint32_t fps, void** result) noexcept {
    return capture_gpu_open(monitor,width,height,fps,10,true,result);
}
extern "C" int32_t nl_capture_gpu_device(void* opaque, void** device, uint64_t* luid) noexcept {
    auto* s = static_cast<GpuCapture*>(opaque);
    if (!s || !device || !luid || s->thread != GetCurrentThreadId()) return E_INVALIDARG;
    const HRESULT hr = check_source_current(*s);
    if (FAILED(hr)) return hr;
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
extern "C" int32_t nl_capture_gpu_source_state(void* opaque, CaptureSourceObservation* result) noexcept {
    if (!result) return E_POINTER;
    *result = CaptureSourceObservation{};
    auto* s = static_cast<GpuCapture*>(opaque);
    if (!s || s->thread != GetCurrentThreadId()) return E_INVALIDARG;
    const HRESULT hr = check_source_current(*s);
    if (FAILED(hr)) return hr;
    result->configured_format = s->capture_format;
    result->observed_format = s->observed_format;
    result->input_color_space = s->precise() ? fp16_input_color : DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;
    result->output_color_space = s->hdr10 ? hdr10_output_color : p010_output_color;
    if (s->display_known) {
        result->display_color_space = s->original_output.ColorSpace;
        result->display_bits_per_color = s->original_output.BitsPerColor;
        result->flags |= 1u;
    }
    if (s->observed_format != DXGI_FORMAT_UNKNOWN) result->flags |= 2u;
    if (s->high_precision_sdr) result->flags |= 4u;
    if (s->conversion_checked) result->flags |= 8u;
    if (s->hdr10) result->flags |= 16u;
    // HDR mode records the checked source/conversion, not physical scanout proof.
    return S_OK;
}
extern "C" int32_t nl_capture_gpu_frame(void* opaque, uint32_t repeated, void** texture) noexcept {
    auto* s = static_cast<GpuCapture*>(opaque);
    if (!s || !texture || s->thread != GetCurrentThreadId()) return E_INVALIDARG;
    *texture = nullptr;
    HRESULT hr = check_source_current(*s);
    if (FAILED(hr)) return hr;
    if (repeated) { if (!s->retained) return S_FALSE; *texture = s->nv12.Get(); return S_OK; }
    if (s->pool) {
        if (s->closed && s->closed->load()) return DXGI_ERROR_ACCESS_LOST;
        try {
            if (!s->wgc_started) { s->session.StartCapture(); s->wgc_started = true; }
            auto frame = s->pool.TryGetNextFrame();
            if (!frame) return S_FALSE;
            const auto size = frame.ContentSize();
            if (size.Width != static_cast<int32_t>(s->width) || size.Height != static_cast<int32_t>(s->height)) {
                if (s->precise()) { s->retired = true; s->retained = false; }
                frame.Close(); return DXGI_ERROR_ACCESS_LOST;
            }
            auto access = frame.Surface().as<::Windows::Graphics::DirectX::Direct3D11::IDirect3DDxgiInterfaceAccess>();
            ComPtr<ID3D11Texture2D> acquired;
            hr = access->GetInterface(IID_PPV_ARGS(&acquired));
            if (SUCCEEDED(hr)) {
                D3D11_TEXTURE2D_DESC desc{}; acquired->GetDesc(&desc);
                ComPtr<ID3D11Device> device; acquired->GetDevice(&device);
                const bool valid = s->precise()
                    ? exact_precision_surface(desc, s->width, s->height, device.Get() == s->device.Get())
                    : device.Get() == s->device.Get() && desc.Width == s->width && desc.Height == s->height && desc.Format == DXGI_FORMAT_B8G8R8A8_UNORM;
                if (s->precise() && s->observed_format == DXGI_FORMAT_UNKNOWN) {
                    std::fprintf(stderr,
                        "capture Float16 acquired: owner_thread=%lu actual_format=%u actual_width=%u actual_height=%u display_bits_per_color=%u native_content_precision_qualified=false\n",
                        static_cast<unsigned long>(s->thread), static_cast<unsigned>(desc.Format), desc.Width, desc.Height,
                        s->original_output.BitsPerColor);
                    std::fflush(stderr);
                }
                s->observed_format = desc.Format;
                if (!valid) {
                    if (s->precise()) {
                        s->retired = true; s->retained = false;
                        std::fprintf(stderr, "capture Float16 source rejected: owner_thread=%lu actual_format=%u actual_width=%u actual_height=%u same_device=%u\n",
                            static_cast<unsigned long>(s->thread), static_cast<unsigned>(desc.Format), desc.Width, desc.Height,
                            device.Get() == s->device.Get() ? 1u : 0u);
                        std::fflush(stderr);
                    }
                    hr = DXGI_ERROR_UNSUPPORTED;
                } else {
                    s->context->CopyResource(s->capture_rgb.Get(),acquired.Get());
                }
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
            else { s->observed_format = desc.Format; s->context->CopyResource(s->capture_rgb.Get(),acquired.Get()); }
        }
        if (info.LastMouseUpdateTime.QuadPart) s->pointer_separate = info.PointerPosition.Visible != FALSE;
        const HRESULT released = s->duplication->ReleaseFrame();
        if (FAILED(hr)) return hr;
        if (FAILED(released)) return released;
    }
    hr = cursor(*s);
    if (SUCCEEDED(hr)) hr = convert(*s);
    if (SUCCEEDED(hr)) hr = check_source_current(*s);
    if (FAILED(hr)) return hr;
    s->retained = true; *texture = s->nv12.Get(); return S_OK;
}
// Synthetic upload probes the real device/conversion/encoder without desktop pixels.
extern "C" int32_t nl_capture_gpu_probe(void* opaque, const uint8_t* pixels, size_t length, void** texture) noexcept {
    auto* s = static_cast<GpuCapture*>(opaque);
    if (!s || !pixels || !texture || s->precise() || s->thread != GetCurrentThreadId() || length != static_cast<size_t>(s->width)*s->height*4) return E_INVALIDARG;
    s->context->UpdateSubresource(s->capture_rgb.Get(),0,nullptr,pixels,s->width*4,0);
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
        static_cast<uint64_t>(width)*height*4>64*1024*1024 || !fps || fps>144) return E_INVALIDARG;
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

// Production conversion/surface/source decisions using actual native metadata
// structures. No device, duplication, WGC session, window or pixels are opened.
extern "C" uint32_t nl_capture_gpu_precision_contract() noexcept {
    uint32_t passed = 0;
    if (capture_format_for_depth(8) == DXGI_FORMAT_B8G8R8A8_UNORM &&
        capture_format_for_depth(10) == DXGI_FORMAT_R16G16B16A16_FLOAT) passed |= 1;
    bool exact_request = false;
    const HRESULT conversion = check_fp16_conversion([&](DXGI_FORMAT input_format, DXGI_COLOR_SPACE_TYPE input_color,
        DXGI_FORMAT output_format, DXGI_COLOR_SPACE_TYPE output_color, BOOL* supported) {
        exact_request = input_format == DXGI_FORMAT_R16G16B16A16_FLOAT && input_color == fp16_input_color &&
            output_format == DXGI_FORMAT_P010 && output_color == p010_output_color;
        *supported = TRUE; return S_OK;
    });
    const auto scenario = [](HRESULT query, BOOL supported) {
        return check_fp16_conversion([&](DXGI_FORMAT, DXGI_COLOR_SPACE_TYPE,
            DXGI_FORMAT, DXGI_COLOR_SPACE_TYPE, BOOL* result) { *result = supported; return query; });
    };
    if (conversion == S_OK && exact_request && scenario(S_OK, FALSE) == DXGI_ERROR_UNSUPPORTED &&
        scenario(E_ACCESSDENIED, TRUE) == E_ACCESSDENIED && FAILED(scenario(S_FALSE, TRUE))) passed |= 2;
    if (exact_precision_colors(fp16_input_color, p010_output_color) &&
        !exact_precision_colors(DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709, p010_output_color) &&
        !exact_precision_colors(fp16_input_color, DXGI_COLOR_SPACE_YCBCR_STUDIO_G2084_LEFT_P2020)) passed |= 4;
    D3D11_TEXTURE2D_DESC surface{};
    surface.Width = 1920; surface.Height = 1080; surface.MipLevels = 1; surface.ArraySize = 1;
    surface.Format = DXGI_FORMAT_R16G16B16A16_FLOAT; surface.SampleDesc.Count = 1;
    bool surfaces = exact_precision_surface(surface, 1920, 1080, true) &&
        !exact_precision_surface(surface, 1920, 1080, false) && !exact_precision_surface(surface, 1920, 1088, true);
    auto changed_surface = surface; changed_surface.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    surfaces = surfaces && !exact_precision_surface(changed_surface, 1920, 1080, true);
    changed_surface = surface; changed_surface.ArraySize = 2;
    surfaces = surfaces && !exact_precision_surface(changed_surface, 1920, 1080, true);
    changed_surface = surface; changed_surface.MipLevels = 2;
    surfaces = surfaces && !exact_precision_surface(changed_surface, 1920, 1080, true);
    changed_surface = surface; changed_surface.SampleDesc.Count = 2;
    if (surfaces && !exact_precision_surface(changed_surface, 1920, 1080, true)) passed |= 8;
    DXGI_OUTPUT_DESC1 original{};
    original.AttachedToDesktop = TRUE; original.BitsPerColor = 8;
    original.ColorSpace = DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;
    original.DesktopCoordinates = RECT{0, 0, 1920, 1080};
    original.RedPrimary[0] = 0.64f; original.GreenPrimary[1] = 0.6f;
    original.BluePrimary[0] = 0.15f; original.WhitePoint[0] = 0.3127f;
    original.MaxLuminance = 300.0f; original.MaxFullFrameLuminance = 250.0f;
    bool retired = false;
    if (sdr_output(original) && same_output_color(original, original) &&
        retain_source_color(retired, true, S_OK, original, original) == S_OK && !retired) passed |= 16;
    const auto rejected = [&](bool factory_current, HRESULT query, const DXGI_OUTPUT_DESC1& current) {
        bool stale = false;
        return FAILED(retain_source_color(stale, factory_current, query, original, current)) && stale;
    };
    auto changed_output = original; changed_output.BitsPerColor = 10;
    bool modes = rejected(true, S_OK, changed_output);
    changed_output = original; changed_output.ColorSpace = DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020;
    if (modes && !sdr_output(changed_output) && rejected(true, S_OK, changed_output) &&
        rejected(false, S_OK, original) && rejected(true, E_ACCESSDENIED, original) &&
        rejected(true, S_FALSE, original)) passed |= 32;
    changed_output = original; changed_output.MaxLuminance += 1;
    bool colors = rejected(true, S_OK, changed_output);
    changed_output = original; changed_output.WhitePoint[0] += 0.01f;
    colors = colors && rejected(true, S_OK, changed_output);
    changed_output = original; changed_output.RedPrimary[0] += 0.01f;
    colors = colors && rejected(true, S_OK, changed_output);
    changed_output = original; changed_output.DesktopCoordinates.left = 8;
    colors = colors && rejected(true, S_OK, changed_output);
    changed_output = original; changed_output.Rotation = DXGI_MODE_ROTATION_ROTATE90;
    if (colors && rejected(true, S_OK, changed_output)) passed |= 64;
    if (retain_source_color(retired, false, S_OK, original, original) == DXGI_ERROR_ACCESS_LOST && retired &&
        retain_source_color(retired, true, S_OK, original, original) == DXGI_ERROR_ACCESS_LOST && retired) passed |= 128;
    return passed;
}
extern "C" uint32_t nl_capture_gpu_hdr10_contract() noexcept {
    uint32_t passed=0;
    DXGI_OUTPUT_DESC1 original{};original.AttachedToDesktop=TRUE;original.BitsPerColor=10;
    original.ColorSpace=DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020;
    original.DesktopCoordinates=RECT{0,0,1920,1080};original.MaxLuminance=1000;
    bool retired=false;
    if(hdr10_output(original) && !sdr_output(original) &&
        retain_hdr_source_color(retired,true,S_OK,original,original)==S_OK && !retired)passed|=1;
    bool exact=false;
    const HRESULT conversion=check_fp16_conversion([&](DXGI_FORMAT in,DXGI_COLOR_SPACE_TYPE input,
        DXGI_FORMAT out,DXGI_COLOR_SPACE_TYPE output,BOOL* supported) {
        exact=in==DXGI_FORMAT_R16G16B16A16_FLOAT && input==fp16_input_color && out==DXGI_FORMAT_P010 && output==hdr10_output_color;
        *supported=TRUE;return S_OK;
    },hdr10_output_color);
    if(conversion==S_OK && exact && !exact_precision_colors(fp16_input_color,hdr10_output_color))passed|=2;
    const auto rejected=[&](bool factory,HRESULT query,const DXGI_OUTPUT_DESC1& current) {
        bool stale=false;return FAILED(retain_hdr_source_color(stale,factory,query,original,current)) && stale &&
            retain_hdr_source_color(stale,true,S_OK,original,original)==DXGI_ERROR_ACCESS_LOST;
    };
    auto changed=original;changed.BitsPerColor=8;
    bool modes=rejected(true,S_OK,changed);changed=original;changed.ColorSpace=DXGI_COLOR_SPACE_RGB_FULL_G22_NONE_P709;
    if(modes && rejected(true,S_OK,changed) && rejected(false,S_OK,original) && rejected(true,S_FALSE,original))passed|=4;
    changed=original;changed.MaxLuminance+=1;
    bool metadata=rejected(true,S_OK,changed);changed=original;changed.WhitePoint[0]+=0.01f;
    metadata=metadata && rejected(true,S_OK,changed);changed=original;changed.DesktopCoordinates.right+=8;
    if(metadata && rejected(true,S_OK,changed))passed|=8;
    return passed;
}
