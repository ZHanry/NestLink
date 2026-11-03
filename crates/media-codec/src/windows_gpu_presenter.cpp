// Window operations run on the glow/UI thread; all MF/D3D resources on one worker.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <mfapi.h>
#include <mfidl.h>
#include <mftransform.h>
#include <mferror.h>
#include <d3d11.h>
#include <d3d11_1.h>
#include <d3d10.h>
#include <dxgi1_2.h>
#include <dxgi1_6.h>
#include <wrl/client.h>
#include <atomic>
#include <memory>
#include <new>
#include <cstdint>
#include <cstring>
#include <array>
#include <cstdio>
#include "owner_observation.h"
#include "shared_surface_abi.h"
using Microsoft::WRL::ComPtr;
namespace {
struct Surface {
    std::atomic<unsigned> references{1};
    std::atomic<bool> live{true}, authorized{false};
    std::atomic<uint64_t> expires{0};
    HWND parent=nullptr;
    std::atomic<HWND> child{nullptr};
    DWORD thread=GetCurrentThreadId();
    uint64_t key=0;
    HDC probe_dc=nullptr;
    HGLRC probe_gl=nullptr;
    bool probe_parent=false;
    bool clip_added=false;
};
// Only the explicitly owned synthetic probe emits these immediate diagnostics.
void trace(Surface* s, const char* stage) {
    if (s && s->probe_parent) { std::fprintf(stderr,"gpu_native_stage=%s\n",stage); std::fflush(stderr); }
}
void trace_result(Surface* s, const char* stage, HRESULT hr) {
    if (s && s->probe_parent) {
        std::fprintf(stderr,"gpu_native_result stage=%s hr=0x%08lx\n",stage,static_cast<unsigned long>(hr));
        std::fflush(stderr);
    }
}
void release(Surface* s) { if (s && --s->references==0) delete s; }
LRESULT CALLBACK child_proc(HWND hwnd, UINT message, WPARAM w, LPARAM l) {
    if (message==WM_NCHITTEST) return HTTRANSPARENT;
    if (message==WM_MOUSEACTIVATE) return MA_NOACTIVATE;
    if (message==WM_APP+41) { ShowWindow(hwnd,SW_HIDE); return 0; }
    return DefWindowProcW(hwnd,message,w,l);
}
LRESULT CALLBACK parent_proc(HWND hwnd, UINT message, WPARAM w, LPARAM l, UINT_PTR id, DWORD_PTR data) {
    auto* s=reinterpret_cast<Surface*>(data);
    if (message==WM_NCDESTROY) {
        s->authorized=false; s->live=false; s->child=nullptr;
        RemoveWindowSubclass(hwnd,parent_proc,id);
        const auto result=DefSubclassProc(hwnd,message,w,l);
        release(s); return result;
    }
    if (message==WM_SIZE || message==WM_SHOWWINDOW || message==WM_DPICHANGED) {
        s->authorized=false;
        if (s->child) ShowWindow(s->child,SW_HIDE);
    }
    return DefSubclassProc(hwnd,message,w,l);
}
struct Presenter;
HRESULT black(Presenter& p);
struct GpuInputGeometry {
    uint32_t coded_width=0,coded_height=0,crop[4]{};
};
static_assert(sizeof(GpuInputGeometry)==24,"GPU input geometry ABI");
struct GpuOutputGeometry {
    UINT width=0,height=0,left=0,top=0;
    bool operator==(const GpuOutputGeometry& other) const {
        return width==other.width && height==other.height && left==other.left && top==other.top;
    }
};
bool same_geometry(const GpuInputGeometry& a,const GpuInputGeometry& b) {
    return a.coded_width==b.coded_width && a.coded_height==b.coded_height &&
        a.crop[0]==b.crop[0] && a.crop[1]==b.crop[1] && a.crop[2]==b.crop[2] && a.crop[3]==b.crop[3];
}
bool valid_input_geometry(const GpuInputGeometry& g,UINT width,UINT height,bool hevc) {
    const uint64_t horizontal=static_cast<uint64_t>(g.crop[0])+g.crop[1];
    const uint64_t vertical=static_cast<uint64_t>(g.crop[2])+g.crop[3];
    if(!width || !height || !g.coded_width || !g.coded_height || g.coded_width>8192 || g.coded_height>8192 ||
        ((width|height|g.coded_width|g.coded_height|g.crop[0]|g.crop[1]|g.crop[2]|g.crop[3])&1) ||
        horizontal+width!=g.coded_width || vertical+height!=g.coded_height ||
        static_cast<uint64_t>(g.coded_width)*g.coded_height*4>65*1024*1024)return false;
    if(hevc)return g.coded_width==width && g.coded_height==height && !horizontal && !vertical;
    return g.coded_width==(width+15)/16*16 && g.coded_height==(height+15)/16*16;
}
// MF raw output can already be cropped or retain exactly the SPS coded extent.
// Padded dimensions alone never establish a display rectangle. They require a
// complete integer aperture which agrees with the independently validated SPS.
HRESULT output_geometry(IMFMediaType* type,UINT width,UINT height,
    const GpuInputGeometry* expected,GpuOutputGeometry* output) {
    if(!type || !output)return E_POINTER;
    UINT32 w=0,h=0;
    HRESULT hr=MFGetAttributeSize(type,MF_MT_FRAME_SIZE,&w,&h);
    if(FAILED(hr))return hr;
    if(!w || !h || ((w|h)&1) || w>8192 || h>8192 ||
        static_cast<uint64_t>(w)*h*4>65*1024*1024)return MF_E_INVALIDMEDIATYPE;
    MFVideoArea area{};UINT32 actual=0;
    hr=type->GetBlob(MF_MT_MINIMUM_DISPLAY_APERTURE,reinterpret_cast<UINT8*>(&area),
        static_cast<UINT32>(sizeof(area)),&actual);
    const bool aperture=SUCCEEDED(hr);
    if(FAILED(hr) && hr!=MF_E_ATTRIBUTENOTFOUND)return MF_E_INVALIDMEDIATYPE;
    if(aperture && (actual!=sizeof(area) || area.OffsetX.fract || area.OffsetY.fract ||
        area.OffsetX.value<0 || area.OffsetY.value<0 || area.Area.cx!=static_cast<LONG>(width) ||
        area.Area.cy!=static_cast<LONG>(height)))return MF_E_INVALIDMEDIATYPE;
    const UINT left=aperture?static_cast<UINT>(area.OffsetX.value):0;
    const UINT top=aperture?static_cast<UINT>(area.OffsetY.value):0;
    if(w==width && h==height) {
        if(left || top)return MF_E_INVALIDMEDIATYPE;
    } else {
        if(!expected || !aperture || w!=expected->coded_width || h!=expected->coded_height ||
            left!=expected->crop[0] || top!=expected->crop[2] ||
            static_cast<uint64_t>(left)+width+expected->crop[1]!=w ||
            static_cast<uint64_t>(top)+height+expected->crop[3]!=h)return MF_E_INVALIDMEDIATYPE;
    }
    *output={w,h,left,top};return S_OK;
}
std::atomic<bool> nl_gpu_probe_owner_reserved{false};
struct Presenter {
    bool hevc=false;
    bool hdr10=false, hdr_retired=false, hdr_display_bound=false;
    DXGI_OUTPUT_DESC1 hdr_display{};
    ComPtr<IDXGIFactory1> hdr_factory;
    bool probe_owner_reserved=false; bool checked_shutdown=false;
    GUID observation_id{}; bool observation_initialized=false;
    bool probe_color_enabled=false; std::array<uint8_t,4> probe_expected{}; uint32_t probe_tolerance=0;
    uint64_t probe_colors=0;
    ComPtr<ID3D11Texture2D> probe_staging;
    Surface* surface=nullptr;
    DWORD thread=GetCurrentThreadId();
    bool com=false, mf=false;
    UINT width=0,height=0,fps=0;
    GpuInputGeometry input_geometry{};
    bool input_geometry_bound=false;
    GpuOutputGeometry output_geometry{};
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IMFDXGIDeviceManager> manager;
    DXGI_FORMAT input_format=DXGI_FORMAT_NV12;
    ComPtr<IMFTransform> decoder;
    ComPtr<IDXGISwapChain1> swap;
    ComPtr<ID3D11VideoDevice> video;
    ComPtr<ID3D11VideoContext> video_context;
    ComPtr<ID3D11VideoProcessorEnumerator> enumerator;
    ComPtr<ID3D11VideoProcessor> processor;
    ComPtr<IMFSample> pending;
    std::array<ComPtr<IMFSample>,8> ready{};
    size_t ready_count=0;
    size_t ready_high_water=0;
    uint64_t decoded_outputs=0, retired_pictures=0;
    ComPtr<ID3D11Query> completion;
    struct Timing { uint64_t pts=0,due=0,expires=0; };
    std::array<Timing,8> times{};
    size_t time_head=0,time_size=0;
    ~Presenter() {
        if (surface && surface->probe_parent) {
            std::fprintf(stderr,"gpu_native_summary decoded=%llu retired=%llu ready_high_water=%llu pending=%llu\n",
                static_cast<unsigned long long>(decoded_outputs),static_cast<unsigned long long>(retired_pictures),
                static_cast<unsigned long long>(ready_high_water),static_cast<unsigned long long>(time_size));
            std::fflush(stderr);
        }
        trace(surface,"destructor_black_begin");
        if (swap && context) black(*this);
        trace(surface,"destructor_decoder_flush_begin");
        if (decoder && !checked_shutdown) decoder->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH,0);
        for (auto& sample:ready) sample.Reset(); pending.Reset(); completion.Reset(); processor.Reset(); enumerator.Reset();
        probe_staging.Reset(); video_context.Reset(); video.Reset(); swap.Reset(); decoder.Reset();
        manager.Reset(); context.Reset(); device.Reset();
        trace(surface,"destructor_mf_shutdown_begin");
        if (mf) MFShutdown(); if (com) CoUninitialize();
        trace(surface,"destructor_end"); release(surface);
        if(probe_owner_reserved)nl_gpu_probe_owner_reserved.store(false);
    }
};
HRESULT black(Presenter& p) {
    if (!p.swap || !p.context) return E_ABORT;
    ComPtr<ID3D11Texture2D> back; ComPtr<ID3D11RenderTargetView> view;
    HRESULT hr=p.swap->GetBuffer(0,IID_PPV_ARGS(&back)); if (FAILED(hr)) return hr;
    hr=p.device->CreateRenderTargetView(back.Get(),nullptr,&view); if (FAILED(hr)) return hr;
    const FLOAT color[4]={0,0,0,1}; p.context->ClearRenderTargetView(view.Get(),color); p.context->Flush();
    return p.swap->Present(0,DXGI_PRESENT_DO_NOT_WAIT);
}
bool hdr_display_current(Presenter& p) {
    if(!p.hdr10)return true;
    if(p.hdr_retired || !p.hdr_factory || !p.hdr_factory->IsCurrent()){p.hdr_retired=true;return false;}
    ComPtr<IDXGIOutput> output;ComPtr<IDXGIOutput6> advanced;DXGI_OUTPUT_DESC1 current{};
    HRESULT hr=p.swap->GetContainingOutput(&output);
    if(hr==S_OK)hr=output.As(&advanced);
    if(hr==S_OK)hr=advanced->GetDesc1(&current);
    bool valid=hr==S_OK && current.AttachedToDesktop && current.BitsPerColor>=10 &&
        current.ColorSpace==DXGI_COLOR_SPACE_RGB_FULL_G2084_NONE_P2020;
    if(valid && p.hdr_display_bound) {
        const auto& old=p.hdr_display;
        valid=old.Monitor==current.Monitor && old.BitsPerColor==current.BitsPerColor && old.ColorSpace==current.ColorSpace &&
            old.Rotation==current.Rotation && old.MinLuminance==current.MinLuminance && old.MaxLuminance==current.MaxLuminance &&
            old.MaxFullFrameLuminance==current.MaxFullFrameLuminance &&
            old.DesktopCoordinates.left==current.DesktopCoordinates.left && old.DesktopCoordinates.top==current.DesktopCoordinates.top &&
            old.DesktopCoordinates.right==current.DesktopCoordinates.right && old.DesktopCoordinates.bottom==current.DesktopCoordinates.bottom;
        for(unsigned i=0;i<2;++i)valid=valid && old.RedPrimary[i]==current.RedPrimary[i] &&
            old.GreenPrimary[i]==current.GreenPrimary[i] && old.BluePrimary[i]==current.BluePrimary[i] && old.WhitePoint[i]==current.WhitePoint[i];
    }
    if(!valid){p.hdr_retired=true;return false;}
    if(!p.hdr_display_bound){p.hdr_display=current;p.hdr_display_bound=true;}
    return true;
}
bool authorized(Presenter& p) {
    LARGE_INTEGER now{}; QueryPerformanceCounter(&now);
    const auto expires=p.surface->expires.load();
    if (p.surface->live && expires && static_cast<uint64_t>(now.QuadPart)<expires && hdr_display_current(p)) return true;
    p.surface->authorized=false;
    black(p);
    HWND child=p.surface->child.load();
    if (child) PostMessageW(child,WM_APP+41,0,0);
    return false;
}
// The transport/CPU conversion contract is SDR BT.709 limited. Negotiate it
// explicitly: MF decoder available types may omit color attributes entirely.
// Never overwrite a concrete conflicting declaration from the decoder.
HRESULT sdr_type(Presenter& p, IMFMediaType* type, bool negotiate) {
    const char* names[]={"matrix","range","primaries","transfer"};
    const GUID* keys[]={&MF_MT_YUV_MATRIX,&MF_MT_VIDEO_NOMINAL_RANGE,
        &MF_MT_VIDEO_PRIMARIES,&MF_MT_TRANSFER_FUNCTION};
    const UINT32 expected[]={MFVideoTransferMatrix_BT709,MFNominalRange_16_235,
        MFVideoPrimaries_BT709,MFVideoTransFunc_709};
    for (size_t i=0;i<4;++i) {
        UINT32 value=0;
        const HRESULT found=type->GetUINT32(*keys[i],&value);
        if (p.surface->probe_parent) {
            std::fprintf(stderr,"gpu_native_color phase=%s attribute=%s hr=0x%08lx value=%u expected=%u\n",
                negotiate?"negotiate":"actual",names[i],
                static_cast<unsigned long>(found),value,expected[i]);
            std::fflush(stderr);
        }
        if (FAILED(found) && found!=MF_E_ATTRIBUTENOTFOUND) return found;
        // Only a missing attribute can inherit the negotiated contract.
        // Explicit Unknown or conflicting values remain unsupported.
        if (SUCCEEDED(found) && value!=expected[i]) return MF_E_INVALIDMEDIATYPE;
        if (!negotiate && (FAILED(found) || value!=expected[i])) return MF_E_INVALIDMEDIATYPE;
        if (negotiate) {
            const HRESULT hr=type->SetUINT32(*keys[i],expected[i]);
            if (FAILED(hr)) return hr;
        }
    }
    return S_OK;
}
HRESULT output_type(Presenter& p) {
    for (DWORD i=0;i<64;++i) {
        ComPtr<IMFMediaType> t;
        HRESULT hr=p.decoder->GetOutputAvailableType(0,i,&t);
        trace_result(p.surface,"output_available_type",hr);
        if (FAILED(hr)) return hr;
        if (p.surface->probe_parent) {
            GUID subtype{}; UINT32 coded_w=0,coded_h=0; MFVideoArea display{}; UINT32 display_size=0;
            const HRESULT sub_hr=t->GetGUID(MF_MT_SUBTYPE,&subtype);
            const HRESULT size_hr=MFGetAttributeSize(t.Get(),MF_MT_FRAME_SIZE,&coded_w,&coded_h);
            const HRESULT area_hr=t->GetBlob(MF_MT_MINIMUM_DISPLAY_APERTURE,reinterpret_cast<UINT8*>(&display),static_cast<UINT32>(sizeof(display)),&display_size);
            std::fprintf(stderr,"gpu_native_output_candidate index=%lu subtype_hr=0x%08lx nv12=%u size_hr=0x%08lx coded=%ux%u required=%ux%u aperture_hr=0x%08lx aperture_bytes=%u origin=%d:%u,%d:%u display=%ldx%ld\n",
                static_cast<unsigned long>(i),static_cast<unsigned long>(sub_hr),SUCCEEDED(sub_hr)&&subtype==MFVideoFormat_NV12,
                static_cast<unsigned long>(size_hr),coded_w,coded_h,p.width,p.height,static_cast<unsigned long>(area_hr),display_size,
                display.OffsetX.value,display.OffsetX.fract,display.OffsetY.value,display.OffsetY.fract,display.Area.cx,display.Area.cy);
            std::fflush(stderr);
        }
        GUID sub{};
        if (FAILED(t->GetGUID(MF_MT_SUBTYPE,&sub)) || sub!=MFVideoFormat_NV12) continue;
        GpuOutputGeometry geometry{};
        hr=output_geometry(t.Get(),p.width,p.height,p.input_geometry_bound?&p.input_geometry:nullptr,&geometry);
        if(FAILED(hr))continue;
        hr=sdr_type(p,t.Get(),true); if (FAILED(hr)) return hr;
        hr=p.decoder->SetOutputType(0,t.Get(),0);
        trace_result(p.surface,"decoder_set_output_type",hr);
        if(SUCCEEDED(hr))p.output_geometry=geometry;
        return hr;
    }
    return MF_E_INVALIDMEDIATYPE;
}
HRESULT configure_output(Presenter& p,UINT fps);
HRESULT configure_processor(Presenter& p,UINT fps);
HRESULT configure(Presenter& p, UINT fps, UINT kbps) {
    trace(p.surface,"configure_begin");
    trace(p.surface,"d3d11_device_create_begin");
    HRESULT hr=D3D11CreateDevice(nullptr,D3D_DRIVER_TYPE_HARDWARE,nullptr,
        D3D11_CREATE_DEVICE_BGRA_SUPPORT|D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
        nullptr,0,D3D11_SDK_VERSION,&p.device,nullptr,&p.context);
    if (FAILED(hr)) return hr;
    ComPtr<ID3D10Multithread> multi;
    hr=p.context.As(&multi); if (FAILED(hr)) return hr;
    multi->SetMultithreadProtected(TRUE);
    hr=p.device.As(&p.video); if (FAILED(hr)) return hr;
    hr=p.context.As(&p.video_context); if (FAILED(hr)) return hr;
    UINT token=0;
    hr=MFCreateDXGIDeviceManager(&token,&p.manager); if (FAILED(hr)) return hr;
    hr=p.manager->ResetDevice(p.device.Get(),token); if (FAILED(hr)) return hr;
    MFT_REGISTER_TYPE_INFO input{MFMediaType_Video,p.hevc?MFVideoFormat_HEVC:MFVideoFormat_H264};
    MFT_REGISTER_TYPE_INFO output{MFMediaType_Video,MFVideoFormat_NV12};
    IMFActivate** choices=nullptr; UINT count=0;
    trace(p.surface,"decoder_enumerate_begin");
    hr=MFTEnumEx(MFT_CATEGORY_VIDEO_DECODER,MFT_ENUM_FLAG_SYNCMFT|MFT_ENUM_FLAG_SORTANDFILTER,
        &input,&output,&choices,&count);
    if (FAILED(hr)) return hr;
    HRESULT selected=MF_E_TOPO_CODEC_NOT_FOUND;
    for (UINT i=0;i<count;++i) {
        if (!p.decoder) selected=choices[i]->ActivateObject(IID_PPV_ARGS(&p.decoder));
        choices[i]->Release();
    }
    CoTaskMemFree(choices); if (!p.decoder) return selected;
    ComPtr<IMFAttributes> attrs;
    hr=p.decoder->GetAttributes(&attrs); if (FAILED(hr)) return hr;
    UINT32 aware=0; hr=attrs->GetUINT32(MF_SA_D3D11_AWARE,&aware);
    if (FAILED(hr) || !aware) return MF_E_UNSUPPORTED_D3D_TYPE;
    attrs->SetUINT32(MF_LOW_LATENCY,TRUE);
    trace(p.surface,"decoder_set_manager_begin");
    hr=p.decoder->ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER,reinterpret_cast<ULONG_PTR>(p.manager.Get()));
    if (FAILED(hr)) return hr;
    ComPtr<IMFMediaType> type;
    hr=MFCreateMediaType(&type); if (FAILED(hr)) return hr;
    type->SetGUID(MF_MT_MAJOR_TYPE,MFMediaType_Video);
    type->SetGUID(MF_MT_SUBTYPE,p.hevc?MFVideoFormat_HEVC:MFVideoFormat_H264);
    type->SetUINT32(MF_MT_INTERLACE_MODE,MFVideoInterlace_Progressive);
    MFSetAttributeSize(type.Get(),MF_MT_FRAME_SIZE,p.width,p.height);
    MFSetAttributeRatio(type.Get(),MF_MT_FRAME_RATE,fps,1);
    hr=type->SetUINT32(MF_MT_AVG_BITRATE,kbps*1000);if(FAILED(hr))return hr;
    hr=sdr_type(p,type.Get(),true); if (FAILED(hr)) return hr;
    trace(p.surface,"decoder_set_input_type_begin");
    hr=p.decoder->SetInputType(0,type.Get(),0); if (FAILED(hr)) return hr;
    trace(p.surface,"decoder_output_type_begin");
    hr=output_type(p); if (FAILED(hr)) return hr;
    hr=configure_output(p,fps);if(FAILED(hr))return hr;
    trace(p.surface,"decoder_begin_streaming_begin");
    hr=p.decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,0); if (FAILED(hr)) return hr;
    return p.decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM,0);
}
HRESULT configure_output(Presenter& p,UINT fps) {
    HRESULT hr=S_OK;
    ComPtr<IDXGIDevice> dxgi; ComPtr<IDXGIAdapter> adapter; ComPtr<IDXGIFactory2> factory;
    hr=p.device.As(&dxgi); if (FAILED(hr)) return hr;
    hr=dxgi->GetAdapter(&adapter); if (FAILED(hr)) return hr;
    hr=adapter->GetParent(IID_PPV_ARGS(&factory)); if (FAILED(hr)) return hr;
    DXGI_SWAP_CHAIN_DESC1 desc{};
    desc.Width=p.width; desc.Height=p.height; desc.Format=p.hdr10?DXGI_FORMAT_R16G16B16A16_FLOAT:DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count=1; desc.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount=2; desc.SwapEffect=DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    trace(p.surface,"swapchain_create_begin");
    hr=factory->CreateSwapChainForHwnd(p.device.Get(),p.surface->child.load(),&desc,nullptr,nullptr,&p.swap);
    if (FAILED(hr)) return hr;
    if(p.hdr10) {
        ComPtr<IDXGISwapChain3> color_swap;hr=p.swap.As(&color_swap);if(hr!=S_OK)return FAILED(hr)?hr:E_UNEXPECTED;
        UINT support=0;hr=color_swap->CheckColorSpaceSupport(DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709,&support);
        if(hr!=S_OK || !(support&DXGI_SWAP_CHAIN_COLOR_SPACE_SUPPORT_FLAG_PRESENT))return FAILED(hr)?hr:DXGI_ERROR_UNSUPPORTED;
        hr=color_swap->SetColorSpace1(DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709);if(hr!=S_OK)return FAILED(hr)?hr:E_UNEXPECTED;
        hr=factory.As(&p.hdr_factory);if(hr!=S_OK)return FAILED(hr)?hr:E_UNEXPECTED;
        if(!hdr_display_current(p))return DXGI_ERROR_UNSUPPORTED;
        std::fprintf(stderr,"hevc_hdr10_presenter swap_format=%u swap_color_space=%u display_color_space=%u display_bits_per_color=%u physical_scanout_qualified=false\n",
            static_cast<unsigned>(desc.Format),static_cast<unsigned>(DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709),
            static_cast<unsigned>(p.hdr_display.ColorSpace),p.hdr_display.BitsPerColor);std::fflush(stderr);
    }
    black(p);
    factory->MakeWindowAssociation(p.surface->child.load(),DXGI_MWA_NO_ALT_ENTER);
    p.fps=fps;
    hr=configure_processor(p,fps);if(FAILED(hr))return hr;
    D3D11_QUERY_DESC query{D3D11_QUERY_EVENT,0};
    return p.device->CreateQuery(&query,&p.completion);
}
HRESULT configure_processor(Presenter& p,UINT fps) {
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC content{};
    content.InputFrameFormat=D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
    content.InputWidth=p.output_geometry.width?p.output_geometry.width:p.width;
    content.InputHeight=p.output_geometry.height?p.output_geometry.height:p.height;
    content.OutputWidth=p.width; content.OutputHeight=p.height;
    content.InputFrameRate={fps,1}; content.OutputFrameRate={fps,1};
    content.Usage=D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
    trace(p.surface,"video_processor_create_begin");
    ComPtr<ID3D11VideoProcessorEnumerator> enumerator;
    ComPtr<ID3D11VideoProcessor> processor;
    HRESULT hr=p.video->CreateVideoProcessorEnumerator(&content,&enumerator); if (FAILED(hr)) return hr;
    UINT flags=0;
    hr=enumerator->CheckVideoProcessorFormat(p.input_format,&flags);
    if (FAILED(hr) || !(flags&D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT)) return E_NOTIMPL;
    hr=enumerator->CheckVideoProcessorFormat(p.hdr10?DXGI_FORMAT_R16G16B16A16_FLOAT:DXGI_FORMAT_B8G8R8A8_UNORM,&flags);
    if (FAILED(hr) || !(flags&D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT)) return E_NOTIMPL;
    hr=p.video->CreateVideoProcessor(enumerator.Get(),0,&processor); if (FAILED(hr)) return hr;
    p.processor=processor;p.enumerator=enumerator;
    if(p.hdr10) {
        ComPtr<ID3D11VideoProcessorEnumerator1> enumerator1;ComPtr<ID3D11VideoContext1> context1;
        hr=enumerator.As(&enumerator1);if(hr==S_OK)hr=p.video_context.As(&context1);
        if(hr!=S_OK)return FAILED(hr)?hr:E_UNEXPECTED;
        BOOL supported=FALSE;
        hr=enumerator1->CheckVideoProcessorFormatConversion(DXGI_FORMAT_P010,DXGI_COLOR_SPACE_YCBCR_STUDIO_G2084_LEFT_P2020,
            DXGI_FORMAT_R16G16B16A16_FLOAT,DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709,&supported);
        if(hr!=S_OK || !supported)return FAILED(hr)?hr:DXGI_ERROR_UNSUPPORTED;
        context1->VideoProcessorSetStreamColorSpace1(processor.Get(),0,DXGI_COLOR_SPACE_YCBCR_STUDIO_G2084_LEFT_P2020);
        context1->VideoProcessorSetOutputColorSpace1(processor.Get(),DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709);
        p.video_context->VideoProcessorSetStreamAutoProcessingMode(processor.Get(),0,FALSE);
        DXGI_COLOR_SPACE_TYPE input=DXGI_COLOR_SPACE_RESERVED,output=DXGI_COLOR_SPACE_RESERVED;
        context1->VideoProcessorGetStreamColorSpace1(processor.Get(),0,&input);context1->VideoProcessorGetOutputColorSpace1(processor.Get(),&output);
        if(input!=DXGI_COLOR_SPACE_YCBCR_STUDIO_G2084_LEFT_P2020 || output!=DXGI_COLOR_SPACE_RGB_FULL_G10_NONE_P709)return DXGI_ERROR_UNSUPPORTED;
    }
    return S_OK;
}
// No CPU readback. Keep the decoder sample until the GPU event confirms consumption.
HRESULT receive(Presenter& p, uint64_t* pts, uint64_t* qpc, uint32_t* submitted,uint32_t* converted) {
    if (p.pending) {
        const HRESULT ready=p.context->GetData(p.completion.Get(),nullptr,0,D3D11_ASYNC_GETDATA_DONOTFLUSH);
        if (ready==S_FALSE) return S_FALSE;
        if (FAILED(ready)) return ready;
        p.pending.Reset();
    }
    HRESULT hr=S_OK;
    // Retire the decoded picture before asking the decoder for another surface.
    // Giving ProcessOutput priority under continuous input retained the entire
    // DXVA surface pool without ever reaching presentation. ProcessOutput could
    // then block waiting for one of the very samples held here. Keep at most one
    // ready output; its scheduled due time and GPU-consumption fence still apply.
    if (!p.ready_count && p.time_size) {
    MFT_OUTPUT_STREAM_INFO info{};
    hr=p.decoder->GetOutputStreamInfo(0,&info); if (FAILED(hr)) return hr;
    // DXVA decoders supply GPU samples; CPU allocation is not a GPU path.
    if (!(info.dwFlags&(MFT_OUTPUT_STREAM_PROVIDES_SAMPLES|MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES))) return MF_E_UNSUPPORTED_D3D_TYPE;
    MFT_OUTPUT_DATA_BUFFER data{}; DWORD status=0;
    trace(p.surface,"decoder_process_output_begin");
    hr=p.decoder->ProcessOutput(0,1,&data,&status);
    trace(p.surface,"decoder_process_output_end");
    trace_result(p.surface,"decoder_process_output",hr);
    if (data.pEvents) data.pEvents->Release();
    auto& received=p.ready[(p.time_head+p.ready_count)%p.ready.size()];
    received.Attach(data.pSample);
    if (hr==MF_E_TRANSFORM_NEED_MORE_INPUT) {received.Reset();goto present_ready;}
    if (hr==MF_E_TRANSFORM_STREAM_CHANGE) {
        received.Reset();trace(p.surface,"stream_change_output_type_begin");
        hr=output_type(p);trace_result(p.surface,"stream_change_output_type",hr);
        if(SUCCEEDED(hr))hr=configure_processor(p,p.fps);
        return FAILED(hr)?hr:S_FALSE;
    }
    if (FAILED(hr)) {received.Reset();return hr;}
    if (!received) return E_UNEXPECTED;
    LONGLONG received_time=0; hr=received->GetSampleTime(&received_time);
    if (FAILED(hr) || received_time<0) return E_UNEXPECTED;
    const auto value=static_cast<uint64_t>(received_time);
    const auto received_pts=value/1000*9+(value%1000*9+500)/1000;
    if (p.times[(p.time_head+p.ready_count)%p.times.size()].pts!=received_pts) return E_UNEXPECTED;
    ++p.ready_count; ++p.decoded_outputs;
    if (p.ready_count>p.ready_high_water) p.ready_high_water=p.ready_count;
    *pts=received_pts;
    return 2; // Actual MF output receipt, once, independent of presentation timing.
    }
present_ready:
    if (!p.ready_count) return S_FALSE;
    auto sample=p.ready[p.time_head];
    if (!sample) return E_UNEXPECTED;
    ComPtr<IMFMediaType> actual_type;
    hr=p.decoder->GetOutputCurrentType(0,&actual_type); if (FAILED(hr)) return hr;
    trace(p.surface,"decoded_output_color_validate_begin");
    hr=sdr_type(p,actual_type.Get(),false); if (FAILED(hr)) return hr;
    GpuOutputGeometry geometry{};
    hr=output_geometry(actual_type.Get(),p.width,p.height,p.input_geometry_bound?&p.input_geometry:nullptr,&geometry);
    if(FAILED(hr) || !(geometry==p.output_geometry))return MF_E_INVALIDMEDIATYPE;
    trace(p.surface,"decoded_output_color_validate_end");
    LONGLONG time=0; hr=sample->GetSampleTime(&time);
    if (FAILED(hr) || time<0) return E_UNEXPECTED;
    const auto actual_pts=static_cast<uint64_t>(time)/1000*9+(static_cast<uint64_t>(time)%1000*9+500)/1000;
    if (!p.time_size || p.times[p.time_head].pts!=actual_pts) return E_UNEXPECTED;
    const auto timing=p.times[p.time_head];
    LARGE_INTEGER now{}; QueryPerformanceCounter(&now);
    const auto ticks=static_cast<uint64_t>(now.QuadPart);
    if (timing.due && ticks<timing.due) return S_FALSE;
    p.ready[p.time_head].Reset(); --p.ready_count; ++p.retired_pictures;
    p.time_head=(p.time_head+1)%p.times.size(); --p.time_size;
    *pts=actual_pts; *qpc=ticks;
    if (timing.expires && ticks>timing.expires) return S_OK; // decoded, deliberately not presented
    if (!p.surface->authorized) return S_OK; // hidden overlay: decode references, no presentation
    ComPtr<IMFMediaBuffer> buffer; ComPtr<IMFDXGIBuffer> gpu;
    hr=sample->GetBufferByIndex(0,&buffer); if (FAILED(hr)) return hr;
    hr=buffer.As(&gpu); if (FAILED(hr)) return MF_E_UNSUPPORTED_D3D_TYPE;
    ComPtr<ID3D11Texture2D> texture; UINT sub=0;
    hr=gpu->GetResource(IID_PPV_ARGS(&texture)); if (FAILED(hr)) return hr;
    hr=gpu->GetSubresourceIndex(&sub); if (FAILED(hr)) return hr;
    D3D11_TEXTURE2D_DESC desc{}; texture->GetDesc(&desc);
    ComPtr<ID3D11Device> source_device; texture->GetDevice(&source_device);
    if (source_device.Get()!=p.device.Get() || desc.Format!=DXGI_FORMAT_NV12 ||
        desc.Width<geometry.width || desc.Height<geometry.height || desc.Width>p.width+255 || desc.Height>p.height+31 ||
        ((desc.Width|desc.Height)&1) || static_cast<uint64_t>(desc.Width)*desc.Height*4>65*1024*1024 ||
        desc.MipLevels!=1 || desc.SampleDesc.Count!=1 || desc.SampleDesc.Quality || sub>=desc.ArraySize) return MF_E_INVALIDMEDIATYPE;
    D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC in{};
    in.ViewDimension=D3D11_VPIV_DIMENSION_TEXTURE2D; in.Texture2D.ArraySlice=sub;
    ComPtr<ID3D11VideoProcessorInputView> input;
    hr=p.video->CreateVideoProcessorInputView(texture.Get(),p.enumerator.Get(),&in,&input);
    if (FAILED(hr)) return hr;
    ComPtr<ID3D11Texture2D> back; hr=p.swap->GetBuffer(0,IID_PPV_ARGS(&back)); if (FAILED(hr)) return hr;
    D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC out{}; out.ViewDimension=D3D11_VPOV_DIMENSION_TEXTURE2D;
    ComPtr<ID3D11VideoProcessorOutputView> output;
    hr=p.video->CreateVideoProcessorOutputView(back.Get(),p.enumerator.Get(),&out,&output); if (FAILED(hr)) return hr;
    RECT rect{0,0,static_cast<LONG>(p.width),static_cast<LONG>(p.height)};
    RECT source_rect{static_cast<LONG>(geometry.left),static_cast<LONG>(geometry.top),
        static_cast<LONG>(geometry.left+p.width),static_cast<LONG>(geometry.top+p.height)};
    p.video_context->VideoProcessorSetStreamSourceRect(p.processor.Get(),0,TRUE,&source_rect);
    p.video_context->VideoProcessorSetStreamDestRect(p.processor.Get(),0,TRUE,&rect);
    p.video_context->VideoProcessorSetOutputTargetRect(p.processor.Get(),TRUE,&rect);
    p.video_context->VideoProcessorSetStreamFrameFormat(p.processor.Get(),0,D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
    // Configuration is SDR BT.709 limited only; other color is rejected above.
    D3D11_VIDEO_PROCESSOR_COLOR_SPACE color{}; color.YCbCr_Matrix=1;
    color.Nominal_Range=D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235;
    p.video_context->VideoProcessorSetStreamColorSpace(p.processor.Get(),0,&color);
    D3D11_VIDEO_PROCESSOR_COLOR_SPACE rgb{}; rgb.RGB_Range=0;
    rgb.Nominal_Range=D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_0_255;
    p.video_context->VideoProcessorSetOutputColorSpace(p.processor.Get(),&rgb);
    D3D11_VIDEO_PROCESSOR_STREAM stream{}; stream.Enable=TRUE; stream.pInputSurface=input.Get();
    if (!authorized(p)) return E_ABORT;
    trace(p.surface,"video_processor_blt_begin");
    hr=p.video_context->VideoProcessorBlt(p.processor.Get(),output.Get(),0,1,&stream);
    if (FAILED(hr)) return hr;
    *converted=1;
    if(p.probe_color_enabled) {
        if(!p.surface->probe_parent)return E_ACCESSDENIED;
        if(!p.probe_staging) {
            D3D11_TEXTURE2D_DESC staging{};back->GetDesc(&staging);
            staging.Usage=D3D11_USAGE_STAGING;staging.BindFlags=0;staging.MiscFlags=0;staging.CPUAccessFlags=D3D11_CPU_ACCESS_READ;
            hr=p.device->CreateTexture2D(&staging,nullptr,&p.probe_staging);if(FAILED(hr))return hr;
        }
        p.context->CopyResource(p.probe_staging.Get(),back.Get());p.context->Flush();
        D3D11_MAPPED_SUBRESOURCE mapped{};const ULONGLONG deadline=GetTickCount64()+50;
        do { hr=p.context->Map(p.probe_staging.Get(),0,D3D11_MAP_READ,D3D11_MAP_FLAG_DO_NOT_WAIT,&mapped);
            if(hr==DXGI_ERROR_WAS_STILL_DRAWING)Sleep(1);
        } while(hr==DXGI_ERROR_WAS_STILL_DRAWING && GetTickCount64()<deadline);
        if(FAILED(hr))return hr;
        bool valid=mapped.pData && mapped.RowPitch>=p.width*4;
        if(valid)for(UINT y=0;y<p.height && valid;++y) {
            const auto* row=static_cast<const uint8_t*>(mapped.pData)+static_cast<size_t>(y)*mapped.RowPitch;
            for(UINT x=0;x<p.width && valid;++x)for(UINT channel=0;channel<4;++channel) {
                const int delta=static_cast<int>(row[x*4+channel])-p.probe_expected[channel];
                const int tolerance=channel==3?0:static_cast<int>(p.probe_tolerance);
                if(delta < -tolerance || delta>tolerance)valid=false;
            }
        }
        p.context->Unmap(p.probe_staging.Get(),0);
        if(!valid)return MF_E_INVALIDMEDIATYPE;
        ++p.probe_colors;
    }
    p.pending=sample; p.context->End(p.completion.Get()); p.context->Flush();
    if (!authorized(p)) return E_ABORT;
    trace(p.surface,"swapchain_present_begin");
    hr=p.swap->Present(0,DXGI_PRESENT_DO_NOT_WAIT);
    trace(p.surface,"swapchain_present_end");
    *submitted=(hr==S_OK)?1u:0u;
    if (FAILED(hr) && hr!=DXGI_ERROR_WAS_STILL_DRAWING) return hr;
    QueryPerformanceCounter(&now); *qpc=static_cast<uint64_t>(now.QuadPart);
    return S_OK;
}
#include "shared_import_presenter.h"
}
extern "C" int32_t nl_gpu_surface_discover(uint64_t key, uint32_t screen_width, uint32_t screen_height, void** result) noexcept {
    if (!result) return E_POINTER; *result=nullptr;
    if (!wglGetCurrentContext()) return E_NOTIMPL;
    HWND parent=WindowFromDC(wglGetCurrentDC()); DWORD process=0;
    if (!parent || GetWindowThreadProcessId(parent,&process)!=GetCurrentThreadId() || process!=GetCurrentProcessId()) return E_INVALIDARG;
    RECT bounds{};
    if (!GetClientRect(parent,&bounds) || bounds.right!=static_cast<LONG>(screen_width) || bounds.bottom!=static_cast<LONG>(screen_height)) return E_INVALIDARG;
    WNDCLASSW klass{}; klass.lpfnWndProc=child_proc; klass.hInstance=GetModuleHandleW(nullptr); klass.lpszClassName=L"NestLinkGpuVideoChild";
    klass.hbrBackground=static_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    if (!RegisterClassW(&klass) && GetLastError()!=ERROR_CLASS_ALREADY_EXISTS) return HRESULT_FROM_WIN32(GetLastError());
    auto* s=new(std::nothrow) Surface(); if (!s) return E_OUTOFMEMORY;
    s->parent=parent; s->key=key;
    const LONG_PTR style=GetWindowLongPtrW(parent,GWL_STYLE);
    if (!(style&WS_CLIPCHILDREN)) {
        SetLastError(0);
        if (!SetWindowLongPtrW(parent,GWL_STYLE,style|WS_CLIPCHILDREN) && GetLastError()) {delete s;return E_FAIL;}
        s->clip_added=true;
    }
    s->child=CreateWindowExW(WS_EX_NOACTIVATE,klass.lpszClassName,L"",WS_CHILD|WS_CLIPSIBLINGS,
        0,0,1,1,parent,nullptr,klass.hInstance,nullptr);
    if (!s->child) { const auto error=HRESULT_FROM_WIN32(GetLastError());if (s->clip_added) SetWindowLongPtrW(parent,GWL_STYLE,style);delete s;return error; }
    if (!SetWindowSubclass(parent,parent_proc,reinterpret_cast<UINT_PTR>(s),reinterpret_cast<DWORD_PTR>(s))) {
        DestroyWindow(s->child);if (s->clip_added) SetWindowLongPtrW(parent,GWL_STYLE,style);delete s;return E_FAIL;
    }
    ++s->references; *result=s; return S_OK;
}
extern "C" int32_t nl_gpu_surface_place(void* handle, int32_t x, int32_t y, uint32_t width, uint32_t height, uint32_t visible) noexcept {
    auto* s=static_cast<Surface*>(handle);
    if (!s || s->thread!=GetCurrentThreadId() || !s->live) return E_ABORT;
    if (!visible) { s->authorized=false;ShowWindow(s->child,SW_HIDE); return S_OK; }
    LARGE_INTEGER now{};QueryPerformanceCounter(&now);
    const auto expires=s->expires.load();
    if (!expires || static_cast<uint64_t>(now.QuadPart)>=expires) {
        s->authorized=false;ShowWindow(s->child,SW_HIDE);return E_ABORT;
    }
    if (!width || !height || width>32768 || height>32768) return E_INVALIDARG;
    const BOOL placed=SetWindowPos(s->child,nullptr,x,y,static_cast<int>(width),static_cast<int>(height),
        SWP_NOACTIVATE|SWP_NOZORDER|SWP_SHOWWINDOW);
    s->authorized=placed!=FALSE;
    if (!placed) ShowWindow(s->child,SW_HIDE);
    return placed?S_OK:E_FAIL;
}
extern "C" void nl_gpu_surface_revoke(void* handle) noexcept {
    auto* s=static_cast<Surface*>(handle); if (!s) return; s->authorized=false;
    if (s->thread==GetCurrentThreadId() && s->live && s->child) ShowWindow(s->child,SW_HIDE);
}
extern "C" void nl_gpu_surface_deadline(void* handle, uint64_t deadline) noexcept {
    auto* s=static_cast<Surface*>(handle); if (s) s->expires=deadline;
}
extern "C" void nl_gpu_surface_detach(void* handle) noexcept {
    auto* s=static_cast<Surface*>(handle);
    if (!s || s->thread!=GetCurrentThreadId() || !s->live.exchange(false)) return;
    s->authorized=false;
    RemoveWindowSubclass(s->parent,parent_proc,reinterpret_cast<UINT_PTR>(s));
    if (s->child) { ShowWindow(s->child,SW_HIDE); DestroyWindow(s->child); s->child=nullptr; }
    if (s->clip_added) SetWindowLongPtrW(s->parent,GWL_STYLE,GetWindowLongPtrW(s->parent,GWL_STYLE)&~static_cast<LONG_PTR>(WS_CLIPCHILDREN));
    if (s->probe_parent) {
        wglMakeCurrent(nullptr,nullptr);
        if (s->probe_gl) wglDeleteContext(s->probe_gl);
        if (s->probe_dc) ReleaseDC(s->parent,s->probe_dc);
        DestroyWindow(s->parent);
    }
    release(s); // subclass reference
}
extern "C" int32_t nl_gpu_probe_surface(uint32_t width,uint32_t height,void** result) noexcept {
    if (!result || !width || !height || width>8192 || height>8192) return E_INVALIDARG;
    *result=nullptr;
    WNDCLASSW klass{}; klass.style=CS_OWNDC; klass.lpfnWndProc=DefWindowProcW;
    klass.hInstance=GetModuleHandleW(nullptr); klass.lpszClassName=L"NestLinkGpuProbe";
    if (!RegisterClassW(&klass) && GetLastError()!=ERROR_CLASS_ALREADY_EXISTS) return HRESULT_FROM_WIN32(GetLastError());
    HWND window=CreateWindowExW(WS_EX_NOACTIVATE,klass.lpszClassName,L"NestLink GPU probe",WS_POPUP,0,0,
        static_cast<int>(width),static_cast<int>(height),nullptr,nullptr,klass.hInstance,nullptr);
    if (!window) return E_FAIL;
    HDC dc=GetDC(window);
    PIXELFORMATDESCRIPTOR pixel{}; pixel.nSize=static_cast<WORD>(sizeof(pixel)); pixel.nVersion=1;
    pixel.dwFlags=PFD_DRAW_TO_WINDOW|PFD_SUPPORT_OPENGL|PFD_DOUBLEBUFFER;
    pixel.iPixelType=PFD_TYPE_RGBA; pixel.cColorBits=32;
    const int format=dc?ChoosePixelFormat(dc,&pixel):0;
    HGLRC gl=nullptr;
    if (format && SetPixelFormat(dc,format,&pixel)) gl=wglCreateContext(dc);
    HRESULT hr=E_NOTIMPL;
    if (gl && wglMakeCurrent(dc,gl)) hr=nl_gpu_surface_discover(1,width,height,result);
    if (FAILED(hr)) {
        wglMakeCurrent(nullptr,nullptr); if (gl) wglDeleteContext(gl);
        if (dc) ReleaseDC(window,dc); DestroyWindow(window); return hr;
    }
    auto* s=static_cast<Surface*>(*result); s->probe_parent=true;s->probe_dc=dc;s->probe_gl=gl;
    s->expires=UINT64_MAX;
    ShowWindow(window,SW_SHOWNOACTIVATE);
    return S_OK;
}
extern "C" void nl_gpu_surface_release(void* handle) noexcept { release(static_cast<Surface*>(handle)); }
static int32_t open_presenter(void* surface, uint32_t width, uint32_t height, uint32_t fps, uint32_t kbps, bool hevc, void** result) noexcept {
    if (!result) return E_POINTER; *result=nullptr;
    if(kbps<64 || kbps>100000)return E_INVALIDARG;
    auto* s=static_cast<Surface*>(surface);
    if (!s || !s->live || !width || !height || ((width|height)&1) || width>8192 || height>8192 ||
        static_cast<uint64_t>(width)*height*4>64*1024*1024 || !fps || fps>(hevc?144u:120u)) return E_INVALIDARG;
    bool probe_reserved=false;
    if(s->probe_parent) {
        bool expected=false;
        if(!nl_gpu_probe_owner_reserved.compare_exchange_strong(expected,true))return HRESULT_FROM_WIN32(ERROR_BUSY);
        probe_reserved=true;
    }
    std::unique_ptr<Presenter> p(new(std::nothrow) Presenter());
    if(!p) { if(probe_reserved)nl_gpu_probe_owner_reserved.store(false);return E_OUTOFMEMORY; }
    p->probe_owner_reserved=probe_reserved;p->hevc=hevc;
    ++s->references; p->surface=s; p->width=width; p->height=height;
    trace(s,"com_initialize_begin");
    HRESULT hr=CoInitializeEx(nullptr,COINIT_MULTITHREADED); if (FAILED(hr)) return hr; p->com=true;
    trace(s,"mf_startup_begin");
    hr=MFStartup(MF_VERSION,MFSTARTUP_NOSOCKET); if (FAILED(hr)) return hr; p->mf=true;
    trace(s,"configure_begin");
    hr=configure(*p,fps,kbps); if (FAILED(hr)) return hr;
    trace(s,"open_end");
    *result=p.release(); return S_OK;
}
extern "C" int32_t nl_gpu_open(void* surface, uint32_t width, uint32_t height, uint32_t fps, uint32_t kbps, void** result) noexcept {
    return open_presenter(surface,width,height,fps,kbps,false,result);
}
extern "C" int32_t nl_gpu_open_hevc(void* surface, uint32_t width, uint32_t height, uint32_t fps, uint32_t kbps, void** result) noexcept {
    if(!result)return E_POINTER;*result=nullptr;
    if((width|height)&7)return E_INVALIDARG;
    return open_presenter(surface,width,height,fps,kbps,true,result);
}
extern "C" int32_t nl_gpu_input_geometry(void* handle,const GpuInputGeometry* geometry) noexcept {
    auto* p=static_cast<Presenter*>(handle);
    if(!p || !geometry || p->thread!=GetCurrentThreadId())return E_INVALIDARG;
    if(!valid_input_geometry(*geometry,p->width,p->height,p->hevc) ||
        (p->input_geometry_bound && !same_geometry(p->input_geometry,*geometry)))return MF_E_INVALIDMEDIATYPE;
    p->input_geometry=*geometry;p->input_geometry_bound=true;return S_OK;
}
extern "C" int32_t nl_gpu_step(void* handle, const uint8_t* bytes, size_t length, uint64_t pts, uint64_t due, uint64_t expires,
    uint32_t* accepted, uint64_t* output_pts, uint64_t* qpc, uint32_t* submitted,uint32_t* converted) noexcept {
    auto* p=static_cast<Presenter*>(handle);
    if (!p || p->thread!=GetCurrentThreadId() || !accepted || !output_pts || !qpc || !submitted || !converted) return E_INVALIDARG;
    *accepted=0; *submitted=0;*converted=0;
    if (!authorized(*p)) return E_ABORT;
    if (length && p->time_size<p->times.size()) {
        if (!bytes || !p->input_geometry_bound || length>8*1024*1024 || pts>static_cast<uint64_t>(INT64_MAX)/1000) return E_INVALIDARG;
        ComPtr<IMFMediaBuffer> buffer; ComPtr<IMFSample> sample;
        HRESULT hr=MFCreateMemoryBuffer(static_cast<DWORD>(length),&buffer); if (FAILED(hr)) return hr;
        BYTE* dest=nullptr; hr=buffer->Lock(&dest,nullptr,nullptr); if (FAILED(hr)) return hr;
        std::memcpy(dest,bytes,length); buffer->Unlock(); buffer->SetCurrentLength(static_cast<DWORD>(length));
        hr=MFCreateSample(&sample); if (FAILED(hr)) return hr;
        sample->AddBuffer(buffer.Get()); sample->SetSampleTime(static_cast<LONGLONG>(pts*1000/9));
        trace(p->surface,"decoder_process_input_begin");
        hr=p->decoder->ProcessInput(0,sample.Get(),0);
        trace(p->surface,"decoder_process_input_end");
        if (SUCCEEDED(hr)) {
            *accepted=1; p->times[(p->time_head+p->time_size)%p->times.size()]={pts,due,expires}; ++p->time_size;
        }
        else if (hr!=MF_E_NOTACCEPTING) return hr;
    }
    return receive(*p,output_pts,qpc,submitted,converted);
}
// Metadata-only regression cases use the same IMFMediaType reader as the live
// owner. They open no window, GPU device, decoder or capture resource.
extern "C" uint32_t nl_gpu_output_geometry_contract() noexcept {
    const HRESULT com=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    if(FAILED(com))return 0;
    if(FAILED(MFStartup(MF_VERSION,MFSTARTUP_NOSOCKET))){CoUninitialize();return 0;}
    uint32_t passed=0;
    {
        GpuInputGeometry sps{1920,1088,{0,0,0,8}};
        const auto type=[](UINT width,UINT height,ComPtr<IMFMediaType>& value)->HRESULT {
            HRESULT hr=MFCreateMediaType(&value);
            return FAILED(hr)?hr:MFSetAttributeSize(value.Get(),MF_MT_FRAME_SIZE,width,height);
        };
        const auto aperture=[](IMFMediaType* value,int top,WORD fraction,UINT width,UINT height)->HRESULT {
            MFVideoArea area{};area.OffsetY.value=static_cast<short>(top);area.OffsetY.fract=fraction;
            area.Area.cx=static_cast<LONG>(width);area.Area.cy=static_cast<LONG>(height);
            return value->SetBlob(MF_MT_MINIMUM_DISPLAY_APERTURE,reinterpret_cast<const UINT8*>(&area),static_cast<UINT32>(sizeof(area)));
        };
        ComPtr<IMFMediaType> visible,padded,foreign;
        GpuOutputGeometry actual{};
        if(SUCCEEDED(type(1920,1080,visible)) &&
            SUCCEEDED(output_geometry(visible.Get(),1920,1080,nullptr,&actual)) &&
            actual.width==1920 && actual.height==1080 && !actual.left && !actual.top)passed|=1;
        if(SUCCEEDED(type(1920,1088,padded)) &&
            FAILED(output_geometry(padded.Get(),1920,1080,&sps,&actual)))passed|=4;
        if(padded && SUCCEEDED(aperture(padded.Get(),0,0,1920,1080))) {
            if(SUCCEEDED(output_geometry(padded.Get(),1920,1080,&sps,&actual)) &&
                actual.width==1920 && actual.height==1088 && !actual.left && !actual.top)passed|=2;
            if(FAILED(output_geometry(padded.Get(),1920,1080,nullptr,&actual)))passed|=8;
            if(SUCCEEDED(type(1920,1096,foreign)) && SUCCEEDED(aperture(foreign.Get(),0,0,1920,1080)) &&
                FAILED(output_geometry(foreign.Get(),1920,1080,&sps,&actual)))passed|=16;
            bool conflicts=SUCCEEDED(aperture(padded.Get(),4,0,1920,1080)) &&
                FAILED(output_geometry(padded.Get(),1920,1080,&sps,&actual));
            conflicts=conflicts && SUCCEEDED(aperture(padded.Get(),0,1,1920,1080)) &&
                FAILED(output_geometry(padded.Get(),1920,1080,&sps,&actual));
            conflicts=conflicts && SUCCEEDED(aperture(padded.Get(),0,0,1920,1072)) &&
                FAILED(output_geometry(padded.Get(),1920,1080,&sps,&actual));
            const UINT8 malformed=0;
            conflicts=conflicts && SUCCEEDED(padded->SetBlob(MF_MT_MINIMUM_DISPLAY_APERTURE,&malformed,1)) &&
                FAILED(output_geometry(padded.Get(),1920,1080,&sps,&actual));
            if(conflicts)passed|=32;
            GpuInputGeometry centered{1920,1088,{0,0,4,4}};
            if(SUCCEEDED(aperture(padded.Get(),4,0,1920,1080)) &&
                valid_input_geometry(centered,1920,1080,false) &&
                SUCCEEDED(output_geometry(padded.Get(),1920,1080,&centered,&actual)) && actual.top==4)passed|=128;
        }
        if(visible && SUCCEEDED(output_geometry(visible.Get(),1920,1080,&sps,&actual)))passed|=64;
    }
    MFShutdown();CoUninitialize();return passed;
}
extern "C" int32_t nl_gpu_owner_observation(void* handle,NlOwnerObservation* out) noexcept {
    auto* p=static_cast<Presenter*>(handle);
    if(!p || !out || p->thread!=GetCurrentThreadId())return E_INVALIDARG;
    return nl_observe_owner(p->device.Get(),p->decoded_outputs>0 && p->retired_pictures>0,p->observation_id,p->observation_initialized,out);
}
extern "C" int32_t nl_gpu_probe_color(void* handle,const uint8_t* expected,uint32_t tolerance) noexcept {
    auto* p=static_cast<Presenter*>(handle);
    if(!p || !expected || p->thread!=GetCurrentThreadId() || !p->surface->probe_parent || p->decoded_outputs || tolerance>64)return E_INVALIDARG;
    std::memcpy(p->probe_expected.data(),expected,4);p->probe_tolerance=tolerance;p->probe_color_enabled=true;return S_OK;
}
extern "C" int32_t nl_gpu_probe_color_count(void* handle,uint64_t* count) noexcept {
    auto* p=static_cast<Presenter*>(handle);
    if(!p || !count || p->thread!=GetCurrentThreadId() || !p->surface->probe_parent || !p->probe_color_enabled)return E_INVALIDARG;
    *count=p->probe_colors;return S_OK;
}
extern "C" int32_t nl_gpu_close_checked(void* handle) noexcept {
    auto* p=static_cast<Presenter*>(handle);if(!p || p->thread!=GetCurrentThreadId())return E_INVALIDARG;
    // Preserve the existing live-owner teardown; checked completion is probe-only.
    if(!p->probe_owner_reserved) { delete p;return S_OK; }
    if(p->pending && p->completion && p->context) {
        const ULONGLONG deadline=GetTickCount64()+50;HRESULT hr=S_FALSE;p->context->Flush();
        do { hr=p->context->GetData(p->completion.Get(),nullptr,0,D3D11_ASYNC_GETDATA_DONOTFLUSH);if(hr==S_FALSE)Sleep(1); }
        while(hr==S_FALSE && GetTickCount64()<deadline);
        if(hr!=S_OK) { return FAILED(hr)?hr:HRESULT_FROM_WIN32(WAIT_TIMEOUT); }
    }
    HRESULT result=S_OK;
    if(p->decoder) {
        result=p->decoder->ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH,0);
        const HRESULT end=p->decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING,0);
        if(SUCCEEDED(result) && FAILED(end))result=end;
        p->checked_shutdown=true;
    }
    delete p;return result;
}
extern "C" int32_t nl_gpu_shared_open(void* surface,const NlSharedRingDescriptor* ring,uint32_t fps,uint64_t driver,void** result) noexcept {
    auto* target=static_cast<Surface*>(surface);
    if(!target || !target->live || !ring || !result || !ring->width || !ring->height || ring->width>8192 || ring->height>8192 ||
        ((ring->width|ring->height)&1) || !fps || fps>144 || !driver)return E_INVALIDARG;
    *result=nullptr;
    std::unique_ptr<SharedPresenter> owner(new(std::nothrow)SharedPresenter());if(!owner)return E_OUTOFMEMORY;
    const HRESULT hr=owner->initialize(target,*ring,fps,driver);if(FAILED(hr))return hr;
    *result=owner.release();return S_OK;
}
extern "C" int32_t nl_gpu_shared_consume(void* handle,const NlSharedFrame* frame,uint64_t deadline,uint64_t* qpc,uint32_t* consumed,uint32_t* converted,uint32_t* submitted) noexcept {
    auto* owner=static_cast<SharedPresenter*>(handle);
    if(!owner || !frame || !qpc || !consumed || !converted || !submitted)return E_INVALIDARG;
    *qpc=0;*consumed=0;*converted=0;*submitted=0;
    return owner->consume(*frame,deadline,qpc,consumed,converted,submitted);
}
extern "C" int32_t nl_gpu_shared_close(void* handle) noexcept {
    auto* owner=static_cast<SharedPresenter*>(handle);if(!owner || owner->output.thread!=GetCurrentThreadId())return E_INVALIDARG;
    delete owner;return S_OK;
}
extern "C" int32_t nl_gpu_shared_check(void* handle) noexcept {
    auto* owner=static_cast<SharedPresenter*>(handle);
    if(!owner || owner->failed || owner->output.thread!=GetCurrentThreadId())return E_INVALIDARG;
    if(!hdr_display_current(owner->output)){owner->failed=true;black(owner->output);return DXGI_ERROR_ACCESS_LOST;}
    return owner->output.device->GetDeviceRemovedReason();
}
