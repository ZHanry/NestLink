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
#include <d3d10.h>
#include <dxgi1_2.h>
#include <wrl/client.h>
#include <atomic>
#include <memory>
#include <new>
#include <cstdint>
#include <cstring>
#include <array>
#include <cstdio>
#include "owner_observation.h"
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
std::atomic<bool> nl_gpu_probe_owner_reserved{false};
struct Presenter {
    bool probe_owner_reserved=false; bool checked_shutdown=false;
    GUID observation_id{}; bool observation_initialized=false;
    bool probe_color_enabled=false; std::array<uint8_t,4> probe_expected{}; uint32_t probe_tolerance=0;
    uint64_t probe_colors=0;
    ComPtr<ID3D11Texture2D> probe_staging;
    Surface* surface=nullptr;
    DWORD thread=GetCurrentThreadId();
    bool com=false, mf=false;
    UINT width=0,height=0;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IMFDXGIDeviceManager> manager;
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
bool authorized(Presenter& p) {
    LARGE_INTEGER now{}; QueryPerformanceCounter(&now);
    const auto expires=p.surface->expires.load();
    if (p.surface->live && expires && static_cast<uint64_t>(now.QuadPart)<expires) return true;
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
        if (FAILED(hr)) return hr;
        GUID sub{};
        if (FAILED(t->GetGUID(MF_MT_SUBTYPE,&sub)) || sub!=MFVideoFormat_NV12) continue;
        UINT32 w=0,h=0;
        if (FAILED(MFGetAttributeSize(t.Get(),MF_MT_FRAME_SIZE,&w,&h)) || w!=p.width || h!=p.height) continue;
        MFVideoArea area{}; UINT32 actual=0;
        if (SUCCEEDED(t->GetBlob(MF_MT_MINIMUM_DISPLAY_APERTURE,reinterpret_cast<UINT8*>(&area),static_cast<UINT32>(sizeof(area)),&actual)) &&
            (actual!=sizeof(area) || area.OffsetX.value || area.OffsetX.fract || area.OffsetY.value || area.OffsetY.fract ||
             area.Area.cx!=static_cast<LONG>(p.width) || area.Area.cy!=static_cast<LONG>(p.height))) return MF_E_INVALIDMEDIATYPE;
        hr=sdr_type(p,t.Get(),true); if (FAILED(hr)) return hr;
        return p.decoder->SetOutputType(0,t.Get(),0);
    }
    return MF_E_INVALIDMEDIATYPE;
}
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
    MFT_REGISTER_TYPE_INFO input{MFMediaType_Video,MFVideoFormat_H264};
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
    type->SetGUID(MF_MT_SUBTYPE,MFVideoFormat_H264);
    type->SetUINT32(MF_MT_INTERLACE_MODE,MFVideoInterlace_Progressive);
    MFSetAttributeSize(type.Get(),MF_MT_FRAME_SIZE,p.width,p.height);
    MFSetAttributeRatio(type.Get(),MF_MT_FRAME_RATE,fps,1);
    hr=type->SetUINT32(MF_MT_AVG_BITRATE,kbps*1000);if(FAILED(hr))return hr;
    hr=sdr_type(p,type.Get(),true); if (FAILED(hr)) return hr;
    trace(p.surface,"decoder_set_input_type_begin");
    hr=p.decoder->SetInputType(0,type.Get(),0); if (FAILED(hr)) return hr;
    trace(p.surface,"decoder_output_type_begin");
    hr=output_type(p); if (FAILED(hr)) return hr;
    ComPtr<IDXGIDevice> dxgi; ComPtr<IDXGIAdapter> adapter; ComPtr<IDXGIFactory2> factory;
    hr=p.device.As(&dxgi); if (FAILED(hr)) return hr;
    hr=dxgi->GetAdapter(&adapter); if (FAILED(hr)) return hr;
    hr=adapter->GetParent(IID_PPV_ARGS(&factory)); if (FAILED(hr)) return hr;
    DXGI_SWAP_CHAIN_DESC1 desc{};
    desc.Width=p.width; desc.Height=p.height; desc.Format=DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc.Count=1; desc.BufferUsage=DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.BufferCount=2; desc.SwapEffect=DXGI_SWAP_EFFECT_FLIP_SEQUENTIAL;
    trace(p.surface,"swapchain_create_begin");
    hr=factory->CreateSwapChainForHwnd(p.device.Get(),p.surface->child.load(),&desc,nullptr,nullptr,&p.swap);
    if (FAILED(hr)) return hr;
    black(p);
    factory->MakeWindowAssociation(p.surface->child.load(),DXGI_MWA_NO_ALT_ENTER);
    D3D11_VIDEO_PROCESSOR_CONTENT_DESC content{};
    content.InputFrameFormat=D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE;
    content.InputWidth=p.width; content.InputHeight=p.height;
    content.OutputWidth=p.width; content.OutputHeight=p.height;
    content.InputFrameRate={fps,1}; content.OutputFrameRate={fps,1};
    content.Usage=D3D11_VIDEO_USAGE_PLAYBACK_NORMAL;
    trace(p.surface,"video_processor_create_begin");
    hr=p.video->CreateVideoProcessorEnumerator(&content,&p.enumerator); if (FAILED(hr)) return hr;
    UINT flags=0;
    hr=p.enumerator->CheckVideoProcessorFormat(DXGI_FORMAT_NV12,&flags);
    if (FAILED(hr) || !(flags&D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_INPUT)) return E_NOTIMPL;
    hr=p.enumerator->CheckVideoProcessorFormat(desc.Format,&flags);
    if (FAILED(hr) || !(flags&D3D11_VIDEO_PROCESSOR_FORMAT_SUPPORT_OUTPUT)) return E_NOTIMPL;
    hr=p.video->CreateVideoProcessor(p.enumerator.Get(),0,&p.processor); if (FAILED(hr)) return hr;
    D3D11_QUERY_DESC query{D3D11_QUERY_EVENT,0};
    hr=p.device->CreateQuery(&query,&p.completion); if (FAILED(hr)) return hr;
    trace(p.surface,"decoder_begin_streaming_begin");
    hr=p.decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,0); if (FAILED(hr)) return hr;
    return p.decoder->ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM,0);
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
    if (data.pEvents) data.pEvents->Release();
    auto& received=p.ready[(p.time_head+p.ready_count)%p.ready.size()];
    received.Attach(data.pSample);
    if (hr==MF_E_TRANSFORM_NEED_MORE_INPUT) {received.Reset();goto present_ready;}
    if (hr==MF_E_TRANSFORM_STREAM_CHANGE) { received.Reset();hr=output_type(p); return FAILED(hr)?hr:S_FALSE; }
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
        desc.Width<p.width || desc.Height<p.height || desc.Width>p.width+255 || desc.Height>p.height+31 ||
        desc.MipLevels!=1 || sub>=desc.ArraySize) return MF_E_INVALIDMEDIATYPE;
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
    p.video_context->VideoProcessorSetStreamSourceRect(p.processor.Get(),0,TRUE,&rect);
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
extern "C" int32_t nl_gpu_open(void* surface, uint32_t width, uint32_t height, uint32_t fps, uint32_t kbps, void** result) noexcept {
    if (!result) return E_POINTER; *result=nullptr;
    if(kbps<64 || kbps>100000)return E_INVALIDARG;
    auto* s=static_cast<Surface*>(surface);
    if (!s || !s->live || !width || !height || ((width|height)&1) || width>8192 || height>8192 ||
        static_cast<uint64_t>(width)*height*4>64*1024*1024 || !fps || fps>120) return E_INVALIDARG;
    bool probe_reserved=false;
    if(s->probe_parent) {
        bool expected=false;
        if(!nl_gpu_probe_owner_reserved.compare_exchange_strong(expected,true))return HRESULT_FROM_WIN32(ERROR_BUSY);
        probe_reserved=true;
    }
    std::unique_ptr<Presenter> p(new(std::nothrow) Presenter());
    if(!p) { if(probe_reserved)nl_gpu_probe_owner_reserved.store(false);return E_OUTOFMEMORY; }
    p->probe_owner_reserved=probe_reserved;
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
extern "C" int32_t nl_gpu_step(void* handle, const uint8_t* bytes, size_t length, uint64_t pts, uint64_t due, uint64_t expires,
    uint32_t* accepted, uint64_t* output_pts, uint64_t* qpc, uint32_t* submitted,uint32_t* converted) noexcept {
    auto* p=static_cast<Presenter*>(handle);
    if (!p || p->thread!=GetCurrentThreadId() || !accepted || !output_pts || !qpc || !submitted || !converted) return E_INVALIDARG;
    *accepted=0; *submitted=0;*converted=0;
    if (!authorized(*p)) return E_ABORT;
    if (length && p->time_size<p->times.size()) {
        if (!bytes || length>8*1024*1024 || pts>static_cast<uint64_t>(INT64_MAX)/1000) return E_INVALIDARG;
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
