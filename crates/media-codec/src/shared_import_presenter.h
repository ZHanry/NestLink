// Included inside the existing presenter namespace. Reuses its UI-owned child
// surface, swapchain, BT.709 video processor and bounded completion query.
#pragma once
struct SharedPresenter {
    Presenter output;
    NlSharedRingDescriptor ring{};
    std::array<ComPtr<ID3D11Texture2D>,3> textures;
    std::array<ComPtr<IDXGIKeyedMutex>,3> mutexes;
    std::array<ComPtr<ID3D11VideoProcessorInputView>,3> inputs;
    std::array<uint64_t,3> keys{};
    uint64_t last_token=0,last_pts=0;
    bool failed=false;
    HRESULT initialize(Surface* surface,const NlSharedRingDescriptor& descriptor,UINT fps,uint64_t driver) {
        auto& p=output;p.surface=surface;++surface->references;
        p.hdr10=descriptor.reserved==NL_SHARED_HDR10_VERSION;
        if((descriptor.bit_depth!=8 && descriptor.bit_depth!=10) || (descriptor.reserved && !p.hdr10) || (p.hdr10 && descriptor.bit_depth!=10))return E_INVALIDARG;
        p.input_format=descriptor.bit_depth==10?DXGI_FORMAT_P010:DXGI_FORMAT_NV12;
        p.width=descriptor.width;p.height=descriptor.height;ring=descriptor;
        HRESULT hr=CoInitializeEx(nullptr,COINIT_MULTITHREADED);if(FAILED(hr))return hr;p.com=true;
        ComPtr<IDXGIFactory1> factory;hr=CreateDXGIFactory1(IID_PPV_ARGS(&factory));if(FAILED(hr))return hr;
        ComPtr<IDXGIAdapter1> selected;
        for(UINT index=0;index<64;++index) {
            ComPtr<IDXGIAdapter1> candidate;hr=factory->EnumAdapters1(index,&candidate);
            if(hr==DXGI_ERROR_NOT_FOUND)break;if(FAILED(hr))return hr;
            DXGI_ADAPTER_DESC1 desc{};hr=candidate->GetDesc1(&desc);if(FAILED(hr))return hr;
            const uint64_t luid=static_cast<uint64_t>(static_cast<uint32_t>(desc.AdapterLuid.HighPart))<<32|desc.AdapterLuid.LowPart;
            if(luid==descriptor.adapter_luid && !(desc.Flags&DXGI_ADAPTER_FLAG_SOFTWARE)) {selected=candidate;break;}
        }
        if(!selected)return DXGI_ERROR_NOT_FOUND;
        LARGE_INTEGER version{};hr=selected->CheckInterfaceSupport(__uuidof(IDXGIDevice),&version);
        if(FAILED(hr) || static_cast<uint64_t>(version.QuadPart)!=driver)return FAILED(hr)?hr:E_ACCESSDENIED;
        hr=D3D11CreateDevice(selected.Get(),D3D_DRIVER_TYPE_UNKNOWN,nullptr,
            D3D11_CREATE_DEVICE_BGRA_SUPPORT|D3D11_CREATE_DEVICE_VIDEO_SUPPORT,nullptr,0,D3D11_SDK_VERSION,&p.device,nullptr,&p.context);
        if(FAILED(hr))return hr;
        ComPtr<ID3D10Multithread> multi;hr=p.context.As(&multi);if(FAILED(hr))return hr;multi->SetMultithreadProtected(TRUE);
        hr=p.device.As(&p.video);if(FAILED(hr))return hr;
        hr=p.context.As(&p.video_context);if(FAILED(hr))return hr;
        ComPtr<ID3D11Device1> importer;hr=p.device.As(&importer);if(FAILED(hr))return hr;
        for(size_t index=0;index<textures.size();++index) {
            const HANDLE handle=reinterpret_cast<HANDLE>(static_cast<uintptr_t>(descriptor.handles[index]));
            hr=importer->OpenSharedResource1(handle,IID_PPV_ARGS(&textures[index]));if(FAILED(hr))return hr;
            D3D11_TEXTURE2D_DESC desc{};textures[index]->GetDesc(&desc);
            const UINT shared=D3D11_RESOURCE_MISC_SHARED_NTHANDLE|D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;
            if(desc.Width!=p.width || desc.Height!=p.height || desc.Format!=p.input_format || desc.ArraySize!=1 || desc.MipLevels!=1 ||
                desc.SampleDesc.Count!=1 || desc.SampleDesc.Quality || desc.CPUAccessFlags || desc.Usage!=D3D11_USAGE_DEFAULT || (desc.MiscFlags&shared)!=shared)
                return MF_E_INVALIDMEDIATYPE;
            hr=textures[index].As(&mutexes[index]);if(FAILED(hr))return hr;
        }
        hr=configure_output(p,fps);if(FAILED(hr))return hr;
        for(size_t index=0;index<inputs.size();++index) {
            D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC desc{};desc.ViewDimension=D3D11_VPIV_DIMENSION_TEXTURE2D;
            hr=p.video->CreateVideoProcessorInputView(textures[index].Get(),p.enumerator.Get(),&desc,&inputs[index]);if(FAILED(hr))return hr;
        }
        return S_OK;
    }
    HRESULT consume(const NlSharedFrame& frame,uint64_t deadline,uint64_t* qpc,uint32_t* consumed,uint32_t* converted,uint32_t* submitted) {
        auto& p=output;
        if(failed || p.thread!=GetCurrentThreadId() || !p.surface->live || frame.slot>=3 || !frame.token || frame.token<=last_token ||
            (last_token && frame.pts<=last_pts) || !frame.acquire_key || !(frame.acquire_key&1) || frame.release_key!=frame.acquire_key+1 ||
            frame.acquire_key<=keys[frame.slot] || !deadline || deadline>frame.expires_qpc)return E_INVALIDARG;
        HRESULT hr=p.device->GetDeviceRemovedReason();if(FAILED(hr)){failed=true;return hr;}
        if(!hdr_display_current(p)){failed=true;black(p);return DXGI_ERROR_ACCESS_LOST;}
        auto& mutex=mutexes[frame.slot];
        hr=mutex->AcquireSync(frame.acquire_key,50);
        if(hr!=S_OK){failed=true;return FAILED(hr)?hr:HRESULT_FROM_WIN32(WAIT_TIMEOUT);}
        LARGE_INTEGER now{};if(!QueryPerformanceCounter(&now) || now.QuadPart<0){failed=true;return E_UNEXPECTED;}
        last_token=frame.token;last_pts=frame.pts;keys[frame.slot]=frame.acquire_key;
        // Hidden/late output is deliberately consumed without a Present claim.
        if(static_cast<uint64_t>(now.QuadPart)<deadline && static_cast<uint64_t>(now.QuadPart)<frame.expires_qpc && p.surface->authorized && authorized(p)) {
            ComPtr<ID3D11Texture2D> back;hr=p.swap->GetBuffer(0,IID_PPV_ARGS(&back));if(FAILED(hr)){failed=true;return hr;}
            D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC desc{};desc.ViewDimension=D3D11_VPOV_DIMENSION_TEXTURE2D;
            ComPtr<ID3D11VideoProcessorOutputView> view;
            hr=p.video->CreateVideoProcessorOutputView(back.Get(),p.enumerator.Get(),&desc,&view);if(FAILED(hr)){failed=true;return hr;}
            RECT rect{0,0,static_cast<LONG>(p.width),static_cast<LONG>(p.height)};
            p.video_context->VideoProcessorSetStreamSourceRect(p.processor.Get(),0,TRUE,&rect);
            p.video_context->VideoProcessorSetStreamDestRect(p.processor.Get(),0,TRUE,&rect);
            p.video_context->VideoProcessorSetOutputTargetRect(p.processor.Get(),TRUE,&rect);
            p.video_context->VideoProcessorSetStreamFrameFormat(p.processor.Get(),0,D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE);
            if(!p.hdr10) {
                D3D11_VIDEO_PROCESSOR_COLOR_SPACE color{};color.YCbCr_Matrix=1;color.Nominal_Range=D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_16_235;
                p.video_context->VideoProcessorSetStreamColorSpace(p.processor.Get(),0,&color);
                D3D11_VIDEO_PROCESSOR_COLOR_SPACE rgb{};rgb.Nominal_Range=D3D11_VIDEO_PROCESSOR_NOMINAL_RANGE_0_255;
                p.video_context->VideoProcessorSetOutputColorSpace(p.processor.Get(),&rgb);
            }
            D3D11_VIDEO_PROCESSOR_STREAM stream{};stream.Enable=TRUE;stream.pInputSurface=inputs[frame.slot].Get();
            hr=p.video_context->VideoProcessorBlt(p.processor.Get(),view.Get(),0,1,&stream);if(FAILED(hr)){failed=true;return hr;}
            *converted=1;p.context->End(p.completion.Get());p.context->Flush();
            const ULONGLONG until=GetTickCount64()+50;
            do {hr=p.context->GetData(p.completion.Get(),nullptr,0,D3D11_ASYNC_GETDATA_DONOTFLUSH);if(hr==S_FALSE)Sleep(1);}
            while(hr==S_FALSE && GetTickCount64()<until);
            if(hr!=S_OK){failed=true;return FAILED(hr)?hr:HRESULT_FROM_WIN32(WAIT_TIMEOUT);}
        }
        // No command or text receipt releases a slot. The actual GPU read has
        // completed (or was deliberately skipped) before returning its mutex.
        hr=mutex->ReleaseSync(frame.release_key);if(hr!=S_OK){failed=true;return FAILED(hr)?hr:E_UNEXPECTED;}
        *consumed=1;
        if(!hdr_display_current(p)){failed=true;black(p);return DXGI_ERROR_ACCESS_LOST;}
        if(!QueryPerformanceCounter(&now) || now.QuadPart<0){failed=true;return E_UNEXPECTED;}
        if(*converted && static_cast<uint64_t>(now.QuadPart)<deadline && p.surface->authorized && authorized(p)) {
            hr=p.swap->Present(0,DXGI_PRESENT_DO_NOT_WAIT);
            if(FAILED(hr) && hr!=DXGI_ERROR_WAS_STILL_DRAWING){failed=true;return hr;}
            if(hr==S_OK) {if(!QueryPerformanceCounter(&now) || now.QuadPart<0){failed=true;return E_UNEXPECTED;}*qpc=static_cast<uint64_t>(now.QuadPart);*submitted=1;}
        }
        return S_OK;
    }
};
