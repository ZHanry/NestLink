// Original decoder-thread resources. A text acknowledgement never releases a
// slot: only the actual DXGI keyed mutex returning its consumption key does.
#pragma once
#include "shared_surface_abi.h"
class SharedDecodeRing {
    struct Slot {
        ComPtr<ID3D11Texture2D> texture;
        ComPtr<IDXGIKeyedMutex> mutex;
        HANDLE source=nullptr;
        bool pending=false;
        uint64_t write_key=0,token=0,pts=0,started_ms=0,expires_qpc=0;
        ~Slot() { if(source)CloseHandle(source); }
    };
    std::array<Slot,3> slots;
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<ID3D11Query> completion;
    HANDLE peer=nullptr;
    DWORD thread=GetCurrentThreadId();
    uint64_t issued=0;
    bool failed=false;
    bool descriptor_committed=false;
    NlSharedRingDescriptor descriptor{};
    HRESULT refresh(Slot& slot) {
        if(!slot.pending)return S_OK;
        HRESULT hr=slot.mutex->AcquireSync(slot.write_key+2,0);
        if(hr==S_OK) {
            slot.write_key+=2;slot.pending=false;
            return slot.mutex->ReleaseSync(slot.write_key);
        }
        if(hr!=static_cast<HRESULT>(WAIT_TIMEOUT))return FAILED(hr)?hr:E_UNEXPECTED;
        if(GetTickCount64()-slot.started_ms>=5000)return HRESULT_FROM_WIN32(WAIT_TIMEOUT);
        return S_FALSE;
    }
public:
    ~SharedDecodeRing() {
        // Before the descriptor is ever returned, no legitimate importer can
        // have used these values. Afterwards the destination owns its handles;
        // never remotely close a numeric handle which it might already reuse.
        if(peer && !descriptor_committed)for(const auto value:descriptor.handles)if(value) {
            HANDLE reclaimed=nullptr;
            if(DuplicateHandle(peer,reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value)),GetCurrentProcess(),
                &reclaimed,0,FALSE,DUPLICATE_CLOSE_SOURCE|DUPLICATE_SAME_ACCESS))CloseHandle(reclaimed);
        }
        if(peer)CloseHandle(peer);
    }
    HRESULT current() {
        if(failed || thread!=GetCurrentThreadId() || !peer || WaitForSingleObject(peer,0)!=WAIT_TIMEOUT)
            return E_ACCESSDENIED;
        HRESULT hr=device->GetDeviceRemovedReason();
        if(FAILED(hr))failed=true;
        return hr;
    }
    HRESULT initialize(ID3D11Device* original,ID3D11DeviceContext* original_context,
        HANDLE destination,uint32_t width,uint32_t height,NlSharedRingDescriptor* result) {
        if(!original || !original_context || !destination || !result || peer || !width || !height ||
            ((width|height)&1) || static_cast<uint64_t>(width)*height*3/2*3>128*1024*1024)
            return E_INVALIDARG;
        if(!DuplicateHandle(GetCurrentProcess(),destination,GetCurrentProcess(),&peer,0,FALSE,DUPLICATE_SAME_ACCESS))
            return HRESULT_FROM_WIN32(GetLastError());
        device=original;context=original_context;
        HRESULT hr=current();if(FAILED(hr))return hr;
        GUID ring{};hr=CoCreateGuid(&ring);if(FAILED(hr))return hr;
        std::memcpy(descriptor.ring_id,&ring,16);
        ComPtr<IDXGIDevice> dxgi;ComPtr<IDXGIAdapter> adapter;DXGI_ADAPTER_DESC adapter_desc{};
        hr=device.As(&dxgi);if(SUCCEEDED(hr))hr=dxgi->GetAdapter(&adapter);
        if(SUCCEEDED(hr))hr=adapter->GetDesc(&adapter_desc);if(FAILED(hr))return hr;
        descriptor.adapter_luid=static_cast<uint64_t>(static_cast<uint32_t>(adapter_desc.AdapterLuid.HighPart))<<32|
            adapter_desc.AdapterLuid.LowPart;
        descriptor.width=width;descriptor.height=height;
        descriptor.bytes=static_cast<uint64_t>(width)*height*3/2*3;
        D3D11_TEXTURE2D_DESC desc{};desc.Width=width;desc.Height=height;desc.ArraySize=1;desc.MipLevels=1;
        desc.Format=DXGI_FORMAT_NV12;desc.SampleDesc.Count=1;desc.Usage=D3D11_USAGE_DEFAULT;
        desc.BindFlags=D3D11_BIND_SHADER_RESOURCE|D3D11_BIND_RENDER_TARGET;
        desc.MiscFlags=D3D11_RESOURCE_MISC_SHARED_NTHANDLE|D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX;
        for(size_t i=0;i<slots.size();++i) {
            auto& slot=slots[i];hr=device->CreateTexture2D(&desc,nullptr,&slot.texture);
            if(SUCCEEDED(hr))hr=slot.texture.As(&slot.mutex);if(FAILED(hr))return hr;
            ComPtr<IDXGIResource1> resource;hr=slot.texture.As(&resource);
            if(SUCCEEDED(hr))hr=resource->CreateSharedHandle(nullptr,DXGI_SHARED_RESOURCE_READ,nullptr,&slot.source);
            if(FAILED(hr))return hr;
            HANDLE remote=nullptr;
            if(!DuplicateHandle(GetCurrentProcess(),slot.source,peer,&remote,0,FALSE,DUPLICATE_SAME_ACCESS))
                return HRESULT_FROM_WIN32(GetLastError());
            descriptor.handles[i]=reinterpret_cast<uintptr_t>(remote);
            GUID id{};hr=CoCreateGuid(&id);if(FAILED(hr))return hr;
            std::memcpy(descriptor.resource_ids[i],&id,16);
        }
        D3D11_QUERY_DESC query{};query.Query=D3D11_QUERY_EVENT;
        hr=device->CreateQuery(&query,&completion);if(FAILED(hr))return hr;
        *result=descriptor;descriptor_committed=true;return S_OK;
    }
    // S_FALSE is bounded native backpressure. No MFT output is consumed until
    // there is a real free surface, and no pending frame can be overwritten.
    HRESULT room() {
        HRESULT hr=current();if(FAILED(hr))return hr;
        bool available=false;
        for(auto& slot:slots) {
            hr=refresh(slot);if(FAILED(hr)){failed=true;return hr;}
            if(!slot.pending)available=true;
        }
        return available?S_OK:S_FALSE;
    }
    HRESULT copy(ID3D11Texture2D* original,UINT subresource,uint64_t pts) {
        HRESULT hr=room();if(hr!=S_OK)return hr;
        Slot* selected=nullptr;
        for(auto& slot:slots)if(!slot.pending){selected=&slot;break;}
        if(!selected || issued>=static_cast<uint64_t>(INT64_MAX) || selected->write_key>static_cast<uint64_t>(INT64_MAX)-2)
            return E_UNEXPECTED;
        auto& slot=*selected;
        hr=slot.mutex->AcquireSync(slot.write_key,0);if(hr!=S_OK){failed=true;return FAILED(hr)?hr:E_PENDING;}
        D3D11_BOX box{0,0,0,descriptor.width,descriptor.height,1};
        context->CopySubresourceRegion(slot.texture.Get(),0,0,0,0,original,subresource,&box);
        context->End(completion.Get());context->Flush();
        const ULONGLONG until=GetTickCount64()+50;
        do {hr=context->GetData(completion.Get(),nullptr,0,0);if(hr==S_FALSE)Sleep(1);}
        while(hr==S_FALSE && GetTickCount64()<until);
        if(hr!=S_OK){failed=true;return FAILED(hr)?hr:HRESULT_FROM_WIN32(WAIT_TIMEOUT);}
        LARGE_INTEGER now{},frequency{};
        if(!QueryPerformanceCounter(&now) || !QueryPerformanceFrequency(&frequency) || now.QuadPart<0 ||
            frequency.QuadPart<=0 || frequency.QuadPart>INT64_MAX/5 || now.QuadPart>INT64_MAX-frequency.QuadPart*5)
            {failed=true;return E_UNEXPECTED;}
        slot.token=++issued;slot.pts=pts;slot.started_ms=GetTickCount64();
        slot.expires_qpc=static_cast<uint64_t>(now.QuadPart+frequency.QuadPart*5);
        hr=slot.mutex->ReleaseSync(slot.write_key+1);if(hr!=S_OK){failed=true;return FAILED(hr)?hr:E_UNEXPECTED;}
        slot.pending=true;return S_OK;
    }
    HRESULT frame(uint64_t pts,NlSharedFrame* result) {
        HRESULT hr=current();if(FAILED(hr) || !result)return FAILED(hr)?hr:E_POINTER;
        LARGE_INTEGER now{};if(!QueryPerformanceCounter(&now) || now.QuadPart<0)return E_UNEXPECTED;
        for(size_t i=0;i<slots.size();++i) {
            const auto& slot=slots[i];if(!slot.pending || slot.pts!=pts)continue;
            if(static_cast<uint64_t>(now.QuadPart)>=slot.expires_qpc)return HRESULT_FROM_WIN32(WAIT_TIMEOUT);
            *result={slot.token,slot.pts,slot.write_key+1,slot.write_key+2,slot.expires_qpc,static_cast<uint32_t>(i),0};
            return S_OK;
        }
        return S_FALSE;
    }
    // Only an output which has never entered the descriptor writer may take
    // this local discard path. Exported output waits for the consumer GPU key.
    HRESULT discard(uint32_t index,uint64_t token) {
        HRESULT hr=current();if(FAILED(hr))return hr;
        if(index>=slots.size())return E_INVALIDARG;
        auto& slot=slots[index];if(!slot.pending || slot.token!=token)return E_INVALIDARG;
        hr=slot.mutex->AcquireSync(slot.write_key+1,0);
        if(hr!=S_OK){failed=true;return FAILED(hr)?hr:E_PENDING;}
        hr=slot.mutex->ReleaseSync(slot.write_key+2);if(hr!=S_OK){failed=true;return FAILED(hr)?hr:E_UNEXPECTED;}
        return refresh(slot);
    }
    HRESULT status(uint32_t index,uint64_t token) {
        HRESULT hr=current();if(FAILED(hr))return hr;
        if(index>=slots.size() || !token || token>slots[index].token)return E_INVALIDARG;
        auto& slot=slots[index];hr=refresh(slot);if(FAILED(hr))return hr;
        return slot.pending && slot.token==token?S_OK:S_FALSE;
    }
};
