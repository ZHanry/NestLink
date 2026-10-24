// Observations from the exact live worker-confined owner, not adapter marketing.
#pragma once
struct NlOwnerObservation {
    uint8_t resource_id[16]{};
    uint64_t adapter_luid=0, driver_version=0;
    uint32_t flags=0;
};
static_assert(sizeof(NlOwnerObservation)==40,"Rust/native owner observation layout");
inline HRESULT nl_observe_owner(ID3D11Device* device,bool hardware_output,
    GUID& id,bool& initialized,NlOwnerObservation* out) noexcept {
    if(!out)return E_POINTER;
    *out=NlOwnerObservation{};
    if(!initialized) {
        const HRESULT hr=CoCreateGuid(&id);if(FAILED(hr))return hr;
        initialized=true;
    }
    std::memcpy(out->resource_id,&id,16);
    if(hardware_output)out->flags|=4;
    if(!device)return S_OK; // Software has no invented hardware identity.
    Microsoft::WRL::ComPtr<IDXGIDevice> dxgi;
    Microsoft::WRL::ComPtr<IDXGIAdapter> adapter;
    DXGI_ADAPTER_DESC desc{};
    HRESULT hr=device->QueryInterface(IID_PPV_ARGS(&dxgi));
    if(SUCCEEDED(hr))hr=dxgi->GetAdapter(&adapter);
    if(SUCCEEDED(hr))hr=adapter->GetDesc(&desc);
    if(FAILED(hr))return S_OK; // Unknown remains unknown and cannot qualify.
    out->flags|=1;
    out->adapter_luid=static_cast<uint64_t>(static_cast<uint32_t>(desc.AdapterLuid.HighPart))<<32|desc.AdapterLuid.LowPart;
    LARGE_INTEGER version{};
    hr=adapter->CheckInterfaceSupport(__uuidof(IDXGIDevice),&version);
    if(SUCCEEDED(hr)) { out->flags|=2;out->driver_version=static_cast<uint64_t>(version.QuadPart); }
    return S_OK;
}
