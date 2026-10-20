// First-party Desktop Duplication bridge. All COM resources stay on the
// authorized capture worker; neither pointers nor shared handles cross IPC.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <wrl/client.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <new>

using Microsoft::WRL::ComPtr;
struct Duplication {
    ComPtr<ID3D11Device> device;
    ComPtr<ID3D11DeviceContext> context;
    ComPtr<IDXGIOutputDuplication> output;
    ComPtr<ID3D11Texture2D> staging;
    uint32_t width = 0, height = 0;
};

extern "C" int32_t nl_dxgi_open(uintptr_t monitor, uint32_t width,
                                uint32_t height, void** result) noexcept {
    if (!result || !monitor || !width || !height || width > 8192 || height > 8192)
        return E_INVALIDARG;
    *result = nullptr;
    ComPtr<IDXGIFactory1> factory;
    HRESULT hr = CreateDXGIFactory1(IID_PPV_ARGS(&factory));
    if (FAILED(hr)) return hr;
    for (UINT ai = 0; ai < 64; ++ai) {
        ComPtr<IDXGIAdapter1> adapter;
        hr = factory->EnumAdapters1(ai, &adapter);
        if (hr == DXGI_ERROR_NOT_FOUND) break;
        if (FAILED(hr)) return hr;
        for (UINT oi = 0; oi < 64; ++oi) {
            ComPtr<IDXGIOutput> output;
            hr = adapter->EnumOutputs(oi, &output);
            if (hr == DXGI_ERROR_NOT_FOUND) break;
            if (FAILED(hr)) return hr;
            DXGI_OUTPUT_DESC desc{};
            hr = output->GetDesc(&desc);
            if (FAILED(hr)) return hr;
            if (reinterpret_cast<uintptr_t>(desc.Monitor) != monitor) continue;
            // Never substitute another output or adapter. Rotation requires
            // a separate transform; retain the explicit compatibility fallback.
            if (!desc.AttachedToDesktop ||
                (desc.Rotation != DXGI_MODE_ROTATION_IDENTITY &&
                 desc.Rotation != DXGI_MODE_ROTATION_UNSPECIFIED) ||
                desc.DesktopCoordinates.right - desc.DesktopCoordinates.left != static_cast<LONG>(width) ||
                desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top != static_cast<LONG>(height))
                return DXGI_ERROR_UNSUPPORTED;
            std::unique_ptr<Duplication> state(new (std::nothrow) Duplication());
            if (!state) return E_OUTOFMEMORY;
            D3D_FEATURE_LEVEL selected{};
            hr = D3D11CreateDevice(adapter.Get(), D3D_DRIVER_TYPE_UNKNOWN, nullptr,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT, nullptr, 0, D3D11_SDK_VERSION,
                &state->device, &selected, &state->context);
            if (FAILED(hr)) return hr;
            ComPtr<IDXGIOutput1> output1;
            hr = output.As(&output1);
            if (FAILED(hr)) return hr;
            hr = output1->DuplicateOutput(state->device.Get(), &state->output);
            if (FAILED(hr)) return hr;
            D3D11_TEXTURE2D_DESC texture{};
            texture.Width = width; texture.Height = height;
            texture.MipLevels = 1; texture.ArraySize = 1;
            texture.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
            texture.SampleDesc.Count = 1;
            texture.Usage = D3D11_USAGE_STAGING;
            texture.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
            hr = state->device->CreateTexture2D(&texture, nullptr, &state->staging);
            if (FAILED(hr)) return hr;
            state->width = width; state->height = height;
            *result = state.release();
            return S_OK;
        }
    }
    return DXGI_ERROR_NOT_FOUND;
}

// S_FALSE means no desktop frame is available yet. Every acquired frame is
// released even when texture validation, copying or mapping fails.
extern "C" int32_t nl_dxgi_read(void* opaque, uint8_t* pixels, size_t length) noexcept {
    auto* state = static_cast<Duplication*>(opaque);
    if (!state || !pixels || length != static_cast<size_t>(state->width) * state->height * 4)
        return E_INVALIDARG;
    DXGI_OUTDUPL_FRAME_INFO info{};
    ComPtr<IDXGIResource> resource;
    HRESULT hr = state->output->AcquireNextFrame(0, &info, &resource);
    if (hr == DXGI_ERROR_WAIT_TIMEOUT) return S_FALSE;
    if (hr != DXGI_ERROR_WAIT_TIMEOUT) {
        if (FAILED(hr)) return hr;
        ComPtr<ID3D11Texture2D> texture;
        hr = resource.As(&texture);
        if (SUCCEEDED(hr)) {
            D3D11_TEXTURE2D_DESC desc{};
            texture->GetDesc(&desc);
            if (desc.Width != state->width || desc.Height != state->height ||
                desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM) hr = DXGI_ERROR_UNSUPPORTED;
            else state->context->CopyResource(state->staging.Get(), texture.Get());
        }
        const HRESULT released = state->output->ReleaseFrame();
        if (FAILED(hr)) return hr;
        if (FAILED(released)) return released;
    }
    D3D11_MAPPED_SUBRESOURCE mapped{};
    hr = state->context->Map(state->staging.Get(), 0, D3D11_MAP_READ, 0, &mapped);
    if (FAILED(hr)) return hr;
    const size_t row_bytes = static_cast<size_t>(state->width) * 4;
    if (!mapped.pData || mapped.RowPitch < row_bytes) {
        state->context->Unmap(state->staging.Get(), 0);
        return E_UNEXPECTED;
    }
    for (uint32_t row = 0; row < state->height; ++row)
        std::memcpy(pixels + row * row_bytes,
                    static_cast<const uint8_t*>(mapped.pData) + row * mapped.RowPitch, row_bytes);
    state->context->Unmap(state->staging.Get(), 0);
    return S_OK;
}

extern "C" void nl_dxgi_close(void* opaque) noexcept {
    delete static_cast<Duplication*>(opaque);
}
