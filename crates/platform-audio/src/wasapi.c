/* First-party narrow Windows SDK WASAPI boundary. Apache-2.0.
 * All audio clients stay on their creating MTA worker. No microphone fallback.
 * Notification objects contain no Rust pointers or application authorization. */
#define COBJMACROS
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <functiondiscoverykeys_devpkey.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NL_MAX_ID 1024u
#define NL_MAX_ENDPOINTS 64u
#define NL_MAX_FRAMES 1920u
#define NL_BAD_DATA HRESULT_FROM_WIN32(ERROR_INVALID_DATA)

typedef struct nl_notice {
    IMMNotificationClient iface;
    LONG refs;
    LONG invalidated;
    WCHAR id[NL_MAX_ID];
} nl_notice;
static HRESULT STDMETHODCALLTYPE nl_query(IMMNotificationClient *self, REFIID iid, void **out) {
    if (!out) return E_POINTER;
    *out = NULL;
    if (IsEqualIID(iid, &IID_IUnknown) || IsEqualIID(iid, &IID_IMMNotificationClient)) {
        *out = self;
        InterlockedIncrement(&((nl_notice *)self)->refs);
        return S_OK;
    }
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE nl_addref(IMMNotificationClient *self) {
    return (ULONG)InterlockedIncrement(&((nl_notice *)self)->refs);
}
static ULONG STDMETHODCALLTYPE nl_release(IMMNotificationClient *self) {
    LONG refs = InterlockedDecrement(&((nl_notice *)self)->refs);
    if (!refs) free(self);
    return (ULONG)refs;
}
static void nl_invalidate(nl_notice *self, LPCWSTR id) {
    if (id && !wcscmp(self->id, id)) InterlockedExchange(&self->invalidated, 1);
}
static HRESULT STDMETHODCALLTYPE nl_state(IMMNotificationClient *self, LPCWSTR id, DWORD state) {
    if (state != DEVICE_STATE_ACTIVE) nl_invalidate((nl_notice *)self, id);
    return S_OK;
}
static HRESULT STDMETHODCALLTYPE nl_added(IMMNotificationClient *self, LPCWSTR id) {
    (void)self; (void)id; return S_OK;
}
static HRESULT STDMETHODCALLTYPE nl_removed(IMMNotificationClient *self, LPCWSTR id) {
    nl_invalidate((nl_notice *)self, id); return S_OK;
}
static HRESULT STDMETHODCALLTYPE nl_default(IMMNotificationClient *self, EDataFlow flow, ERole role, LPCWSTR id) {
    /* Explicitly selected endpoints remain fixed when the OS default changes. */
    (void)self; (void)flow; (void)role; (void)id; return S_OK;
}
static HRESULT STDMETHODCALLTYPE nl_property(IMMNotificationClient *self, LPCWSTR id, const PROPERTYKEY key) {
    (void)key; nl_invalidate((nl_notice *)self, id); return S_OK;
}
static IMMNotificationClientVtbl nl_notice_vtable = {
    nl_query, nl_addref, nl_release, nl_state, nl_added, nl_removed, nl_default, nl_property
};

typedef struct nl_audio {
    IMMDeviceEnumerator *enumerator;
    IMMDevice *device;
    IAudioClient *client;
    IAudioCaptureClient *capture;
    IAudioRenderClient *render;
    nl_notice *notice;
    UINT32 frames;
    unsigned channels;
    int registered;
    int com;
    int started;
} nl_audio;

static size_t nl_wide_length(const WCHAR *text, size_t max) {
    size_t n = 0;
    if (!text) return max;
    while (n < max && text[n]) ++n;
    return n;
}
static HRESULT nl_enumerator(IMMDeviceEnumerator **out) {
    return CoCreateInstance(&CLSID_MMDeviceEnumerator, NULL, CLSCTX_INPROC_SERVER,
        &IID_IMMDeviceEnumerator, (void **)out);
}
typedef int (*nl_endpoint_callback)(void *, const uint16_t *, size_t, const uint16_t *, size_t);
int32_t nl_audio_enumerate(nl_endpoint_callback callback, void *context) {
    if (!callback || !context) return E_POINTER;
    IMMDeviceEnumerator *enumerator = NULL;
    IMMDeviceCollection *collection = NULL;
    HRESULT result = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    UINT count = 0;
    if (FAILED(result)) return result;
    result = nl_enumerator(&enumerator);
    if (SUCCEEDED(result)) result = IMMDeviceEnumerator_EnumAudioEndpoints(enumerator, eRender, DEVICE_STATE_ACTIVE, &collection);
    if (SUCCEEDED(result)) result = IMMDeviceCollection_GetCount(collection, &count);
    if (SUCCEEDED(result) && count > NL_MAX_ENDPOINTS) result = NL_BAD_DATA;
    for (UINT i = 0; SUCCEEDED(result) && i < count; ++i) {
        IMMDevice *device = NULL;
        IPropertyStore *properties = NULL;
        WCHAR *id = NULL;
        PROPVARIANT name;
        memset(&name, 0, sizeof(name));
        result = IMMDeviceCollection_Item(collection, i, &device);
        if (SUCCEEDED(result)) result = IMMDevice_GetId(device, &id);
        if (SUCCEEDED(result)) result = IMMDevice_OpenPropertyStore(device, STGM_READ, &properties);
        if (SUCCEEDED(result)) result = IPropertyStore_GetValue(properties, &PKEY_Device_FriendlyName, &name);
        size_t id_len = nl_wide_length(id, NL_MAX_ID);
        size_t name_len = name.vt == VT_LPWSTR ? nl_wide_length(name.pwszVal, NL_MAX_ID) : NL_MAX_ID;
        if (SUCCEEDED(result) && (!id_len || id_len >= NL_MAX_ID || !name_len || name_len >= NL_MAX_ID)) result = NL_BAD_DATA;
        if (SUCCEEDED(result) && callback(context, (const uint16_t *)id, id_len, (const uint16_t *)name.pwszVal, name_len)) result = E_ABORT;
        PropVariantClear(&name);
        if (id) CoTaskMemFree(id);
        if (properties) IPropertyStore_Release(properties);
        if (device) IMMDevice_Release(device);
    }
    if (collection) IMMDeviceCollection_Release(collection);
    if (enumerator) IMMDeviceEnumerator_Release(enumerator);
    CoUninitialize();
    return result;
}

/* Resolve the actual Windows multimedia render default without starting it.
 * The caller runs this on a fresh MTA worker and later opens the returned
 * opaque ID through the same local endpoint inventory. */
int32_t nl_audio_default_render_id(uint16_t *output, size_t capacity, size_t *written) {
    if (!output || !written || capacity < 2 || capacity > NL_MAX_ID) return E_INVALIDARG;
    *written = 0;
    HRESULT result = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(result)) return result;
    IMMDeviceEnumerator *enumerator = NULL;
    IMMDevice *device = NULL;
    LPWSTR id = NULL;
    result = nl_enumerator(&enumerator);
    if (SUCCEEDED(result)) result = IMMDeviceEnumerator_GetDefaultAudioEndpoint(enumerator, eRender, eMultimedia, &device);
    if (SUCCEEDED(result)) result = IMMDevice_GetId(device, &id);
    size_t length = nl_wide_length(id, NL_MAX_ID);
    if (SUCCEEDED(result) && (!length || length >= capacity || length >= NL_MAX_ID)) result = NL_BAD_DATA;
    if (SUCCEEDED(result)) {
        memcpy(output, id, length * sizeof(*output));
        output[length] = 0;
        *written = length;
    }
    if (id) CoTaskMemFree(id);
    if (device) IMMDevice_Release(device);
    if (enumerator) IMMDeviceEnumerator_Release(enumerator);
    CoUninitialize();
    return result;
}

int32_t nl_audio_close(nl_audio *audio) {
    if (!audio) return S_OK;
    HRESULT result = S_OK;
    if (audio->client) {
        HRESULT stop = audio->started ? IAudioClient_Stop(audio->client) : S_OK;
        HRESULT reset = IAudioClient_Reset(audio->client);
        if (FAILED(stop)) result = stop;
        else if (FAILED(reset)) result = reset;
    }
    if (audio->capture) IAudioCaptureClient_Release(audio->capture);
    if (audio->render) IAudioRenderClient_Release(audio->render);
    if (audio->client) IAudioClient_Release(audio->client);
    if (audio->device) IMMDevice_Release(audio->device);
    HRESULT removed = audio->registered ? IMMDeviceEnumerator_UnregisterEndpointNotificationCallback(audio->enumerator, &audio->notice->iface) : S_OK;
    if (SUCCEEDED(removed)) {
        if (audio->notice) nl_release(&audio->notice->iface);
        if (audio->enumerator) IMMDeviceEnumerator_Release(audio->enumerator);
    } else {
        /* Preserve independent notifier + enumerator on uncertain callback lifetime.
         * This contains only endpoint identity and a latch, never borrowed memory. */
        if (SUCCEEDED(result)) result = removed;
    }
    if (audio->com) CoUninitialize();
    free(audio);
    return result;
}
int32_t nl_audio_check(nl_audio *audio) {
    if (!audio || !audio->client || !audio->notice) return E_POINTER;
    if (InterlockedCompareExchange(&audio->notice->invalidated, 0, 0)) return AUDCLNT_E_DEVICE_INVALIDATED;
    DWORD state = 0;
    HRESULT result = IMMDevice_GetState(audio->device, &state);
    if (FAILED(result)) return result;
    if (state != DEVICE_STATE_ACTIVE) return AUDCLNT_E_DEVICE_INVALIDATED;
    UINT32 padding = 0;
    result = IAudioClient_GetCurrentPadding(audio->client, &padding);
    if (SUCCEEDED(result) && padding > audio->frames) return NL_BAD_DATA;
    return result;
}
int32_t nl_audio_open(const uint16_t *id, unsigned channels, int loopback, nl_audio **out) {
    if (!out) return E_POINTER;
    *out = NULL;
    size_t length = nl_wide_length((const WCHAR *)id, NL_MAX_ID);
    if (!length || length >= NL_MAX_ID || channels < 1 || channels > 2 || (loopback != 0 && loopback != 1)) return E_INVALIDARG;
    nl_audio *audio = (nl_audio *)calloc(1, sizeof(*audio));
    if (!audio) return E_OUTOFMEMORY;
    HRESULT result = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(result)) { free(audio); return result; }
    audio->com = 1;
    audio->channels = channels;
    result = nl_enumerator(&audio->enumerator);
    if (SUCCEEDED(result)) {
        audio->notice = (nl_notice *)calloc(1, sizeof(nl_notice));
        if (!audio->notice) result = E_OUTOFMEMORY;
        else {
            audio->notice->iface.lpVtbl = &nl_notice_vtable;
            audio->notice->refs = 1;
            memcpy(audio->notice->id, id, (length + 1) * sizeof(WCHAR));
            result = IMMDeviceEnumerator_RegisterEndpointNotificationCallback(audio->enumerator, &audio->notice->iface);
            if (SUCCEEDED(result)) audio->registered = 1;
        }
    }
    if (SUCCEEDED(result)) result = IMMDeviceEnumerator_GetDevice(audio->enumerator, (const WCHAR *)id, &audio->device);
    IMMEndpoint *endpoint = NULL;
    EDataFlow flow = eAll;
    if (SUCCEEDED(result)) result = IMMDevice_QueryInterface(audio->device, &IID_IMMEndpoint, (void **)&endpoint);
    if (SUCCEEDED(result)) result = IMMEndpoint_GetDataFlow(endpoint, &flow);
    if (endpoint) IMMEndpoint_Release(endpoint);
    if (SUCCEEDED(result) && flow != eRender) result = E_ACCESSDENIED;
    if (SUCCEEDED(result)) result = IMMDevice_Activate(audio->device, &IID_IAudioClient, CLSCTX_INPROC_SERVER, NULL, (void **)&audio->client);
    WAVEFORMATEX format;
    memset(&format, 0, sizeof(format));
    format.wFormatTag = WAVE_FORMAT_PCM;
    format.nChannels = (WORD)channels;
    format.nSamplesPerSec = 48000;
    format.wBitsPerSample = 16;
    format.nBlockAlign = (WORD)(channels * 2);
    format.nAvgBytesPerSec = 48000 * format.nBlockAlign;
    DWORD flags = AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
    if (loopback) flags |= AUDCLNT_STREAMFLAGS_LOOPBACK;
    if (SUCCEEDED(result)) result = IAudioClient_Initialize(audio->client, AUDCLNT_SHAREMODE_SHARED, flags, 400000, 0, &format, NULL);
    if (SUCCEEDED(result)) result = IAudioClient_GetBufferSize(audio->client, &audio->frames);
    if (SUCCEEDED(result) && (!audio->frames || audio->frames > NL_MAX_FRAMES)) result = AUDCLNT_E_BUFFER_SIZE_ERROR;
    if (SUCCEEDED(result)) result = loopback ? IAudioClient_GetService(audio->client, &IID_IAudioCaptureClient, (void **)&audio->capture)
        : IAudioClient_GetService(audio->client, &IID_IAudioRenderClient, (void **)&audio->render);
    if (SUCCEEDED(result)) result = nl_audio_check(audio);
    if (FAILED(result)) { (void)nl_audio_close(audio); return result; }
    *out = audio;
    return S_OK;
}
int32_t nl_audio_start(nl_audio *audio) {
    HRESULT result = nl_audio_check(audio);
    if (SUCCEEDED(result) && !audio->started) {
        result = IAudioClient_Start(audio->client);
        if (SUCCEEDED(result)) audio->started = 1;
    }
    return result;
}

/* Shared by production capture and the boundary corpus; input is SDK-owned. */
int32_t nl_audio_copy_samples(const int16_t *input, unsigned frames, unsigned channels,
    unsigned flags, int16_t *out, size_t capacity) {
    size_t count = (size_t)frames * channels;
    if (!out || !frames || frames > NL_MAX_FRAMES || channels < 1 || channels > 2 || count > capacity
        || (flags & ~(AUDCLNT_BUFFERFLAGS_SILENT | AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY))
        || (!input && !(flags & AUDCLNT_BUFFERFLAGS_SILENT))) return NL_BAD_DATA;
    if (flags & AUDCLNT_BUFFERFLAGS_SILENT) memset(out, 0, count * sizeof(int16_t));
    else memcpy(out, input, count * sizeof(int16_t));
    return S_OK;
}
int32_t nl_audio_capture(nl_audio *audio, int16_t *out, size_t capacity, unsigned *frames,
    uint64_t *position, uint64_t *age_100ns, unsigned *flags) {
    if (!audio || !audio->capture || !out || !frames || !position || !age_100ns || !flags) return E_POINTER;
    *frames = 0;
    HRESULT result = nl_audio_check(audio);
    if (FAILED(result)) return result;
    UINT32 available = 0;
    result = IAudioCaptureClient_GetNextPacketSize(audio->capture, &available);
    if (FAILED(result) || !available) return result;
    BYTE *data = NULL;
    UINT32 received = 0;
    DWORD packet_flags = 0;
    UINT64 qpc = 0;
    result = IAudioCaptureClient_GetBuffer(audio->capture, &data, &received, &packet_flags, position, &qpc);
    if (FAILED(result)) return result;
    HRESULT copied = nl_audio_copy_samples((const int16_t *)data, received, audio->channels, packet_flags, out, capacity);
    LARGE_INTEGER now, frequency;
    if (SUCCEEDED(copied)) {
        if (!QueryPerformanceCounter(&now) || !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) copied = NL_BAD_DATA;
        else {
            double timestamp = (double)now.QuadPart * 10000000.0 / (double)frequency.QuadPart;
            if (timestamp < (double)qpc || timestamp - (double)qpc > 50000000.0) copied = NL_BAD_DATA;
            else *age_100ns = (uint64_t)(timestamp - (double)qpc);
        }
    }
    result = IAudioCaptureClient_ReleaseBuffer(audio->capture, received);
    if (FAILED(copied)) return copied;
    if (FAILED(result)) return result;
    result = nl_audio_check(audio);
    if (FAILED(result)) return result;
    *frames = received;
    *flags = packet_flags;
    return S_OK;
}
/* Independent driver facts; no enqueue receipt implies audible completion. */
int32_t nl_audio_timing(nl_audio *audio, unsigned *padding, int64_t *latency_100ns) {
    if (!audio || !audio->render || !padding || !latency_100ns) return E_INVALIDARG;
    HRESULT result = nl_audio_check(audio);
    if (FAILED(result)) return result;
    UINT32 current = 0; REFERENCE_TIME latency = 0;
    result = IAudioClient_GetCurrentPadding(audio->client, &current);
    if (FAILED(result)) return result;
    result = IAudioClient_GetStreamLatency(audio->client, &latency);
    if (FAILED(result)) return result;
    if (current > audio->frames || latency < 0 || latency > 2500000) return NL_BAD_DATA;
    *padding = current; *latency_100ns = latency; return S_OK;
}
int32_t nl_audio_write(nl_audio *audio, const int16_t *input, unsigned frames, unsigned *written) {
    if (!audio || !audio->render || !input || !written || !frames || frames > 960) return E_INVALIDARG;
    *written = 0;
    HRESULT result = nl_audio_check(audio);
    if (FAILED(result)) return result;
    UINT32 padding = 0;
    result = IAudioClient_GetCurrentPadding(audio->client, &padding);
    if (FAILED(result)) return result;
    if (padding > audio->frames) return NL_BAD_DATA;
    UINT32 take = frames < audio->frames - padding ? frames : audio->frames - padding;
    if (!take) return S_OK;
    BYTE *data = NULL;
    result = IAudioRenderClient_GetBuffer(audio->render, take, &data);
    if (FAILED(result)) return result;
    if (!data) {
        (void)IAudioRenderClient_ReleaseBuffer(audio->render, take, AUDCLNT_BUFFERFLAGS_SILENT);
        return NL_BAD_DATA;
    }
    memcpy(data, input, (size_t)take * audio->channels * sizeof(int16_t));
    result = IAudioRenderClient_ReleaseBuffer(audio->render, take, 0);
    if (FAILED(result)) return result;
    *written = take;
    return S_OK;
}

/* No audio samples or live endpoints: deterministic production callback probe. */
int32_t nl_audio_notice_probe(unsigned event) {
    nl_notice notice;
    memset(&notice, 0, sizeof(notice));
    notice.iface.lpVtbl = &nl_notice_vtable;
    notice.id[0] = L'a';
    switch (event) {
    case 0: nl_state(&notice.iface, L"b", DEVICE_STATE_DISABLED); break;
    case 1: nl_state(&notice.iface, L"a", DEVICE_STATE_ACTIVE); break;
    case 2: nl_state(&notice.iface, L"a", DEVICE_STATE_DISABLED);
        nl_state(&notice.iface, L"a", DEVICE_STATE_ACTIVE); break;
    case 3: nl_removed(&notice.iface, L"a"); nl_added(&notice.iface, L"a"); break;
    case 4: nl_property(&notice.iface, L"a", PKEY_Device_FriendlyName); break;
    case 5: nl_default(&notice.iface, eRender, eMultimedia, L"b"); break;
    default: return -1;
    }
    return notice.invalidated;
}
int32_t nl_audio_started(nl_audio *audio) { return audio ? audio->started : -1; }
