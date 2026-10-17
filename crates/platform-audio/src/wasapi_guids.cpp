// Apache-2.0. Resolve interface IDs from official SDK type metadata.
// The C ABI does not provide __uuidof; these contain no implementation code.
#include <windows.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
extern "C" const IID IID_IMMNotificationClient = __uuidof(IMMNotificationClient);
extern "C" const IID IID_IMMEndpoint = __uuidof(IMMEndpoint);
extern "C" const IID IID_IMMDeviceEnumerator = __uuidof(IMMDeviceEnumerator);
extern "C" const CLSID CLSID_MMDeviceEnumerator = __uuidof(MMDeviceEnumerator);
extern "C" const IID IID_IAudioClient = __uuidof(IAudioClient);
extern "C" const IID IID_IAudioRenderClient = __uuidof(IAudioRenderClient);
extern "C" const IID IID_IAudioCaptureClient = __uuidof(IAudioCaptureClient);
