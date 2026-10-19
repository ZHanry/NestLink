# 0.4.0 RC desktop design

`0.4.0-desktop-prototype.html` is the lavender prototype produced with Gemini CLI in plan mode, then reviewed to remove labels for unavailable product features. It is a design reference, not a screenshot or a claim that every prototype control is implemented.

The desktop implementation uses the shared tokens in `config/ui-tokens.json`: lavender canvas and navigation, white surfaces, purple actions, and a corresponding dark palette. The remote workspace prioritizes local enrollment, searchable remote devices, explicit permissions and a connection action. Authorization/routing options and protocol diagnostics are progressively disclosed. Wide windows use two columns; narrow windows stack them with scrolling.

An isolated development fixture exercised the real desktop UI, local IPC and HTTP service with an initially unregistered installation. It checked that the device was enrolled once, then captured the application window at 1200×800, 800×650 and in dark appearance. The fixture used synthetic account/device data and did not connect to the user's deployment. Screenshots and validation notes belong to the development evidence; installed-platform and cross-network acceptance remain separate.
