# NestLink 0.3.0 RC product design

NestLink uses a quiet blue workspace and one linked-N identity. The desktop's primary flow is selecting a computer, choosing permissions, requesting access and opening the authorized remote screen. UU Remote's device and session workflows informed this design; NestLink retains its own self-hosted authorization model and VP8/Opus media stack.

## Tokens

| Role | Color |
| --- | --- |
| Primary actions | `#246BCE` |
| Selected text | `#205EB5` |
| Navigation | `#EAF0F8` |
| Canvas | `#F2F5FA` |
| Content | `#FFFFFF` |
| Text | `#182B43` |
| Muted text | `#64748B` |
| Border | `#DCE4EF` |

`config/ui-tokens.json` defines light/dark colors, spacing and type metrics. Desktop reads it directly; generated Web and Android adapters use the same tokens. System UI fonts include a Chinese fallback. Navigation and commands share a custom 24-unit outline icon set rather than platform-dependent text symbols. Names and actions align left; rows have no shadows and remain readable at narrow widths.

```text
 [linked N] NestLink                      language / theme / version / window controls
 Device management  | All devices                                      Search devices
 Remote assistance  | Computers 2
 Tunnels            | [PC] This computer    local                                 info
                    | [PC] Another computer  enrolled                  connect / info
                    | Phones / tablets 1
                    | [phone] Device name  enrolled                             info
                    |
 Account and settings |
```

Device names lead rows and remote windows. Enrollment is described as enrollment; it is never presented as online presence. Permission and path choices explain their effect. Request IDs, connection generations and cleanup traces appear in expandable diagnostics. Connect continues through approval, permit and transport setup; progress, cancellation and actionable failures remain visible. The SVG source defines the executable, tray, installer, Android and Web marks.

Files, text clipboard, keyboard/mouse, multiple displays and audio remain subject to explicit permissions and host-side selection. Do not advertise gaming, HDR, gamepads, Wake-on-LAN or unimplemented platforms as shipped capabilities. Windows/Linux, Web and Android share the 0.3.0 RC identity. This RC uses development signing; fixed signing, installed-product and real-network acceptance remain pending in the release materials.

Run `packaging/windows/install-local-clean.ps1` before every local installation; it backs up and removes the prior install and configuration before running the installer. Local installation and published installer upgrade acceptance are recorded separately.
