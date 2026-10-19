# NestLink 0.4.0 RC product design

NestLink uses a light lavender workspace and the existing linked-N identity. Its main task is choosing a computer and establishing an explicitly authorized remote session. Gemini CLI supplied the layout prototype in `docs/design/0.4.0-desktop-prototype.html`; the native egui implementation retains real device, approval and session state.

| Role | Color |
| --- | --- |
| Primary actions | `#7850B2` |
| Selected text | `#684298` |
| Navigation | `#EEE8F8` |
| Canvas | `#F6F3FC` |
| Content | `#FFFFFF` |
| Text | `#2E2540` |
| Muted text | `#746783` |
| Border | `#DDD3EB` |

`config/ui-tokens.json` defines colors, spacing and type metrics. Desktop reads it directly; generated Web CSS and Android Compose adapters share it. Dark mode uses purple-tinted surfaces. System UI fonts include Chinese fallback. Navigation uses one custom outline icon vocabulary. Names and actions align left; visible scrollbars keep dense settings usable.

```text
[linked N] NestLink | Remote control                     account / window controls
Remote control     | [This computer · enrolled]                  Copy device ID
Services           |
My devices         | Your computers          | Connect to selected computer
                   | Search / refresh        | View / control
                   | [PC] Home workstation   | Audio / files / clipboard
                   | [PC] Office laptop      | Authorization / connection path
                   |                         | Connect device
Server / settings  | Pending requests and screen approval appear before the list
```

The default window is 1200×800. Wide content places devices beside a 300-point connection panel. Narrow content stacks them; the sidebar compacts below 900 points. Technical identifiers, lease and generation values appear in expandable diagnostics. Device enrollment is never presented as live presence.

After sign-in, the desktop loads device records and registers this installation once if absent. Existing and revoked identities are preserved. A browser request wakes the host automatically after access approval. Screen preparation and local approval happen before the controller requests the first short permit. Media still requires a verified permit and mutual endpoint proof.

`brand/icon.svg` is the source geometry. `scripts/generate-brand-icons.py` generates the multi-size ICO, PNG and installer artwork. The executable embeds the ICO; window and tray use the same colors and linked-N geometry. Candidate installers provide Simplified Chinese and English while preserving their installation and state identities. Upgrades must preserve existing private state.

Files, clipboard, keyboard/mouse, multiple displays and audio remain individually authorized. Formal signing and installed-device/cross-network acceptance are reported in release materials.
