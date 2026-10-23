# NestLink 0.7.0 RC product design

NestLink provides intranet tunneling and remote desktop through Windows and Web clients. The 2026-10-23 redesign follows a Gemini CLI proposal reviewed against actual capabilities; see `docs/design/2026-10-23-workspace.md`. Preserve the existing purple linked-N assets byte for byte and never recolor the logo with the current theme.

| Role | Color |
| --- | --- |
| Primary actions | `#7850B2` |
| Selected text | `#653F9B` |
| Navigation | `#ECEEF3` |
| Canvas | `#F4F6F9` |
| Content | `#FFFFFF` |
| Text | `#14171F` |
| Muted text | `#525B6C` |
| Border | `#858DA0` |

`config/ui-tokens.json` defines colors, spacing and type metrics. Windows reads it directly and Web uses its generated CSS adapter. Use installed Segoe UI and Chinese fallback fonts. Names and actions align left; independently scrolling details preserve fixed action areas. Builds and installers are produced on GitHub.

```text
[linked N] NestLink | Remote desktop                     account / window controls
Remote desktop     | Fixed local status and session actions
Intranet tunneling | Device list           | Connection workspace
Devices            | Search / refresh      | Authorized capabilities and state
                   |                       | Fixed connection action area
Server / settings  | Scrolling details, fixed header and footer
```

The default window is 1200×800, usable from 760×560. Device selection and connection details form a workspace; tunnel entrances, targets, protocols and actions form the other primary task. Device enrollment is never presented as live presence. Show direct or relay only after actual path selection. Long names, errors and refreshes must not move pointer targets.

After sign-in, the desktop loads device records and registers this installation once if absent. Existing and revoked identities are preserved. One initial session authorization covers the selected desktop permissions; there is no second NestLink screen approval. Media still requires a verified permit and mutual endpoint proof. Revocation and input cleanup remain mandatory.

`brand/icon.svg` is the source geometry. `scripts/generate-brand-icons.py` generates the multi-size ICO, PNG and installer artwork. The executable embeds the ICO; window and tray use the same colors and linked-N geometry. Candidate installers provide Simplified Chinese and English while preserving their installation and state identities. Upgrades must preserve existing private state.

Files, clipboard, keyboard/mouse, multiple displays and audio remain individually authorized. Formal signing and installed-device/cross-network acceptance are reported in release materials.
