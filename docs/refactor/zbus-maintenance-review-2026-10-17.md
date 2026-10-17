# Linux D-Bus maintenance advisory review (2026-10-17)

The dependency job in [Rust core run 39046720983](https://github.com/ZHanry/NestLink/actions/runs/39046720983)
failed on three RustSec advisories published on 2026-10-16. The failed run remains
failed. Its bans, licenses and sources checks passed. This review records the
disposition of the maintenance notices; it does not establish a successful audit.

| Advisory | Locked crate | Cargo.lock archive SHA-256 |
| --- | --- | --- |
| [RUSTSEC-2026-0370](https://rustsec.org/advisories/RUSTSEC-2026-0370) | zvariant 5.15.0 | `c1d34c27cc6cdd1f458427519dd6b8612f7b7e3f7b9a0b2355d041dda9869147` |
| [RUSTSEC-2026-0371](https://rustsec.org/advisories/RUSTSEC-2026-0371) | zbus_names 4.3.4 | `d8bf88b4a3ff53e883001e0e0115b297a9d53c31b9c1edd2bfdd853e3428624e` |
| [RUSTSEC-2026-0372](https://rustsec.org/advisories/RUSTSEC-2026-0372) | zvariant_derive 5.15.0 | `864155e69b4352db0c7f374917bf45d1e0c8d17659c8b3dbf9795f3673f8c497` |

All three advisory records use `informational = "unmaintained"` and have no
patched versions. They identify no concrete vulnerability. The upstream
[post-6.0 release issue](https://github.com/z-galaxy/zbus/issues/2043) confirms
that these standalone crates were merged into the names, wire and derive APIs
of zbus 6. The final standalone releases document that transition; updating to
those releases would not clear these notices.

`cargo tree --locked --target all --invert zbus_names --edges normal,build`
and the corresponding zvariant query show two retained paths:

- NestLink's Linux clipboard, capture, file, input, audio, session and tray
  backends explicitly use zbus 5.19.0, which depends on both crates and their
  derive macros.
- eframe 0.34.3 reaches AccessKit Unix 0.21.1 through egui-winit 0.34.3 and
  accesskit_winit 0.32.2. Its AT-SPI stack (including atspi-common 0.13.0) also
  requires the standalone zbus 5 types. Those are part of the desktop's
  accessibility support.

Replacing only NestLink's direct zbus requirements with version 6 would leave
the AccessKit path. A complete migration also requires compatible AT-SPI and
AccessKit releases and validation of the portal, session, input, clipboard,
audio and tray backends. The new merged APIs are a major-version migration,
not a compatible replacement under the current requirements.

For this development RC, `deny.toml` therefore ignores only these three
individually reviewed advisory IDs. Cargo.lock, package versions, checksums,
licenses and enabled accessibility features remain unchanged. The global
maintenance policy, vulnerability checks and all other dependency checks remain
enabled; any future vulnerability advisory has a separate ID and remains
blocking. This exception does not claim these crates are still maintained.

Recheck the exact graph whenever zbus, AccessKit, AT-SPI or their users change.
Before a stable release, migrate the complete graph to maintained replacements,
remove these exceptions, and repeat the Linux integration and accessibility
checks. Final audit results are recorded with the RC validation materials.
