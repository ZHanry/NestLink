# NestLink

Self-hosted remote control and service publishing. The current version is **0.1.0 RC1** (`0.1.0-rc.1`), published from a new repository with fresh Git history and a single `main` branch.

[中文](README.md) · [Releases](https://github.com/ZHanry/NestLink/releases) · [Build instructions](docs/refactor/CANDIDATE-BUILD.md) · [Implementation and checks](docs/refactor/IMPLEMENTATION.md)

A shared Rust core handles device identity, authorization, sessions, media, files and service channels. The desktop uses egui, Android uses Kotlin/JNI, and the Web application uses Leptos/WASM. Remote sessions and service publications have separate approvals and lifetimes. Connection authorization supports local approval, trusted devices and passwords.

| Platform | Targets | Deliverables |
| --- | --- | --- |
| Windows x64 | Windows 10/11 | Desktop installer and optional privilege broker package |
| Linux x64 / ARM64 | Ubuntu 24.04, X11 / GNOME / KDE | Desktop and server DEBs |
| Android ARM64 / x86_64 | Android 11–16, API 30–36 | Separate ABI APKs |
| Web | Current stable Chrome / Edge / Firefox | Management, browser remote control and static site |
| Server / OCI | Linux x64 / ARM64 | Server packages and native architecture OCI archives |

Screen, input, multiple displays, audio, files and text clipboard directions require explicit authorization. HTTP, HTTPS, TCP and UDP publications include source ACLs, quotas and revocation. See the [server documentation](docs/refactor/SERVER.md) for deployment.

This RC is for subsequent real-world acceptance. Windows packages currently have no Authenticode identity; Android uses a development signer and the isolated `com.zhanry.nestlink.candidate` application ID. Fixed release signing, ARM64 hardware, installed desktops and external networks remain pending. Verify the release SHA-256 values and fixed source manifest before testing.

The build workflow produces every platform, source, SBOM, licenses and materials from one clean commit. The internal `v15` protocol and state namespaces remain separate from the public product version. First-party source is Apache-2.0; upstream license texts remain in their source directories and release materials.
