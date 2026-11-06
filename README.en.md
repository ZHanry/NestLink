# NestLink

**Private-network tunneling + remote desktop.** NestLink provides authorized access to internal HTTP, HTTPS, TCP and UDP services alongside remote desktop sessions. The supported clients are **Windows desktop and Web**. The NestLink name and existing logo remain unchanged.

[中文](README.md) · [GitHub build instructions](docs/refactor/CANDIDATE-BUILD.md) · [Remediation acceptance](docs/refactor/REMEDIATION-ACCEPTANCE.md) · [Changelog](CHANGELOG.md)

| Component | Targets | Deliverables |
| --- | --- | --- |
| Windows desktop | Windows 10/11 x64 | Desktop installer and optional privilege broker package |
| Web | Current stable Chrome / Edge / Firefox | Device management, private services and browser remote desktop |
| Linux backend | Ubuntu 24.04 x64 / ARM64 | Server DEBs and OCI image archives |

Windows registers the local computer, publishes private services and hosts remote desktops. The Web client manages devices and connects to authorized services and desktops. A shared Rust core handles identity, authorization, sessions, media, files and channels. Tunnels and remote sessions have separate permissions and lifetimes; access supports local approval, trusted devices and passwords.

Sign in with the server address, account and password. Server configuration is verified over HTTPS. Each device or browser login renews independently, and signing out ends only that login. Remote sessions use one initial authorization; screen, input, audio, files and clipboard permissions remain visible, and the host can stop the session at any time.

Remote desktop automatically prefers the physical network interface for direct connections. Authorized relay remains available when network conditions require it; the actual connection path must be reported honestly. Service publication includes source ACLs, quotas and revocation. See [server deployment](docs/refactor/SERVER.md) and [cross-network setup](docs/REMOTE-CONNECTION.md).

The current target is **0.8.1RC** (`0.8.1-rc.1`). See the [desktop redesign and upgrade notes](docs/RELEASE-0.8.1-RC.md). The Windows workspace uses the approved lilac design; login devices are account sessions, and file transfer lives within Remote Desktop. The [original network scope and acceptance records](docs/network-rewrite/RELEASE-0.8.0-RC.md) retain their actual failures and pending cases. UI publication authorization does not mark those cases passed. Release status and immutable artifact digests are recorded in GitHub Releases; local UI verification must use the fixed Windows bytes. Formal Windows, Linux update and OCI signatures remain unconfigured, and preview candidates are ineligible for production automatic updates.

All distribution builds and packaging run on GitHub Actions. User computers and deployment servers consume verified artifacts. One clean commit produces Windows, Web, backend, source, SBOM, licenses and build materials. [product-scope.json](config/product-scope.json) defines the current scope. Android sources, JNI, APK production and CI have been removed; old platform evidence remains historical.

The internal `v15` protocol and state namespaces remain separate from the public version. First-party source is Apache-2.0; upstream licenses remain in source and release materials.
