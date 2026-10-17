# NestLink Web

The Leptos application builds to a static site served by the Caddy file server at `/usr/share/nestlink/web`.

For a release bundle, install the `wasm32-unknown-unknown` Rust target, Trunk 0.21.14, and `wasm-bindgen-cli` 0.2.129, then run from this directory:

```sh
trunk build --release
```

The output is `dist/`. The pinned production build and artifact-structure check run in [web-build.yml](../../.github/workflows/web-build.yml). Deploy the generated files from one fixed CI run; do not rebuild them on the server.

The application provides the authenticated management workbench and a browser remote-control flow. Each deployment/account scope keeps one persistent controller installation: its Ed25519 seed is encrypted with a non-extractable WebCrypto key in IndexedDB and its registered device remains revocable through device management. Reloads and concurrent tabs reuse that identity; damaged or revoked records fail closed. Each remote request separately uses host approval, explicit existing trusted-device approval, or a password bound to the displayed request and host configuration revision. It obtains a verified short-lived permit and uses the managed peer in `src/browser_peer.rs`. It exchanges signed SDP, verifies the permitted direct or trusted TURN path, presents video/audio tracks, sends approved keyboard/pointer/text input, and stops on cancellation or expiry. Answer signaling binds to the exact offer sequence; each endpoint owns its local network generation.

The page implements directory browsing, selected-file upload, digest-verified private downloads, and two-step text clipboard delivery over four separately authorized DataChannels. Each local direction starts disabled. A browser-managed Web Lock protects private storage across tabs and permits bounded recovery of abandoned implementation-owned directories after a page dies. Failed disk cleanup or unconfirmed server revocation retains the original owner for explicit retry. See [browser business data](../../docs/refactor/WEB-BUSINESS.md) and the [WebRTC contract](../../protocol-spec/browser-webrtc.md) for the implementation and current verification boundary.

Connect using the server origin and account password. HTTPS discovers server metadata before a fresh signed identity challenge. The account-security page provides password change with sign-out and explicit login refresh. TOTP and recovery codes were removed in 0.2.0. Wrong reauthentication preserves a still-valid login after checking the server; uncertain writes are reported without an application retry. Remote controls include fullscreen entry/exit and observe external native fullscreen changes.

Historical 0.1 validation: production release site builds and full WASM all-target strict Clippy passed. Current stable Chrome, Edge and stock Firefox development runs cover the frozen production entry and protected persistent browser identity, including reload/concurrent-tab reuse, account separation and tamper rejection. A separate real HTTPS/control-server Chrome probe passed nine production UI security cases covering sign-in, trusted/password access boundaries, fullscreen, TOTP/recovery codes and password-change revocation. Its precise scope, retained failed attempts and physical Escape limitation are in [Web security verification](../../docs/refactor/WEB-SECURITY-VERIFICATION.md); the [current verification index](../../docs/refactor/current-verification-2026-10-17.json) binds source and artifact evidence. Native SDK tests also exercised the real proved SCTP file and clipboard services. Installed browser-to-host acceptance, platform signing, accessibility and external-network/TURN reachability remain pending; the local development results do not establish those outcomes.
