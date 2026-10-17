# Production Web security workflow check

On 2026-10-17, the focused production UI probe passed all nine selected cases in
14.628 seconds using Windows Chrome 155.0.8059.82, Node 20.19.5 and the reviewed
Playwright Core 1.64.1. The probe is
[`refactor-web-security-check.cjs`](../../scripts/refactor-web-security-check.cjs).
It uses the actual production Leptos/WASM page, shared SDK and a real control
server initialized through the public CLI. It does not replace API success
responses or invoke the separate verification binary.

The final originals are:

- `artifacts/core-verification/web-security-ui-20261017-attempt12.json`, SHA-256
  `cb016cf7cb1dc2895e1e450556f7ba222c22029b0a382efd4a4b004a8378b6c0`.
- `artifacts/core-verification/web-security-ui-20261017-attempt12.log`, SHA-256
  `70730f422b6932951c8ad6aba8b713f87330032007a40a439f28bae354e245c0`.
- `artifacts/core-verification/web-security-ui-20261017-attempt12.receipt.json`,
  SHA-256 `d8f314dce9732e1f13861e906251b1a519d6be83118c95fa252f875558df42e9`.

The command receipt covers 1,061 selected inputs under `apps/web`, `apps/server`,
`crates`, `protocol-spec` and the probe, together with the workspace manifests.
Their before/after fingerprints were identical. The production static files were
also hashed before and after, independently of the source fingerprint. Their
bytes and the server executable stayed unchanged. The exact server executable
SHA-256 was `ea2a02861e2b251d5f6bb4e00d6a563d414792926b78c8ef166a31e3dc284899`.
These results bind the recorded development artifacts, not a later release build.

## Exercised behavior

The nine cases cover:

- Independent deployment pin verification and real account sign-in.
- Explicit trusted-device access rejection without silently creating a manual
  approval request, removal of its cleanup owner, and a successful later manual
  request followed by actual server revocation.
- Real fullscreen entry, exit through the toolbar and observation of an external
  native `document.exitFullscreen()` call.
- Refusal to send a password after its displayed host configuration revision
  changes; incorrect remote password rejection and request revocation.
- A real successful password authorization whose response body is truncated
  after the backend commits. The application does not repeat that submission,
  and it confirms revocation through the real DELETE endpoint.
- Failed account reauthentication followed by `/auth/me` verification, retaining
  the still-valid workspace.
- Actual TOTP enrollment/confirmation, ten distinct recovery codes, clearing
  one-time material on navigation and dismissal, and authenticated recovery-code
  replacement.
- Local rejection of mismatched new-password confirmation; actual password change
  and sign-out; rejection of the previous login session and password; successful
  login with the replacement password and a recovery code; explicit login refresh.

The new host is enrolled with its own Ed25519 installation key through the real
challenge and device APIs. Its password configuration is signed with that key.
Random 63-bit security epochs are retained exactly as integers in the Node probe;
ordinary JavaScript JSON number rounding is not used in signed claims.

## Isolation and limits

Each run creates a fresh private directory, new deployment, bootstrap account,
host identity, HTTPS certificate and Chromium profile. The deployment trust pin
is independently derived from only that run's newly created DPAPI-protected
permit key. Only the temporary leaf certificate's SPKI is excepted in the owned
browser launch. System trust stores and normal browser profiles are untouched.
The temporary bootstrap password file is private and removed after CLI bootstrap.
Reports contain method/path/status observations and public fingerprints; API
bodies, console text, screenshots and exception text are excluded. Browser,
control process and HTTPS owner all stopped, and both the probe's scratch and the
outer command wrapper's scratch were removed.

Attempts 01–11 are retained. Early failures arose while adapting the probe's
PowerShell/ACL setup, UUID/signature encoding and asynchronous assertions. In
attempt10, headless Chromium's CDP Escape key did not invoke the browser default
fullscreen exit. The final probe verifies real external native fullscreen exit;
physical Escape remains an installed-product acceptance item. Attempt11 also
preserves Chromium's transport retry when an entire POST response is lost before
headers: the first authorization committed, the backend rejected the repeated
authorization, and cleanup revoked it. The final fault sends the genuine backend
headers and first body byte before interruption to observe application behavior
after response reading begins. No successful backend result is fabricated.

This is a local Chrome development check. It does not establish Caddy/ACME,
cross-network, installed host media/input, physical keyboard, accessibility,
other browser engines, platform signing or complete fixed-release acceptance.
