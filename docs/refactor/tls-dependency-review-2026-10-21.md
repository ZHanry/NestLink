# Public TLS dependency repair, 2026-10-21

The exact-source dependency job for 3f335ce rejected RUSTSEC-2026-0381
(webpki-roots) and RUSTSEC-2026-0382 (rustls-webpki). The latter is updated
from 0.103.15 to 0.103.16. The only root bundle is now webpki-roots 1.0.10,
which removes the distrusted emSign root. No advisory exclusion was added.

The root 0.26.11 compatibility package came from tokio-tungstenite 0.29.0;
0.30.0 also still declares that old dependency. Its bundled-roots feature is
therefore disabled. The pinned 0.29 Rustls transport feature is enabled and
both production WSS connection paths supply an explicit Connector::Rustls
built from the patched 1.x roots. This keeps Android/Linux/Windows on the
same bundled public authorities without relying on platform certificate files.
Reqwest and hyper-rustls resolve to that same patched root bundle.

The public client configuration uses Rustls's normal certificate verifier,
server-name validation and safe protocol defaults. It does not use the
installation-key verifier intended for the inner relay TLS connection.
A real local TLS handshake test checks that an installation self-signed
certificate is rejected with UnknownIssuer. Existing pinned mutual TLS,
relay, node-control and SDK tests remain part of the required workspace suite.

Validation before CI: locked dependency tree contains only webpki-roots1.0.10
and rustls-webpki0.103.16. Full cargo-deny and cross-platform tests must pass
for the final source revision before building the next candidate.

The separately locked browser/native fixture is also synchronized to 0.7 path
packages, the same eefd2137 dependency fork, and the two patched TLS packages.
Its lock file must resolve with --locked before any fixture evidence is used.
