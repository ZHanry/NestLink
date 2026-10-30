# Browser lab scope and current engines

W17 / AC27 / AC28 retain the existing production browser WebRTC, deployment
ICE/TURN configuration, signed signaling and permit lifecycle. The actual
Web/native integration already exercises a 36-second VP8/Opus session, trusted
input, owned file transfer, permit renewals, authority revocation and physical
process/socket/database cleanup. Those results are owned Linux loopback
integration, not installed Windows or independent NAT acceptance.

The Actions integration now runs independently against Chrome and Microsoft
Edge. The production release site is built once by the same workflow, then each
engine receives that artifact and builds the native fixture from the same SHA.
Every case, media threshold, response-owner check and cleanup requirement is
identical. Engine failures do not cancel the other engine. No Chromium result
is relabeled as Firefox.

Chrome uses the GitHub runner's stable binary; the actual browser version and
executable SHA-256 are retained. Edge is stable 156.0.4314.56, published
2026-10-29. Its Linux amd64 Debian package was selected from Microsoft's official
release metadata at <https://edgeupdates.microsoft.com/api/products>. The
package URL is
<https://packages.microsoft.com/repos/edge/pool/main/m/microsoft-edge-stable/microsoft-edge-stable_156.0.4314.56-1_amd64.deb>.
Microsoft's SHA-256 is
`808447677313fda7bb2b74a9428734d193a0b3d1d8308844ce29144fde6e2b82`.
Actions verifies that digest before extracting with the existing Debian tool;
package installation hooks are never needed. Puppeteer remains the existing
reviewed 25.14.0 runtime. The private profile trusts only the exact owned TLS
leaf SPKI. The runner records the requested product, checks the browser's
actual product user agent, and refuses mismatches before qualification.

These new sources require Actions results. Firefox stable, managed TURN on
independent networks, ICE restart under an actual network change and the
remaining AC27/AC28 target cases are still required. The existing Firefox
tool entry remains available, but this new CI matrix does not qualify it.
