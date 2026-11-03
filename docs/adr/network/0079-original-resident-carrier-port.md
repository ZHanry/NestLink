# 0079 — Select an original resident port through its actual carrier

Date: 2026-11-03. Status: implemented; exact-source hosted qualification pending.
Scope: the original resident integration fixture's peer-address selection.

Full Rust run41562145692, exact source c5893625ebbe3b50406810bd7eb34c60cbbea849,
failed all four early Windows resident cases in 51.84s. Each fixed socket
diagnostic identifies peer_udp_bind with PermissionDenied / Os10013. The
fixture first bound TCP loopback port zero, obtained that TCP-selected port,
then tried to bind UDP at the same numeric address. All four failures occurred
at that second fixture operation, before the actual selected QUIC/TLS resident
listener was created. This now proves the failing operation; the historical
source4ec logs did not identify it and are not retroactively reconstructed.
The c589 focused run41562179075 separately passed all four cases on both OS.

TCP's successful bind does not establish UDP bind permission or availability
at that port. The logs do not record Windows's UDP excluded-port ranges or
other OS policy, so no particular exclusion, security product or port owner is
claimed as the cause. The error is not attributed to VP8 or platform ownership.

All three call sites already have a fixed carrier. The complete data/rebuild
case receives quic or tls; all eight management fence cases explicitly use
quic; the four pending cases explicitly alternate quic/tls. Resident::spawn
passes that transport and the same peer/listen address to both original CLI
processes. Original cleanup assertions physically rebind the selected carrier.
There is no requirement to reserve the same numeric port in both protocols.
Existing app-core native_offline tests also bind the standard UDP/TCP port-zero
APIs separately and select the address by the actual NativeOfflineTransport.

Keeping dual-protocol reservation would require a general search for a shared
available port, additional ownership and failure policy, none of which serves
these single-carrier cases. Reuse the standard OS port-zero allocator through
the selected UDP socket for quic or TCP listener for tls instead. The small
peer helper now requires the existing explicit transport and propagates every
bind/local-address error with its fixed diagnostic. Unsupported transports
fail InvalidInput. There is no retry, swallowed Os10013, new port range or
deadline change. The temporary socket is dropped before the unchanged actual
resident listener binds that selected address, as in the original handoff.

The original four names/counts, real initial/rebuilt pixels and files, EOF/IPC
Exit, pending stop/logout/identity behavior, physical rebind/cleanup assertions,
independent public-PKI HTTPS owner, ordinary Windows token, cumulative authority
and all timing gates remain. This source adjustment needs a newer complete
hosted matrix; a prior focused success does not qualify it. No local project
build, formatter, lint, test, Python execution or packaging was performed.

The final [sourcec589 complete Rust evidence](../../network-rewrite/evidence/full-rust-core-c589362.json)
preserves all four original Windows early `peer_udp_bind` Os10013 diagnostics,
the original failed result and independent artifact ZIP/digests. The same
source's [focused resident run](../../network-rewrite/evidence/native-offline-resident-c589362.json)
passes both original four-case suites and emits no socket-failure diagnostic.
These are separate observed results; the focused success does not reconstruct
the earlier OS cause or qualify the later carrier-selection fix in `00f5e7a`.
Both complete workspaces independently fail the four original resident setups
because their fresh job omitted the pinned original HTTPS fixture tool;
`dd8c39d` restores that prerequisite without changing the cases. A newer exact
source must execute the original complete matrix before claiming either
adjustment validated. The original 25-second Luanti failure stays unchanged.
