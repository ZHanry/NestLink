# Retain redacted native connection history outside the live session

Status: partial W29 source implementation; hosted formatting, compilation and
tests pending. This does not complete AC49/AC50 or service/browser diagnostics.

The native Core already exposes an original-session quality projection. The
desktop shows it while connected, but replacing the snapshot or closing a failed
session could remove the user's only explanation of a failure. GPU and browser
diagnostics already have separate bounded recorders; their measurements do not
substitute for native connection observations.

Two alternatives were considered: serialize the entire Core Snapshot, or project
only explicit diagnostic fields into the existing bounded-history pattern. A
Snapshot contains account information, device names, addresses and local consent,
so the latter is used. No general logging framework or second network observer
is introduced. The recorder cannot dial, choose a route, extend a lease or stop
any owner.

`apps/desktop/src/network_diagnostics.rs` reads the existing Core session,
generation, terminal reason and sanitized quality. Request and PathGrant IDs are
SHA-256 correlations using the existing protocol helper. Grant bytes, server
addresses, public keys, local prefixes, file contents, screen data and arbitrary
errors are excluded. Route preferences are not reported as actual authorization
or observed routes. Missing quality, network generation, MTU, queue delay and
outer VPN route remain null. RTT change and packet-loss counters retain the
original measurement semantics; they are not one-way jitter or a loss estimate.

The recorder retains at most 128 events and one independent latest terminal
event. Repeated quality is sampled at most once per second; lifecycle changes
are recorded immediately. Losing daemon IPC records source loss without sampling
the stale Snapshot. The last terminal record survives subsequent live sessions
and ring eviction in this desktop process. Local monotonic elapsed time and an
event sequence establish local order, not cross-machine latency. The desktop
does not automatically deserialize historical files into live observations.

The existing private-metadata writer persists at most 256 KiB to
`native-network-diagnostics.json` in the installation directory. A write failure
keeps the in-memory report and a fixed failure label; it never changes network
or media behavior. The desktop's More menu exposes **Copy connection
diagnostics** after either success or failure, including after daemon disconnect.

Actions must exercise redaction with private source values, null unknowns,
disconnected IPC, terminal retention and bounded history. Complete W29 still
requires service/browser event correlation, full route-policy/forward-node and
first-frame/recovery coverage, and target failure/export evidence.
