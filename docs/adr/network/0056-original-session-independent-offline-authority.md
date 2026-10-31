# Independent offline authority in the original remote Session

Finite remote control must preserve existing endpoint proof, queues, channel
permissions, input generations, file consent, cleanup and direct QUIC handling.
Creating a parallel remote protocol would duplicate those controls. Re-signing
or changing an old online permit would incorrectly extend an online lease.

The original Session now accepts a separate, already consumed offline admission
owner. Its unchanged verified online permit is retained only for exact original
device/resource/capability and local source metadata. The independent complete
offline bundle supplies permissions, direct-only path, deadline and cumulative
bytes/file/connection budgets. Native endpoint proof binds the offline digest,
and every business delivery charges the original admission. Online permit
renewal, online reconnection export and online input-permit export are rejected.

The SDK accepts only its opaque authenticated online-consume receipt. Before
opening the existing native QUIC channel queues, both endpoints prove their
installation keys and their original in-memory ephemeral process keys over fresh
challenges. That proof reuses the existing private-service offline proof code;
the two businesses remain isolated by their complete signed bundle digests and
different QUIC ALPNs. Only exact mutually pinned direct peers are accepted.

The original owner can retain its cumulative budget after transport loss. Each
new attempt spends another original connection reservation and requires fresh
process and native endpoint proof. Explicit stop, process loss, deadline,
quota exhaustion and received revocation are terminal. The SDK observes central
recovery and retires offline channels before returning to current online
authorization; it never quietly replaces an offline reservation with a renewed
online permit. Recovery does not promise retroactive central revocation while
the center is unreachable.

Hosted source tests cover the independent Session after online expiry, denied
extra operation/relay/export/renewal, retained counters, and real two-account
HTTP approval/consume followed by management socket closure, online expiry,
process proof, original QUIC frame delivery, process stop and UDP rebind.
The source still requires hosted validation. Full native media/input/file OS
adapters, TLS fallback, resident UI and target-device acceptance remain open.
