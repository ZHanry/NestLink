# Native directory metadata over FileRead

`DirectoryBrowseBegin`, `DirectoryBrowseNext` and `DirectoryBrowsePage` are
additive actions in `NativeFileRead` (tags 18, 19 and 20). They use the existing
proved, encrypted FileRead channel, FileRead permission, connection generation,
strict global request sequence, exclusive incoming claimant, and source UUID
accounting. They add no ambient filesystem authority and no channel. A peer
without FileRead permission cannot attach either file client or service.

The shared `FileReadClient` exposes `begin_browse`, `next_browse` and
`cancel_browse` alongside downloads. One client can alternate those operations
without retiring/reclaiming the channel. A `DirectoryBrowse` is a non-cloneable
handle tied to the exact client instance. Its current page is metadata already
delivered to that caller. `finished` means either a terminal failure/cancellation
or a page without continuation; it is not a file-content verification result.
An active browse must be completed or cancelled before retiring the client.
Cancelling a request future leaves the client's original in-flight marker set;
a late response cannot answer a replacement operation.

## Local authority and native provider

`BrowseRoots<D>` decorates an existing `FileReadDevice` with up to 16 independent
`BrowseSelection`s. Construction does not access disk. The existing owned file
worker lazily opens each locally selected root once, then clones that actual
directory handle for each new snapshot. Reusing a root ID or changing an ambient
pathname cannot cause a peer operation to reopen it. Local browse consent is
independent from content-read consent, even when both use the same display root
ID. Metadata-only approval never permits downloading a listed file.

The adapter retains the no-follow, same-filesystem, portable-name and fixed
metadata-snapshot rules in `native-directory-storage.md`. Every page rescans the
whole bounded target and requires equality with the original snapshot. An entry
that cannot be represented or safely inspected fails the whole page. No recursive
enumeration, content reads, hashes or ambient peer paths are involved.

## Requests, snapshots and cursors

Begin contains an approved root UUID, a directory (empty selects that root), and
a maximum of 1–128 entries. Nonempty directories use the existing portable
relative-path contract. A reply contains the exact root/directory, a 32-byte
opaque random snapshot identity, starting offset, fixed total count, sorted
single-component entries, and either an opaque 32-byte next cursor or no cursor.
Files have a bounded byte size; directories have no claimed content size.
Modification times use signed Unix milliseconds (sub-millisecond precision is
discarded) and are metadata rather than content identity.

The native adapter obtains snapshot and cursor tokens from OS randomness. It
retains one expected token and one private `BrowseCursor` per active source.
There is no growing token map. A token is usable only with its exact source UUID,
selected root instance, directory, fixed snapshot, next offset and original
connection generation. Taking a token out of that context, replaying a consumed
token under a later sequence, or using it after refresh fails. The remote client
also checks fixed total count, snapshot identity, exact offset, page maximum and
strict ordering between consecutive pages. It rejects a token handle belonging
to a different client without sending it.

An exact retry of the immediately preceding request may receive the cached
matching reply. A changed retry or a skipped global sequence is a protocol
violation. Retrying an old metadata page never extends its original operation
deadline or snapshot lifetime, and revocation/expiry replaces the sensitive
cached page with a bounded business failure.

## Disclosure deadlines and quotas

The first operation's original start caps snapshot lifetime at 300 seconds;
the native selection may set a shorter lifetime. Every operation is bounded by
the existing 30-second original request budget and any tighter local operation
budget. Native callbacks check the current FileRead lease/generation, local
consent and deadline around disk operations. These checks perform no disk I/O
inside the lease lock. Client decoding, exact response binding/action checks,
chunk verification and final result consume also recheck the same absolute
request deadline. The server's request decode, completed worker reply consume,
reply encode and bounded queue insertion use that deadline rather than starting
another timeout. A Tokio timer alone cannot preempt synchronous work; the
decode/consume fence checks both before and after it.

Every page carries a pure delivery guard through the worker reply, retry cache
and outgoing bounded queue. The TLS/WSS framed writer and QUIC reliable writer
recheck it after dequeue, immediately before starting the frame. A revoked or
expired queued page becomes the matching `FileReadDenied` or `FileReadChanged`
reply, with the same generation, UUID and sequence. Each writer also checks the
current lease. A queued page that expires abandons its source so the idle owned
worker retires its handles. Bytes already delivered to a peer cannot be
retracted. An OS call already blocked inside the kernel is not forcefully killed;
the existing file-worker monitor certifies actual resource destruction.

Downloads and browse snapshots share four active sources and 256 total UUIDs
per FileRead runtime. Completed, cancelled, failed and server capacity-rejected
IDs are tombstones. Client-side rejection before sending a new request consumes
no wire UUID; a server acceptance/failure does. Directory storage adds no extra
active pool: each active native snapshot is bounded to 4,096 entries and 1 MiB
of names, and each wire page remains within the existing 65,536-byte envelope.
There is no unbounded queue of worker replies or tokens.

Directory changes, stale cursors and deadlines report `FileReadChanged` and
require a new browse UUID. Denial, unavailable roots and capacity use the
existing bounded file failure codes. Business failures preserve View and other
approved channels. Invalid wire messages, sequence/generation violations and
addressing a download as a browse (or conversely) remain protocol failures.
Network I/O failures retain the transport's stop classification. A late stopped,
authorization or cleanup observation and an implicit owner Drop after a
retryable network stop add no new revocation. A live permission failure, actual
protocol failure or explicit later revocation still forbids recovery. Any
reconnection requires fresh proof and current authorization; an old browse or
cursor cannot migrate into it.

## Evidence and remaining product integration

Native platform tests and real local TLS/QUIC fixtures cover sorted pagination,
empty/final pages, child directories, downloads through the same client,
independent consent, metadata changes, exact retries, cursor replay/cross-source
and cross-client binding, original cursor expiry, permissions, and shared active
quotas. A bounded real AsyncWrite fixture holds the writer behind a preceding
frame and proves that revocation and original expiry are checked only when the
guarded page is actually dequeued, while View remains usable.
Additional remote tests cover synchronous decode crossing the original deadline,
completed worker results consumed too late, real queue BrokenPipe classification,
and retry eligibility after late stop observations and implicit teardown.

The native SDK facade is described in
[`native-sdk-directory-browse.md`](native-sdk-directory-browse.md). Daemon/GUI
selection flow and the desktop/Android/Web file browser remain unconnected.
Android SAF and Web storage require
their own approved-handle adapters. Local native fixtures do not constitute
formal Windows/Linux desktop, Android-device or cross-network acceptance.
# Approved root discovery

`NativeFileRead` has a `FileRootsRequest` action and a `FileRoots` response.
The response is a single bounded page (at most `FILE_READ_ROOTS`) of root IDs
and display names supplied by the host's local chooser. It never contains a
native path. Entries are unique and sorted by root ID. Root disclosure requires
the active local directory-metadata approval; the host checks that approval
again when the queued response is about to be written, and replaces a stale
response with a denial if any listed approval was revoked.

