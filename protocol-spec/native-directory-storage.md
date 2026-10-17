# Local directory metadata capability

`nestlink-platform-files::browse` implements first-party local directory metadata
storage and one owned blocking worker. Its `browse::network` adapter also exposes
these checked snapshots through the FileRead protocol described in
[`native-directory-browse.md`](native-directory-browse.md). The native SDK flow
is described in [`native-sdk-directory-browse.md`](native-sdk-directory-browse.md);
desktop/Android/Web file-browser flows remain unconnected. A directory
selection does not grant file download or upload authority.

## Local consent and object selection

The local application chooses a UUID root ID, an absolute native directory path,
and optional lower limits. `BrowseSelection::new` performs no disk I/O. The
separate `BrowseConsent` owner must remain alive; revoking or dropping it
invalidates future work, existing cursors, and completed worker replies that have
not been delivered. The root ID and a peer-supplied relative path never supply
independent authority.

Opening the selection happens on the directory worker, or on an explicitly
blocking caller for the synchronous adapter. The local selection's parent is
opened with ambient authority and its final component is opened without
following links. The actual selected directory handle becomes the capability;
the original ambient pathname is never reopened for a peer operation. Locally
selected filesystem root paths are opened directly. The selection's trusted
local parent lookup is not itself a remotely supplied traversal.

`None` lists the selected root. Other target paths must be nonempty portable
UTF-8 relative paths under the existing file path contract. Each parent is opened
one validated component at a time, relative to the previous handle, with
no-follow semantics. Every returned directory must remain on the selected root's
filesystem. Symlinks, Windows reparse points, device/special files, and regular
files with multiple hard links are rejected. An unsupported, unreadable, or
nonportable entry fails the whole scan; no partial page or error containing that
entry's name is intentionally returned. This version does not silently skip
unsupported names. A listed child's full relative path must also fit the
existing file path depth and byte bounds.

Each file's metadata comes from its opened, regular single-link handle. On
Linux/Android it uses O_PATH to inspect metadata without acquiring file
content-read authority or invoking a device/FIFO's open behavior after a
type-changing race. Other Unix targets use NONBLOCK to avoid waiting for a FIFO
writer. On Windows it requests FILE_READ_ATTRIBUTES rather than
FILE_READ_DATA, with read sharing only. Root and active target directory handles
remain pinned. Only one entry metadata handle is held while scanning; this does
not pin every listed file against later changes.

## Fixed metadata snapshot and pages

The data model distinguishes files from directories. A file has a byte size;
a directory has no claimed content length. Both have a portable single-component
name and a modification timestamp. Entry order is stable UTF-8 lexical order.

The entire bounded directory is scanned before the first page. The adapter
checks current caller authority, local consent, and the original operation
deadline around platform calls. It records the selected target's device/inode,
link count, size, and modification time, plus each entry's name, type and handle
metadata. It compares the target metadata before and after each scan, and rejects
duplicate names observed during enumeration.

Before every page, including the first, the adapter rescans the complete bounded
directory and requires exact equality with the original metadata snapshot.
Observed entry additions/removals, identity/type/size/timestamp changes, or target
changes fail with `InvalidData` and require a fresh browse. A failed next request
retires the snapshot. Starting a new browse replaces the previous snapshot. The
adapter never silently mixes old and new metadata in one browse.

This is a checked metadata snapshot, not an OS transactional directory snapshot
or a content digest. Changes made and then completely restored between observed
metadata reads may not be detectable. Downloading a listed file must still use
the file-read manifest, opened source, and full checksum protocol. Metadata
already delivered to the caller cannot be retracted by later revocation.

`BrowseCursor` is an opaque local Rust capability, bound by private identity to
the actual root instance, one fixed snapshot, and the expected next offset. A
different root with the same ID/path cannot use it. Replay, stale offsets and
pre-refresh cursors are rejected. It is not a serialized network token. A remote
adapter must retain a bounded expected token and bind it to the current lease,
session/resource identity, connection generation and protocol sequence. The
native network adapter keeps one expected token per active source.

## Hard resource bounds

| Resource | Hard upper bound |
| --- | --- |
| Roots per worker | 1 |
| Active snapshots per root | 1 |
| Pending/running worker operations or retained replies | 1 |
| Entries in a full scan | 4,096 |
| Total entry name bytes in a full scan | 1,048,576 |
| Entries in a returned page | 128 |
| Entry component bytes | Existing portable path limit: 255 |
| Operation budget | 30 seconds from the original submission/start |
| Cursor lifetime | 300 seconds from the original snapshot start |
| Cleanup observation budget | 250 milliseconds |

The local application can lower entry, name byte, operation and cursor bounds;
it cannot raise them. An oversized directory fails the whole operation rather
than appearing as a truncated complete list. Full revalidation needs at most two
bounded vectors of entry metadata/names in addition to one bounded returned page.
There is no recursive scan and no file-content read. Paging progress never
renews the snapshot's fixed lifetime or the operation's original budget.

## Owned worker and truthful teardown

`DirectoryWorker::start` accepts a local selection and a thread-safe current
authority check. The caller must bind this check to the current FileRead/session
authorization and connection generation. It must be short and perform no disk
I/O. A failure of this check makes this worker terminal even if the callback
later returns success. It does not stop the caller's viewing/input session.

One owned std thread opens, enumerates, validates and destroys the directory
handles. Submission and `BrowseTicket::try_result` never wait on disk or a
running thread. They only run the short authorization check, local atomics, and
nonblocking message operations. Idle workers recheck authority/consent at most
every 50 milliseconds. Every operation gets a unique reply channel; a cancelled
ticket's late result cannot answer a replacement request. A work slot remains
occupied until the actual operation has ended and the corresponding result has
been consumed or dropped. There is no accumulating queue of completed pages.

The ticket checks current authorization, root consent, worker cancellation and
the original deadline before and after consuming a reply. A completed page also
retains the snapshot's original lifetime; the final delivery check rejects a
stored reply that has outlived that fixed deadline. Revocation or timeout
suppresses sensitive result delivery even when the blocking OS operation has not
returned yet. A network integration must recheck authority again at actual
outbound send; a local page is not a permanent authorization token.

`stop` requests termination. `poll_shutdown` never joins a running thread and
reports Waiting/TimedOut/Finished. Dropping the worker requests stop and detaches
an unfinished thread. `DirectoryMonitor` records actual root opening, actual
owned handle destruction, completed/failed operations and sticky cleanup
timeout. A delayed operation cannot be falsely reported as cleaned up at the
250-millisecond boundary. If it finishes later, both `handles_closed` and the
earlier `cleanup_timed_out` remain true. The monitor's `finished` field means
that the owned root, snapshot and iterator handles have been destroyed. Native
thread exit is certified separately: `poll_shutdown` returns Finished only after
observing `JoinHandle::is_finished` and joining that already-ended thread.
No attempt is made to kill a thread inside a blocking OS call.

## Integration still required

The native remote adapter now supplies protobuf validation, FileRead routing,
strict sequencing, permission/generation binding, bounded serialized cursor
handling, shared resource quotas, and actual-send consent/deadline checks.
UI selection and browsing, refresh/error presentation, Android SAF and Web
storage adapters, and formal platform/network acceptance remain required. The
local fixture tests are evidence for this adapter and worker only; they do not
constitute a complete product browser or formal multi-platform acceptance.
