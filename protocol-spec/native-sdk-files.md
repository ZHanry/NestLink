# Native SDK file downloads

`nestlink_sdk::files` provides a native Rust application flow on a mutually
proved `ChannelRuntime`. It is excluded from WASM. Its source is an approved
remote root ID plus a validated portable relative path; its destination is an
independent `FileDestinationFactory` selected and approved by the local user.
The SDK does not turn the remote file name into an ambient local save path.

```rust,ignore
use nestlink_sdk::files::{NativeDownloadRequest, NativeFileDownload};
use nestlink_platform_files::download::LocalDownloadSelection;

// Keep save_consent alive until the user's local save approval ends.
let (selection, save_consent) = LocalDownloadSelection::new(
    &local_fresh_private_area,
    "chosen-local-name.bin",
    local_size_limit,
)?;
let request = NativeDownloadRequest::new(&approved_remote_root_id, "folder/file.bin")?;
let mut download = NativeFileDownload::attach(
    &mut native_session.channels,
    proved_connection_generation,
    request,
    selection,
)?;
let monitor = download.monitor();
let file_control = download.control(); // Retain in the application's UI actor.
download.ready().await?;
download.download_to_end().await?;
download.release_client().await?; // Retires FileRead; viewing remains authorized.
```

The calling application must have a Tokio runtime. The SDK's owned asynchronous
actor consumes each source operation's exact response. Disk initialization,
bounded writes, prefix rereads, hashing, publication and temporary cleanup run
on `FileDownloadWorker`'s owned standard thread, outside Tokio and authorization
locks. Neither progress observation nor a pure local consent check reads disk.

`pull()` waits for one at most 61,440-byte source chunk and its disk write before
another pull is allowed. Each command has a separate response channel. The
source RPC and disk operation keep their original lower-layer budgets. Dropping
an application command wait does not abandon a source RPC; it leaves the handle
requiring an acknowledged `pause()` before another data command. A later reply
cannot satisfy a replacement command. An invalid local request is rejected
before opening a native channel or sending a file request.

`received_bytes` reports source progress. `destination.destination.confirmed_bytes`
reports the provider's actual confirmed disk prefix. They may differ after a
pause or cancellation. `source_verified` is true only after the matching End
was consumed; `finish()` then verifies and publishes through the destination.
Publication, file close, temporary removal, directory synchronization, poisoned
state, thread completion, cleanup errors and sticky cleanup timeout remain
separate observable facts. A published file is still reported as published
when a subsequent close or cleanup operation fails.

An application may call `file_control.cancel()` while awaiting a source reply
or a disk call. The actor first requests destination shutdown. `cancel()`
returns its bounded local stop receipt without waiting for a remote Cancel
reply. It consumes a source request already issued before sending the exact
file Cancel. This does not call the session's stop API. An underlying transport
timeout or invalid peer response can still stop the session according to its
ordinary contract; the SDK reports that failure. `monitor.wait_finished()`
waits separately for the source owner to return and the destination thread's
actual completion. It does not turn a cleanup timeout into successful cleanup.

`pause()` waits for a destination idle barrier and for the old source's precise
End/Cancel/failure fact. It retains the actual partial only while the worker's
local consent and current authorization permit it. `resume(None)` reopens the
same root/path on the live client. `resume(Some(fresh_client))` uses a newly
proved connection. Both open a fresh transfer UUID at the actual confirmed disk
prefix with the original complete SHA-256. The worker additionally checks the
unchanged signed scope, original source, content identity, connection ownership
and real disk prefix before releasing the pause. An extra pause/cancellation
revision cannot be overwritten by a late resume reply. Rejected candidates are
cancelled exactly and safely retired; they cannot replace the original client.

`source_attempts` retains bounded per-attempt End, Cancel, failure and client
retirement facts, including rejected successors. A successful resume does not
erase an earlier cleanup failure. The flow permits at most `FILE_READ_TRANSFERS`
source attempts across connections, bounding retained metadata.

At a terminal transfer state, `take_client()` waits for precise source cleanup
and returns a `NativeDownloadClient` guard. Its `start(request, destination)`
reuses the original FileRead claim, sequence and owner for another transfer on
the same live connection. Dropping the guard or calling `retire()` permanently
retires only that claimed FileRead consumer after lower-layer verification that
there are no unconsumed requests or open remote transfers. `release_client()`
is the direct retirement convenience. Retirement errors remain observable and
are returned by explicit retirement. The advanced `into_client()` transfers
ownership to another raw client owner; raw client/receiver Drop retains the
ordinary session-stop semantics, so applications should use the guard for
routine file completion and cancellation.

This is an application SDK flow and native storage adapter integration. It
does not implement a GUI, uploads, directory browsing, Android SAF, browser
storage, durable restart recovery, native connection discovery or automatic
reconnection. SDK fixture checks use local encrypted TLS/QUIC and controlled
faults; they are development checks, not real-device, cross-network or whole
product acceptance.
