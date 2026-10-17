# Native SDK directory browsing

`nestlink_sdk::browse` provides one fixed metadata snapshot on an already proved
native `ChannelRuntime`. It is excluded from WASM. FileRead permission and the
original connection generation are checked before attaching, before every page
request and again when the application consumes a reply. Metadata approval is
independent from file-content or destination approval.

```rust,ignore
use nestlink_sdk::browse::{NativeBrowseRequest, NativeDirectoryBrowse};

let request = NativeBrowseRequest::new(&approved_remote_root_id, None, 128)?;
let mut browse = NativeDirectoryBrowse::attach(
    &mut native_session.channels,
    proved_connection_generation,
    request,
)?;
let cancel = browse.control(); // Keep in the UI actor during a pending page.
let first = browse.ready().await?; // Consumed exactly once.
while let Some(page) = browse.next_page(128).await? {
    // Render or retain these already delivered metadata entries.
}
browse.release_client().await?;
```

`NativeBrowseRequest` accepts only an approved root UUID, an optional portable
relative directory and a page maximum of 1–128. Invalid local requests do not
claim a channel or consume a source cursor. `NativeDirectoryPage` contains the
root, directory, opaque snapshot identity, fixed total count, offset, entries and
`has_more`. It exposes no continuation token. The native platform's `BrowseCursor`
is a separate local Rust capability and is never imported into this SDK module
or serialized into a wire token. The actor alone owns the exact remote
`DirectoryBrowse` handle and its expected network continuation.

The caller needs a Tokio runtime. One owned asynchronous actor consumes the
initial BrowseBegin reply and each exact successor. No disk work runs in this
actor; the native provider uses its existing owned FileRead worker. A bounded
command slot and an atomic page-wait slot reject concurrent `next_page` calls
before a second operation enters the actor. Dropping a page wait makes local
cancellation sticky. It never drops an already issued lower-layer RPC or allows
its late response to satisfy another request. A fresh browse requires a fresh
UUID after exact source cleanup.

`cancel()` and `control.cancel()` immediately suppress further page delivery.
They carry no session-stop authority. The actor drains an outstanding Begin or
Next response, then sends the exact source Cancel when continuation remains.
`monitor.wait_finished()` separately waits for that owner to finish. Status
distinguishes pages actually received from pages delivered to the application,
an outstanding source request, requested/acknowledged Cancel, source failures,
cleanup failures and actual client retirement. `source_closed` means that a
matching final page, bounded business failure or Cancel response was consumed;
it does not claim that remote OS handles have already been destroyed.

The original SDK submission starts each page's at most 30-second delivery budget.
The fixed snapshot lifetime is at most 300 seconds from the initial submission.
`request.with_budgets` can lower both local bounds; it does not change the remote
selection's own, possibly tighter limits. Actor conversion and final application
consume check the original absolute deadlines. An on-time actor reply retained
until a late `ready()` cannot renew its budget. A deadline or authorization
failure suppresses delivery immediately while the actor continues exact cleanup.
Successful page progress never extends the original snapshot lifetime. A tighter
remote expiry or local metadata revocation returns its FileRead business failure
and permits viewing to continue. Bytes or metadata already returned to the
application cannot be recalled.

At completion or after cancellation, `take_client()` waits for exact cleanup and
returns `NativeBrowseClient`. Its `begin(request)` starts a fresh browse using
the original claimant, global sequence and permission binding. `start_download`
hands that same idle client to the SDK download actor, with separate local save
approval. `retire()` or guard Drop retires only FileRead after exact source
closure. The advanced `into_client()` transfers a raw client; ordinary raw-client
Drop retains its session-stop behavior.

When transport loss or revocation prevents an exact reply, the monitor does not
report acknowledged source cleanup. The guard refuses reuse and reports the
bounded cleanup error. Its Drop does not invoke protocol-failure retirement on
an unconsumed RPC, preserving an existing retryable network stop. An explicitly
revoked session or a genuinely invalid peer response still forbids recovery.
A freshly proved connection must start a fresh snapshot; old SDK handles and
network tokens cannot migrate into it.

The SDK fixtures exercise real encrypted TLS and QUIC, native approved roots,
pagination and same-claim downloads, independent content approval, mutation and
revocation, local/remote expiry, concurrent and abandoned page waits, slow source
cancellation, incorrect snapshots and network-recovery classification. They do
not constitute desktop/Android/Web UI integration, Android SAF or Web storage
adapters, real-device or cross-network product acceptance. Automatic discovery
and reconnecting a browse remain outside this facade.
