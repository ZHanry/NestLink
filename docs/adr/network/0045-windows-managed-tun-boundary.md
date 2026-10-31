# ADR 0045: Shared packet owner and Windows Wintun privilege boundary

Status: common owner, Windows provider/CLI/NetIO lifecycle and dedicated native workflow are implemented in source; hosted compilation and native qualification are pending. No Windows TUN acceptance or completed W22 claim.

Date: 2026-10-31. Applies to W22 and subsequent subnet/WireGuard adapters. R01/R02 apply.

## Frozen interfaces

The ordinary owner remains the only owner of protected login recovery, installation identity, one-use online start, pinned physical mTLS carrier, packet ACL, reply state, cumulative budget and current authority observations. It stops the original business on logout, maintenance, observation loss, revocation, original expiry or OS/provider failure. No administrator process opens a SessionStore or connects to a management or peer network endpoint.

`TunPlan` advances to schema 2 before this unreleased implementation is published. Its existing bounded public signed grant, digest, peer pair, exact local/remote IPv4/IPv6 hosts, original process identity and finite lifetime remain common. The former bare Linux UID becomes an explicitly tagged `principal`: Linux captures the original ordinary UID; Windows captures SID, interactive session and original executable volume/file index. A helper must compare these values with actual OS facts, exact original process incarnation and the protected installed executable. Cross-platform principals are rejected by the platform's parser. The Linux helper retains its current exclusive queue and durable journal ordering.

The shared ordinary packet-device boundary consists only of whole-packet `recv`, bounded whole-packet `send` and terminal `shutdown`. Linux uses the reviewed `tun-rs::AsyncDevice` directly. Windows uses a bounded authenticated local pipe to a separate minimal administrative provider owner. Both feed the same ordinary `OnlinePacketAccess` and existing carrier codec. A descriptor/pipe reconnect cannot create a new packet budget or retry a consumed start.

The Windows IPC binding captures the original ordinary `ProcessIdentity` from the existing privileged WFP process primitives, owner UUID, SHA256 of the exact common plan and original expiry. A protected administrator receipt binds that object to the original high-integrity helper, pipe and actual adapter identity. The ordinary client checks the protected receipt and OS-reported pipe server PID against the original helper incarnation; the helper checks the OS-reported pipe client PID/token/session/incarnation/image against the original ordinary process. A pathname, owner UUID or same SID alone is insufficient.

The pipe has one local instance, protected DACL, no remote clients and bounded buffers. Its handshake binds the exact original plan. Frames contain a two-byte length and one complete IP packet, at most 1280 bytes. Reader progress survives async cancellation, including cancellation of a partial header or body by the ordinary packet loop's timers. An interrupted/failed write poisons the stream; it cannot be retried or resumed as a fresh request. There is no unbounded packet queue, alternate login, broker input capability or network listener in this adapter.

Windows helper OS state records the actual GUID/LUID/index, root-generated fresh identity, MTU, exact addresses and host routes. It never adopts an existing named adapter, replaces a default/foreign route, changes DNS/forwarding, enables `delete_driver`, or deletes a shared Wintun driver. Cleanup and recovery compare the original protected resource identity before removal and confirm physical absence; external replacements are preserved with the failed journal.

The helper journals a fresh random adapter GUID/name before loading the provider. It records actual identity before assigning addresses, isolates only that original adapter with forwarding/weak-host/router discovery/link-local autoconfiguration disabled, and records the exact dual-stack address/route/family snapshot before accepting packets. NetIO observations use bounded allocated tables with RAII `FreeMibTable` and retained stable fields; volatile counters and route age cannot produce false ownership changes. Only local host routes are retained from automatic configuration, and only the two signed remote host routes are installed. No PowerShell/CIM process is launched on the 250ms observation path.

### Family-specific autoconfiguration control

Hosted source `e83a791e3c6ec0447376326f703a1616f936c3df`, run `41200744938`,
reached the actual signed driver/session and identified Win32 error 87 at
`SetIpInterfaceEntry`, IPv4 family 2, member `LinkLocalAddressBehavior`.
The complete original readback had succeeded for the preceding members; this
failure is not an authorization or unsigned-driver exception and remains a
failed mechanism attempt.

IPv6 continues to require `LinkLocalAlwaysOff` through IP Helper. IPv4 uses
Windows `netsh interface ipv4 set address` on the original captured numeric
index with `source=static`, the exact approved local `/32`, `gateway=none` and
`store=active`. The executable comes from `GetSystemDirectoryW`, never PATH;
the existing bounded child owner clears inherited loader/module variables,
sets the OS SystemRoot explicitly, suppresses a window and joins/kills within
its fixed timeout. GUID/name/LUID/index are checked before and after that
single startup operation. No command is launched by periodic observations.

Success is independently proved using `GetAdaptersInfo` on the same original
GUID and index with `DhcpEnabled == false`, plus the existing complete IP
Helper inventory requiring exactly the two signed manual `/32` and `/128`
addresses and only their local and signed remote host routes. Extra link-local
addresses, learned prefixes, default routes, DHCP, forwarding or replacement
identities still fail closed. The DHCP table uses owned aligned storage,
bounded allocation/retries, validated in-buffer list pointers and cycle limits.
This selects supported family-specific control rather than treating error 87
as success or dropping the original isolation requirements.

Alternatives considered were retaining the failing identical IPv4/IPv6 setter,
or accepting an unchecked IPv4 state. The former prevents every Windows native
run; the latter cannot establish the required address/route isolation. The
selected static operation reuses the OS network configurator and separately
measures its effective state. Exact-source native qualification remains pending.

References: [MIB_IPINTERFACE_ROW](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipinterface_row),
[SetIpInterfaceEntry](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-setipinterfaceentry),
[GetAdaptersInfo](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersinfo).

Protected receipt publication also has durable ordering: bind the single pipe and capture its receipt, save that exact receipt in the administrator journal, then publish it through the existing protected file adapter. A crash before publication is recovered as actual receipt absence; a changed receipt is never removed. Closing the original provider releases its own driver session/adapter; recovery verifies its GUID/name is physically absent. Recovery never reopens a surviving adapter just to delete it, and preserves a visible failed record if absence is not observed within five seconds. This conservative recovery case remains an explicit native qualification requirement.

## Provider choice and alternatives

The reviewed `tun-rs 2.8.16` Windows source keeps Wintun adapter/session pointers and ring mappings inside its process-private implementation. Its public device API cannot adopt a privileged-created Windows adapter/session into an ordinary process. `DuplicateHandle` cannot transfer a Wintun library pointer or a process-local memory mapping, and standard-user `WintunOpenAdapter`/`WintunStartSession` access has not been established.

Options compared:

1. Elevate the full business daemon or assume a standard-user open succeeds. Rejected: it changes the security boundary or relies on an unproven provider capability.
2. Reimplement Wintun rings, manufacture opaque pointers or fork the provider for a custom driver/session protocol. Rejected while a thin local packet adapter can reuse the maintained driver and provider.
3. Keep only the provider descriptor and exact OS resource lifecycle in a separately invoked administrative helper, with authenticated bounded local whole packets. Selected. The helper has no installation private key, network transport or login recovery; the ordinary owner validates every packet before transmission or injection. This differs from the Linux descriptor handoff while preserving the same business owner.

The Windows privilege/token/pipe and protected-file operations reuse `nestlink-privileged`'s existing broker/WFP primitives. Product code does not add a second SID/ACL implementation or an ad hoc IP stack. Existing pinned `tun-rs` owns driver/session/framing operations. Existing `etherparse` remains the packet parser/builder.

## Strict driver loading and evidence

The official Wintun site was read on 2026-10-31. It lists 0.14.1 at `https://www.wintun.net/builds/wintun-0.14.1.zip`, SHA256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`. The site distinguishes GPL-2.0 source from its signed DLL distribution, whose more permissive license is included in that exact ZIP. The ZIP license, architecture-specific DLL hashes and Authenticode identity must be read and retained by GitHub Actions before distribution. A website statement is not a substitute for preserving the binary license.

A helper loads only the explicitly selected, exact-hash provider in a protected local directory. Protected ancestor/file handles are retained with write/delete sharing denied throughout loading and provider ownership. No PATH/current-directory lookup, unpinned `wintun.dll`, caller-controlled loader environment, network share, reparse point or driver-deletion fallback is accepted. The driver path/hash are administrative installation/CLI inputs, outside an untrusted network plan; a network grant cannot select executable code.

All dependency resolution, driver acquisition/verification, compilation, formatting, tests, standard-user/admin experiments and package generation run on GitHub-hosted Actions. Windows actual standard-user packet transfer, helper/client process-authentication negatives, driver/load pin negatives, adapter conflict/replacement protection, crash/partial install, exact cleanup and VPN coexistence remain mandatory. A Linux green job or a compiled Windows pipe substrate does not complete these requirements.

The dedicated `windows-managed-tun.yml` workflow builds the exact daemon test image and reuses `refactor-windows-normal-user.py` for a real medium non-elevated token. It copies the identical image into a protected ProgramFiles fixture, uses a separate administrator process of that same file identity, and obtains the official frozen ZIP only on the hosted runner. The fixture must retain the archive license, per-architecture DLL hashes and valid WireGuard LLC Authenticode identity. It exercises full 1280-byte kernel IPv4/IPv6 UDP requests/replies through the authenticated helper pipe, a foreign same-SID process denial, normal cleanup, helper termination, live-owner recovery denial, original owner termination and exact recovery. Its receipts explicitly exclude production online authorization and two-target acceptance.
