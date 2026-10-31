# Administrative split-DNS ownership and recovery

Status: source implementation awaiting GitHub-hosted formatter, compilation,
unit tests and real OS tests. No local DNS or system configuration was changed.

The first exact-source OS experiment at `5f969a2` failed on both systems.
Linux rejected an existing resolved domain because the adapter incorrectly
unwrapped `busctl get-property` as a method reply. The v255 implementation
(`src/busctl/busctl.c`, `get_property` and `json_transform_variant`) returns the
property directly in `data`. The repaired adapter checks the exact D-Bus
signature and complete typed rows, preserving empty arrays and scalar values.
Windows reached its original three-second command deadline during the initial
administrator check, before any policy was installed. Process/token actions
now avoid importing the unrelated DnsClient module. Failures identify their
specific constrained action. All deadlines and recovery assertions remain;
these repairs require another hosted run and are not passing OS evidence.

This is the next W19/AC32 and W22/AC36 slice after ADR 0031. The normal resolver
retains its current-session and same-account boundary. A separate administrative
command installs only one explicit `s-<canonical-space-UUID>.nestlink.internal`
routing suffix. DNS still grants no IP, route, remote-control or service access.
This does not complete TUN, system route conflict detection, cross-account name
access or full target/VPN coexistence qualification.

## Alternatives and mature OS components

On Windows, replacing an adapter's DNS server or a global resolver would also
redirect unrelated and other-VPN queries. The selected mature DnsClient NRPT
cmdlets instead create a unique local namespace rule for this exact suffix.
Existing local/GPO/VPN suffix conflicts cause rejection. The rule uses
`127.0.0.1` and therefore requires an explicitly selected TCP/UDP port 53
resolver; an arbitrary high port is never silently substituted. The generated
rule GUID, complete selected policy view, display name and comment are tracked.
No registry schema or general DNS policy implementation is recreated.

On Linux, editing `resolv.conf`, taking over a physical/VPN interface, or
reverting a shared link would lose independent DNS configuration. The selected
`systemd-resolved` routing domain is attached to a freshly created, uniquely
tagged dummy link. Mature iproute2 creates/deletes that link; resolvectl configures
its route-only suffix and loopback DNS server; typed busctl D-Bus property
observations verify actual DNS state. The product never rewrites `resolv.conf`,
installs a default route or supplies a public upstream. A running resolved stub
at `127.0.0.53` is a prerequisite. Unsupported resolver arrangements fail
explicitly rather than adopting or modifying them.

The dummy remains DOWN while its configuration is assembled. Default-route is
disabled and the exact routing domain is set before introducing a DNS server;
LLMNR, mDNS, DNSSEC and DNS-over-TLS are disabled only on this private DNS link.
IPv6 automatic address generation is disabled in a separate DOWN-state request
and read back before activation. The original addressless-dummy design was
disproved by exact-source hosted run `41174235577` at `22c9722`: configuration
and cleanup succeeded, but the actual system query returned `Name not found`.
`systemd v255` (`db11bab38ccf1ed257f310d29070843d4c58ea01`),
`resolved-link.c::link_relevant` and `link_allocate_scopes`, require an UP,
carrier-present link with a non-tentative address whose scope is below LINK
before creating its unicast DNS scope. A link-local address alone is insufficient.

The adapter therefore assigns exactly one owner-derived, globally scoped ULA
`/128`, with `nodad` and `noprefixroute`, to this new dummy. SHA-256 of the full
random owner marker determines the ULA, so the prepared journal can independently
recover its exact address after a crash. Mature `ipnet 2.12.2` checks all existing
IPv6 interface prefixes and non-default routes before creation; an overlap is a
hard error, including broad VPN ULA prefixes. No existing address or VPN route
is replaced. The only permitted unicast route is the kernel's exact local host
route for that address; no connected prefix, gateway, export or default route
is installed. Additional addresses, prefix routes or altered address flags cause
readback/recovery to preserve the resource and journal for operator review.

The alternative of installing global resolved DNS/domain settings would share
ownership with unrelated and VPN configuration and is rejected. Taking over a
physical interface is rejected for the same reason. `systemd v255` explicitly
sends localhost DNS servers through the loopback interface regardless of their
associated link. The ULA activates the isolated DNS scope; DNS packets still go
to the explicitly selected loopback resolver. The repaired complete behavior
still requires the real OS test; source repair alone is not passing evidence.

Read sources:

- [Windows Add-DnsClientNrptRule](https://learn.microsoft.com/en-us/powershell/module/dnsclient/add-dnsclientnrptrule?view=windowsserver2025-ps)
- [Windows Remove-DnsClientNrptRule](https://learn.microsoft.com/en-us/powershell/module/dnsclient/remove-dnsclientnrptrule?view=windowsserver2025-ps)
- [resolvectl interface configuration](https://www.freedesktop.org/software/systemd/man/latest/resolvectl.html)
- [systemd v255 localhost DNS interface selection](https://github.com/systemd/systemd/blob/v255/src/resolve/resolved-dns-server.c)
- [systemd v255 DNS scope and address eligibility](https://github.com/systemd/systemd/blob/db11bab38ccf1ed257f310d29070843d4c58ea01/src/resolve/resolved-link.c)
- [typed resolve1 properties and methods](https://github.com/systemd/systemd/blob/v255/man/org.freedesktop.resolve1.xml)
- [iproute2 interface identity lookup](https://github.com/iproute2/iproute2/blob/main/lib/ll_map.c)

The OS tools are existing system components, not new downloaded runtime
dependencies. The adapter contains product-specific plan, ownership and
lifecycle logic, not a replacement DNS resolver or network configuration stack.

## Explicit product entry and privilege boundary

`space-dns --system-dns-plan <absolute-private-output-path>` explicitly opts in
to exporting a public, create-new JSON plan. Without this option the resolver
continues to change no system setting. The plan contains only schema, owner and
space UUIDs, exact suffix/socket, process PID/incarnation/image and finite expiry.
It contains no account credentials, protected store path or arbitrary command.
The expiry cannot exceed the resolver's current management access expiry.

The normal CLI remains unelevated and owns the existing daemon singleton. The
separate `space-dns-system` command has review, init-journal, apply, inspect and
recover operations. Apply/recover/init-journal require administrator/root;
the helper imports no SessionStore and reads no management tokens. Its plan
parser rejects unknown fields, invalid UUIDs, unsupported schema, non-loopback
addresses and an altered suffix. Apply requires a plan generated within five
minutes, a still-live process with the exact PID/start incarnation and same
executable image, and the resolver's live TCP socket. PID reuse alone cannot
inherit ownership. The helper never silently opens another account or suffix.

Expanding the existing Windows input-only privileged broker was considered and
rejected here: it would mix DNS configuration with remote input grants and
require a new broker authorization protocol. The separate reviewable
administrative command has a smaller, concrete surface. It is not an automatic
elevation flow or an already integrated desktop switch. The administrative
helper must remain running while its resolver runs; stopping either withdraws
the managed rule. Linux SIGTERM and Ctrl-C are handled. A killed/crashed helper
leaves the durable recovery journal for the next explicit managed startup.

Tool execution uses trusted absolute system paths, no shell input from a plan,
bounded output and a three-second Linux process deadline. Windows retains a
separate fifteen-second cold-provider deadline, with bounded stage diagnostics
preserved on timeout. It obtains the real
system directory through the existing platform boundary, starts hidden
PowerShell without a profile, and imports DnsClient only from the system module
directory. The subprocess inherits no caller-controlled loader, D-Bus or module
search environment. No administrator command runs on this workstation as part
of development; all automatic verification belongs to Actions under R02.

## Journal and compare-before-delete

The administrator chooses an absolute private journal directory. `init-journal`
creates only that leaf with the existing platform-security ACL/mode helper;
existing directories must already pass the ownership/private-directory check.
No permission widening or silent chmod of an existing directory is performed.
All mutations retain a stable OS file lock. The bounded fixed journal is written
with the existing durable atomic metadata API before the first system change.
A visible-but-not-confirmed-durable commit is a failure, not installation success.

The prepared record contains the complete public plan. After actual readback,
the journal records the installed resource snapshot. A crash before readback
can recover only an exact ownership marker with a safe subset of planned
settings; an unrelated or inconsistent resource remains untouched. A crashed
journal is recovered before a new apply, and a still-live resolver and socket
prevent an unrelated recovery invocation from taking it over.

Windows removal re-reads the precise rule GUID and compares every recorded
policy field, ownership display/comment markers, exact namespace, loopback server
and disabled DA/DNSSEC flags. External changes, duplicate owned rules or an
unexpected GUID preserve both resource and journal. Linux compares interface
index, exact full owner alias, dummy kind, MAC, MTU and stable configuration
flags, IPv6 address-generation mode, plus actual addresses/routes and the typed per-link DNS settings. Carrier,
operstate and counters are omitted from the stable projection. Any address or
unicast route beyond the exact owner-derived ULA `/128` and its local host route,
foreign DNS setting or changed installed configuration prevents deletion.
Only the kernel's intrinsic IPv6 multicast route is excluded. No
physical/VPN link is ever adopted. Deletion is preceded by another readback;
kernel link absence and resolved's removal of that index's DNS/domain entries
must then be observed before the fixed journal file is removed.

The OS does not offer a transactional compare-and-delete through these mature
command interfaces. An independently privileged administrator can race the
last comparison; that cannot be represented as an atomic OS CAS. The unique
resource and full ownership checks protect ordinary coexistence, and uncertain
cleanup is reported with the journal retained. No force-delete fallback exists.

Normal expiry, resolver process/port loss and user stop attempt cleanup. A
system-policy change fails visibly and preserves the changed resource for
operator review. Upgrade/rollback/uninstall must stop the resolver and run
recover with the same journal directory before removing the executable or
journal. Packaging integration and five-second target cleanup timing still
need evidence; a three-second bound on each OS command alone is not proof that
all cleanup meets the total target deadline.

## Verification and remaining evidence

Normal daemon tests cover real canonical UUIDs, suffix/bind/unknown-field
rejection, private-directory/symlink checks, durable prepared/installed journal
restart and exclusive journal ownership. The ignored, explicitly opted-in
hosted-VM test starts the actual Store/HTTP/SDK/SpaceDns stack, installs the real
OS policy, resolves its issued A record through the real system resolver and
checks unrelated policy before and after. It also proves external MTU/NRPT
comment changes prevent deletion, and reopens both prepared and installed
journals after losing controller state and stopping the DNS owner.

See `docs/network-rewrite/SPLIT-DNS-OPERATIONS.md` for user commands, dedicated
Actions prerequisites and recovery. None of these new tests is recorded as
passed until its exact-source hosted run is reviewed. Windows/multiple-VPN,
Linux distribution variations, actual crash/upgrade/uninstall execution and
the five-second target remain explicit qualification work.
