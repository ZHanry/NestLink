# ADR 0037: Explicit Linux kernel admission for ordinary raw clients

Status: implemented source; exact-source hosted verification pending. This does
not complete W21 or AC34, nor the Windows raw port boundary.

SOCKS authentication and owner-private native streams remain the ordinary-user
entries described in ADR 0036. A raw TCP/UDP client has no proxy authentication
bytes, and Linux TCP/UDP sockets do not expose Unix-domain peer credentials.
Reading a guessed peer PID after accept is not an atomic authorization boundary.
The raw adapter therefore requires an explicit administrator-installed kernel
UID gate for one exact loopback destination, port and transport before binding.

Reuse the installed nftables system component for JSON transactions and actual
kernel filtering, Tokio for sockets/copy/queues, and the existing private service
grant, exact approved target, transport and shared cumulative quota. A separate
privileged daemon command has no installation, login, private target or service
grant. It never registers this computer as an Actions runner. No custom packet
parser, firewall implementation, Internet gateway or service allowance is added.

The ordinary-user daemon writes a private create-new plan and remains the exact
same process while waiting. The administrator explicitly chooses that plan,
root-private journal and root-controlled receipt path, and starts the same
executable as a helper. Installation checks the original PID/start-time/boot,
UID, executable device/inode and fixed endpoint, creates only its own fresh table,
and reads back the complete rules and object handles. A UID allow/return precedes
the exact destination drop in output; input drops the selected destination from
interfaces other than loopback. Existing firewall decisions still apply.

The helper publishes a bounded root-owned receipt atomically beneath no-follow,
root-controlled directory descriptors. A normal-user adapter verifies its exact
current process and plan, the complete kernel configuration receipt, the original
helper's root UID and boot/start incarnation, and the original expiry. The helper
is observed without reading its root executable through procfs, which an ordinary
user need not be permitted to do. This receipt is local OS policy, not remote
membership or business authority. Kernel admission covers the selected OS user;
it does not distinguish applications belonging to that same user.

Each TCP flow uses the existing fixed-service grant and byte-stream owner,
including FIN/half-close and physical carrier cleanup. Each UDP source endpoint
gets its own grant and original private connection. Endpoints never rebind into
an existing UDP mapping. A bounded per-peer queue, owner/process worker limits,
finite byte allowance, idle timeout and event limits apply; empty datagrams retain
their boundary and oversize packets are dropped. No failed TCP stream or queued
UDP packet is replayed under a new grant.

The stream retains the existing private host's application-byte semantics. For
a selected HTTPS service, that host establishes and verifies TLS to its approved
backend; the local entry carries HTTP application bytes. An HTTP client can
therefore reach the HTTPS backend through this adapter. A standard HTTPS client
that initiates TLS at the local entry still requires a separate local TLS
termination or approved passthrough implementation and qualification. The raw
gate adds neither capability, and existing backend TLS verification remains in
force for this service type. The same distinction applies to SOCKS and native
stream access.

Both ordinary and privileged owners observe their original deadlines. The normal
owner stops on a missing helper, changed identity, expiry or its original product
lifecycle. The helper atomically changes its output gate to deny-all on expiry
or orderly termination. A helper crash leaves the existing kernel gate and
journal in place; it never opens the endpoint through Drop cleanup. An inherited
journal flock remains held by an actual in-flight nft child, so recovery cannot
race a kernel transaction still running after its helper exits.

Deletion requires the original socket process's actual boot/PID/start incarnation
to be gone. An exec, UID change or changed image is not a physical exit receipt,
since the process might retain inherited sockets. Recovery compares the original
full rules, handles and durable mutation intent. Foreign or changed objects are
preserved and reported. The helper does not trust a user assertion that a port
has closed; the dedicated ordinary daemon command joins its sockets and exits.

Alternatives: a raw capability port gives every local user access during its
lifetime; post-accept PID lookup races socket ownership. A dedicated network
namespace could isolate clients but requires launching existing applications in
that namespace and does not provide the requested ordinary client entry. The
selected nftables gate is a small opt-in OS adapter with an explicit privileged
setup; SOCKS/native streams retain their unprivileged setup. Windows requires
its own kernel admission implementation and qualification and is not declared
supported by this Linux source.

All formatting, dependency resolution, compilation, automated kernel experiments
and packaging execute on GitHub-hosted Actions under R02. Actual raw SDK kernel
scenarios are separate from production protected-login CLI and target device
qualification. No source-only test or unit fixture qualifies those latter gates.

References: https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation
and https://netfilter.org/projects/nftables/manpage.html.
