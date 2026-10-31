# Managed private DNS operation and recovery

Implementation: W19/AC32 and the DNS ownership portion of W22/AC36. Current
status: source implementation awaiting hosted execution and target qualification.
The resolver exposes current active devices in the signed-in account only.
Names do not grant IP or service access. This feature does not install TUN,
network export or default routes, and it does not provide cross-account
private-name access.

## Start the normal resolver and review a public plan

Use the installed normal-user daemon executable. Stop the ordinary daemon first
because this standalone resolver owns the same protected management session and
daemon singleton. Sign in and enable protected login recovery beforehand. Do
not run the business resolver as administrator/root.

Linux example:

```text
nestlink-daemon space-dns --state-dir <absolute-private-instance-directory> --space <canonical-space-UUID> --listen 127.0.0.1:5354 --system-dns-plan <absolute-private-instance-directory>/split-dns-plan.json
```

Windows uses the same arguments but **requires `--listen 127.0.0.1:53`** for
NRPT. Port 53 must be free for both UDP and TCP. A conflicting resolver causes a
clear bind error; NestLink does not stop it or select another system port.

The plan output must be a fresh filename in an already private directory. It is
public JSON containing the exact suffix/socket, process incarnation and finite
expiry, with no password or management token. A different space/session or an
expired plan requires a new resolver/plan. No system rule is installed by this
normal-user command.

In a separate shell, review:

```text
nestlink-daemon space-dns-system review --plan <absolute-plan-file>
```

## Apply with a separate administrative owner

Use the **same executable** in an administrator shell on Windows or through
sudo on Linux. The normal resolver stays unelevated. Choose a persistent
administrator-owned directory with a trusted existing parent, for example
`C:\ProgramData\NestLink-DNS` or `/var/lib/nestlink-dns`. The parent must already
exist; init-journal creates only the requested leaf and never repairs an unsafe
existing directory.

```text
nestlink-daemon space-dns-system init-journal --journal-dir <absolute-admin-journal-directory>
nestlink-daemon space-dns-system apply --plan <absolute-plan-file> --journal-dir <absolute-admin-journal-directory>
```

Apply requires a plan created within five minutes, its original process and
birth identity still live from this executable, an active resolver TCP port and
an unexpired access deadline. The helper reads no protected login data. Keep it
running while using the system suffix. It watches the resolver process, socket,
expiry and exact owned configuration. Ctrl-C on either process, Linux SIGTERM,
logout, account/session rotation or authorization loss initiates cleanup.

Windows requires the DnsClient NRPT cmdlets. Linux requires iproute2,
resolvectl/busctl and a running `systemd-resolved`, with the existing system
resolver already using its `127.0.0.53` stub. These prerequisites are detected;
NestLink does not edit `resolv.conf` or install OS components. Unsupported DNS
managers and insufficient privileges are errors. On Linux a unique tagged dummy
link holds only this route-only DNS suffix and loopback server. Its default DNS
route, LLMNR and mDNS are disabled. To satisfy resolved's DNS-scope eligibility,
it also owns one deterministically derived random ULA `/128` and that address's
exact kernel local host route. Automatic IPv6 addressing and connected prefix
routes are disabled. Existing IPv6 address and non-default route prefix overlap
causes rejection before link creation, including overlap with another VPN's ULA
range. Existing physical/VPN interfaces are unused; actual DNS traffic goes
through the loopback interface to the selected resolver.

The helper refuses an existing overlapping private DNS namespace. It never
replaces another NRPT rule, global DNS server, physical interface, VPN domain or
default route. Multiple managed owners require distinct private journal
directories and suffixes; a name collision or policy conflict fails explicitly.

## Inspect, recover, upgrade and uninstall

After an unexpected termination, retain the journal directory and use the same
installed administrative executable:

```text
nestlink-daemon space-dns-system inspect --journal-dir <absolute-admin-journal-directory>
nestlink-daemon space-dns-system recover --journal-dir <absolute-admin-journal-directory>
```

Recover refuses to take over a still-live original process and resolver port.
Stop the normal resolver first. Recovery compares the exact persisted owner and
configuration with the OS, then removes only that resource and confirms absence
before clearing the fixed journal. The stable lock file is retained.

If an administrator, VPN or user changed the owned resource, recover reports the
conflict and keeps both resource and journal. Inspect the reported OS settings
and journal. Restore the exact recorded product configuration or remove the
specific owned resource through normal OS administration, then rerun recover.
There is no force-delete fallback. Do not delete the journal to suppress a
failed cleanup report.

For upgrade, rollback or uninstall: stop the normal resolver, wait for the
administrative owner to finish, run recover, and confirm it succeeds **before**
removing the installed executable or journal. If the helper itself crashed,
the next apply first recovers its old journal; it cannot silently replace a live
owner. Packaging must retain this recovery step. Full installer integration and
target timing are not yet qualified by this source delivery.

## GitHub-hosted verification

All commands below run only inside Actions under R02. No local compile, test,
OS policy installation or dependency installation is part of development.

Ordinary source tests:

```text
cargo test --locked -p nestlink-sdk --test space_dns -- --show-output --test-threads=1
cargo test --locked -p nestlink-daemon --bin nestlink-daemon space_dns_system:: -- --show-output --test-threads=1
```

The real OS test is ignored by default. Run it only on a fresh, dedicated,
ephemeral GitHub-hosted VM, never on a developer computer, deployment server or
self-hosted runner. Set `NESTLINK_SYSTEM_DNS_LAB=1`, then run elevated:

```text
cargo test --locked -p nestlink-daemon --bin nestlink-daemon space_dns_system::tests::actual_os_split_dns_resolves_and_recovers_without_changing_unrelated_policy -- --ignored --exact --show-output --test-threads=1
```

The Linux job needs root or an equivalent isolated administrative execution,
CAP_NET_ADMIN, iproute2, systemd-resolved, resolvectl, busctl, an active system
D-Bus and the resolved stub. Hosted setup may prepare these dependencies and
the ephemeral VM's stub configuration before the test; record that infrastructure
setup separately from product behavior. Windows needs an elevated hosted VM,
the system DnsClient module and loopback port 53 free. Build on Actions first;
privilege elevation executes that exact already-built test artifact rather than
recompiling on a target device.

The test uses actual Store/HTTP/SDK authorization and Hickory sockets, resolves
an issued name through `resolvectl query` or `Resolve-DnsName` without an explicit
DNS server override, checks unrelated policy unchanged, proves changed owned
configuration is preserved, and tests prepared/installed crash-journal recovery.
A cleanup failure retains its temporary recovery journal and prints its path.
Upload test logs and retained journal as failed-run artifacts. Record the source
SHA, workflow/run/attempt, runner, lock hash and artifact digests as build and
execution provenance. A built test is not an executed or passed test.

Remaining target evidence includes Windows with other VPNs, representative Linux
DNS arrangements, abrupt process/service/OS failure, installer rollback and
uninstall, and successful normal cleanup within the specified five seconds.
