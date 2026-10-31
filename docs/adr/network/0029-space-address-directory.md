# Identity-bound space address and name directory

Status: source implementation; GitHub-hosted validation pending.

This W19 slice reuses the product space account roles, current installation
keys, account/member epochs, existing management-session authentication,
SQLite transactions and audit journal. The new storage dependency is the
already locked `ipnet 2.12.2` (MIT OR Apache-2.0), used for address pool parsing,
network calculation and containment. It adds no DNS, IP stack or wire protocol.

One alternative was to reuse authority revision and policy epoch for directory
writes. That would invalidate unrelated short-lived network grants whenever an
operator renames a device. Migration 038 instead adds an independent directory
revision and observation clock, checked under the same immediate transaction as
the mutation and audit event. Every write also checks the fresh existing space
authority, account access, archive state and owner/admin role. Failed auditing
rolls back the record and directory revision together.

Another alternative was to reuse virtual addresses in separate spaces and
depend on future OS routing isolation. This slice chooses deployment-wide unique
active IPv4 and IPv6 addresses, enforced by unique indexes, so joining two spaces
cannot itself allocate duplicate addresses. The virtual pools are
`100.64.0.0/10` and `fd4e:6573:744c::/48`. Automatic allocation monotonically
advances a persisted allocation slot across all directory rows and pairs the
same offset in both pools. Every IPv4 /24 position `.0`, `.1` and `.255`, and the
IPv6 pool's zero and gateway addresses, are reserved. Explicit reservations must
remain within the usable pools and cannot conflict with another active record
in any space. IPv6 input is stored in canonical form before uniqueness checks.
Directory capacity per space follows the existing 4,096-device space budget;
exhaustion fails explicitly. One automatic allocation probes at most 128 slot
positions, including reserved positions, and returns `RateLimited` without a
write when that window is occupied; it never scans the whole pool in one
management request. An operator can explicitly reserve a different free pair.

These pools can overlap addresses on a user's physical network or another VPN.
This management directory has no observation of those routes and does not claim
to detect or solve that overlap. A future managed route/TUN installer must check
the actual host route table and explicitly isolate, reassign or reject conflicts
before installation. A directory record alone is never route-export,
NetworkAccess, remote-control or service authorization.

Each binding captures account ID and account member epoch, installation ID,
current Ed25519 public key, device membership epoch and an address epoch. Every
read recomputes whether that exact identity remains current; revoked devices,
removed/disabled members, changed keys/epochs and archived spaces cannot return
an effective record. Regular members may inspect only their own current records;
owners/admins also see inactive records and tombstones for cleanup. Inactive
unrevoked records continue to occupy their name and addresses until an operator
explicitly revokes them. This prevents implicit takeover. A replacement must
explicitly revoke and issue with the latest address epoch and current membership
epoch; automatic reissue selects a new slot. Retrying issue for the unchanged
current identity and same normalized name returns the original stable record
without a new directory revision. Reservation and rename preserve the identity
binding and advance the address epoch. Revocation advances it again.

The private namespace is frozen as
`<lowercase-ascii-label>.s-<space-id>.nestlink.internal`. Labels are 1–63 ASCII
letters/digits/hyphens with alphanumeric first and last characters. The opaque
space ID separates otherwise identical names across spaces. No `.local` or
unrelated resolver suffix is captured. Returned names convey no trust and have
zero cache lifetime in this slice: consumers must obtain a fresh authoritative
directory observation. There is no DNS response cache or DNS resolver here.

Production calls are connected through five authenticated HTTP routes and typed
SDK methods: directory read, automatic issue, explicit reservation, rename and
revoke. Source tests use the actual SQLite store, concurrent writers, atomic
audit failure and the actual SDK/server HTTP path, including permission denial,
duplicate names, canonical address collisions across spaces, reserved addresses,
stale CAS, member/device generation changes, key replacement and archive.
These are pending hosted execution, not claimed target evidence.

The slice does not complete W19. Split-DNS serving through a mature DNS component,
resolver installation/restoration, offline/cache expiry, target-platform DNS
cleanup and the managed TUN integration remain separate implementation work.
