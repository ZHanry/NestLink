# ADR 0008: signed native ICE with one frozen physical candidate

Status: production source implemented; exact-source Actions verification pending.
Date: 2026-10-31, Asia/Shanghai. Scope: a W09 slice, not complete AC13/AC14.

The existing same-socket feasibility experiment uses the locked mature
webrtc-ice dependency and Quinn. We compare extending that adapter into the
production native establishment path with implementing a separate STUN/check
engine. We reuse the existing component, mutual TLS pins, signed management
signals, SessionPermit business proof, bounded channels and resource owners.
The prototype and production now import the same ICE-to-Quinn socket adapter.
No dependency version or upstream implementation is copied into this change.

Both endpoints must have signed device registrations advertising
`native-ice-quic-v1`. The management service includes that capability in the
signed initial permit only for two native endpoints with Direct permission;
renewal freezes it. The local SDK also requires the deployment's optional
health version hint. Health alone cannot authorize the dialect. A signal with
native ICE fields requires that signed permit capability. Absent optional
fields retain the previous signal serialization. Old deployments and peers,
and existing device registrations without the capability, retain the legacy
path. The current feature-refresh API does not upgrade existing registrations.
The business permit, TLS pins and local supported media capabilities remain
independent checks. ICE credentials are redacted from Debug and zeroized by
their protocol owner on drop.

The first production dialect freezes exactly one candidate and one address
family. It selects an active address under the current physical-interface
policy. An explicitly configured STUN server may gather one server-reflexive
candidate; otherwise the mature agent gathers one host candidate. The socket
factory binds once through NetworkPathManager. Quinn uses the selected mature
AgentConn and opens no replacement socket. Trusted STUN gathering and actual
business therefore use the selected original UDP socket. Additional interface
selection and legacy direct/authorized relay fallback remain available through
the existing native endpoint; this slice does not replace W08's dual-stack work.

The mature agent's local ip_filter does not constrain authenticated
peer-reflexive sources. A peer with the ICE password could otherwise cause
checks toward an unapproved private address before an after-the-fact selected
pair check. Before installing a remote candidate or starting checks, the SDK
validates the signed literal candidate against AddressPolicy and calls connect
on a duplicate handle to the original OS socket. This does not bind another
socket. Kernel receive filtering admits only that exact peer tuple, preventing
the agent from discovering other authenticated source tuples. The selected
remote tuple must still equal the signed tuple. Changed mappings require
fallback or a new establishment; advanced NAT is not claimed. Selected-pair
changes and consent failure terminate the adapter. Generic dynamic migration
requires a separately qualified contract.

The adapter retains one reader, one writer, bounded 32-packet queues, 250-ms
queue ages, 1200-byte packets and one transmit/receive segment. Quinn disables
migration and dynamic MTU discovery for this dialect. This is not a physical
PMTU, fragmented IPv6, multi-hop, ECN or TUN qualification. It still performs
pinned mutual TLS and the existing two-sided business proof before channel I/O.
An actual security failure is terminal; a reachability failure can use the
existing authorized fallback. Cleanup failure retains its primary cause and
its own source, and is terminal even when that primary cause was reachability.

The gathering owner lives outside its cancelable/timeout future. Normal gather
failure and cancellation await the original agent close and physical release
before returning. Completed carriers first stop Quinn, join adapter tasks, close
and drop the actual Agent/Conn references, release the duplicate socket handle,
then physically rebind every original address under one fixed cleanup deadline.
Retries never extend it. An externally dropped overall operation can only request
Drop cleanup, which is not counted as a successful close receipt.

Actions must verify the new native_session production HTTP/signature flow,
actual selected ICE carrier, 256-KiB FileRead, denied Input, network invalidation
and all original ICE/legacy port rebinds. The existing raw ICE/Quinn tests still
cover wrong TLS pins and cancellation. Storage tests cover the two-endpoint
capability matrix, Web exclusion, renewal freeze and signed inbox discovery.
No local compiler, formatter, lint or test was run. Public NAT sites, broader
faults/role conflicts, real external IPv6, consent qualification and complete
acceptance remain required separately.
