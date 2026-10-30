# ADR 0012: Keep signed deadlines and live observation continuity distinct

Date: 2026-10-31 (Asia/Shanghai). W11 follow-up. New source still requires
GitHub-hosted Actions execution, including both real-node integration and the
complete workspace. This decision does not qualify a release.

At `bd1f298c2babe601087176d1834a1fec2ef52b19`, the Linux two-node test still
failed the first outer QUIC client-certificate check. The bounded reuse of an
identical network chain did not resolve that failure. Before and after the
failure, both nodes had current snapshots and accepted both endpoint pins;
these samples do not establish what happened during the failed TLS callback.
The original logs are retained in Actions run 41123321886, artifact 13009179143.

Manual review identified two independent, constructible deadline errors:

1. Resource snapshots and node leases added the remaining signed wall-clock
   lifetime to request start. That remaining lifetime had already lost the
   response latency, so the conversion deducted latency twice. For a request at
   monotonic 0, receipt at 600 and signed expiry at wall time corresponding to
   monotonic 1000, this produced deadline 400 and rejected a still-current
   response. The query's unchanged 700 ms budget permits that receipt.
2. A new network pairing candidate froze the deadline of the snapshot observed
   at admission. Even explicitly signed, current snapshots retaining the same
   route every 250 ms could not keep that pending candidate current after the
   original observation ended. Pairing could therefore fail well before its
   existing establishment budget.

Convert a signed expiry at receipt using the minimum of:

- receipt monotonic time plus remaining signed wall-clock time;
- original request monotonic time plus the signed lifetime, or the existing
  one-second snapshot TTL.

Both additions are checked for overflow. Receipt and request clocks still must
be ordered. Wall expiry, rollback checks, query binding, sequence checks and
the original request-relative ceiling remain enforced. Reobserving an unchanged
allocation retains its original monotonic deadline; no repeated observation can
renew the allocation's signed authority.

A pending candidate freezes the original allocation/ticket and node lease
ceilings. Each check additionally requires the current live snapshot to contain
the same issuer, route and binding. It uses that current snapshot's observation
deadline rather than permanently saving an earlier observation deadline.
Candidate possession proofs, current TLS pins and final capacity reservation
remain separate checks.

Simply removing the saved observation deadline would permit an uncommitted
candidate to revive if its resource disappeared and reappeared before its next
check. Each live resource entry therefore owns an opaque `Arc` continuity token.
A valid refresh of the same still-live resource retains it. Omission, expiry,
issuer/quota replacement or stop discards it; reintroduction creates a new token.
Pending candidates require pointer identity with the current entry. This adds
no global cache or map and changes no wire protocol. It never revives a stopped
pair or refunds its existing cumulative budget.

Alternatives were extending the snapshot TTL or retrying rejected TLS clients.
Neither corrects the two time conversions or proves continuous authorization.
The chosen change preserves TLS authentication, the one-second authority window,
the 700 ms query budget, the three-second endpoint proof budget and all existing
physical cleanup requirements.

Regression coverage must include 300/600 ms receipts, request and wall-clock
ceilings, continuous fresh observations after the initial snapshot expires,
unchanged allocation/node ceilings, omission and reintroduction, expiry, stop
and issuer replacement. Those deterministic cases complement, and do not replace,
the actual two-node business transfer, independent revocation and socket-release
checks. A successful new Actions run is required before attributing the observed
TLS failure to either defect.
