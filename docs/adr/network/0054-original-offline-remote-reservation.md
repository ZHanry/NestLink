# Original remote authority for finite offline reservation

The private-service offline lifecycle already has durable enable, two endpoint
approvals, a frozen draft digest, one-use process-bound consumption and permanent
quota promises. Remote control needs that lifecycle with its own original
business authority. It cannot be represented as a private service or relay.

One option is an unrelated remote offline permission store and quota. That
duplicates approval and consumption and lets online and offline promises exceed
their shared total. Another is the existing offline lifecycle retaining the
original remote permit and trusted-device consent. We use the second option.

Migration 050 stores frozen original remote permits separately from private
service definitions. Draft creation requires a current online remote permit,
both current native installation memberships, explicit operations, finite
deadline and process nonces. Subsequent online review intersects the original
trusted-device consent, device keys, request generation, policy, security epoch
and original remote budget. The offline deadline can outlive the short online
permit; it cannot outlive original device trust or registration. An old permit
is never renewed to manufacture offline authority.

The second endpoint approval reserves bytes, file-write bytes and connection
attempts in the original remote cumulative account, device and resource ledgers
inside the same SQLite IMMEDIATE transaction. Failure rolls back the approval
and all ledger updates. Repeated approval, revoke and expiry never refund or
reserve a second promise. Existing offline digest review, signing and one-use
process proof remain mandatory for each endpoint.

Source regressions cover atomic second approval, quota exhaustion, one-use
consumption, revoke without refund and independence from short online expiry.
Hosted validation is required before these implementations are verified. This
change alone does not implement the complete offline remote media/input/file
carrier, user interface or target-device acceptance.
