-- A signed offline envelope is never a durable reservation/consume receipt.
CREATE TABLE offline_settings (
    space_id TEXT PRIMARY KEY REFERENCES network_authorities(space_id),
    revision INTEGER NOT NULL CHECK(revision>0),
    enabled INTEGER NOT NULL CHECK(enabled IN(0,1)),
    revocation_epoch INTEGER NOT NULL CHECK(revocation_epoch>0)
) STRICT;
CREATE TABLE offline_bundles (
    bundle_id TEXT PRIMARY KEY,
    space_id TEXT NOT NULL REFERENCES offline_settings(space_id),
    requester_account TEXT NOT NULL REFERENCES accounts(id),
    requester_login TEXT NOT NULL REFERENCES management_sessions(id),
    claims_json TEXT NOT NULL,
    draft_digest BLOB NOT NULL UNIQUE CHECK(length(draft_digest)=32),
    authority_key BLOB NOT NULL CHECK(length(authority_key)=32),
    private_rule_id TEXT NOT NULL REFERENCES private_service_acl(rule_id),
    private_exposure_revision INTEGER NOT NULL CHECK(private_exposure_revision>0),
    approval0 TEXT, approval1 TEXT,
    consume_challenge0 BLOB NOT NULL CHECK(length(consume_challenge0)=32),
    consume_challenge1 BLOB NOT NULL CHECK(length(consume_challenge1)=32),
    consumed0 INTEGER NOT NULL DEFAULT 0 CHECK(consumed0 IN(0,1)),
    consumed1 INTEGER NOT NULL DEFAULT 0 CHECK(consumed1 IN(0,1)),
    signed_json TEXT,
    revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1))
) STRICT;
CREATE INDEX offline_bundles_space ON offline_bundles(space_id,bundle_id);
-- Permanent spend: expiry, revocation, withdrawal and client reports never refund.
CREATE TABLE offline_service_reservations (
    reservation_id TEXT PRIMARY KEY,
    bundle_id TEXT NOT NULL UNIQUE REFERENCES offline_bundles(bundle_id),
    service_id TEXT NOT NULL REFERENCES services(id),
    promised_bytes INTEGER NOT NULL CHECK(promised_bytes>0)
) STRICT;
