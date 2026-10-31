-- Reuse the existing offline settings/review/consume lifecycle without a fake
-- private service ACL or service lease. Original remote authority is frozen.
CREATE TABLE offline_remote_bundles (
 bundle_id TEXT PRIMARY KEY,
 space_id TEXT NOT NULL REFERENCES offline_settings(space_id),
 requester_account TEXT NOT NULL REFERENCES accounts(id),
 requester_login TEXT NOT NULL REFERENCES management_sessions(id),
 claims_json TEXT NOT NULL,
 draft_digest BLOB NOT NULL UNIQUE CHECK(length(draft_digest)=32),
 authority_key BLOB NOT NULL CHECK(length(authority_key)=32),
 original_permit_json TEXT NOT NULL CHECK(json_valid(original_permit_json)),
 approval0 TEXT, approval1 TEXT,
 consume_challenge0 BLOB NOT NULL CHECK(length(consume_challenge0)=32),
 consume_challenge1 BLOB NOT NULL CHECK(length(consume_challenge1)=32),
 consumed0 INTEGER NOT NULL DEFAULT 0 CHECK(consumed0 IN (0,1)),
 consumed1 INTEGER NOT NULL DEFAULT 0 CHECK(consumed1 IN (0,1)),
 signed_json TEXT,
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
) STRICT;
CREATE INDEX offline_remote_bundles_space ON offline_remote_bundles(space_id,bundle_id);
