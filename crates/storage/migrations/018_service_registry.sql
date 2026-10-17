-- Configuration and explicit target consent only; none of these rows owns a listener.
CREATE TABLE services (
 id TEXT PRIMARY KEY,
 account_id TEXT NOT NULL REFERENCES accounts(id),
 management_session_id TEXT NOT NULL REFERENCES management_sessions(id),
 host_device_id TEXT NOT NULL REFERENCES devices(id),
 edge_node_id TEXT NOT NULL REFERENCES data_nodes(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 definition_json TEXT NOT NULL CHECK(json_valid(definition_json) AND length(definition_json)<=16384),
 definition_sha256 BLOB NOT NULL CHECK(length(definition_sha256)=32),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
) STRICT;
CREATE INDEX services_owner ON services(account_id,id);
CREATE TABLE service_approval_challenges (
 id TEXT PRIMARY KEY,
 service_id TEXT NOT NULL REFERENCES services(id),
 account_id TEXT NOT NULL REFERENCES accounts(id),
 management_session_id TEXT NOT NULL REFERENCES management_sessions(id),
 service_revision INTEGER NOT NULL CHECK(service_revision>0),
 policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
 security_epoch INTEGER NOT NULL CHECK(security_epoch>0),
 nonce BLOB NOT NULL CHECK(length(nonce)=32),
 issued_at INTEGER NOT NULL CHECK(issued_at>0),
 expires_at INTEGER NOT NULL CHECK(expires_at>issued_at AND expires_at-issued_at<=60000),
 consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
) STRICT;
CREATE INDEX service_challenge_owner ON service_approval_challenges(account_id,expires_at);
CREATE TABLE service_target_approvals (
 service_id TEXT PRIMARY KEY REFERENCES services(id),
 management_session_id TEXT NOT NULL REFERENCES management_sessions(id),
 service_revision INTEGER NOT NULL CHECK(service_revision>0),
 policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
 security_epoch INTEGER NOT NULL CHECK(security_epoch>0),
 definition_sha256 BLOB NOT NULL CHECK(length(definition_sha256)=32),
 host_key_sha256 BLOB NOT NULL CHECK(length(host_key_sha256)=32),
 target_id TEXT NOT NULL,
 target_sha256 BLOB NOT NULL CHECK(length(target_sha256)=32),
 approved_at INTEGER NOT NULL CHECK(approved_at>0),
 expires_at INTEGER NOT NULL CHECK(expires_at>approved_at),
 proof_json TEXT NOT NULL CHECK(json_valid(proof_json) AND length(proof_json)<=16384),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
) STRICT;
