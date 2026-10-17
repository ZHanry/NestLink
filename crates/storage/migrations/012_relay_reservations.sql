CREATE TABLE relay_reservation_settings (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 restore_fenced INTEGER NOT NULL DEFAULT 0 CHECK(restore_fenced IN (0,1)),
 control_runtime_id TEXT
) STRICT;
INSERT INTO relay_reservation_settings VALUES(1,0,NULL);
CREATE TABLE relay_reservations (
 id TEXT PRIMARY KEY,
 kind TEXT NOT NULL CHECK(kind IN ('combined','node')),
 session_id TEXT NOT NULL REFERENCES remote_requests(id),
 security_epoch INTEGER NOT NULL CHECK(security_epoch>0),
 controller_account_id TEXT NOT NULL REFERENCES accounts(id),
 host_account_id TEXT NOT NULL REFERENCES accounts(id),
 node_id TEXT REFERENCES data_nodes(id),
 runtime_id TEXT NOT NULL,
 control_runtime_id TEXT NOT NULL,
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>=0),
 connection_generation INTEGER NOT NULL CHECK(connection_generation>0),
 policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
 quota_revision INTEGER NOT NULL CHECK(quota_revision>0),
 binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32),
 promised_until INTEGER NOT NULL CHECK(promised_until>0),
 closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1)),
 claims_json TEXT CHECK(claims_json IS NULL OR json_valid(claims_json)),
 CHECK((kind='combined' AND node_id IS NULL AND runtime_generation=0 AND claims_json IS NULL) OR
       (kind='node' AND node_id IS NOT NULL AND runtime_generation>0 AND claims_json IS NOT NULL))
) STRICT;
CREATE INDEX relay_reservation_expiry ON relay_reservations(promised_until);
CREATE INDEX relay_reservation_node ON relay_reservations(node_id,promised_until);
CREATE UNIQUE INDEX combined_live_reservation ON relay_reservations(session_id,runtime_id,connection_generation) WHERE kind='combined' AND closed=0;
CREATE TABLE relay_reservation_connections (
 reservation_id TEXT NOT NULL REFERENCES relay_reservations(id),
 role INTEGER NOT NULL CHECK(role IN (1,2)),
 connection_id TEXT NOT NULL UNIQUE,
 lease_sequence INTEGER NOT NULL CHECK(lease_sequence>0),
 expires_at INTEGER NOT NULL CHECK(expires_at>0),
 PRIMARY KEY(reservation_id,role)
) STRICT;
CREATE INDEX relay_connection_expiry ON relay_reservation_connections(expires_at);
