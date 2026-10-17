CREATE TABLE turn_endpoints (
 node_id TEXT PRIMARY KEY REFERENCES data_nodes(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 config_json TEXT NOT NULL CHECK(json_valid(config_json))
) STRICT;
CREATE TABLE turn_grants (
 id TEXT PRIMARY KEY,
 session_id TEXT NOT NULL REFERENCES remote_requests(id),
 account_id TEXT NOT NULL REFERENCES accounts(id),
 device_id TEXT NOT NULL REFERENCES devices(id),
 node_id TEXT NOT NULL REFERENCES data_nodes(id),
 runtime_id TEXT NOT NULL,
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 security_epoch INTEGER NOT NULL CHECK(security_epoch>0),
 control_runtime_id TEXT NOT NULL,
 promised_until INTEGER NOT NULL CHECK(promised_until>0),
 closed INTEGER NOT NULL DEFAULT 0 CHECK(closed IN (0,1)),
 claims_json TEXT NOT NULL CHECK(json_valid(claims_json)),
 password_cipher BLOB NOT NULL CHECK(length(password_cipher) BETWEEN 40 AND 1024)
) STRICT;
CREATE INDEX turn_grant_expiry ON turn_grants(promised_until);
CREATE INDEX turn_grant_node ON turn_grants(node_id,promised_until);
CREATE TABLE turn_peer_bindings (
 session_id TEXT PRIMARY KEY REFERENCES remote_requests(id),
 claims BLOB NOT NULL CHECK(length(claims) BETWEEN 1 AND 16384),
 controller_signature BLOB CHECK(controller_signature IS NULL OR length(controller_signature)=64),
 host_signature BLOB CHECK(host_signature IS NULL OR length(host_signature)=64)
) STRICT;
CREATE TABLE turn_snapshot_sequences (
 node_id TEXT PRIMARY KEY REFERENCES data_nodes(id),
 runtime_id TEXT NOT NULL,
 runtime_generation INTEGER NOT NULL CHECK(runtime_generation>0),
 request_sequence INTEGER NOT NULL CHECK(request_sequence>0),
 snapshot_sequence INTEGER NOT NULL CHECK(snapshot_sequence>0)
) STRICT;
