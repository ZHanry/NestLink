CREATE TABLE deployment (
  singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
  id TEXT NOT NULL UNIQUE,
  security_epoch INTEGER NOT NULL CHECK(security_epoch > 0),
  policy_revision INTEGER NOT NULL CHECK(policy_revision > 0),
  policy_json TEXT NOT NULL CHECK(json_valid(policy_json))
) STRICT;
CREATE TABLE accounts (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  disabled INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0, 1))
) STRICT;
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  key_sha256 BLOB NOT NULL UNIQUE CHECK(length(key_sha256) = 32),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1))
) STRICT;
CREATE TABLE credentials (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id),
  purpose TEXT NOT NULL CHECK(purpose IN ('management', 'background', 'node')),
  token_sha256 BLOB NOT NULL UNIQUE CHECK(length(token_sha256) = 32),
  generation INTEGER NOT NULL CHECK(generation > 0),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1))
) STRICT;
CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  controller_device_id TEXT NOT NULL REFERENCES devices(id),
  host_device_id TEXT NOT NULL REFERENCES devices(id),
  connection_generation INTEGER NOT NULL CHECK(connection_generation > 0),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1)),
  CHECK(controller_device_id <> host_device_id)
) STRICT;
CREATE INDEX sessions_controller ON sessions(controller_device_id);
CREATE INDEX sessions_host ON sessions(host_device_id);
CREATE TABLE leases (
  id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL REFERENCES sessions(id),
  security_epoch INTEGER NOT NULL CHECK(security_epoch > 0),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0, 1))
) STRICT;
CREATE INDEX leases_session ON leases(session_id);
CREATE TABLE idempotency (
  request_id TEXT PRIMARY KEY,
  operation TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  result INTEGER NOT NULL
) STRICT;
CREATE TABLE audit (
  sequence INTEGER PRIMARY KEY,
  event TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  security_epoch INTEGER NOT NULL
) STRICT;
