CREATE TABLE remote_passwords (
  host_device_id TEXT PRIMARY KEY REFERENCES devices(id),
  revision INTEGER NOT NULL CHECK(revision>0),
  encoded TEXT,
  host_key_sha256 BLOB NOT NULL CHECK(length(host_key_sha256)=32),
  permissions_json TEXT NOT NULL CHECK(json_valid(permissions_json)),
  paths_json TEXT NOT NULL CHECK(json_valid(paths_json)),
  security_epoch INTEGER NOT NULL,
  configured_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  window_start INTEGER NOT NULL DEFAULT 0,
  window_count INTEGER NOT NULL DEFAULT 0 CHECK(window_count BETWEEN 0 AND 5)
) STRICT;
CREATE TABLE remote_password_account_limits (
  account_id TEXT PRIMARY KEY REFERENCES accounts(id),
  window_start INTEGER NOT NULL,
  window_count INTEGER NOT NULL CHECK(window_count BETWEEN 0 AND 30)
) STRICT;
ALTER TABLE remote_requests ADD COLUMN password_revision INTEGER;
ALTER TABLE remote_requests ADD COLUMN password_controller_key_sha256 BLOB
  CHECK(password_controller_key_sha256 IS NULL OR length(password_controller_key_sha256)=32);
