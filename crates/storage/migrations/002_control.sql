CREATE TABLE account_security (
  account_id TEXT PRIMARY KEY REFERENCES accounts(id),
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0 CHECK(is_admin IN (0,1)),
  totp_ciphertext BLOB,
  totp_pending BLOB,
  totp_pending_expires INTEGER,
  totp_last_step INTEGER,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  blocked_until INTEGER NOT NULL DEFAULT 0
) STRICT;
CREATE TABLE recovery_codes (
  account_id TEXT NOT NULL REFERENCES accounts(id),
  code_sha256 BLOB NOT NULL CHECK(length(code_sha256)=32),
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1)),
  PRIMARY KEY(account_id,code_sha256)
) STRICT;
CREATE TABLE management_sessions (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  access_sha256 BLOB NOT NULL UNIQUE CHECK(length(access_sha256)=32),
  refresh_sha256 BLOB NOT NULL UNIQUE CHECK(length(refresh_sha256)=32),
  generation INTEGER NOT NULL CHECK(generation>0),
  security_epoch INTEGER NOT NULL CHECK(security_epoch>0),
  access_expires INTEGER NOT NULL,
  refresh_expires INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
) STRICT;
CREATE INDEX management_account ON management_sessions(account_id);
CREATE TABLE enrollment_challenges (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  nonce BLOB NOT NULL CHECK(length(nonce)=32),
  expires INTEGER NOT NULL,
  consumed INTEGER NOT NULL DEFAULT 0 CHECK(consumed IN (0,1))
) STRICT;
CREATE TABLE device_details (
  device_id TEXT PRIMARY KEY REFERENCES devices(id),
  public_key BLOB NOT NULL UNIQUE CHECK(length(public_key)=32),
  name TEXT NOT NULL,
  platform TEXT NOT NULL,
  capabilities_json TEXT NOT NULL CHECK(json_valid(capabilities_json)),
  path_mode TEXT NOT NULL CHECK(path_mode IN ('direct_only','direct_preferred','relay_only'))
) STRICT;
CREATE TABLE remote_requests (
  id TEXT PRIMARY KEY,
  controller_device_id TEXT NOT NULL REFERENCES devices(id),
  host_device_id TEXT NOT NULL REFERENCES devices(id),
  controller_account_id TEXT NOT NULL REFERENCES accounts(id),
  permissions_json TEXT NOT NULL CHECK(json_valid(permissions_json)),
  paths_json TEXT NOT NULL CHECK(json_valid(paths_json)),
  request_json TEXT NOT NULL CHECK(json_valid(request_json)),
  last_permit_json TEXT CHECK(last_permit_json IS NULL OR json_valid(last_permit_json)),
  capability_sha256 BLOB NOT NULL CHECK(length(capability_sha256)=32),
  nonce BLOB NOT NULL CHECK(length(nonce)=32),
  policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
  expires INTEGER NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected','revoked')),
  lease_sequence INTEGER NOT NULL DEFAULT 0,
  connection_generation INTEGER NOT NULL DEFAULT 1,
  last_renewed INTEGER NOT NULL DEFAULT 0,
  CHECK(controller_device_id<>host_device_id)
) STRICT;
CREATE INDEX requests_host ON remote_requests(host_device_id,status);
