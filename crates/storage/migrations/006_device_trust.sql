CREATE TABLE trusted_devices (
  host_device_id TEXT NOT NULL REFERENCES devices(id),
  controller_device_id TEXT NOT NULL REFERENCES devices(id),
  host_key_sha256 BLOB NOT NULL CHECK(length(host_key_sha256)=32),
  controller_key_sha256 BLOB NOT NULL CHECK(length(controller_key_sha256)=32),
  permissions_json TEXT NOT NULL CHECK(json_valid(permissions_json)),
  paths_json TEXT NOT NULL CHECK(json_valid(paths_json)),
  revision INTEGER NOT NULL CHECK(revision>0),
  security_epoch INTEGER NOT NULL CHECK(security_epoch>0),
  granted_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL CHECK(expires_at>granted_at),
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
  source_request_id TEXT NOT NULL REFERENCES remote_requests(id),
  PRIMARY KEY(host_device_id,controller_device_id),
  CHECK(host_device_id<>controller_device_id)
) STRICT;
ALTER TABLE remote_requests ADD COLUMN trust_revision INTEGER CHECK(trust_revision IS NULL OR trust_revision>0);
CREATE INDEX requests_trust ON remote_requests(host_device_id,controller_device_id,trust_revision);
