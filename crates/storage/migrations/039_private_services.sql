-- Exposure is separate from legacy definition JSON so old exact target proofs
-- retain their bytes. A row is a permanent fence against legacy fallback.
CREATE TABLE service_exposures (
 service_id TEXT PRIMARY KEY REFERENCES services(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 service_revision INTEGER NOT NULL CHECK(service_revision>0),
 target_sha256 BLOB NOT NULL CHECK(length(target_sha256)=32),
 space_id TEXT NOT NULL REFERENCES network_spaces(space_id),
 mode TEXT NOT NULL CHECK(mode IN ('private','public','both')),
 private_bytes INTEGER NOT NULL CHECK(private_bytes>=0),
 public_bytes INTEGER NOT NULL CHECK(public_bytes>=0)
) STRICT;
CREATE TABLE private_service_acl (
 rule_id TEXT PRIMARY KEY,
 service_id TEXT NOT NULL REFERENCES service_exposures(service_id),
 exposure_revision INTEGER NOT NULL CHECK(exposure_revision>0),
 subject_kind TEXT NOT NULL CHECK(subject_kind IN ('account','installation')),
 subject_id TEXT NOT NULL,
 subject_epoch INTEGER NOT NULL CHECK(subject_epoch>0),
 host_epoch INTEGER NOT NULL CHECK(host_epoch>0),
 expires_at INTEGER NOT NULL CHECK(expires_at>0),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
) STRICT;
CREATE INDEX private_service_acl_service ON private_service_acl(service_id,exposure_revision,expires_at);
CREATE TABLE private_service_hosts (
 service_id TEXT PRIMARY KEY REFERENCES service_exposures(service_id),
 runtime_id TEXT NOT NULL,
 request_sequence INTEGER NOT NULL CHECK(request_sequence>0),
 claims_sha256 BLOB NOT NULL CHECK(length(claims_sha256)=32),
 claims_json TEXT NOT NULL CHECK(json_valid(claims_json)),
 expires_at INTEGER NOT NULL CHECK(expires_at>0)
) STRICT;
-- Reservations remain in service_usage_grants, not in a second quota balance.
CREATE TABLE private_service_leases (
 grant_id TEXT PRIMARY KEY REFERENCES service_usage_grants(grant_id),
 service_id TEXT NOT NULL REFERENCES services(id),
 space_id TEXT NOT NULL REFERENCES network_spaces(space_id),
 exposure_revision INTEGER NOT NULL,
 acl_rule_id TEXT NOT NULL REFERENCES private_service_acl(rule_id),
 host_device_id TEXT NOT NULL REFERENCES devices(id),
 host_epoch INTEGER NOT NULL,
 runtime_id TEXT NOT NULL,
 consumer_device_id TEXT NOT NULL REFERENCES devices(id),
 request_id TEXT NOT NULL UNIQUE,
 request_sha256 BLOB NOT NULL CHECK(length(request_sha256)=32),
 lease_json TEXT NOT NULL CHECK(json_valid(lease_json)),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
) STRICT;
CREATE INDEX private_service_leases_service ON private_service_leases(service_id,revoked);
CREATE TABLE private_service_usage_reports (
 grant_id TEXT NOT NULL REFERENCES private_service_leases(grant_id),
 report_sequence INTEGER NOT NULL CHECK(report_sequence>0),
 report_sha256 BLOB NOT NULL CHECK(length(report_sha256)=32),
 report_json TEXT NOT NULL CHECK(json_valid(report_json)),
 ack_json TEXT NOT NULL CHECK(json_valid(ack_json)),
 PRIMARY KEY(grant_id,report_sequence)
) STRICT;
