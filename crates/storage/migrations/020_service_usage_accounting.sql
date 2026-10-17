-- Durable lifetime byte budgets and immutable report/stop highwaters.
CREATE TABLE service_quota_settings (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 revision INTEGER NOT NULL CHECK(revision>0),
 restore_fenced INTEGER NOT NULL DEFAULT 0 CHECK(restore_fenced IN (0,1))
) STRICT;
INSERT INTO service_quota_settings(singleton,revision) VALUES(1,1);

CREATE TABLE service_quota_limits (
 scope_kind TEXT NOT NULL CHECK(scope_kind IN ('account','device','node','resource')),
 scope_key TEXT NOT NULL CHECK(length(scope_key)=36),
 limit_bytes INTEGER NOT NULL CHECK(limit_bytes BETWEEN 0 AND 9223372036854775807),
 revision INTEGER NOT NULL CHECK(revision>0),
 PRIMARY KEY(scope_kind,scope_key)
) STRICT;

CREATE TABLE service_quota_ledgers (
 scope_kind TEXT NOT NULL CHECK(scope_kind IN ('account','device','node','resource')),
 scope_key TEXT NOT NULL CHECK(length(scope_key)=36),
 spent_bytes INTEGER NOT NULL DEFAULT 0 CHECK(spent_bytes BETWEEN 0 AND 9223372036854775807),
 PRIMARY KEY(scope_kind,scope_key),
 FOREIGN KEY(scope_kind,scope_key) REFERENCES service_quota_limits(scope_kind,scope_key)
) STRICT;

CREATE TABLE service_usage_grants (
 grant_id TEXT PRIMARY KEY,
 grant_sequence INTEGER NOT NULL CHECK(grant_sequence>0),
 publication_id TEXT NOT NULL,
 publication_generation INTEGER NOT NULL CHECK(publication_generation>0),
 deployment_id TEXT NOT NULL,
 security_epoch INTEGER NOT NULL CHECK(security_epoch>0),
 policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
 quota_revision INTEGER NOT NULL CHECK(quota_revision>0),
 account_id TEXT NOT NULL,
 host_device_id TEXT NOT NULL,
 service_id TEXT NOT NULL,
 node_id TEXT NOT NULL,
 edge_runtime_id TEXT NOT NULL,
 edge_runtime_generation INTEGER NOT NULL CHECK(edge_runtime_generation>0),
 grant_json TEXT NOT NULL CHECK(json_valid(grant_json) AND length(grant_json)<=32768),
 grant_sha256 BLOB NOT NULL CHECK(length(grant_sha256)=32),
 grant_bytes INTEGER NOT NULL CHECK(grant_bytes BETWEEN 1 AND 9223372036854775807),
 admitted_bytes INTEGER NOT NULL DEFAULT 0 CHECK(admitted_bytes BETWEEN 0 AND grant_bytes),
 opened_connections INTEGER NOT NULL DEFAULT 0 CHECK(opened_connections>=0),
 closed_connections INTEGER NOT NULL DEFAULT 0 CHECK(closed_connections>=0 AND closed_connections<=opened_connections),
 maximum_connections INTEGER NOT NULL CHECK(maximum_connections BETWEEN 1 AND 128),
 bytes_per_second INTEGER NOT NULL CHECK(bytes_per_second>0),
 report_sequence INTEGER NOT NULL DEFAULT 0 CHECK(report_sequence>=0),
 report_sha256 BLOB NOT NULL CHECK(length(report_sha256)=32),
 sampled_at INTEGER NOT NULL DEFAULT 0 CHECK(sampled_at>=0),
 report_json TEXT,
 report_ack_json TEXT,
 terminal INTEGER NOT NULL DEFAULT 0 CHECK(terminal IN (0,1)),
 stop_nonce BLOB UNIQUE CHECK(stop_nonce IS NULL OR length(stop_nonce)=32),
 stop_sha256 BLOB CHECK(stop_sha256 IS NULL OR length(stop_sha256)=32),
 stopped_at INTEGER,
 UNIQUE(publication_id,publication_generation,grant_sequence)
) STRICT;
CREATE INDEX service_usage_grants_account ON service_usage_grants(account_id,terminal);
CREATE INDEX service_usage_grants_device ON service_usage_grants(host_device_id,terminal);
CREATE INDEX service_usage_grants_node ON service_usage_grants(node_id,terminal);
CREATE INDEX service_usage_grants_resource ON service_usage_grants(service_id,terminal);

CREATE TABLE service_usage_reports (
 grant_id TEXT NOT NULL REFERENCES service_usage_grants(grant_id),
 report_sequence INTEGER NOT NULL CHECK(report_sequence>0),
 report_sha256 BLOB NOT NULL CHECK(length(report_sha256)=32),
 report_json TEXT NOT NULL CHECK(json_valid(report_json) AND length(report_json)<=32768),
 ack_json TEXT NOT NULL CHECK(json_valid(ack_json) AND length(ack_json)<=32768),
 PRIMARY KEY(grant_id,report_sequence)
) STRICT;

CREATE TABLE service_usage_stops (
 grant_id TEXT PRIMARY KEY REFERENCES service_usage_grants(grant_id),
 stop_nonce BLOB NOT NULL UNIQUE CHECK(length(stop_nonce)=32),
 stop_sha256 BLOB NOT NULL CHECK(length(stop_sha256)=32),
 stop_json TEXT NOT NULL CHECK(json_valid(stop_json) AND length(stop_json)<=32768),
 acknowledged_at INTEGER NOT NULL CHECK(acknowledged_at>0)
) STRICT;
