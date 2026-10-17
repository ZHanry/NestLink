ALTER TABLE data_nodes ADD COLUMN runtime_id TEXT;
ALTER TABLE data_nodes ADD COLUMN runtime_generation INTEGER NOT NULL DEFAULT 0 CHECK(runtime_generation>=0);
ALTER TABLE data_nodes ADD COLUMN lease_policy_revision INTEGER NOT NULL DEFAULT 0 CHECK(lease_policy_revision>=0);
CREATE TABLE node_runtimes (
  node_id TEXT NOT NULL REFERENCES data_nodes(id),
  runtime_id TEXT NOT NULL,
  generation INTEGER NOT NULL CHECK(generation>0),
  security_epoch INTEGER NOT NULL CHECK(security_epoch>0),
  started_at INTEGER NOT NULL CHECK(started_at>0),
  report_sequence INTEGER NOT NULL DEFAULT 0 CHECK(report_sequence>=0),
  opened INTEGER NOT NULL DEFAULT 0 CHECK(opened>=0),
  closed INTEGER NOT NULL DEFAULT 0 CHECK(closed BETWEEN 0 AND opened),
  admitted_bytes INTEGER NOT NULL DEFAULT 0 CHECK(admitted_bytes>=0),
  sampled_at INTEGER NOT NULL DEFAULT 0 CHECK(sampled_at>=0),
  accepted_at INTEGER NOT NULL DEFAULT 0 CHECK(accepted_at>=0),
  report_digest BLOB CHECK(report_digest IS NULL OR length(report_digest)=32),
  ack_claims BLOB CHECK(ack_claims IS NULL OR length(ack_claims)<=4096),
  PRIMARY KEY(node_id,runtime_id),
  UNIQUE(node_id,generation)
) STRICT;
