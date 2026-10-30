-- This scope only restricts existing independently approved service publishing.
-- A revoked binding is a permanent fence until its service owner rebinds;
-- deleting a rule must never restore legacy publication rights.
CREATE TABLE space_service_bindings (
 service_id TEXT PRIMARY KEY REFERENCES services(id),
 space_id TEXT NOT NULL REFERENCES network_spaces(space_id),
 account_id TEXT NOT NULL REFERENCES accounts(id),
 host_device_id TEXT NOT NULL REFERENCES devices(id),
 service_revision INTEGER NOT NULL CHECK(service_revision>0),
 binding_epoch INTEGER NOT NULL CHECK(binding_epoch>0),
 protocol TEXT NOT NULL CHECK(protocol IN ('http','https','tcp','udp')),
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 UNIQUE(space_id,service_id)
) STRICT;
CREATE INDEX space_service_bindings_space ON space_service_bindings(space_id,service_id);
CREATE TABLE space_service_rules (
 rule_id TEXT PRIMARY KEY,
 space_id TEXT NOT NULL,
 service_id TEXT NOT NULL,
 binding_epoch INTEGER NOT NULL CHECK(binding_epoch>0),
 subject_kind TEXT NOT NULL CHECK(subject_kind IN ('account','device')),
 subject_id TEXT NOT NULL,
 subject_epoch INTEGER NOT NULL CHECK(subject_epoch>0),
 host_membership_epoch INTEGER NOT NULL CHECK(host_membership_epoch>0),
 protocol TEXT NOT NULL CHECK(protocol IN ('http','https','tcp','udp')),
 port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
 operation TEXT NOT NULL CHECK(operation='publish'),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>0),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 FOREIGN KEY(space_id,service_id) REFERENCES space_service_bindings(space_id,service_id)
) STRICT;
CREATE INDEX space_service_rules_current ON space_service_rules(space_id,service_id,binding_epoch,expires_at_ms);
