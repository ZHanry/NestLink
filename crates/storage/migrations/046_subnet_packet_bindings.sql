-- A gateway owner must explicitly bind independently proven installation and
-- node identities. Equal UUID text or an unselected equal key grants nothing.
ALTER TABLE network_packet_access ADD COLUMN subnet_binding_count INTEGER NOT NULL DEFAULT 0 CHECK(subnet_binding_count BETWEEN 0 AND 2);
CREATE TABLE network_subnet_installations (
 space_id TEXT NOT NULL,
 mapping_id TEXT NOT NULL,
 installation_id TEXT NOT NULL REFERENCES devices(id),
 membership_grant_id TEXT NOT NULL,
 public_key BLOB NOT NULL CHECK(length(public_key)=32),
 membership_digest BLOB NOT NULL CHECK(length(membership_digest)=32),
 mapping_digest BLOB NOT NULL CHECK(length(mapping_digest)=32),
 mapping_revision INTEGER NOT NULL CHECK(mapping_revision>0),
 approved_at_ms INTEGER NOT NULL CHECK(approved_at_ms>0),
 PRIMARY KEY(space_id,mapping_id),
 UNIQUE(space_id,mapping_id,installation_id,membership_grant_id),
 FOREIGN KEY(space_id,mapping_id) REFERENCES network_subnet_mappings(space_id,grant_id),
 FOREIGN KEY(space_id,membership_grant_id) REFERENCES network_grants(space_id,grant_id)
) STRICT;
CREATE TABLE network_subnet_packet_bindings (
 space_id TEXT NOT NULL,
 access_grant_id TEXT NOT NULL,
 endpoint INTEGER NOT NULL CHECK(endpoint IN(0,1)),
 mapping_id TEXT NOT NULL,
 installation_id TEXT NOT NULL,
 membership_grant_id TEXT NOT NULL,
 mapping_digest BLOB NOT NULL CHECK(length(mapping_digest)=32),
 mapping_revision INTEGER NOT NULL CHECK(mapping_revision>0),
 access_digest BLOB NOT NULL CHECK(length(access_digest)=32),
 PRIMARY KEY(space_id,access_grant_id,endpoint),
 UNIQUE(space_id,access_grant_id,mapping_id),
 FOREIGN KEY(space_id,access_grant_id) REFERENCES network_packet_access(space_id,access_grant_id),
 FOREIGN KEY(space_id,mapping_id,installation_id,membership_grant_id) REFERENCES network_subnet_installations(space_id,mapping_id,installation_id,membership_grant_id)
) STRICT;
CREATE INDEX network_subnet_packet_mapping ON network_subnet_packet_bindings(space_id,mapping_id);
