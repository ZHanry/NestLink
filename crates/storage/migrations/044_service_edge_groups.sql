-- Group members use the original publication promises and four quota ledgers.
-- A group never owns an independent balance that can be spent a second time.
ALTER TABLE service_publications ADD COLUMN edge_group_id TEXT CHECK(edge_group_id IS NULL OR length(edge_group_id)=36);
ALTER TABLE service_publications ADD COLUMN edge_group_revision INTEGER CHECK(edge_group_revision IS NULL OR edge_group_revision>0);
DROP INDEX service_definition_owner;
CREATE UNIQUE INDEX service_definition_owner ON service_publications(service_id) WHERE state IN (0,1) AND edge_group_id IS NULL;
CREATE UNIQUE INDEX service_definition_member_owner ON service_publications(service_id,node_id) WHERE state IN (0,1);

CREATE TABLE service_edge_groups (
 service_id TEXT PRIMARY KEY REFERENCES services(id),
 group_id TEXT NOT NULL UNIQUE CHECK(length(group_id)=36),
 revision INTEGER NOT NULL CHECK(revision>0),
 service_revision INTEGER NOT NULL CHECK(service_revision>0),
 view_json TEXT NOT NULL CHECK(json_valid(view_json) AND length(view_json)<=16384),
 aggregate_sha256 BLOB NOT NULL CHECK(length(aggregate_sha256)=32),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN(0,1))
) STRICT;
-- A web hostname is exclusive across all nodes. Fixed TCP/UDP front doors are
-- exclusive by IP+port. The old promise remains held after group withdrawal.
CREATE TABLE service_edge_group_ingress (
 ingress_key TEXT PRIMARY KEY CHECK(length(ingress_key)<=320),
 service_id TEXT NOT NULL REFERENCES services(id),
 group_id TEXT NOT NULL REFERENCES service_edge_groups(group_id),
 promised_until INTEGER NOT NULL CHECK(promised_until>0)
) STRICT;
CREATE INDEX service_edge_group_ingress_promises ON service_edge_group_ingress(promised_until,service_id);
