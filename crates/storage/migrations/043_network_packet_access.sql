-- Independent explicit raw-IP business authority. Membership and management
-- roles do not create these rows or opt a local operating system into a TUN.
CREATE TABLE network_packet_access (
 space_id TEXT NOT NULL REFERENCES network_spaces(space_id),
 access_grant_id TEXT NOT NULL,
 connectivity_grant_id TEXT NOT NULL,
 path_grant_id TEXT NOT NULL,
 source_installation_id TEXT NOT NULL REFERENCES devices(id),
 destination_installation_id TEXT NOT NULL REFERENCES devices(id),
 source_membership_id TEXT NOT NULL,
 destination_membership_id TEXT NOT NULL,
 policy_epoch INTEGER NOT NULL CHECK(policy_epoch>0),
 digest BLOB NOT NULL CHECK(length(digest)=32),
 request_json TEXT NOT NULL CHECK(length(request_json)>0 AND length(request_json)<=16384 AND json_valid(request_json)),
 addresses_json TEXT NOT NULL CHECK(length(addresses_json)>0 AND length(addresses_json)<=8192 AND json_valid(addresses_json)),
 access_claims BLOB NOT NULL CHECK(length(access_claims)>0 AND length(access_claims)<=16384),
 access_signature BLOB NOT NULL CHECK(length(access_signature)=64),
 connectivity_claims BLOB NOT NULL CHECK(length(connectivity_claims)>0 AND length(connectivity_claims)<=16384),
 connectivity_signature BLOB NOT NULL CHECK(length(connectivity_signature)=64),
 path_claims BLOB NOT NULL CHECK(length(path_claims)>0 AND length(path_claims)<=16384),
 path_signature BLOB NOT NULL CHECK(length(path_signature)=64),
 issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>0),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>issued_at_ms),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 -- These commitments are never cleared by readback, stop, retry or revocation.
 -- Even a retry of the same public owner ID is a second, rejected start.
 source_claim_owner TEXT CHECK(source_claim_owner IS NULL OR length(source_claim_owner)=36),
 destination_claim_owner TEXT CHECK(destination_claim_owner IS NULL OR length(destination_claim_owner)=36),
 PRIMARY KEY(space_id,access_grant_id),
 UNIQUE(space_id,connectivity_grant_id),
 UNIQUE(space_id,path_grant_id),
 CHECK(access_grant_id!=connectivity_grant_id AND access_grant_id!=path_grant_id AND connectivity_grant_id!=path_grant_id),
 CHECK(source_installation_id!=destination_installation_id),
 FOREIGN KEY(space_id,source_membership_id) REFERENCES network_grants(space_id,grant_id),
 FOREIGN KEY(space_id,destination_membership_id) REFERENCES network_grants(space_id,grant_id)
) STRICT;
CREATE INDEX network_packet_access_current ON network_packet_access(space_id,policy_epoch,expires_at_ms);
