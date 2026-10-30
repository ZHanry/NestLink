-- Immutable, consent-bound direct path chains. Revocation never renews a row.
CREATE TABLE network_remote_paths (
 space_id TEXT NOT NULL REFERENCES network_authorities(space_id),
 path_grant_id TEXT NOT NULL,
 connectivity_grant_id TEXT NOT NULL,
 request_id TEXT NOT NULL REFERENCES remote_requests(id),
 controller_membership_id TEXT NOT NULL,
 host_membership_id TEXT NOT NULL,
 policy_epoch INTEGER NOT NULL CHECK(policy_epoch>0),
 business_digest BLOB NOT NULL CHECK(length(business_digest)=32),
 connectivity_claims BLOB NOT NULL CHECK(length(connectivity_claims)>0 AND length(connectivity_claims)<=16384),
 connectivity_signature BLOB NOT NULL CHECK(length(connectivity_signature)=64),
 path_claims BLOB NOT NULL CHECK(length(path_claims)>0 AND length(path_claims)<=16384),
 path_signature BLOB NOT NULL CHECK(length(path_signature)=64),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>0),
 revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1)),
 PRIMARY KEY(space_id,path_grant_id),
 UNIQUE(space_id,connectivity_grant_id),
 CHECK(path_grant_id<>connectivity_grant_id),
 FOREIGN KEY(space_id,controller_membership_id) REFERENCES network_grants(space_id,grant_id),
 FOREIGN KEY(space_id,host_membership_id) REFERENCES network_grants(space_id,grant_id)
) STRICT;
CREATE INDEX network_remote_paths_current ON network_remote_paths(space_id,policy_epoch,expires_at_ms);
