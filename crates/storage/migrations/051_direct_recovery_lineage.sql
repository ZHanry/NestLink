-- Additive ancestry, retained independently of the latest reconnect receipt.
-- Older Store versions reject user_version=51 before opening any business.
CREATE INDEX network_remote_paths_business ON network_remote_paths(space_id,request_id,business_digest,path_grant_id);
CREATE TABLE network_direct_recovery_lineage (
 space_id TEXT NOT NULL,
 path_grant_id TEXT NOT NULL,
 parent_path_grant_id TEXT NOT NULL,
 previous_permit_json TEXT NOT NULL CHECK(json_valid(previous_permit_json)),
 next_permit_json TEXT NOT NULL CHECK(json_valid(next_permit_json)),
 submission_json TEXT NOT NULL CHECK(json_valid(submission_json)),
 parent_fingerprint BLOB NOT NULL CHECK(length(parent_fingerprint)=32),
 depth INTEGER NOT NULL CHECK(depth BETWEEN 1 AND 16),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>0),
 PRIMARY KEY(space_id,path_grant_id),
 FOREIGN KEY(space_id,path_grant_id) REFERENCES network_remote_paths(space_id,path_grant_id),
 FOREIGN KEY(space_id,parent_path_grant_id) REFERENCES network_remote_paths(space_id,path_grant_id),
 CHECK(path_grant_id<>parent_path_grant_id)
) STRICT;
