CREATE TABLE path_limits (
  scope TEXT NOT NULL CHECK(scope IN ('account','device','resource','login_session')),
  resource_id TEXT NOT NULL,
  path_mode TEXT NOT NULL CHECK(path_mode IN ('direct_only','direct_preferred','relay_only')),
  PRIMARY KEY(scope,resource_id)
) STRICT;
ALTER TABLE remote_requests ADD COLUMN management_session_id TEXT REFERENCES management_sessions(id);
ALTER TABLE audit ADD COLUMN created_at INTEGER NOT NULL DEFAULT 0;
UPDATE audit SET created_at=unixepoch() WHERE created_at=0;
