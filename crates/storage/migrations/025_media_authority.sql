-- No positional legacy device_details columns are changed.
CREATE TABLE device_media_announcements (
 device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
 direction TEXT NOT NULL CHECK(direction IN ('encode','decode')),
 revision INTEGER NOT NULL CHECK(revision>0),
 json TEXT NOT NULL CHECK(json_valid(json) AND length(json)<=65536),
 sha256 BLOB NOT NULL CHECK(length(sha256)=32),
 expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms>0),
 probe_generation INTEGER NOT NULL CHECK(probe_generation>0),
 action_json TEXT NOT NULL CHECK(json_valid(action_json) AND length(action_json)<=4096),
 signature BLOB NOT NULL CHECK(length(signature)=64),
 PRIMARY KEY(device_id,direction)
) STRICT;
CREATE TABLE remote_media_scopes (
 request_id TEXT PRIMARY KEY REFERENCES remote_requests(id) ON DELETE CASCADE,
 json TEXT NOT NULL CHECK(json_valid(json) AND length(json)<=65536),
 sha256 BLOB NOT NULL CHECK(length(sha256)=32)
) STRICT;
