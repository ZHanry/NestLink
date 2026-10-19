-- Preparation is a bounded rendezvous hint, never a media/session lease.
CREATE TABLE browser_host_readiness (
  request_id TEXT PRIMARY KEY REFERENCES remote_requests(id),
  connection_generation INTEGER NOT NULL CHECK(connection_generation>0),
  ready_until INTEGER NOT NULL
) STRICT;
