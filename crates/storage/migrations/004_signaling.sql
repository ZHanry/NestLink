CREATE TABLE remote_signals (
  session_id TEXT NOT NULL REFERENCES remote_requests(id),
  device_id TEXT NOT NULL REFERENCES devices(id),
  network_generation INTEGER NOT NULL CHECK(network_generation>0),
  sequence INTEGER NOT NULL CHECK(sequence>0),
  lease_sequence INTEGER NOT NULL CHECK(lease_sequence>0),
  received_at INTEGER NOT NULL,
  signal_json TEXT NOT NULL CHECK(json_valid(signal_json) AND length(signal_json)<=98304),
  PRIMARY KEY(session_id,device_id)
) STRICT;
