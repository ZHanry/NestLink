ALTER TABLE browser_host_readiness ADD COLUMN protocol_features TEXT NOT NULL DEFAULT '[]'
  CHECK(json_valid(protocol_features) AND length(protocol_features)<=128);
