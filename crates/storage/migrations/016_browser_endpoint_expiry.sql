ALTER TABLE devices ADD COLUMN expires_at INTEGER CHECK(expires_at IS NULL OR expires_at > 0);
CREATE INDEX devices_expiry ON devices(expires_at) WHERE expires_at IS NOT NULL;
