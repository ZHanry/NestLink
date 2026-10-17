CREATE TABLE audit_settings (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  revision INTEGER NOT NULL CHECK(revision>0),
  retention_seconds INTEGER NOT NULL CHECK(retention_seconds BETWEEN 3600 AND 31536000),
  high_watermark INTEGER NOT NULL CHECK(high_watermark>=0),
  pruned_through INTEGER NOT NULL DEFAULT 0 CHECK(pruned_through>=0 AND pruned_through<=high_watermark),
  last_cleanup_at INTEGER NOT NULL DEFAULT 0 CHECK(last_cleanup_at>=0)
) STRICT;
INSERT INTO audit_settings(singleton,revision,retention_seconds,high_watermark)
  SELECT 1,1,2592000,COALESCE(MAX(sequence),0) FROM audit;
CREATE INDEX audit_expiry ON audit(created_at,sequence);
