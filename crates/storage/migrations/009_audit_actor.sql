-- Existing records cannot establish an actor retrospectively.
ALTER TABLE audit ADD COLUMN actor_json TEXT NOT NULL DEFAULT '{"kind":"legacy"}'
    CHECK(length(actor_json) BETWEEN 1 AND 512 AND json_valid(actor_json));
