-- Advisory metadata is independent of immutable identity, runtime and budgets.
-- An absent row means revision zero with both attributes unknown.
CREATE TABLE node_relay_attributes (
 node_id TEXT PRIMARY KEY REFERENCES data_nodes(id),
 revision INTEGER NOT NULL CHECK(revision>0),
 region TEXT CHECK(region IS NULL OR (length(region) BETWEEN 1 AND 32 AND region NOT GLOB '*[^a-z0-9-]*')),
 cost_weight INTEGER CHECK(cost_weight IS NULL OR cost_weight BETWEEN 0 AND 1000000)
) STRICT;
