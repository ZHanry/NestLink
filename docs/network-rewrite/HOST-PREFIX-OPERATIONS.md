# Explicit host-prefix observations

The relay can measure TCP reachability of explicitly selected hosts and publish
the resulting short-lived observations through its existing signed topology
reporter. This is an observation feature. NetworkAccess, packet forwarding,
TUN/LAN routes and subnet access require separate authority and implementation.

First create and verify the exact RouteExport and topology publisher grants for
the registered relay in the space. A /32 IPv4 or /128 IPv6 prefix must appear
exactly in the publisher's allowed prefixes, backed by its stored export. A
broader subnet export does not authorize a narrower prefix under this contract.

Create a private JSON file using the same OS ownership and ACL protection as the
node configuration and identity key. Each choice binds the deployment, node,
space, exact publisher grant, host prefix and fixed TCP destination:

```json
{
  "schema_version": 1,
  "deployment_id": "11111111-1111-4111-8111-111111111111",
  "node_id": "22222222-2222-4222-8222-222222222222",
  "choices": [
    {
      "space_id": "33333333-3333-4333-8333-333333333333",
      "publisher_grant_id": "44444444-4444-4444-8444-444444444444",
      "prefix": { "network": "192.0.2.10", "prefix_len": 32 },
      "target": "192.0.2.10:443"
    }
  ]
}
```

Use actual IDs and a host/port which the local administrator permits the relay
to probe. The connection sends no application payload. Hostnames, loopback,
default routes, mapped IPv6 addresses, mismatched hosts, duplicate space/prefix
choices and unknown fields are rejected. The existing protocol prefix limit
also caps this file. A remote report or management setting cannot supply the
local choice.

Start the verified server artifact with:

```text
nestlink-server relay --config /private/node.toml --local-prefixes /private/host-prefixes.json
```

The existing protected-file reader checks the file before listeners start.
Without `--local-prefixes`, the relay continues publishing neighbor observations
with no locally measured prefixes. An explicitly empty choices list also leaves
prefix measurement disabled.

Each choice starts once when its exact publisher grant first appears in a
current authenticated resource snapshot. Signature/export failure consumes the
choice and logs a refusal. Omission, replacement, expiry or revocation of the
original authority permanently invalidates that owner; new grants and renewed
leases do not extend or silently recreate it. Review current authority and
explicitly restart with a new protected choice to approve another owner.

The reporter includes only currently reachable owners and rechecks their exact
evidence after HTTP acknowledgements. Failed TCP observations withdraw the
prefix. Recovery advances the observation continuity fence; it cannot validate
an acknowledgement from before the failure. Neighbor and prefix reports use
the original per-runtime sequence owner and shared report limits.

Shutdown withdraws all evidence immediately, aborts and joins in-flight reports
and probes, then joins every local prefix owner under the same five-second
cleanup deadline. An unjoined task or surviving report reference causes cleanup
to fail. Dropping a canceled owner requests abort without claiming a physical
join. Only run Actions-built and digest-verified artifacts on target devices;
source tests and hosted observations do not qualify subnet forwarding.
