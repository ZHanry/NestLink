# Controlled LAN discovery candidate

This is the W28 source candidate. No real-game, cross-site, actual DNS-SD,
Windows or Linux execution pass is claimed by this document.

`nestlink-daemon network-lan` is an ordinary-user resident command. It requires
the protected original installation/login, an exact pinned space authority,
separately issued and locally approved one-use NetworkAccess, a concrete
physical peer endpoint, and a separately reviewed owner-private LAN policy.
The NetworkAccess rules must explicitly allow UDP between the two current
virtual hosts on the policy's `transport_port`, in the intended directions.
Joining a space, seeing a directory entry or receiving a DNS name is insufficient.

Example policy, with IDs, interface, addresses and server changed to the actual
approved deployment:

```json
{
  "schema_version": 1,
  "space_id": "20000000-0000-4000-8000-000000000002",
  "interface_index": 2,
  "interface_address": "192.168.42.2",
  "local_prefix": "192.168.42.0/24",
  "transport_port": 37828,
  "packets_per_second": 100,
  "bytes_per_second": 131072,
  "udp": [
    {
      "id": "teeworlds",
      "port": 8303,
      "local_target": "192.168.42.3:8303",
      "allow_local_to_peer": true,
      "allow_peer_to_local": true,
      "allow_broadcast_discovery": true
    }
  ],
  "mdns": [
    {
      "service_type": "_http._tcp.local.",
      "port": 8080,
      "allow_export": true,
      "allow_import": true
    }
  ]
}
```

The file must be absolute, private to the original owner and at most 16 KiB.
Review every field and calculate its SHA256 with an ordinary file hashing tool;
pass the 32 hash bytes as URL-safe, unpadded base64 in `--approve-policy`.
`--approve-digest` is the independently reviewed signed NetworkAccess digest.
Use the verified same-source Actions executable:

```text
nestlink-daemon network-lan --state-dir <original-private-directory>
  --space <space-id> --grant <original-one-use-grant-id>
  --authority <pinned-space-authority-base64>
  --approve-digest <original-grant-digest-base64>
  --interface <underlay-interface-index> --bind <physical-local-ip:port>
  --dial <exact-physical-peer-ip:port>
  --policy <absolute-owner-private-json>
  --approve-policy <reviewed-policy-sha256-base64>
```

Omit `--dial` on the accepting side. The `interface_index` inside the policy
selects the local application LAN; `--interface` selects the physical encrypted
carrier. They are explicit independent choices. Reusing a consumed start,
editing a policy live or restarting from an old saved plan does not obtain a
new authorization. Stop both originals, obtain fresh one-use grants and review
new policies when changing the deployment.

The UDP adapter host must be separate from the actual LAN game server, with an
available exclusive approved UDP port. It checks real receive interface and
destination metadata, deduplicates broadcasts, pins the only allowed server
response, and proxies later UDP traffic to that exact server. Per direction,
the configured caps are at most 100 envelopes/second and 128 KiB/second. Full
application datagrams use the existing 1400-byte framing ceiling. Oversized
application datagrams, embedded-address protocols, arbitrary layer-2 traffic,
IPv6 multicast discovery and TCP game payloads are outside this adapter.

The two frozen *target candidates*, pending actual compatibility and execution,
are:

| Application | Exact source | Required evidence |
| --- | --- | --- |
| Teeworlds 0.7.5 | official tag commit `4fc25a17fef3e6c2bf4d52b0421e0d69ecaa1e79` | Real LAN browser broadcast on UDP 8303, room discovery/join, sustained gameplay, exit and revocation on two real sites. Upstream probes 8303–8310; this policy approves only an actual server on 8303. |
| Luanti 5.13.0 | official annotated tag `d8f9ef53e312365cef5db1261fa82cd6a8241b93`, target commit `5ab66da6f72e89fe9c9b71b3e952da1676a8e172` | Real direct-IP join on an independently approved host/subnet path, sustained gameplay, exit and revocation on two real sites. The actual selected game/content package, its license/hash and server configuration must be recorded with the run. |

Sources: [Teeworlds LAN browser](https://github.com/teeworlds/teeworlds/blob/4fc25a17fef3e6c2bf4d52b0421e0d69ecaa1e79/src/engine/client/serverbrowser.cpp),
[Teeworlds packet ceiling](https://github.com/teeworlds/teeworlds/blob/4fc25a17fef3e6c2bf4d52b0421e0d69ecaa1e79/src/engine/shared/network.h),
[Luanti release source](https://github.com/luanti-org/luanti/tree/5ab66da6f72e89fe9c9b71b3e952da1676a8e172).
These are lawfully available upstream candidates, not completed game tests.

For separate real DNS-SD verification, run a permitted `_http._tcp.local.`
service on each adapter host listening on the selected actual physical address
and accessible approved virtual host address/port. A real independent browser
on the other LAN must discover the imported service's PTR/SRV/TXT and pinned
virtual address, access the actual service over its independently authorized
data path, then observe withdrawal after stop/revoke. Binary TXT must survive.
The imported DNS name never creates that data path or grants service access.

Record Actions workflow/run/attempt, source SHA, lock hash and executable hash
separately from actual target OS, game/content version, topology, time/duration,
packet capture, room/join evidence, traffic and cleanup logs. Exercise cross-
space messages, replay, wrong interface/source/port, looped packets, flood,
policy change, logout, revoke, owner kill, stale runtime restore and physical
socket rebind. Keep AC47/AC48 open until all applicable scenarios pass. A DNS-SD
fixture, UDP response, ping or successful build is not real-game evidence.
