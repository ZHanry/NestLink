# Managed TURN node deployment

`nestlink-server node-turn` runs managed TURN beside an authenticated relay node. NodeControl alone verifies the signed node lease and TURN resource snapshots; the TURN service receives only `NodeControl::turn_authorization()` and accepts no unauthenticated grant configuration.

Copy [node-turn.toml](config-templates/node-turn.toml) to `/etc/nestlink/turn.toml` beside `node.toml`, replace the example values, then start the service:

```text
nestlink-server node-turn --config /etc/nestlink/node.toml
```

The command reads `turn.toml` beside the node configuration by default. Pass `--turn-config /absolute/path/turn.toml` to use another file. The node must have the `relay` role. The TURN listener waits for NodeControl to accept its first live lease before binding; lease expiry, renewal failure, policy failure, or process shutdown immediately revokes the shared TURN grants and closes the listeners.

The example enables TURN/UDP on 3478, TURN/TCP on 3478, and TURN/TLS on 5349. The certificate file must contain the server certificate followed by any required intermediate certificates in PEM format. The private key must be a PEM private key supported by rustls. `with_single_cert` checks that it matches the server certificate. TLS files are read at process startup; certificate renewal requires replacing the files and restarting `node-turn`.

On Unix, keep `turn.toml` and the private key owned by the node service account and readable only by that account (`0600`). `turn.toml` may contain the private key path but never key contents. The certificate chain is public material and is read with a 1 MiB bound. Avoid symlinked certificate/key paths: copy the active ACME certificate and key into the node service's protected configuration directory as part of the certificate deploy hook, then restart the service.

Each `[[relay_port_pools]]` row maps a local bind address and UDP port range to its advertised public IP. Firewall/NAT configuration must pass both the selected listener ports and every port in the relay pool to the node. `public_ip` must be the externally reachable address; for a static one-to-one NAT, `bind_ip` can be the node's private interface address. The example uses the documentation-only `203.0.113.10` and must be replaced with the real routed address.

In the management plane, configure the relay node's TURN endpoint set with the same `realm` and published listener addresses, for example `turn:turn.example.net:3478?transport=udp`, `turn:turn.example.net:3478?transport=tcp`, and `turns:turn.example.net:5349?transport=tcp`. Endpoint publication is an administrator action; starting listeners does not publish DNS, open firewall ports, request a public certificate, or change management configuration. Nodes expose only grants present in a valid signed control snapshot, and allocations remain peerless until the current browser-session candidate pair has been signed by both endpoints.

Peer-binding expiry is independent of the TURN grant lease. NodeControl derives a monotonic deadline from the binding's signed issue/expiry interval and the start of the control request; identical binding claims keep their original deadline across later snapshots. A snapshot that omits the binding clears its active peer allowlist, and a replacement must have a later signed issue time. TURN rejects peer-bearing operations as soon as the binding deadline passes. The service reaper closes an allocation with an expired binding on its 250 ms polling cadence while leaving the grant's own lease deadline intact.

The template documents configuration shape only. It does not include an issued certificate or claim public DNS, firewall, NAT, or external-network validation. Native/browser media integration still needs a real browser-to-host acceptance run, and this configuration guide does not claim external-network TURN reachability.
