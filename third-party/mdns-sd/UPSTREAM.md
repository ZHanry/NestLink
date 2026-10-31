# mdns-sd 0.21.6 bounded publication adapter

The complete official crates.io archive is retained as `UPSTREAM.crate` with
SHA256 `8562654710f72a9cbce4b0d5b7c366a2f94330ba1ce3740f15e932ea2d37b161`.
Its original Git revision is `1a5cdb6ebb7299ee74dda75099461a2921b6e740` in
https://github.com/keepsimple1/mdns-sd. Original authors, package identity,
manifest declarations, README, tests, examples and both full license texts are
retained. `LICENSE` is an exact additional copy of upstream `LICENSE-MIT` for
the existing release notice collector; `LICENSE-APACHE` is also unchanged.

The only source edit is in `src/service_info.rs`. It adds an optional interface
index, default `None`, and a public setter rejecting index zero. When explicitly
enabled on one exact interface, a caller-supplied unicast IPv4 service address
may be included in the original publisher's address records despite belonging
to a routed subnet. Other interfaces and the default retain upstream same-subnet
filtering. Unspecified, loopback, multicast and limited-broadcast addresses
cannot use this opt-in. IPv6 behavior is unchanged. A pure component regression
covers default denial, exact interface, invalid index, invalid address classes
and restoring the default.

This change supplies no route, grant, peer authentication, forwarding or new
protocol implementation. NestLink separately requires a locally reviewed policy
with `allow_routable_publication`, the original selected interface, and the
authenticated peer's original virtual IPv4 assignment. The maintained component
still owns all DNS parsing/serialization, multicast sockets, probing, conflict
handling, caching, refresh, TTL, withdrawal and daemon shutdown. A discovered
name cannot grant access; a usable independently authorized virtual route is
still required by the application.

The full upstream/local file inventories and edited-source SHA256 bindings are
in `UPSTREAM.json`. The explicit source diff is retained under
`docs/network-rewrite/patches/mdns-sd-0.21.6-routable.patch`. Hosted compilation,
strict checks, component regression and actual dual-LAN DNS-SD execution are
separate evidence; this provenance review is not a test-pass claim.
