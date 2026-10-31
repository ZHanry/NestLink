# Private Web gateway first slice — W25

Implementation state: in progress. The new source and its automated cases still
require exact-source GitHub Actions compilation and execution. Public HTTPS and
browser execution require the separately configured deployment below.

This entry runs on the explicitly enrolled gateway installation. It is a native
gateway process; the visiting browser needs no TUN, SOCKS configuration or native
network transport. It forwards only one previously approved HTTP/HTTPS service.
TCP/UDP clients use `private-service-proxy` and are refused by this browser entry.

Sign in on the gateway installation, enable protected login recovery, enroll it,
join the intended space and explicitly grant it the service's private ACL. Stop
the existing runtime for that same installation before starting this headless
owner; the existing singleton protects the refresh credentials. No gateway
installation or permission is created automatically by a browser request.

Choose a dedicated private application domain on a different final two DNS labels
from management. For example, management `control.example.com` can use service
origin `https://<service-UUID>.private.example.net`. It cannot use a sibling under
`example.com`. The service UUID must be the first DNS label. Provision DNS and a
trusted HTTPS certificate for that exact hostname in the operator's Caddy server.
The server must set `strict_sni_host: true`, bound request heads and an unknown-host
404 response. Its service route comes from the private bootstrap file below.

Run the verified Actions-built daemon as the normal installation owner:

```text
nestlink-daemon private-web-gateway \
  --state-dir <existing-private-installation-directory> \
  --service <service-UUID> --space <space-UUID> \
  --origin https://<service-UUID>.private.example.net \
  --maximum-bytes 1048576 --lifetime-seconds 300 \
  --listen 127.0.0.1:29840 \
  --bootstrap <new-absolute-file-in-an-owner-private-directory>
```

The bootstrap contains a `caddy_https_route` object and `launch_url`. It contains
credentials and must remain owner-private. Install the route only in the stated
HTTPS server, with no additional public route bypassing its upstream. Caddy must
share the gateway's real loopback network namespace. The listener accepts only
TLS. Each owner creates a fresh short-lived CA, leaf certificate and private key;
the route's transport pins that CA and its fixed generated `server_name`. Keep
the generated `transport.tls` object intact: Caddy must finish certificate chain
and name validation before sending any browser Cookie or private-hop header.
The CA pool contains only this owner's CA, and no skip-verification option is
used. The gateway additionally authenticates the private hop using a random
token and the real HTTPS scheme/SNI. A remote browser cannot supply that token.

Open `launch_url` within 60 seconds. The ticket is in its fragment, is exchanged
once by an exact-origin POST and is removed from browser history before exchange.
Do not paste the link into logs, diagnostics, public configuration or an unrelated
application. The gateway then supplies only its host-only secure session cookie.
The application can use server cookie login, streaming upload/download and
WebSocket. Each actual HTTP request or upgrade reserves its finite share through
the original private-service API; all requests still share the original service
budget with any public/both exposure. An application URL, Host or redirect never
selects another target.

The current adapter stores application cookies server-side per gateway session.
It strips incoming browser application cookies and consumes backend Set-Cookie.
Applications requiring JavaScript-readable cookies, HTTP Basic/Bearer auth,
third-party scripts/connections, service workers or embedding need further
explicit compatibility work. CSP and origin isolation are enforced. Management
workspace one-click launch, multi-user gateway delegation and public browser
qualification remain unfinished; this CLI slice does not stand for full W25.

Send an exact-origin POST to `/.nestlink/logout` to revoke the browser session.
This closes already upgraded connections as well as refusing new requests.
Management ACL/member/host revocation is rechecked through the existing private
lease path and by the original host. The native owner also closes on its protected
login changing, maintenance, Ctrl-C or its fixed lifetime. Cleanup waits for all
original private carriers and removes only the exact unchanged bootstrap file.
An incomplete physical receipt remains a cleanup failure or pending state.

Remove the dedicated Caddy route separately after the owner has stopped. The
daemon's local cleanup receipt proves listener/worker/carrier release and exact
bootstrap removal; it does not claim a Caddy Admin delete ACK or certificate
revocation. A leftover route cannot send credentials to a replacement endpoint:
the replacement lacks the original owner's private TLS key and cannot complete
Caddy's pinned-CA and fixed-name validation. Removing the route is still required
for operator cleanup. The generated key is held only by the live SDK TLS owner
and is never included in the bootstrap.

Automated source cases are the `web_gateway::headers::tests` unit cases and the
`web::` cases in the SDK `private_services` integration target. They verify policy,
real management/Quinn/fixed-backend/cookie/upload/WebSocket bytes, logout and ACL
withdrawal, and original cumulative accounting. Their Caddy hop is supplied by
a strict independent-CA/name TLS test client; cases also refuse plaintext, a
wrong TLS name and a same-address/same-name replacement with an unrelated key.
This remains a TLS loopback-contract test rather than an actual Caddy run.
Actual Caddy HTTPS plus a supported browser must separately prove certificate
validation, SNI/Host refusal, the real Secure cookie, upload/download, same-service
redirect, WebSocket, logout, ACL withdrawal and final route removal. Build and
execution provenance must be recorded separately, with exact source and artifact
digests. R02 applies to all automated tooling and builds.

The generated transport uses Caddy 2.10.2's documented upstream TLS JSON shape:
`tls.ca.provider=inline`, `tls.ca.trusted_ca_certs` (base64 DER), and
`tls.server_name`. The matching source is
[HTTP transport TLSConfig](https://github.com/caddyserver/caddy/blob/v2.10.2/modules/caddyhttp/reverseproxy/httptransport.go)
and [inline CA pool](https://github.com/caddyserver/caddy/blob/v2.10.2/modules/caddytls/capools.go).
