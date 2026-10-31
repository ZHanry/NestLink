# Private Web gateway first slice — W25

Implementation state: in progress. The new source and its automated cases still
require exact-source GitHub Actions compilation and execution. Public HTTPS and
browser execution require the separately configured deployment below.

The management workspace's Services page includes **Access private Web
services**. Read your installations, select the actual native gateway, then read
its original private consumer directory. Select one ready HTTP/HTTPS entry,
enter the isolated origin, per-connection sub-reservation and fixed owner
lifetime, and download the request. The download contains no credential and
grants no rights. Save it in that installation owner's private directory. The
daemon refuses a different management origin or installation, stale service or
exposure revision, changed target, offline entry or excess allowance. Refresh the
directory and download a new request after any such change.

The page accepts only the selected service's one-use launch fragment URL,
checks its origin and reserved path, and opens it in a separate tab with
`noopener`, `noreferrer` and no Referer. Changing selection, logging out or
leaving the page clears the local link. TCP/UDP entries hand off to the existing
native proxy or a protocol client. This is an explicit native-owner handoff; it
does not provide one-click remote gateway delegation.

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
  --bootstrap <new-absolute-private-route.json> \
  --launch-output <new-absolute-private-launch.json>
```

Alternatively replace the service/space/origin/allowance/lifetime arguments with
`--request <absolute-owner-private-NestLink-private-web-request.json>`, the
management page's bounded selection. Keep `--state-dir`, `--bootstrap` and
`--launch-output` as above.

For an independently administered enterprise HTTPS origin, the native owner may
also supply `--https-root <absolute-owner-private-single-CA.der>`. This is one DER
certificate, limited to 16 KiB and read through the existing protected-file
checks. It is selected only by this local CLI invocation, never by the downloaded
management request. This explicit mode replaces the probe's normal WebPKI roots
with that single CA and still verifies the exact HTTPS hostname; it provides no
TLS verification bypass. Omitting it preserves the ordinary WebPKI root set.
The visiting browser must independently trust the frontend certificate. The
gateway does not alter browser or operating-system trust. Invalid probe trust is
rejected and the original gateway is joined before a route or ticket is written.

The schema-2 bootstrap contains `caddy_https_route` and the public correlation
`gateway_owner_id`, with no launch ticket. It contains the hop credential and
must remain owner-private. Install the route only in the stated
HTTPS server, with no additional public route bypassing its upstream. Caddy must
share the gateway's real loopback network namespace. The listener accepts only
TLS. Each owner creates a fresh short-lived CA, leaf certificate and private key;
the route's transport pins that CA and its fixed generated `server_name`. Keep
the generated `transport.tls` object intact: Caddy must finish certificate chain
and name validation before sending any browser Cookie or private-hop header.
The CA pool contains only this owner's CA, and no skip-verification option is
used. The gateway additionally authenticates the private hop using a random
token and the real HTTPS scheme/SNI. A remote browser cannot supply that token.

The daemon polls only the selected origin's reserved `/.nestlink/ready` URL over
normally verified public HTTPS. It refuses redirects, sends no authorization,
Cookie, hop header or ticket, and accepts only the original owner's UUID within
a 64-byte response limit. The reserved endpoint is handled before any private
application backend. The UUID correlates readiness and grants no access.
The optional local `--https-root` changes only this probe's trust anchor.
Preparation, probes and active sessions share the original fixed owner lifetime;
neither waiting nor ticket renewal extends it. Ctrl-C, login changes, maintenance,
expiry and original worker cleanup still apply during preparation.

Only after this check succeeds does the daemon atomically invalidate the initial
ticket and create the separate owner-private launch JSON. Copy only its
`launch_url` into the management page, then open it within 60 seconds (or before
the owner's earlier expiry). Do not import or paste the route bootstrap into
the page. Renewal is refused after any browser session has used a ticket,
including after logout. The ticket is in its fragment, is exchanged
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
workspace remote one-click launch, multi-user gateway delegation and public
browser qualification remain unfinished; this handoff does not stand for full W25.

Application cookies retain the real backend transport semantics. HTTP backends
requiring `Secure` application cookies are unsupported: the adapter does not
pretend that an HTTP private target is HTTPS or downgrade a Secure cookie. Use
an explicitly approved HTTPS private backend with its original host-side CA/name
verification. The management launch panel shows this limit before launch.
Ordinary non-Secure server cookies over HTTP and server cookies over HTTPS
continue through the separate per-session Jar.

The application-authentication interface stays separate from gateway admission:
the gateway session cookie proves access to one selected service; application
login requests and responses go only through that service's fixed private lease
and mature cookie Jar. Future compatibility modes must be explicit local policy,
must report unsupported transport/authentication requirements, and must never
import management cookies, browser bearer credentials or another service's Jar.
No Basic/Bearer or JavaScript-cookie authentication adapter is implemented here.

Send an exact-origin POST to `/.nestlink/logout` to revoke the browser session.
This closes already upgraded connections as well as refusing new requests.
Management ACL/member/host revocation is rechecked through the existing private
lease path and by the original host. The native owner also closes on its protected
login changing, maintenance, Ctrl-C or its fixed lifetime. Cleanup waits for all
original private carriers and removes only the exact unchanged bootstrap and
launch files that this owner created.
Both file removals are attempted independently. If launch creation succeeded but
its confirmation failed, its exact expected content remains with the same owner
so physical-stop cleanup can still remove an unchanged capability file. An
ambiguous failed creation or a changed/unreadable file is retained for explicit
owner inspection and is reported as failure.
An incomplete physical receipt remains a cleanup failure or pending state.

Remove the dedicated Caddy route separately after the owner has stopped. The
daemon's local cleanup receipt proves listener/worker/carrier release and exact
bootstrap removal; it does not claim a Caddy Admin delete ACK or certificate
revocation. A leftover route cannot send credentials to a replacement endpoint:
the replacement lacks the original owner's private TLS key and cannot complete
Caddy's pinned-CA and fixed-name validation. Removing the route is still required
for operator cleanup. The generated key is held only by the live SDK TLS owner
and is never included in the bootstrap.

Automated source cases are the `web_launch::tests`, `web_gateway::probe_tests`,
`web_gateway::headers::tests` unit cases and the
`web::` cases in the SDK `private_services` integration target. They verify policy,
real management/Quinn/fixed-backend/cookie/upload/WebSocket bytes, logout and ACL
withdrawal, and original cumulative accounting. Their Caddy hop is supplied by
a strict independent-CA/name TLS test client; cases also refuse plaintext, a
wrong TLS name and a same-address/same-name replacement with an unrelated key.
This remains a TLS loopback-contract test rather than an actual Caddy run.

The separate **Private Web gateway real Caddy and Chrome** workflow
(`.github/workflows/private-web-gateway.yml`) builds the exact SDK/private-service
test executable on an ordinary GitHub-hosted Ubuntu runner. The ignored
`web::hosted::caddy_browser_fixture_role` is an explicit cooperation role, not a
passing ordinary unit/integration case. Only this hosted runner enables it. It
starts two actual private SDK installations/hosts/leases and their original
authorization, carrier and cumulative accounting owners, then hands their actual
generated routes to the repository's pinned Caddy 2.11.7 binary. The existing
reviewed Puppeteer 25.14.0 driver runs the hosted Chrome executable. Script syntax
checks, dependency resolution, native codec construction and Rust compilation
also run only in that Actions job. This source is not a passed run by itself.

The fixture maps two isolated service UUID names, a management cookie sentinel
and a cross-origin attacker name through the hosted VM's actual hosts file. It
creates a short-lived frontend CA/certificate, installs that test CA in the VM's
OS and user NSS trust stores and passes the same single DER CA to the production
SDK readiness probe. Chrome does not ignore certificate errors. This is a hosted
L2 environment with simulated DNS/test trust; it does not establish public DNS,
ACME, external Internet reachability, installed-daemon login or any L3/L4
target-platform acceptance. The management origin is a cookie boundary sentinel,
not the production management workspace UI.

The actual Caddy/Chrome cases cover frontend CA/name validation, SNI/Host
mismatch, wrong upstream root and name, production HTTPS readiness before ticket
renewal, fragment removal and ticket replay, real Secure/HttpOnly/host-only
session cookies, original backend cookie login with separate service Jars,
management-cookie isolation, exact upload/download bytes, same-service redirects
and external redirect refusal, browser cross-origin POST without backend side
effects, real WSS echo, logout/ACL withdrawal closing existing upgrades, and
refusal after a stopped owner's endpoint is rebound with the old public TLS name
but unrelated root/key. The replacement must receive zero completed TLS
handshakes and zero application bytes. Original gateway/host physical joins and
zero outstanding original quota are required. Finally the driver requires the
real Caddy Admin route-removal ACK and readback without the two exact owned IDs.

The evidence receipt separates `build_source` (source/workflow SHA, run/attempt,
Cargo.lock and test-executable digest) from `execution` (runner, case results,
Chrome identity, physical and quota receipts). The same run retains the browser
tool dependency lock. Only bounded, redacted runtime diagnostics and structured
receipts enter artifacts; route hop credentials, tickets, cookies, private keys
and the browser profile remain in a fresh private directory and are removed.
Cleanup independently attempts original process groups, test trust, owned hosts
line and private files; any failed physical receipt or cleanup makes the run
fail. Exact-source success still needs the resulting Actions evidence, and the
remaining real application/browser/platform qualification keeps W25 in progress.

The generated transport uses Caddy 2.10.2's documented upstream TLS JSON shape:
`tls.ca.provider=inline`, `tls.ca.trusted_ca_certs` (base64 DER), and
`tls.server_name`. The matching source is
[HTTP transport TLSConfig](https://github.com/caddyserver/caddy/blob/v2.10.2/modules/caddyhttp/reverseproxy/httptransport.go)
and [inline CA pool](https://github.com/caddyserver/caddy/blob/v2.10.2/modules/caddytls/capools.go).
