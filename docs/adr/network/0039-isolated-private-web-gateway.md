# 0039 — Isolated private Web gateway over the existing private service owner

Status: first production slice implemented, unverified; W25 remains in progress.

The existing public gateway uses Caddy for public HTTP/TLS and WebSocket parsing,
then opens an independently authorized public service stream. A private service
lease binds an account login and the public key of an actual enrolled space
installation. Reusing a public publication as private admission would erase that
distinction. Giving a server the browser's installation key would also change the
current possession boundary.

The selected first slice runs an explicit normal-user gateway installation. The
operator enrolls and joins that installation through the existing product and
grants it the existing private-service ACL. The daemon restores its existing
protected login, retains the existing headless runtime lease and installation
key, and selects one current HTTP/HTTPS directory entry. Every browser request
and WebSocket upgrade obtains a new original private service lease and connects
through the original SDK carrier. The original host pins the locally approved
target, performs backend HTTPS verification, owns the durable cumulative meter,
reports usage and observes current management revocation. There is no new public
service grant, RemotePermit, host target selector or service budget owner.

A separately authenticated management-to-gateway delegation protocol was the
alternative. It would let the management workspace launch a remote gateway for a
different browser login, but requires a new explicit holder/delegation contract
and distribution lifecycle. The first slice instead uses an explicit management
to native selection handoff. The Services panel reads the original private
consumer directory for one selected installation and exports a bounded request
pinned to management origin, installation, service/space, revisions and target.
The daemon restores only that installation's original SessionStore and validates
the current private directory before constructing its original local choice. A
downloaded file creates no membership or authority. This is visible in the CLI
and is not reported as one-click remote gateway delegation.

The browser opens a fixed service HTTPS origin, whose first DNS label is the
service UUID. The gateway rejects an origin sharing the management site's last
two DNS labels; this conservative restriction also refuses some safe independent
domains under multi-label public suffixes. It avoids introducing an incomplete
public-suffix parser and prevents application JavaScript from tossing cookies at
the existing management cookie domain. Each application has a separate service
origin. Caddy must use strict SNI/Host validation and forwards only to the random
loopback address over TLS. Every gateway owner generates a distinct short-lived
CA and server certificate/key in memory. The generated Caddy transport trusts
only that CA and verifies a fixed owner-specific TLS name before sending any
Cookie or private-hop header. No verification bypass is configured. In addition,
the gateway verifies the random private-hop token, scheme and exact SNI/Host
before handling bootstrap or application data. An inbound token alone would not
authenticate a server that rebinds a stopped owner's loopback address.

A reserved readiness endpoint returns only this original owner's public UUID;
the application backend cannot handle that namespace. The daemon checks that
fixed public HTTPS origin using no credentials, no redirects and a 64-byte body
limit. Waiting shares the original owner expiry and remains cancelable. Only
after readiness does it replace the initial ticket and create a separate private
launch file; the route bootstrap never enters the management page. The page
checks the exact selected service's launch origin/path/fragment and opens it with
no opener or Referer. Renewal invalidates the previous ticket under the original
admission lock, does not extend expiry/quota, and is refused after any session
has used a ticket, including after logout.

Normal readiness uses the existing WebPKI roots. A native-local optional
`--https-root` selects one protected, absolute DER CA file no larger than 16 KiB
and replaces those roots only for this probe. It is not a launch-request field,
cannot be inherited from management/browser input and never disables certificate
or exact-name verification. Browser trust remains independently administered.
An invalid local root joins the original gateway before publishing either output.
After a launch file was created, its expected bytes remain with the same owner
even if readback fails, so final physical cleanup attempts route and launch-file
removal independently and retains changed/ambiguous files as explicit failures.

A 60-second, single-use ticket appears only in the launch URL fragment. A static
bootstrap page first removes the fragment from browser history, then exchanges
it through an exact-origin POST. The gateway stores only purpose-hashed ticket
and session values. The browser receives a Secure, HttpOnly, SameSite=Strict,
host-only `__Host-nl_private_web` cookie. Logout invalidates the session and
signals its existing upgraded workers. The daemon also stops on its protected
login snapshot changing, maintenance or its fixed deadline.

Backend cookies are held in a separate mature reqwest cookie Jar per browser
session and service. Incoming browser application cookies are not forwarded,
and backend Set-Cookie headers are consumed rather than exposed to the browser.
This preserves ordinary server cookie login while preventing cross-service
Domain-cookie injection. JavaScript-readable cookies, HTTP Basic/Bearer auth and
applications requiring third-party origins remain explicit first-slice
compatibility limits; this slice must not be described as universal application
compatibility. The Jar uses the actual backend scheme; HTTP targets requiring
Secure application cookies need an independently approved HTTPS backend rather
than a scheme rewrite or cookie downgrade. The launch UI displays this limit.
Cookie storage has a cumulative 64 KiB input limit per session.

Hyper 1.12.0 and hyper-util 0.1.21 already exist in the dependency graph. They now
own HTTP/1 framing, streaming bodies and protocol upgrades in this adapter;
reqwest's maintained cookie feature supplies parsing and storage. No HTTP parser,
WebSocket frame stack or cookie grammar is implemented here. The adapter supplies
only fixed-origin policy: unsafe methods and upgrades require exact Origin,
cross-site fetches are refused, hop/internal credentials are removed, Host and
Origin map to the fixed approved service name, and only same-target or relative
redirects are rewritten to the gateway. Redirects are never followed by the
gateway. CSP restricts forms/connections/resources to the service and disables
workers, objects and framing. Opener/resource policies isolate the application.

Outer request heads are capped at 32 KiB and 128 headers with a two-second read
deadline. The owner has 32 accepted connection workers and a bounded 32-entry
forwarding queue. Bodies stream through Hyper and the original private byte
meter; upgraded data uses Tokio's bounded bidirectional copy buffers. The adapter
does not assemble WebSocket frames or messages. It retains each original carrier
until all its HTTP/upgrade owners have dropped, then requires the original
physical close receipt. Timeout leaves the same daemon owner pending rather than
aborting it or reporting completed cleanup. Caddy route removal remains a separate
operator lifecycle action. A replacement process that rebinds the stopped
listener cannot obtain credentials from the old route because it lacks the old
owner's private TLS key and fails the transport's pinned CA/name verification.

The first automated cases use real management authorization, installation-pinned
private Quinn, the original local host/target/meter, real HTTP uploads and real
WebSocket framing. They separately exercise the authenticated Caddy loopback
contract over strict TLS, including wrong-name, plaintext and stopped-address
replacement refusal. They do not establish an actual Caddy run, public DNS/ACME, real-browser cookie behavior,
HTTPS browser execution, management workspace integration or target-platform
qualification. R02 requires all compilation, lock derivation and verification in
GitHub-hosted Actions. No success is recorded before those exact-source results.

The additional `private-web-gateway.yml` hosted L2 candidate uses this actual SDK
private-service fixture and both generated owner routes with pinned Caddy 2.11.7
and real Chrome through the repository's reviewed Puppeteer driver. The hosted
driver deliberately simulates DNS with the VM's hosts file and frontend trust
with a temporary OS/NSS CA; the SDK uses the production single-root readiness
method. No Chrome certificate bypass is permitted. Its management cookie
sentinel tests origin boundaries without claiming production management UI or
installed-daemon login acceptance. It exercises actual browser cookie/login,
upload/download/redirect/WSS/logout/ACL flows, actual Caddy wrong-root/name and
same-port replacement failures, original physical/carrier/quota receipts and
Caddy Admin route deletion plus readback. Secrets stay in a private temporary
directory; evidence separates source/build provenance from runtime observations.
All tooling, script validation, dependency work, formatting, compilation and
execution remain GitHub-hosted. This checked-in candidate supplies no pass until
its exact-source run succeeds and cannot qualify public Internet/ACME, L3/L4 or
other browser/platform behavior. W25 therefore remains in progress.
