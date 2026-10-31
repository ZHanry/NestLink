# Local private service proxy

This source implements restricted SOCKS TCP/UDP and OS-authenticated native
stream access to one locally selected private service. The new sources need
exact-source hosted build and execution results before qualification. Linux raw
loopback TCP/UDP source is described below; its kernel and product qualification
remains pending. Windows raw mappings and target ordinary-user qualification
remain mandatory work. The native stream is an additional authenticated local entry.

The normal-user daemon command uses the existing installed device identity and
protected management login. Sign in using the product and enable protected login
recovery first. Stop the running daemon through its existing shutdown command
before starting this independent headless owner: the same installation permits
only one runtime to rotate its management session.

List the services currently authorized for that installation:

```text
nestlink-daemon private-service-proxy --state-dir <private-state-directory> list
```

Choose a listed service and space, a local alias and destination port, a finite
per-connection reservation and an owner lifetime:

```text
nestlink-daemon private-service-proxy --state-dir <private-state-directory> serve --service <service-id> --space <space-id> --alias docs.nestlink.internal --port 443 --maximum-bytes 10485760 --lifetime-seconds 300 --listen 127.0.0.1:0
```

The command prints its bound loopback address and the path of a private local
credentials file. Configure a SOCKS5 client with the username and password from
that file, and send the destination as the exact alias and port selected above.
Use the client's proxy-side name option so it sends the alias in SOCKS rather
than attempting local DNS resolution. The alias routes only to the selected
private service. The SDK obtains independent current service authority for each
connection and connects the host's approved fixed target.

For a selected HTTPS service, the host establishes TLS to the approved backend
and verifies its configured server name and trusted CA. The local stream entry
therefore carries HTTP application bytes; an HTTP client can use it to access
that HTTPS backend. This applies to SOCKS, native streams and Linux raw TCP.
The private carrier and the host's verified backend TLS retain their existing
protection. A standard HTTPS client that starts its own TLS handshake at the
local entry needs a separate local TLS termination or approved passthrough
implementation and qualification. Those client modes remain pending; the
current adapter does not qualify them.

The command never prints credentials or places them in a command line or URL.
The file is created with the existing OS private-file checks, using a random
create-new name. An optional `--credentials-dir` selects an existing private
directory; the default is this installation's protected state directory.

The owner stops on Ctrl-C, termination, maintenance, login snapshot change or its
original lifetime. That lifetime is also capped by the current management access
expiry. The command joins the original connections and reports cleanup only when
the owner returns its actual receipt. A pending wait retains the original task.
Successful cleanup closes the sockets and removes the exact original credentials
file. If another process replaces the file, cleanup preserves it and reports a
failure. It never deletes the directory.

The TCP mode refuses no-auth negotiation, BIND, UDP ASSOCIATE, literal IP
destinations, other aliases and other ports. It does not resolve or dial a
client-selected Internet address. Every service connection has the original
service lease, cumulative quota and revocation checks; the proxy adds no access
rights. Per-owner and process-wide concurrency limits bound local admission.

For a selected UDP service the same `serve` command accepts password-authenticated
SOCKS UDP ASSOCIATE. Bind a local loopback UDP socket first and supply its exact IP
and nonzero port in the request over the authenticated TCP control connection.
Keep that control connection open. Send SOCKS UDP packets to the returned relay,
using the selected alias and port. The original source address is fixed; wildcard
sources, other destinations and fragments are rejected. Empty packets retain their
boundaries; payloads over 1169 bytes are discarded. The local packet work limit is
separate from the original shared service byte allowance.

For a TCP/HTTP/HTTPS service, add `--native-stream` to `serve` to create an
owner-private Unix socket or Windows byte-mode named pipe. Both endpoints verify
the connected OS user; Windows also binds the interactive session. This mode
prints the endpoint without creating a loopback listener or credentials file.
Standard native socket/pipe clients can use it directly. For SSH ProxyCommand or
another program that can redirect byte streams, use:

```text
nestlink-daemon private-service-proxy --state-dir <private-state-directory> connect --endpoint <printed-native-endpoint>
```

The connect command writes only remote application bytes to stdout and exits on
remote EOF or termination, including when its redirected stdin remains open.
Unix input EOF preserves the reverse response. Windows byte pipes do not provide
an independent write-half EOF; applications that require a request FIN before
the response should use SOCKS TCP. Windows stdio requires redirected pipes.
Stopping the owner drains its original workers before returning cleanup results;
a replaced Unix pathname is preserved and reported as a cleanup failure.

The component and its minimal credential secrecy/RFC1929 security patch are
recorded in ADR 0036 and third-party/fast-socks5/UPSTREAM.json. The original MIT
license, author attribution and exact published archive accompany the source.
Standard-client protocol, FIN, secrecy and cleanup tests run only in hosted
Actions. Target ordinary-user acceptance remains required for AC34.

Linux raw clients can select `serve --raw-loopback` with the same explicit
service, space, byte limit and lifetime, a fixed nonzero `--listen` endpoint,
an absolute fresh owner-private `--gate-plan` path, and an absolute fresh
`--gate-receipt` path beneath a root-controlled public directory. This mode
supports unmodified TCP and UDP clients, and HTTP application clients for the
chosen HTTP or HTTPS backend, with the HTTPS stream semantics described above.
It requires explicit administrator setup for its kernel UID gate; SOCKS and
native streams retain their ordinary-user setup.

The ordinary daemon writes its plan and waits in the same process. While it is
waiting, run the same verified executable as administrator:

```text
nestlink-daemon local-port-gate install --plan <printed-plan-path> --journal-dir <fresh-root-private-directory> --receipt <chosen-root-public-receipt-path>
```

The administrator must select a protected root-owned parent, for example a
dedicated directory under `/run`, rather than the user's home or temporary
directory. Keep the helper running. It installs only this exact loopback
address/port/transport and allows the selected OS user's client sockets. Other
OS users and non-loopback ingress cannot use it. Applications belonging to the
same OS user share that user's local access. The helper consumes no private
service target, installation key or management login.

Only after the complete root receipt is verified does the original ordinary
daemon bind its port. Each connection or UDP source still requires current
private service authority and the existing original cumulative meter. UDP
packets retain their individual boundaries, including empty datagrams; payloads
over 1169 bytes are discarded. There is no SOCKS framing in raw mode. TCP keeps
the existing half-close behavior. Kernel receipts cannot select a remote target.

The original owner lifetime is never extended by waiting for the helper. On
termination the ordinary daemon joins its workers and exits; the helper waits
for that actual process exit before deleting the gate. Expiry or an orderly
helper stop changes it to deny-all. A helper crash retains its kernel fence and
recovery journal, and the ordinary owner stops when it detects the missing
helper. After the original process has exited, inspect or recover with:

```text
nestlink-daemon local-port-gate inspect --journal-dir <original-root-private-directory>
nestlink-daemon local-port-gate recover --journal-dir <original-root-private-directory>
```

An active original helper holds the journal lock, so these recovery commands
cannot race it. Changed rules, handles or foreign objects are preserved and
reported. The immutable public receipt remains an audit record of that one
installation and cannot authorize a different process or a new lifetime. Raw
Windows support and production ordinary-user target qualification remain open;
the Linux source and forthcoming hosted kernel scenarios do not qualify them.
