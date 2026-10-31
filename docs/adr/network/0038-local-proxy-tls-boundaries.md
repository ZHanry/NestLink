# 0038 — Explicit local TLS for a selected private stream service

Status: implemented in source; Actions compilation, standard-client kernel-gate
business execution and target qualification are pending. This is not a release
qualification record.

The existing private HTTPS host verifies its fixed backend's locally approved CA,
server name and certificate validity. Its private service stream carries HTTP
application bytes. A standard HTTPS client cannot use that plain local stream by
sending a second unprocessed TLS handshake through the host's established TLS
connection.

Two options were considered: forwarding opaque client TLS to the backend, or
terminating a separate explicit TLS connection at the local proxy. Opaque
passthrough would need a distinct signed service target/trust contract and would
change the existing HTTPS host's approved verification boundary. This change
therefore uses the already locked rustls/Tokio-rustls server implementation for
explicit local termination. It does not implement a TLS protocol or change the
remote host's approved TLS configuration.

`LocalRawServiceTls::from_der` accepts a bounded certificate chain and matching DER
private key chosen by the local user. The existing raw SDK entry gains an optional
TLS configuration; the original entry still forwards application bytes. The CLI
requires explicit `--local-tls-certificate` and `--local-tls-key` files with the
existing owner-private file permissions. Certificates are leaf-first, with at
most eight certificates and 16 KiB per certificate or key. UDP refuses TLS
configuration before the CLI asks for administrator gate installation.

Every accepted socket still requires the original administrator-installed exact
user/address/port/protocol gate. The original bounded worker performs a finite
TLS handshake, then requests a new original private service grant and uses the
existing selected-target, relay policy, accounting, revocation and physical-close
owner. Cancellation or deadline during the local TLS handshake drops that socket;
there is no remote grant at that point. Early data, server session caching and
TLS 1.3 session tickets are disabled. ALPN advertises HTTP/1.1, matching the
existing host backend TLS configuration.

Clients must trust the explicitly supplied local CA and verify the certificate's
name. The proxy never disables client certificate validation on their behalf.
There are separate encrypted segments from client to local proxy, across the
private service carrier, and from the private host to its HTTPS backend. This
does not make them one browser-to-backend TLS session.

The Actions test additions cover malformed/mismatched certificate material,
ordinary rustls name validation, binary application bytes and a finite local
handshake. These are configuration/transport tests, not kernel admission or full
HTTPS business acceptance. The dedicated raw experiment must additionally send
standard TLS client traffic through the actual SDK raw owner and exact kernel
gate. Protected-login CLI, complete HTTPS backend and Windows target acceptance
remain separately required.
