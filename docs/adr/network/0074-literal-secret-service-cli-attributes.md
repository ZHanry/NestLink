# 0074 — Preserve opaque login bindings as literal Secret Service attributes

Date: 2026-11-03. Status: implemented; real hosted regression pending.
Scope: the existing Linux Secret Service CLI adapter and original resident
fixture. There is no new dependency, service replacement or stored binding format.

Original sourcee202 run41478056075 failed its Linux QUIC fixture at
`source_protected_login`, before that case started a real native session.
The unchanged ten-second store gate made187 attempts with last exit2.
All three original helper processes were sleeping/alive, and the original
login collection's Locked property was false. The same run's complete TLS
pixel/file/rebuild case and other resident cases passed. These observations
identify the protected-store stage; they do not prove that a keyring process
died, became locked or rejected a particular secret.

The reviewed actual runner supplier is libsecret0.21.4. Its original
`tool/secret-tool.c`, tag0.21.4 commit
`6b5a6c28afc6dd93c232a4907a87c881079ff91b`, parses store and lookup arguments
through GLib GOptionContext. A parser/usage failure exits2. An actual failed
Secret Service store returns1; a successful store returns0. The fixture's
label and attribute names are fixed. The dynamic instance value is the
unchanged URL_SAFE_NO_PAD encoding of the management-store token hash, which
can begin with `-`. Without an option terminator, that valid attribute can be
parsed as a CLI option instead. Both production SessionStore and its fixture
used that incomplete argv boundary. The failed sourcee202 receipt did not log
the binding prefix; its exact binding is not reconstructed or exposed here.
Reviewed GLib2.80.0 `goption.c` explicitly stops option parsing at `--`, removes
that separator after collecting the remaining attributes, and rejects unknown
options before the caller reaches the store operation.

The repair uses the CLI's standard `--` separator after fixed options and
before every literal attribute. One tiny fixed-argv module supplies the same
store/lookup arguments to production, the original fixture and a dedicated
real regression. The original binding bytes, labels, stored keys, encryption,
lookup verification, OS service, authentication, retry gate and deadlines are
unchanged. Repository-wide tool-call review found these two store/lookup groups
and no runtime clear/search invocation requiring the same repair. No command
shell is involved, and no upstream parser or Secret Service code is copied.

The independent Linux regression reuses the original Platform's real private
D-Bus, gnome-keyring and owned lifecycle. Its valid URL-safe base64 attribute
deliberately begins with `-`. Both retired actual store/lookup argv must return2;
then the production argv helper must really store and retrieve the exact secret
under that literal attribute. Secret buffers remain Zeroizing, stdout/stderr
are never logged, and equality failures report only fixed messages. The store
uses the original ten-second readiness allowance. This is an extra integration
target and strict-clippy command; it does not replace or alter any of the four
original resident cases or their expected names/counts. A failure-only boolean
records whether a future original binding had an option prefix, without its value.

The new regression has not yet run. Preserve sourcee202's failure and require
actual hosted old-argv rejection plus new-argv retained-data success, and the
complete original resident matrix. No local build, format, lint, test, Python
execution or packaging occurred. This does not resolve earlier unrelated SDK
management-response-invalid or public-PKI fixture DNS failures by inference.

Reviewed mature interfaces and source:

- <https://github.com/GNOME/libsecret/blob/6b5a6c28afc6dd93c232a4907a87c881079ff91b/tool/secret-tool.c>
- <https://github.com/GNOME/glib/blob/2.80.0/glib/goption.c>
- <https://docs.gtk.org/glib/struct.OptionContext.html>
- <https://docs.gtk.org/glib/method.OptionContext.parse.html>

The existing distribution supplies libsecret/secret-tool under its LGPL-2.1-or-
later source notice and gnome-keyring under its original distribution notices.
NestLink calls that existing CLI; it does not vendor, rebuild or newly redistribute
those suppliers as part of this change.
