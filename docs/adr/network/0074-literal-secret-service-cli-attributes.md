# 0074 — Preserve opaque login bindings as literal Secret Service attributes

Date: 2026-11-03. Status: implemented; real hosted regression, additional strict
clippy and complete original both-OS focused resident matrix passed on source4a.
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

Preserve sourcee202's failure and require actual hosted old-argv rejection plus
new-argv retained-data success, strict lint and the complete original resident
matrix. No local build, format, lint, test, Python execution or packaging occurred.
This does not resolve earlier unrelated SDK management-response-invalid or
public-PKI fixture DNS failures by inference.

Run [41483674367](https://github.com/ZHanry/NestLink/actions/runs/41483674367),
exact source `4ec2c3c0addea9d708629d58b2932ec035bd5569`, exercised the real
Linux regression successfully: one test passed in0.11s, including both retired
CLI exit2 assertions and repaired store/read retained-data equality. All other
focused tests and the original three strict commands passed on both OS. The
new integration target's extra strict command failed `clippy::duplicate_mod`:
it loaded the production argv module directly and through original support.
Newer `2285fd1f01887efb130433e81f21c941c8b01bb2` reuses support's single
module with `use`, without suppressing a lint or changing runtime behavior.
The source4ec run predates and cannot qualify that lint repair.

Original Linux resident remains3/4: management8 and both full carrier cases
passed, but pending case2/logout failed before SDK setup at the unchanged
public-PKI fixture DNS deadline. Original Windows resident remains0/4: after
management case0 actually ran and stopped, case1 and the remaining cases
reported original socket Os10013 PermissionDenied. The receipt does not identify
the failing bind stage or OS cause. Keep these failures and require newer
exact-source strict lint and the original both-OS matrix. Full receipts and
independent hashes of all46 downloaded files, with38 matching producer entries,
are in [source4ec evidence](../../network-rewrite/evidence/native-offline-resident-4ec2c3c.json).

Run [41488486927](https://github.com/ZHanry/NestLink/actions/runs/41488486927),
exact source `4a4496b77cf5923a1b39c85c757b7cc6a7f3dc00`, now passes the same
real Linux leading-hyphen regression1/1 in0.23s and its added strict-clippy
command. The single-module reuse repair is therefore exercised on the hosted
runner, alongside original resident4/4 on both Linux and Windows. Every
management/pending case and both real pixel/file/rebuild carrier cases passed;
all other focused tests and original strict commands passed on both OS.
The fixed socket diagnostics emitted no failure, so the older source4ec
Os10013 cause remains unproven. No retry or socket selection change was made.

The complete original deadlines,10-second store gate,3-second production
helper timeout, token hash/base64 binding, key/cipher/lookup and independent
HTTPS owner remain. The preserved historical failures are not reclassified.
All46 artifact files and both complete job logs were independently hashed,
with38 matching producer records and identical clean source facts. See
[source4a evidence](../../network-rewrite/evidence/native-offline-resident-4a4496b.json).
This focused completion does not establish full Rust-core, physical-device,
public-NAT or advanced-media acceptance, and no local project checks ran.

Reviewed mature interfaces and source:

- <https://github.com/GNOME/libsecret/blob/6b5a6c28afc6dd93c232a4907a87c881079ff91b/tool/secret-tool.c>
- <https://github.com/GNOME/glib/blob/2.80.0/glib/goption.c>
- <https://docs.gtk.org/glib/struct.OptionContext.html>
- <https://docs.gtk.org/glib/method.OptionContext.parse.html>

The existing distribution supplies libsecret/secret-tool under its LGPL-2.1-or-
later source notice and gnome-keyring under its original distribution notices.
NestLink calls that existing CLI; it does not vendor, rebuild or newly redistribute
those suppliers as part of this change.
