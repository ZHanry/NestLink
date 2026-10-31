# Hosted Windows raw TCP/UDP WFP experiment

Implementation status: source implemented, unverified until the exact-source
GitHub Actions workflow executes successfully. No Windows kernel pass or
production CLI/device acceptance is claimed by this document.

The dedicated `windows-local-port-gate.yml` workflow builds the existing native
codecs and the real SDK `private_services` integration executable on the hosted
Windows VM. It then copies that exact hashed executable into a fresh protected
ProgramFiles directory. The normal business owner, separate administrator
helper and all probe roles execute this same file. The production gate's
process creation, SID/session, medium/high integrity and executable file-ID
checks remain enabled.

The coordinator first checks the runner's elevated token, a real filtered
medium token, BFE and native local-account/logon capabilities. It creates one
disposable non-administrator account using `NetUserAdd`. Its password stays in
the coordinator's memory; it is never an argument, environment variable,
artifact or log. `CreateProcessWithLogonW` starts a real probe process under that
account. The probe reports its actual OS SID, process creation and non-elevated
medium interactive token. Missing account/logon/session capability fails the
experiment; there is no administrator-only or model replacement.

Permissions are scoped to fresh fixture paths. The protected executable is
read/execute for ordinary users; its administrator owner and write protection
are retained. The runner's ordinary SID can write its fresh evidence directory.
The different SID can write only the fixture probe output directory. No
workspace, production installation, routing or global firewall ACL is widened.

The ordinary SDK owner creates a real management server, enrolled host and
consumer identities, private space/service ACL, durable service usage and the
original authenticated Quinn/fixed-backend path through the existing fixture.
The administrator consumes only its private local port plan. TCP and UDP test
same-SID success, different-SID denial and same-SID success again, with distinct
actual process identities. Admission is checked against bytes witnessed by the
approved backend. UDP also tests an empty request/reply. An occupied listener
must be refused without being adopted.

TCP waits for actual plan expiry and observes the helper retaining exactly the
two deny filters. The SDK must physically release its listener/carriers. In the
same still-live original process the fixture binds a local-only echo witness to
that same endpoint plus a separate ungated control socket. Both same-SID and
different-SID connections to the denied endpoint must fail while the control
socket succeeds. Standard TCP probes half-close the complete request before
reading the echo, avoiding a server active-close TIME_WAIT timer masquerading
as an unreleased socket. The original helper removes the exact gate only after
the original process exits.

UDP terminates the original helper through its retained process handle. The
exact persistent WFP snapshot must survive, while the SDK notices the lost
helper and physically closes its listener/carriers. Recovery while the original
owner is alive must fail for that reason. A local-only socket witness in that
same process then proves same-SID admission and different-SID denial remain
active after the crash; these witness bytes have no private-service authority
and are recorded separately from real SDK/backend bytes.

After that original process physically exits, the coordinator adds one uniquely
identified diagnostic filter only inside its own fixture provider/sublayer and
for its exact original endpoint/protocol. Recovery must refuse it and leave the
complete observed configuration unchanged. The coordinator removes only that
filter after comparing its complete native metadata, original filter ID and
owner/group/DACL inside the same WFP transaction. Exact product recovery can
then clear its original gate and journal. A separately named inert Windows
Firewall sentinel must remain unchanged throughout. No global WFP enumeration
deletion, firewall flush, VPN modification or privileged recursive cleanup is
used.

The evidence artifact separates `build_provenance` and `execution_provenance`:
source/workflow SHA, run/attempt/job, hosted runner image, lock digest, executable
digest, real OS identities, command/log digests, complete WFP/ACL snapshots,
original process-exit and cleanup observations. Phase waits are bounded.
Failure copies the original protected receipts, journal and last readback into
the artifact before attempting only exact recovery. Foreign/changed objects
remain preserved on the disposable VM. A missing required observation or
incomplete cleanup makes the workflow fail.

This is scoped L2 hosted kernel/SDK evidence. It does not prove packaged CLI
login recovery, a signed installed product, AppContainer compatibility, GPU,
mobile, real public NAT, or production deployment. Those acceptance levels
require their own exact build and execution provenance.
