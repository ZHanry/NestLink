# 0040 — Exact Windows user admission for a raw local endpoint

Status: source implemented, independently reviewed; compilation and native kernel
execution remain pending. No Windows device qualification or release is claimed.

The existing authenticated SOCKS entry and same-user/session named pipe remain
ordinary-user alternatives. A raw TCP or UDP client cannot supply that protocol's
credential before the OS accepts its traffic. A loopback bind alone is therefore
insufficient local admission.

The reviewed alternatives were native Windows Filtering Platform ALE rules,
AppContainer isolation, and the existing authenticated pipe. AppContainer would
require changing how ordinary Win32 applications are launched and handling their
default loopback restrictions. A pipe cannot serve standard TCP/UDP clients. The
selected adapter uses the OS's mature WFP implementation through the already
locked windows-sys ABI, with NestLink owning only its exact local plan, resource
identity, finite lifetime, receipt and recovery policy.

One separately elevated invocation receives a plan from the original ordinary
process. It verifies the real user SID, process creation time, retained process
handle and executable file identity. The helper and original process use the same
administrator-protected executable on a fixed local volume. The helper does not
load installation keys, management login or private service credentials. The SDK
continues to require the original private service lease and possession proof.

An owned persistent provider/sublayer applies exact address, destination port and
IP protocol selectors at ALE_AUTH_CONNECT_V4/V6. The higher-weight rule matches a
native security descriptor for the selected user SID with the documented equality
operator. Its soft permit retains other providers' policy; the lower-weight
endpoint block prevents a different SID from passing. A matching receive/accept
rule blocks non-loopback arrival at that endpoint. This grants access to that
user's applications, not just one client process.

The rules are persistent because a dynamic WFP session would remove them when
the helper crashes while the raw socket could still be alive. Expiry removes the
permit in one transaction. Only the original process handle becoming signaled
permits final cleanup. Before any deny or remove transaction, complete native
provider, sublayer and filter configuration is read and compared, including
filter IDs, effective weight, conditions, action, data and owner/group/DACL.
Changed objects are preserved. SACL auditing is not needed for admission and no
additional security privilege is requested to read it.

Plan/receipt/journal storage reuses the existing Windows token and ACL parser.
Trust paths retain directory/image handles, reject reparse points and removable
or mapped volumes, and require administrator-controlled write/owner/DACL access.
Ancestor directories may permit creation of a separate child while retaining
the prohibition on deleting/replacing the opened child. The original strict
input broker ACL entry keeps its existing behavior.

All Windows raw, authenticated SOCKS and private Web listeners also reserve their
endpoint with Winsock SO_EXCLUSIVEADDRUSE before bind. The existing Socket2
implementation owns socket creation, nonblocking mode, bind and conversion; one
small platform adapter supplies that native option because Socket2 0.6.5 does not
expose its setter. Disabling SO_REUSEADDR alone would not prevent another process
from enabling it. The added OS test attempts precisely that competing bind and
then confirms the original endpoint can be rebound after its actual close.

Native descriptor/rule/receipt tests do not prove WFP arbitration, established
TCP/UDP reauthorization, helper crash behavior or deployment ACL behavior. Those
must run with the ordinary SDK process, independent administrator helper and
another user SID on GitHub-hosted Windows, followed by the required target-device
qualification. All compilation, lock derivation, formatting and automated tests
remain in Actions under R02.
