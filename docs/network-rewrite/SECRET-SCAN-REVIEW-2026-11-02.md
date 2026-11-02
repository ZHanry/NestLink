# Historical public digest findings

Run [41473518526](https://github.com/ZHanry/NestLink/actions/runs/41473518526)
at `9f00b068a67e5db9d1ed5285e7bda90afe004600` used the previously reviewed
Gitleaks 8.30.1 default rules against complete Git history. It failed with six
findings. The earlier e226eec scan used an older default scanner that did not
apply the repository's existing multiple allowlists correctly; that failure
remains recorded too.

Four findings are public SHA256 provenance values (ordinary process-token check
log, official Authenticode report, medium-token capability check log, and native
ICE Actions ZIP). The others are the pinned public cloudflared source commit
and the public Windows API field identifier `MIB_IF_ROW2.Mtu`. They are neither
authentication credentials nor signing secrets. Their complete values remain
visible in their original evidence; no historical evidence is rewritten.

Run [41475582322](https://github.com/ZHanry/NestLink/actions/runs/41475582322)
at `3cac12ff6166cc979005c5078824c13c09bd8a8c` cleared the four SHA256 findings
but retained two failures. The first review had incorrectly associated those
two redacted findings with nearby digest values. Reading the exact historical
blobs from commits `39ed299` and `67db656` corrected the classification: the
Cloudflare rule captures the 40-character source revision, and the generic
rule captures the field name after the words “API semantics. First,”. Only
these actual complete values are now excluded at their precise rule/path;
the two unused nearby-value exclusions have been removed. Both failed runs
remain failures. A new hosted scan must establish the corrected result.

Each new allowlist is restricted jointly to its exact file path and complete
public value, and to the rule that reported it. No directory, whole commit, generic
hash expression or credential rule is excluded. A changed value in the same
file and the same value in a different file remain subject to default scanning.
The original three independently recomputed test-vector exclusions remain.

The workflow explicitly selects Gitleaks 8.30.1; the configuration states the
8.25.0 minimum for its existing syntax. These edits require a fresh hosted scan
before a success claim. No scanner or automated check is executed locally.
