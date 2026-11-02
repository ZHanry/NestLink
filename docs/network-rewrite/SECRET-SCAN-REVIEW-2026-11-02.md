# Historical public digest findings

Run [41473518526](https://github.com/ZHanry/NestLink/actions/runs/41473518526)
at `9f00b068a67e5db9d1ed5285e7bda90afe004600` used the previously reviewed
Gitleaks 8.30.1 default rules against complete Git history. It failed with six
findings. The earlier e226eec scan used an older default scanner that did not
apply the repository's existing multiple allowlists correctly; that failure
remains recorded too.

The six new findings were manually traced to their exact historical source
locations. Five are public SHA256 provenance values (ordinary process-token
check log, cloudflared release binary, official Authenticode report, medium-token
capability check log, and native ICE Actions ZIP). The remaining value is the
public Wintun source revision in a GitHub link. They are neither authentication
credentials nor signing secrets. Their complete values remain visible in their
original evidence; no historical evidence is rewritten.

Each new allowlist is restricted jointly to its exact file path and complete
digest, and to the rule that reported it. No directory, whole commit, generic
hash expression or credential rule is excluded. A changed value in the same
file and the same value in a different file remain subject to default scanning.
The original three independently recomputed test-vector exclusions remain.

The workflow explicitly selects Gitleaks 8.30.1; the configuration states the
8.25.0 minimum for its existing syntax. These edits require a fresh hosted scan
before a success claim. No scanner or automated check is executed locally.
