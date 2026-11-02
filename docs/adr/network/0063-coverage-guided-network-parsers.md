# 0063 — Coverage-guided properties for production network parsers

Date: 2026-11-02. Scope: W36 / AC62 preparation; no completed security review claim.

The new network grant, offline authority and exact media dialects add untrusted
byte boundaries. Existing contract, property and real lifecycle tests remain
necessary. A random byte loop alone provides no coverage feedback and must not
be called equivalent to an instrumented fuzzer.

Reuse LLVM libFuzzer through the maintained rust-fuzz cargo-fuzz 0.13.2 and
libfuzzer-sys 0.4.13 adapters. The alternative was a handwritten mutation loop;
it was rejected because it duplicates a general fuzzing engine while providing
weaker corpus discovery and sanitizer integration. This harness adds no product
runtime dependency and implements no alternate protocol parser.

The separately locked fuzz workspace calls the actual production protocol
decoders. Its properties cover exact canonical round trips, v1/v2 dialect
separation, malformed inputs, rejected forwarding leaving its input unchanged,
and an admitted relay hop changing only the existing hop byte. Decode success
does not issue a grant or prove any permission. Native video preserves decoded
semantics while retaining its existing optional-field compatibility.

All tool installation, dependency resolution, corpus generation, instrumented
builds and execution run on GitHub-hosted Actions. First derive the separate
Cargo.lock on Actions and review/import that exact artifact. Fuzz execution
requires the reviewed lock, fetches with --locked, then runs with Cargo network
access disabled and requires byte-identical lock preservation. Receipts retain
both product and fuzz lock digests, exact source, commands, logs and corpus/crash
hashes. This separately resolved graph and bounded ASan run do not qualify the
entire product dependency graph or deployment.

The initial 120-second campaign is a repeatable development experiment, not a
claim of exhaustive fuzzing, independent review, permission/lifecycle safety,
24-hour stability, a target pass or complete W36/AC62. A crash fails the job and
retains its input. Fix the production boundary and add a focused reproducer;
never remove the property or suppress the sanitizer to turn a crash green.

Reviewed sources and exact published checksums:

- <https://crates.io/crates/cargo-fuzz/0.13.2>, published 2026-06-09, not yanked;
  SHA256 `5acfd01930e49823e58c30dd8012d3338a620377d7c7d4cc140ca4b2169400e2`;
  MIT OR Apache-2.0; source <https://github.com/rust-fuzz/cargo-fuzz/>.
- <https://crates.io/crates/libfuzzer-sys/0.4.13>, published 2026-06-04, not yanked;
  SHA256 `a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2`;
  `(MIT OR Apache-2.0) AND NCSA`; source <https://github.com/rust-fuzz/libfuzzer>.
- <https://rust-fuzz.github.io/book/cargo-fuzz.html> and
  <https://llvm.org/docs/LibFuzzer.html> document the mature engine boundary.

Publication metadata and source review establish provenance only. The hosted
compile and actual fuzzer result remain pending until their exact-source run.
