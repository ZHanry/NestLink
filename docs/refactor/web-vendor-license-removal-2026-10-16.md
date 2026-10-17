# Web consumer dependency removal review — 2026-10-16

The locked Web dependency graph no longer requires `convert_case_extras 0.2.0` or `erased 0.1.2`. Two narrow local consumer forks preserve their upstream MIT sources and attribution. This review does not clear the remaining `dispatch 0.2.0` original-notice gap or authorize a release.

## Source preservation and implementation

`crates/web-vendor/leptos_macro` preserves all 41 files of the published 0.8.19 archive, checksum `0902af1e6947ffc7e906b7003a165f76f178dc711a47b74241025090b0c32a72`. Its normalized manifest removes one dependency; its two naming predicates use the already present `convert_case::Casing` snake-case fixed point. The conversion branches remain unchanged. No `convert_case_extras` source was imported.

`crates/web-vendor/tachys` preserves all 62 files of the published 0.2.19 archive, checksum `e47e2220bb9d2a3be976a22a0fb7685a0b84499bb11ea5cb3bbc82907675ac68`. Its normalized manifest removes `erased`; the replacement module independently uses `Box<dyn Any + Send>` and `Box<dyn Any>`, checked standard-library downcasts, compiler-enforced Send, ownership transfer and concrete destructor dispatch. No `erased` implementation was imported. Wrong-type retrieval now consistently checks and panics, including the `erase_components` configuration; correct typed consumer operations preserve ownership and return behavior. This makes no performance-equivalence claim.

Each fork retains its exact original archive, published manifest, `Cargo.toml.orig`, VCS declaration, every original source member and an explicit original/local hash inventory. The original Greg Johnston MIT grant is retained byte for byte. Tachys uses the exact embedded upstream revision. The Leptos macro embedded revision is unavailable upstream; its `UPSTREAM.md` and `UPSTREAM.json` explicitly retain that limitation and the already reviewed reachable release-family original grant binding. No author/year was inferred and no standard MIT template was promoted to package notice evidence. The earlier review and supplement policy remain unchanged.

Both directories are excluded from workspace members, retain `license = "MIT"`, and enter Cargo through exact local patches. The verified lock delta changes only the two consumer sources and deletes the two now-unused dependency records. It changes no other package fields or supplier versions. Browser-native fixture locks contain neither Leptos nor Tachys and need no change.

## Verification and evidence

The evidence root is `artifacts/cargo-notice-followup-20261016/`.

- `erasure-checks-attempt02/checks.receipt.json`: 12 passing tests across ordinary and `erase_components` builds plus one successful compile rejection for sending `ErasedLocal` across threads. These cover actual destructor counts, extraction, mutation, Send, Rc, wrong-type panics and retained payload cleanup. The fixture forbids unsafe code, and the installed module bytes equal those tested.
- `web-validation-attempt02/validation.receipt.json`: exact original casing crate compared over 54 named Unicode/digit/acronym/separator cases and all 22,621 bounded short strings; both actual naming branches match. Verified Trunk 0.21.14, wasm-bindgen 0.2.129 and wasm-opt 133 binary hashes precede real all-target/all-feature WASM Clippy with `-D warnings` and a complete optimized Trunk production build. All 440 recorded source inputs remain unchanged. The production build retains one existing upstream `ident_from_tag_name` dead-code warning under its default feature selection; no warning is suppressed.
- `web-validation-attempt02/COMPILED_SOURCE.json`: deterministic 899-file exact compiled-source archive, all members independently reread and hashed. The frozen output directory is `D:/NestLinkBuilds/web-license-replacements-20261016-attempt01/validation/production-dist`; all HTML/CSS/JavaScript/WASM bytes and hashes are recorded in the validation receipt. This is the isolated compiled snapshot, not subsequently edited root sources.
- `root-integration-attempt01/APPLIED.json`: preserved root baselines, exact verified manifest/lock integration and explicit three native-only SDK source differences caused by concurrent work. No Web or fork input differs at integration.
- `collector-validation-attempt01/checks.receipt.json`: 13 passing collector unit checks and two passing actual release-metadata packaging integration checks. The unit transcript is retained in the original tool session rather than represented as a synthetic log.
- `root-integration-attempt01/COLLECTION.json` and `cargo-notices/index.json`: real integrated all-feature locked/offline metadata covers 766 packages. The removed dependencies are absent, both local forks remain third-party packages, and the sole remaining missing original is `dispatch 0.2.0`. The collector intentionally reports `incomplete`.

The collector permits only these exact two new paths and versions, pins each full provenance record and archive, checks every original member and allowed local edit, rejects unexpected or linked sources, preserves original and patched manifest attribution separately, and verifies actual MIT grant bytes. It rejects classifying these suppliers as first-party workspace members. It does not broaden the existing WebRTC path exception or alter unrelated missing-notice status.

The initial complete-build attempt failed because the isolated copy omitted the unchanged `protocol-spec` inputs. Its failed receipt and logs remain in `web-validation-attempt01`; attempt02 records the exact original files copied to repair the fixture. The earlier shell-quoting failure and the eight passing standard-template policy experiments also retain their own scopes and do not become production-license approval.

## Remaining boundary

`dispatch 0.2.0` remains unresolved. Its archive, embedded Git tree source comparison, upstream missing-license issue and downstream material are preserved in the same evidence root. Five target-tree queries show the Apple-only edge and its positive control; this target information does not clear the global source/notice requirement. A successor-consumer investigation is an independent increment.

No browser media/input/file runtime or installed-product, signature, hardware, external-network or release acceptance is inferred from these checks. Previously rejected cleanup targets remain retained; no deletion retry or alternate removal method was used.
