# objc2-foundation 0.2.2 consumer fork

All original archive members and manifest/VCS declarations are preserved; UPSTREAM.crate is the exact checksum-verified published archive. UPSTREAM.json records every original file and the two permitted local edits.

The normalized optional dependency uses already locked dispatch2 0.3.1 while the public dispatch feature name remains unchanged. Only run_on_main off-main queue submission is adapted: DispatchQueue::main().exec_sync runs the closure synchronously and the caller retains its generic Send result. The original main-thread fast path, marker creation, signatures, ownership and caller feature gates are retained. No dispatch 0.2.0 implementation is imported. Verification and panic/return-boundary comparisons are separate evidence; source preparation alone does not establish Apple runtime behavior.

LICENSE is the original full Steven Sheldon MIT grant at the exact archive-embedded monorepo revision e282618be4c3a3b9542957e0c8540e9588472ce8. Its bytes come from the existing reviewed upstream supplement and are unmodified. Original authors metadata is empty and remains empty; no author/year is inferred. This grant is used for this Foundation consumer, not represented as recovered notice text for the removed dispatch package.
