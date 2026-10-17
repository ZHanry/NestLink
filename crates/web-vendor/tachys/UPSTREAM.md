# tachys local fork

This directory preserves the checksum-verified published 0.2.19 archive in `UPSTREAM.crate`; `UPSTREAM.json` inventories every original member and every local edit. `Cargo.toml.orig` and `.cargo_vcs_info.json` retain the original upstream declarations unchanged.

The external erased crate is replaced by new standard-library Box<dyn Any + Send>/Box<dyn Any> storage, checked downcast and compiler-enforced Send. No erased source code is vendored. Typed retrieval, ownership transfer and concrete destructor dispatch use Rust std::any::Any and Box semantics.

The package declares MIT and the original author metadata remains unchanged. `LICENSE` is copied byte for byte from the already reviewed source identified in `UPSTREAM.json`. Full original root license texts and associated notices at the exact Git revision embedded in this locked crate archive; bytes verified against Git tree blob IDs. License compatibility is a separate review.

This fork adds no inferred copyright holders or years. Original source headers and any original notice files are retained. The complete standard-template follow-up materials are not this fork's license source.
