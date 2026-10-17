# Browser business adapter dependency edges

The Web application now directly depends on workspace `sha2` and locked
`futures-channel` 0.3.34. Both were already present in the reviewed lock graph; no registry
package identity, version, source or checksum changed when these two edges were added.
The comparison baseline is the retained development artifact
`artifacts/core-verification/web-business-Cargo.lock-before-20261015.txt`.

`sha2` provides bounded incremental source/chunk/final hashes; `futures-channel` keeps
owned response actors alive when a UI waiter is abandoned. Existing `web-sys` 0.3.106
features add browser File/Blob, clipboard, file-input and save-anchor bindings. No native
filesystem, desktop clipboard, SQLite, Tokio networking or native codec dependency is
introduced into the browser target.

Final SBOM/NOTICE and the license-policy checks still run from the frozen release source;
the unchanged registry graph does not by itself certify the new product flow.
