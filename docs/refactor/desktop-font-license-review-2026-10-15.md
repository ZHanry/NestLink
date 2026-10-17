# Desktop font dependency and license review (2026-10-15)

The desktop update to `eframe` 0.34.3 replaces the old `epaint` font parser path through `ab_glyph`, `owned_ttf_parser`, and `ttf-parser`. The current lockfile no longer contains those packages. The new font type and parsing path is `epaint 0.34.3` → `font-types 0.11.3` and `skrifa 0.40.0` → `read-fonts 0.37.0`.

All three exact registry archives were downloaded from crates.io and their archive SHA-256 values match the corresponding Cargo.lock checksums. Each crate manifest declares `MIT OR Apache-2.0`, and each identifies `https://github.com/googlefonts/fontations` as its upstream repository. The archive-embedded VCS metadata records the source commits. Full copies of both license files from each verified archive are in [`packaging/notices`](../../packaging/notices); their byte counts and hashes are recorded in [the machine-readable review](desktop-font-license-review-2026-10-15.json).

| Crate | Locked version | Cargo.lock / archive SHA-256 | Upstream source commit | License |
| --- | --- | --- | --- | --- |
| `font-types` | 0.11.3 | `5b38ad915f6dadd993ced50848a8291a543bd41ca62bc10740d5e64e2ab4cfd7` | `9af3f3188ab5522e23446a1fb98135cb3f7d96b6` | MIT OR Apache-2.0 |
| `skrifa` | 0.40.0 | `7fbdfe3d2475fbd7ddd1f3e5cf8288a30eb3e5f95832829570cd88115a7434ac` | `338e2c0dcf3646554ae57b852705092a7611e230` | MIT OR Apache-2.0 |
| `read-fonts` | 0.37.0 | `7b634fabf032fab15307ffd272149b622260f55974d9fad689292a5d33df02e5` | `338e2c0dcf3646554ae57b852705092a7611e230` | MIT OR Apache-2.0 |

The desktop manifest sets `default-features = false` and selects only `accesskit`, `glow`, `wayland`, and `x11`. `epaint_default_fonts` is absent from Cargo.lock, so this build does not package egui's bundled Ubuntu font; its `OFL-1.1` and `Ubuntu-font-1.0` terms are not introduced by this feature selection.

The existing `cargo-deny` allow list already covers MIT and Apache-2.0. This review adds no license exception or advisory ignore. It covers only this new font dependency scope and does not mark desktop compilation, cross-platform regression testing, or release acceptance as complete.
