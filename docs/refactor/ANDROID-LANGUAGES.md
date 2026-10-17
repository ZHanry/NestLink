# Android display languages

Current recorded result, 2026-10-16: Kotlin/JVM attempt 04 compiled main Kotlin,
JVM tests and instrumentation source, then passed 127 tests in 20 suites with
zero failures, errors or skips. All five `UiTextTest` regressions passed.
The command receipt confirms all 77 captured inputs stayed unchanged and its
owned scratch was removed. The log and all 20 XML files were checked against
their recorded SHA-256 values; the XML test counts and successful testcase
records agree with `kotlin-jvm-attempt04.results.json`.

Attempt 04 adds
`tallLargeAndOddScreensPrepareTheSameBoundedGeometryThatCaptureActivates`.
It checks prepared and activated capture sizes for 1080×2400 → 864×1920,
1440×2560 → 1080×1920, 2560×1440 → 1920×1080 and
1079×1919 → 1078×1918. The same case checks that a different permit cannot
read prepared geometry, geometry lookup cannot activate or expose pixels,
and the exact binding can activate only once. The prior prepared-grant and
owner-retirement regressions also remain in the passing 19-case capture-port
suite.

Evidence is retained in
`artifacts/android-language-20261016/kotlin-jvm-attempt04.{log,receipt.json,results.json}`.
The log SHA-256 is
`27ddc30423e1f93e6bb058d66a8a54628ba5fce07cbedb73c66e15fe28fd1306`.
Cargo/JNI tasks were excluded. Current JNI and APK compilation, focused emulator
execution and physical-device verification still require separate completed
receipts; the JVM and instrumentation-source result does not establish those
outcomes. Android support remains 11–16; Android 10 is excluded.

Android 11–16 supports System, 中文 and English in the language selector on every
page. The selected preference is stored locally. System chooses simplified
Chinese for a Chinese system language and English for other system languages.

`UiTextCatalog.kt` contains 577 explicitly selected local templates, including
request and session display labels. Template arguments preserve remote names,
paths and original diagnostic text. Unknown future protocol statuses are shown
unchanged, and no language preference enters a Rust command or proof binding.

`AppLanguageScope` changes the Compose resource context in place while keeping
the Activity in its context wrapper chain. Existing network settings resources
use that context too. Switching language does not recreate the Activity, grant
MediaProjection consent, replace a ViewModel, or restart capture. The capture
service observes language changes only to refresh its foreground notification
and channel copy. A failed notification refresh cannot interrupt selection.

Already recorded event messages retain the language in which they were
generated. New local messages use the current choice. Remote diagnostics remain
exact values. System Settings renders the accessibility and keyboard service
labels according to the system locale using the included Chinese and English
Android resources.

The static migration audit checks catalog key references, formatting argument
counts, matching placeholders and XML resource parity. JVM tests cover English
coverage, literal argument preservation, system fallback and observer isolation.
The Android smoke test switches the real picker with a draft and a retained
one-use browser consent binding, checking Activity/ViewModel identity, unchanged
session/capture state, resource locale and persisted preference initialization.
It does not create a MediaProjection grant or claim active device capture
acceptance.

Historical attempt 03 on 2026-10-16, using
`artifacts/android-language-20261016/run-kotlin-check.ps1`, compiled its captured
main Kotlin, JVM tests and instrumentation source
and ran all 126 JVM tests in 20 suites, including all five `UiTextTest`
regressions, with zero failures, errors or skips. That snapshot also covers the
network-settings revision and durability fields. Two new BrowserHost cases
check proof-free candidate geometry against one staged system binding and
owner retirement during a geometry read without lock inversion. Neither
candidate lookup activates capture or makes pixels available.
The command receipt records all 77 source inputs unchanged and its owned scratch
removed. The log SHA-256 is
`2a01f42e09b286ef1bd21c59355c69f904e9f956aa9d70395f985adcc6c83ec6`;
the matching receipt and XML index are retained beside that log. This check
excluded Cargo/JNI tasks. JNI/APK builds and the focused emulator test remained
pending after that attempt; compilation does not prove device behavior.
