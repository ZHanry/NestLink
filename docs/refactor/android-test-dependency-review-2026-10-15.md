# Android JVM test dependency review (2026-10-15)

> 历史记录：Android 客户端已于 2026-10-23 从产品范围、源码和构建清单移除。本文仅保存当时的实现、来源与测试证据，不再作为当前产品要求或构建入口。

`org.json:json:20250517` is pinned as an Android app `testImplementation` dependency so local JVM tests execute against a real `JSONObject`; the Android SDK's JVM test stubs throw `Method ... not mocked` for JSON operations. The dependency is limited to `debugUnitTest` compile/runtime configurations and is not in the app's production or APK dependency graph.

The artifact and its POM were fetched from the Maven Central HTTPS coordinates below and compared byte-for-byte by SHA-256 with the artifacts in the local Gradle cache. The exact hashes are also recorded in [`apps/android/gradle/verification-metadata.xml`](../../apps/android/gradle/verification-metadata.xml); dependency verification remains enabled.

| File | Maven Central coordinate | Size | SHA-256 |
| --- | --- | ---: | --- |
| `json-20250517.jar` | [`org/json/json/20250517/json-20250517.jar`](https://repo.maven.apache.org/maven2/org/json/json/20250517/json-20250517.jar) | 82,710 bytes | `3ea61b2a06e31edf1c91134fe9106b0ebb16628be169f3db75bc7a2b06b45796` |
| `json-20250517.pom` | [`org/json/json/20250517/json-20250517.pom`](https://repo.maven.apache.org/maven2/org/json/json/20250517/json-20250517.pom) | 10,175 bytes | `71a1fb86a2b05537a3cfc1c87db42d036efdbbfc7e9c349b635d21ac1fa876a7` |

The published POM declares the license as `Public Domain` and links to the upstream [`LICENSE` at tag `20250517`](https://github.com/stleary/JSON-java/blob/20250517/LICENSE). The versioned source file contains the complete text `Public Domain.` followed by two line feeds; its GitHub API blob SHA-1 is `2ef9799e082fa18e62fc5f1fd5ec853e7547bb8e`. The same text is retained byte-for-byte in [`JSON-java-20250517-PUBLIC-DOMAIN.txt`](../../packaging/notices/JSON-java-20250517-PUBLIC-DOMAIN.txt), SHA-256 `86cc84f1773e3318ba26fd61b3ae508a167df38b361695e105f6e499e7a2736f`.

This records the one test-only dependency added for Android JVM JSON tests. It is not the complete Android dependency inventory, APK notice, or release SBOM.
