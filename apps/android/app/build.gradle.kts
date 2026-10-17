import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// One version authority for Rust, Android, native packages and Web materials.
val workspaceRoot = rootProject.projectDir.resolve("../..").canonicalFile
val workspaceManifest = workspaceRoot.resolve("Cargo.toml").readText()
val packageSection = Regex("(?ms)^\\[workspace\\.package]\\s*\\n(.*?)(?=^\\[|\\z)")
    .find(workspaceManifest)?.groupValues?.get(1) ?: error("Missing Cargo workspace package section")
val productVersion = Regex("(?m)^version\\s*=\\s*\"([^\"]+)\"\\s*$")
    .find(packageSection)?.groupValues?.get(1) ?: error("Missing Cargo workspace version")
val semanticVersion = Regex("^([0-9]+)\\.([0-9]+)\\.([0-9]+)(?:-[0-9A-Za-z.-]+)?$")
    .matchEntire(productVersion) ?: error("Unsupported Cargo version")
val releaseSequence = providers.environmentVariable("NESTLINK_RELEASE_SEQUENCE").orElse("1").get().toInt()
val versionParts = (1..3).map { semanticVersion.groupValues[it].toInt() }
require(versionParts[0] in 0..200 && versionParts[1] in 0..99 && versionParts[2] in 0..99 && releaseSequence in 1..999) {
    "Version or release sequence exceeds the reviewed Android versionCode allocation"
}
val productVersionCode = versionParts[0] * 10000000 + versionParts[1] * 100000 + versionParts[2] * 1000 + releaseSequence
val signingValues = listOf("NESTLINK_ANDROID_KEYSTORE", "NESTLINK_ANDROID_STORE_PASSWORD", "NESTLINK_ANDROID_KEY_ALIAS", "NESTLINK_ANDROID_KEY_PASSWORD")
    .associateWith { providers.environmentVariable(it).orNull }
val releaseSigningReady = signingValues.values.all { !it.isNullOrBlank() }
val splitReleaseAbi = providers.gradleProperty("nestlinkSplitAbi").orElse("false").get().toBooleanStrict()

android {
    namespace = "com.zhanry.nestlink"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.zhanry.nestlink"
        minSdk = 30
        targetSdk = 36
        versionCode = productVersionCode
        versionName = productVersion
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { if (!splitReleaseAbi) abiFilters += listOf("arm64-v8a", "x86_64") }
    }

    if (releaseSigningReady) {
        signingConfigs.create("fixedRelease") {
            storeFile = File(signingValues.getValue("NESTLINK_ANDROID_KEYSTORE")!!)
            storePassword = signingValues.getValue("NESTLINK_ANDROID_STORE_PASSWORD")
            keyAlias = signingValues.getValue("NESTLINK_ANDROID_KEY_ALIAS")
            keyPassword = signingValues.getValue("NESTLINK_ANDROID_KEY_PASSWORD")
            enableV1Signing = false
            enableV2Signing = true
            enableV3Signing = true
            enableV4Signing = false
        }
    }
    buildTypes.getByName("release") {
        isDebuggable = false
        isJniDebuggable = false
        if (releaseSigningReady) signingConfig = signingConfigs.getByName("fixedRelease")
    }
    splits.abi {
        isEnable = splitReleaseAbi
        reset()
        include("arm64-v8a", "x86_64")
        isUniversalApk = false
    }

    buildFeatures { compose = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    packaging { jniLibs.useLegacyPackaging = false }
}

dependencyLocking {
    lockAllConfigurations()
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.10.00")
    implementation(composeBom)
    androidTestImplementation(composeBom)
    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.4")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.9.4")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    testImplementation("junit:junit:4.13.2")
    // Uses JSON-java's real runtime in local JVM tests instead of android.jar's throwing org.json stubs.
    // The artifact is test-only and its published Maven POM declares Public Domain.
    testImplementation("org.json:json:20250517")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

val nativeOutput = layout.buildDirectory.dir("generated/nestlink-jni").get().asFile
android.sourceSets.getByName("main").jniLibs.srcDir(nativeOutput)
val cargoTargetRoot = providers.environmentVariable("CARGO_TARGET_DIR")
    .map { configuredPath: String ->
        val configured = File(configuredPath)
        if (configured.isAbsolute) configured.canonicalFile
        else File(workspaceRoot, configuredPath).canonicalFile
    }
    .orElse(workspaceRoot.resolve("target"))
val codecPrefixes = mapOf(
    "aarch64-linux-android" to providers.environmentVariable("NESTLINK_CODEC_ARM64_PREFIX"),
    "x86_64-linux-android" to providers.environmentVariable("NESTLINK_CODEC_X86_64_PREFIX"),
)
val nativeInputs = listOf(
    workspaceRoot.resolve("Cargo.toml"),
    workspaceRoot.resolve("Cargo.lock"),
    workspaceRoot.resolve("rust-toolchain.toml"),
)

fun registerAndroidNativeBuild(target: String, abi: String) = tasks.register<Exec>("buildNestlink${if (abi == "arm64-v8a") "Arm64" else "X86_64"}") {
    group = "build"
    description = "Build the Rust SDK for Android $abi with its verified native codec prefix."
    val codecPrefix = codecPrefixes.getValue(target).orElse("").map { it.trim() }
    workingDir = workspaceRoot
    environment("NESTLINK_CODEC_PREFIX", codecPrefix.get())
    environment("RUSTFLAGS", "-C link-arg=-Wl,-z,max-page-size=16384")
    commandLine("cargo", "ndk", "-t", abi, "-p", "30", "build", "--release", "--locked", "-p", "nestlink-android-bridge")
    inputs.files(nativeInputs)
    inputs.dir(codecPrefix.get())
    inputs.files(fileTree(workspaceRoot.resolve("crates")) {
        include("**/*.rs", "**/Cargo.toml", "**/build.rs")
    })
    inputs.files(fileTree(workspaceRoot.resolve("protocol-spec")) {
        include("**/*.json", "**/*.proto", "**/*.rs")
    })
    val sharedObject = cargoTargetRoot.map { it.resolve("$target/release/libnestlink_android.so") }
    val abiOutput = nativeOutput.resolve(abi)
    outputs.file(sharedObject)
    outputs.dir(abiOutput)
    doFirst {
        require(codecPrefix.get().isNotBlank()) { "Set ${if (abi == "arm64-v8a") "NESTLINK_CODEC_ARM64_PREFIX" else "NESTLINK_CODEC_X86_64_PREFIX"} to the verified Android codec receipt" }
        delete(abiOutput)
    }
    doLast {
        copy {
            from(sharedObject.get())
            into(abiOutput)
        }
    }
}

val buildNestlinkArm64 = registerAndroidNativeBuild("aarch64-linux-android", "arm64-v8a")
val buildNestlinkX86_64 = registerAndroidNativeBuild("x86_64-linux-android", "x86_64")

fun registerAndroidNativeVerification(target: String, abi: String, dependency: TaskProvider<Exec>) = tasks.register<Exec>("verifyNestlink${if (abi == "arm64-v8a") "Arm64" else "X86_64"}") {
    group = "verification"
    description = "Verify the Android $abi JNI library uses 16 KiB ELF LOAD segments."
    dependsOn(dependency)
    workingDir = workspaceRoot
    val sharedObject = cargoTargetRoot.map { it.resolve("$target/release/libnestlink_android.so") }
    commandLine("python3", workspaceRoot.resolve("scripts/verify-android-binary.py"), "--library", sharedObject.get(), "--abi", abi)
    inputs.file(sharedObject)
    inputs.file(workspaceRoot.resolve("scripts/verify-android-binary.py"))
}

val verifyNestlinkArm64 = registerAndroidNativeVerification("aarch64-linux-android", "arm64-v8a", buildNestlinkArm64)
val verifyNestlinkX86_64 = registerAndroidNativeVerification("x86_64-linux-android", "x86_64", buildNestlinkX86_64)
tasks.named("preBuild") { dependsOn(verifyNestlinkArm64, verifyNestlinkX86_64) }

// Direct assembleRelease/bundleRelease also refuse an unsigned or development
// artifact. The producer checks the actual APK signer against the public pin.
tasks.configureEach {
    if (name == "preReleaseBuild") doFirst {
        require(!productVersion.contains('-')) { "Release requires a committed final Cargo version" }
        require(releaseSigningReady) { "Fixed Android Release keystore, alias and password environment variables are required" }
        require(File(signingValues.getValue("NESTLINK_ANDROID_KEYSTORE")!!).isFile) { "Release keystore is unavailable" }
        require(providers.environmentVariable("NESTLINK_ANDROID_CERTIFICATE_SHA256").orElse("").get().matches(Regex("[0-9a-f]{64}"))) {
            "Enroll the fixed public Android certificate SHA256 before producing Release bytes"
        }
    }
}
