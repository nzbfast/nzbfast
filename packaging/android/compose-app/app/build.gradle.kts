plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// ONE version, and it is the crate's. packaging/bump-version.sh moves
// crates/nzbfast/Cargo.toml and the sixteen website download pages in
// lockstep; reading it here puts the APK on that same lockstep instead of
// on somebody remembering to edit this file. A version that cannot be read
// is a FAILURE, never a default: an APK that quietly ships as 0.0.1 is a
// release nobody can tell apart from the test build it replaced.
val engineVersion: String = run {
    val f = rootProject.file("../../../crates/nzbfast/Cargo.toml")
    if (!f.isFile) throw GradleException(
        "cannot read ${f.path} - the APK version comes from the crate, " +
        "so there is nothing to fall back to.")
    val m = Regex("""(?m)^version = "([0-9]+)\.([0-9]+)\.([0-9]+)"""")
        .find(f.readText())
        ?: throw GradleException(
            "no [package] version = \"X.Y.Z\" in ${f.path}")
    m.groupValues[1] + "." + m.groupValues[2] + "." + m.groupValues[3]
}

// Monotonic in the dotted version and nothing else, so it cannot go
// backwards while the crate version goes forwards. Play and the package
// manager both refuse a downgrade by this number, and Android's own
// installer refuses one too - which is why it is derived rather than
// hand-counted. Ceiling: minor and patch below 100.
val engineVersionCode: Int = engineVersion.split(".").let { (a, b, c) ->
    val (maj, min, pat) = Triple(a.toInt(), b.toInt(), c.toInt())
    if (min > 99 || pat > 99) throw GradleException(
        "version $engineVersion does not fit major*10000 + minor*100 + patch " +
        "- widen this arithmetic AND keep it monotonic, never reset it.")
    maj * 10000 + min * 100 + pat
}

// The release identity. Android identifies an app by its signing key
// FOREVER: a new key is not an update, it is a different app, and every
// user has to uninstall and lose their settings, queue and downloads. So
// the key never lives in this repo and is never generated on the fly - it
// is handed in by path, and a build that is not given one produces an
// UNSIGNED release APK rather than a debug-signed one wearing a release
// name. That failure is loud at install time; a debug-signed release is
// silent until the first user cannot upgrade.
//   NZBFAST_ANDROID_KEYSTORE        path to the PKCS12 keystore
//   NZBFAST_ANDROID_KEYSTORE_PASS_FILE   file holding the password (preferred:
//                                   a password in the environment is visible
//                                   in `ps` to every process on the box)
//   NZBFAST_ANDROID_KEYSTORE_PASS   the password itself (for CI secrets)
//   NZBFAST_ANDROID_KEY_ALIAS       defaults to nzbfast
val releaseKeystore: File? = System.getenv("NZBFAST_ANDROID_KEYSTORE")
    ?.takeIf { it.isNotBlank() }?.let { file(it) }
val releaseKeyPassword: String? = releaseKeystore?.let {
    val pf = System.getenv("NZBFAST_ANDROID_KEYSTORE_PASS_FILE")
    when {
        !pf.isNullOrBlank() -> file(pf).readText().trim()
        else -> System.getenv("NZBFAST_ANDROID_KEYSTORE_PASS")?.takeIf { p -> p.isNotBlank() }
    } ?: throw GradleException(
        "NZBFAST_ANDROID_KEYSTORE is set but no password is: give " +
        "NZBFAST_ANDROID_KEYSTORE_PASS_FILE or NZBFAST_ANDROID_KEYSTORE_PASS.")
}


android {
    namespace = "app.nzbfast.mobile"
    compileSdk = 36

    defaultConfig {
        applicationId = "app.nzbfast.mobile"
        minSdk = 26
        targetSdk = 34
        versionCode = engineVersionCode
        versionName = engineVersion
    }

    // The engine ships as libnzbfast.so and is exec'd from
    // nativeLibraryDir; that needs a real file on disk.
    packaging {
        jniLibs {
            useLegacyPackaging = true
        }
    }

    sourceSets {
        getByName("main") {
            // fetch-engine.sh copies the cargo-ndk slim binary here as
            // engine/arm64-v8a/libnzbfast.so (gitignored).
            jniLibs.srcDir("engine")
        }
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = releaseKeystore
                storeType = "PKCS12"
                storePassword = releaseKeyPassword
                keyAlias = System.getenv("NZBFAST_ANDROID_KEY_ALIAS") ?: "nzbfast"
                keyPassword = releaseKeyPassword
                // v1 (JAR signing) is only consulted below API 24 and
                // minSdk here is 26, so it buys nothing; v2 is what every
                // phone that can install this actually verifies. v3 is on
                // for the one thing that softens "the key is forever": it
                // is the scheme that carries a proof-of-rotation block, so
                // a future key change is an UPDATE on Android 9+ rather
                // than an uninstall. Turning it off later would take that
                // escape hatch away from every install made meanwhile.
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (releaseKeystore != null) {
                signingConfig = signingConfigs.getByName("release")
            } else {
                logger.warn(
                    "nzbfast: no NZBFAST_ANDROID_KEYSTORE - assembleRelease " +
                    "will produce an UNSIGNED apk. That is deliberate: a " +
                    "debug-signed release would install and then be " +
                    "unupgradable. packaging/android/build-release-apk.sh " +
                    "refuses rather than reaching this line.")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.media3:media3-exoplayer:1.5.1")
    implementation("androidx.media3:media3-ui:1.5.1")

    // Host-side tests: the app itself uses the platform org.json; the
    // JVM needs the standalone artifact to run the same parsers.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
