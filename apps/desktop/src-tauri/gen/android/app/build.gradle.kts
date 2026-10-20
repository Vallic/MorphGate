import java.util.Properties
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

// Release builds are signed with the key at MORPHGATE_ANDROID_KEYSTORE (CI, or a local release
// build: RELEASING.md); without it they come out unsigned.
val releaseKeystore: String? = System.getenv("MORPHGATE_ANDROID_KEYSTORE")?.takeIf { it.isNotBlank() }
// Dev builds (the develop branch) install next to the release app, with their own id and name.
val devBuild = System.getenv("MORPHGATE_CHANNEL") == "dev"

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

android {
    compileSdk = 37
    namespace = "com.morphgate.app"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "com.morphgate.app"
        minSdk = 24
        targetSdk = 37
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
        if (devBuild) {
            applicationIdSuffix = ".dev"
            resValue("string", "app_name", "MorphGate Dev")
            resValue("string", "main_activity_title", "MorphGate Dev")
        }
    }
    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = System.getenv("MORPHGATE_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("MORPHGATE_ANDROID_KEY_ALIAS") ?: "morphgate"
                keyPassword = System.getenv("MORPHGATE_ANDROID_KEYSTORE_PASSWORD")
            }
        }
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {
                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            if (releaseKeystore != null) {
                signingConfig = signingConfigs.getByName("release")
            }
            optimization {
               enable = true
            }
            proguardFiles(
                *fileTree(".") {
                  include("**/*.pro")
                  exclude("build/**")
                }.files.toTypedArray()
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    buildFeatures {
        buildConfig = true
        resValues = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_1_8
    }
}

rust {
    rootDirRel = "../../../"
}

// HTTPS certificates are checked by Android's own verifier (rustls-platform-verifier, under the
// sync client). Its Kotlin half must be the version of the rustls-platform-verifier-android crate
// in Cargo.lock.
val rustlsVerifierVersion: String = rootProject.file("../../../../../Cargo.lock").readLines().let { lines ->
    val at = lines.indexOfFirst { it.trim() == "name = \"rustls-platform-verifier-android\"" }
    require(at >= 0) { "rustls-platform-verifier-android isn't in Cargo.lock" }
    lines[at + 1].substringAfter('"').substringBefore('"')
}

repositories {
    maven { url = uri("https://raw.githubusercontent.com/rustls/rustls-platform-verifier/maven-archive/android-release-support/maven/") }
}

dependencies {
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    implementation("org.rustls:rustls-platform-verifier:$rustlsVerifierVersion")
    // Unlocking with a fingerprint or face (BiometricKeyPlugin).
    implementation("androidx.biometric:biometric:1.1.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

apply(from = file("tauri.build.gradle.kts"))
