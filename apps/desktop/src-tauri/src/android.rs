//! Android: HTTPS certificates are checked by the platform's own verifier
//! (rustls-platform-verifier, under the sync client's reqwest), which calls into the JVM. It needs
//! the JVM and the app's context before the first request, or that request fails. Its Kotlin half
//! comes in through the Gradle build (`gen/android/app/build.gradle.kts`).

use jni::objects::JObject;

/// Hands the verifier the JVM and the application context, which tao keeps in `ndk-context` once
/// the activity is created (before the app's setup runs).
pub fn init_tls() -> Result<(), String> {
    let ctx = ndk_context::android_context();
    // SAFETY: tao set both from the running app: the process's JavaVM, and a global reference to
    // the application context, which lives as long as the process.
    let vm = unsafe { jni::JavaVM::from_raw(ctx.vm().cast()) };
    vm.attach_current_thread(|env| -> Result<(), jni::errors::Error> {
        // SAFETY: a valid reference (global) to the context; nothing else wraps it here, and the
        // local copy below is what the verifier gets.
        let global = unsafe { JObject::from_raw(env, ctx.context().cast()) };
        let context = env.new_local_ref(&global)?;
        rustls_platform_verifier::android::init_with_env(env, context)
    })
    .map_err(|e| format!("setting up HTTPS certificate checks: {e}"))
}
