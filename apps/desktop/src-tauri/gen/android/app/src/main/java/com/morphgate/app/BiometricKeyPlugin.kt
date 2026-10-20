package com.morphgate.app

import android.app.Activity
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Unlocking with a fingerprint or face: the key that opens the vault on this phone is encrypted
 * with an AES key that lives in Android's Keystore (in secure hardware where the phone has it) and
 * that Android only lets the app use right after a strong biometric check. Enrolling a new
 * fingerprint or face invalidates it: then the master password is needed once.
 *
 * Commands (called from Rust, not from the web view): `status`, `seal` (encrypts a secret, after a
 * check), `open` (decrypts it, after a check) and `forget`.
 */
@TauriPlugin
class BiometricKeyPlugin(private val activity: Activity) : Plugin(activity) {
    private val alias = "morphgate-vault-unlock"

    @Command
    fun status(invoke: Invoke) {
        val code = BiometricManager.from(activity).canAuthenticate(BIOMETRIC_STRONG)
        val reason = when (code) {
            BiometricManager.BIOMETRIC_SUCCESS -> null
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "no fingerprint or face is set up in Android's settings"
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "this phone has no fingerprint or face sensor that Android trusts for this"
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "the fingerprint or face sensor is unavailable right now"
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "Android needs a security update before it allows this"
            else -> "Android doesn't allow fingerprint or face checks here"
        }
        invoke.resolve(JSObject().put("available", code == BiometricManager.BIOMETRIC_SUCCESS).put("reason", reason))
    }

    /** A new Keystore key, then the secret encrypted with it once the user is verified. */
    @Command
    fun seal(invoke: Invoke) {
        val args = invoke.getArgs()
        val secret = Base64.decode(args.getString("secret"), Base64.NO_WRAP)
        val cipher = try {
            Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, newKey()) }
        } catch (e: Exception) {
            invoke.reject("Android's Keystore refused a key: ${e.message}", "KEYSTORE")
            return
        }
        prompt(args, cipher, invoke) { c ->
            val sealed = c.iv + c.doFinal(secret)
            JSObject().put("sealed", Base64.encodeToString(sealed, Base64.NO_WRAP))
        }
    }

    @Command
    fun open(invoke: Invoke) {
        val args = invoke.getArgs()
        val sealed = Base64.decode(args.getString("sealed"), Base64.NO_WRAP)
        if (sealed.size <= IV_BYTES) {
            invoke.reject("the stored key is damaged", "DAMAGED")
            return
        }
        val key = existingKey()
        if (key == null) {
            invoke.reject("the key is gone from Android's Keystore", "GONE")
            return
        }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, sealed.copyOfRange(0, IV_BYTES)))
        } catch (e: KeyPermanentlyInvalidatedException) {
            deleteKey()
            invoke.reject("the fingerprints or faces on this phone changed", "INVALIDATED")
            return
        } catch (e: Exception) {
            invoke.reject("Android's Keystore refused the key: ${e.message}", "KEYSTORE")
            return
        }
        prompt(args, cipher, invoke) { c ->
            val secret = c.doFinal(sealed.copyOfRange(IV_BYTES, sealed.size))
            JSObject().put("secret", Base64.encodeToString(secret, Base64.NO_WRAP))
        }
    }

    @Command
    fun forget(invoke: Invoke) {
        deleteKey()
        invoke.resolve()
    }

    private fun prompt(args: JSObject, cipher: Cipher, invoke: Invoke, done: (Cipher) -> JSObject) {
        val title = args.getString("title", "MorphGate") ?: "MorphGate"
        val subtitle = args.getString("subtitle", null)
        activity.runOnUiThread {
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        invoke.resolve(done(result.cryptoObject!!.cipher!!))
                    } catch (e: Exception) {
                        invoke.reject("the key couldn't be used: ${e.message}", "KEYSTORE")
                    }
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    val cancelled = code == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        code == BiometricPrompt.ERROR_USER_CANCELED ||
                        code == BiometricPrompt.ERROR_CANCELED
                    invoke.reject(message.toString(), if (cancelled) "CANCELLED" else "BIOMETRIC")
                }
                // onAuthenticationFailed (a finger or face it didn't recognize): the prompt stays
                // up and says so.
            }
            val prompt = BiometricPrompt(activity as FragmentActivity, ContextCompat.getMainExecutor(activity), callback)
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .apply { if (subtitle != null) setSubtitle(subtitle) }
                .setNegativeButtonText("Use master password")
                .setAllowedAuthenticators(BIOMETRIC_STRONG)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    private fun existingKey(): SecretKey? = keyStore().getKey(alias, null) as SecretKey?

    private fun deleteKey() {
        val store = keyStore()
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }

    private fun newKey(): SecretKey {
        deleteKey()
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    // Every use needs its own check, with a strong biometric only (no PIN).
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                }
            }
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE).apply { init(spec) }.generateKey()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_BYTES = 12
    }
}
