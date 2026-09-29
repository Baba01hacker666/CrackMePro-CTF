package com.ctf.crackme

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Encrypted storage for the purchase token + pro flag.
 * Uses AndroidX EncryptedSharedPreferences (AES256-GCM) so a plain
 * /data/data/<pkg>/shared_prefs dump is not enough — attacker must
 * also defeat keystore or patch the validator.
 */
object SecurePrefs {
    private const val FILE = "crackme_secure"
    private const val K_TOKEN = "purchase_token"
    private const val K_PRO = "pro_cached"

    private fun prefs(ctx: Context): SharedPreferences {
        return try {
            val masterKey = MasterKey.Builder(ctx)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                ctx, FILE, masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (t: Throwable) {
            // Fallback for CTF emulators without keystore — still functional.
            ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        }
    }

    fun savePurchase(ctx: Context, token: String) {
        prefs(ctx).edit().putString(K_TOKEN, token).putBoolean(K_PRO, true).apply()
    }

    fun getToken(ctx: Context): String? = prefs(ctx).getString(K_TOKEN, null)

    fun clear(ctx: Context) { prefs(ctx).edit().clear().apply() }
}
