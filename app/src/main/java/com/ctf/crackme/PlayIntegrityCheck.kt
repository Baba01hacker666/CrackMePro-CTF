package com.ctf.crackme

import android.app.Activity
import android.util.Log
import com.google.android.play.integrity.IntegrityManagerFactory
import kotlinx.coroutines.tasks.await
import java.util.UUID

/**
 * Google Play Integrity verdict (external protection #2).
 * Classic request with a nonce. Offline / sideloaded CTF builds
 * gracefully return null (API unavailable) so the challenge still runs —
 * a real Play-installed build is expected to obtain a token, whose
 * verdict your SERVER decrypts via Google's API.
 */
object PlayIntegrityCheck {

    /** @return true = got token, false = failed, null = unavailable (offline CTF). */
    suspend fun deviceGenuine(activity: Activity, nonce: String? = null): Boolean? {
        return try {
            val mgr = IntegrityManagerFactory.create(activity)
            val req = com.google.android.play.integrity.IntegrityTokenRequest.builder()
                .setNonce(nonce ?: UUID.randomUUID().toString())
                .build()
            val resp = mgr.requestIntegrityToken(req).await()
            Log.d("CrackMe", "integrity token len=${resp.token().length}")
            true
        } catch (t: Exception) {
            Log.w("CrackMe", "integrity unavailable (offline CTF mode): ${t.message}")
            null
        }
    }
}
