package com.ctf.crackme

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Server-side purchase verification hook.
 *
 * If BuildConfig.SERVER_URL is set (e.g. CI -PSERVER_URL=https://...),
 * the purchase token is POSTed to your server which must reply
 * {"ok":true} after verifying the HMAC (and Play purchase via
 * Developer API for real-money builds). See /server/server.py reference.
 *
 * Empty SERVER_URL = offline CTF mode: verify locally (still HMAC +
 * native dual-check, so not trivially patchable with one edit).
 */
object ServerVerifier {

    suspend fun verify(token: String): Boolean = withContext(Dispatchers.IO) {
        val url = try { BuildConfig.SERVER_URL } catch (t: Throwable) { "" }
        if (url.isBlank()) {
            // offline CTF fallback
            return@withContext LicenseValidator.isValidToken(token)
        }
        try {
            val c = (URL(url).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = 8000; readTimeout = 8000
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
            }
            c.outputStream.use { it.write(JSONObject().put("token", token).toString().toByteArray()) }
            val code = c.responseCode
            val body = try { c.inputStream.bufferedReader().readText() } catch (t: Throwable) { "" }
            Log.d("CrackMe", "server verify $code $body")
            code == 200 && JSONObject(body).optBoolean("ok", false)
        } catch (t: Exception) {
            Log.w("CrackMe", "server unreachable, local fallback: ${t.message}")
            LicenseValidator.isValidToken(token)
        }
    }
}
