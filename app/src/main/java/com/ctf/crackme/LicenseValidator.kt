package com.ctf.crackme

import android.util.Base64
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Paid-tier gate. There is NO license-key input anywhere in the app —
 * PRO unlocks only via [BillingManager.payForPro], which mints a signed
 * purchase token. This validator verifies that token.
 *
 * Token format:  base64url(payloadJson) + "." + base64url(hmacSha256(payload, key))
 * payloadJson : {"p":"pro_lifetime","ts":<epoch>,"n":"<nonce>"}
 *
 * Key = SHA256hex(JAVA_PART + nativePart + "|purchase") used as HMAC key bytes.
 * Verification happens in BOTH Java and native (defense in depth).
 */
object LicenseValidator {
    const val PRODUCT_PRO = "pro_lifetime"

    // Obfuscated java half — XOR'd so it never appears as a plain string in dex.
    private val OBF = byteArrayOf(
        0x10.toByte(), 0x6e.toByte(), 0x2c.toByte(), 0x6e.toByte(), 0x05.toByte(),
        0x6a.toByte(), 0x38.toByte(), 0x3c.toByte(), 0x2f.toByte(), 0x29.toByte(),
        0x39.toByte(), 0x6e.toByte(), 0x2e.toByte(), 0x69.toByte(), 0x3e.toByte(),
        0x05.toByte(), 0x2a.toByte(), 0x6e.toByte(), 0x28.toByte(), 0x2e.toByte(),
        0x05.toByte(), 0x6d.toByte(), 0x37.toByte(), 0x11.toByte(), 0x6f.toByte()
    )
    private const val XOR = 0x5A

    fun javaPart(): String {
        val out = ByteArray(OBF.size)
        for (i in OBF.indices) out[i] = (OBF[i].toInt() xor XOR).toByte()
        return String(out) // == "J4v4_0bfusc4t3d_p4rt_7mK5"
    }

    fun purchaseKey(): ByteArray {
        val full = javaPart() + NativeBridge.safeGetKeyPart() + "|purchase"
        return java.security.MessageDigest.getInstance("SHA-256")
            .digest(full.toByteArray())
    }

    fun hmac(data: ByteArray, key: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun b64uEncode(b: ByteArray): String =
        Base64.encodeToString(b, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    fun b64uDecode(s: String): ByteArray =
        Base64.decode(s, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

    /** Full verification: structure + HMAC + product + native re-check. */
    fun isValidToken(token: String): Boolean {
        try {
            val parts = token.split(".")
            if (parts.size != 2) return false
            val payload = b64uDecode(parts[0])
            val sig = b64uDecode(parts[1])
            val expect = hmac(payload, purchaseKey())
            if (!java.security.MessageDigest.isEqual(sig, expect)) return false
            val json = String(payload)
            if (!json.contains("\"p\":\"$PRODUCT_PRO\"")) return false
            // Native must agree (kills pure-Java patch bypass unless native also patched).
            if (!NativeBridge.safeVerify(token)) return false
            return true
        } catch (t: Throwable) {
            return false
        }
    }

    fun isPro(ctx: android.content.Context): Boolean {
        val t = SecurePrefs.getToken(ctx) ?: return false
        return isValidToken(t)
    }
}
