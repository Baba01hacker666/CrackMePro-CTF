package com.ctf.crackme

import android.content.Context
import android.util.Base64
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * PRO-only Flag Vault. AES-256-GCM ciphertext is bundled, but the key is
 * derived from the SAME secret as purchases, so dumping the .so or dex
 * alone is insufficient — you need both halves.
 *
 * gated by LicenseValidator.isPro() first (payment check), then decrypt.
 */
object CryptoVault {
    // AES-GCM("CTF{buy_p4ss_but_pwn3d_4nyw4y_2026}") with key=SHA256(FULL+"|vault-v1"), iv below.
    private const val CT_B64 = "0o5UsCF+pwuRITRdMXfeFbE85gw6bI8qT5SptRmV4aLcSNZCMobiLvmQoEBMgWj+vWag"
    private const val IV_B64 = "Q1JLTUVQUjBJVjEy" // "CRKMEPR0IV12"

    sealed class VaultResult {
        data class Flag(val text: String) : VaultResult()
        object Locked : VaultResult()       // not PRO
        object RaspBlocked : VaultResult()  // RASP tripped
        data class Error(val msg: String) : VaultResult()
    }

    private fun vaultKey(): ByteArray {
        val full = LicenseValidator.javaPart() + NativeBridge.safeGetKeyPart() + "|vault-v1"
        return MessageDigest.getInstance("SHA-256").digest(full.toByteArray())
    }

    fun open(ctx: Context): VaultResult {
        // 1. RASP gate — rooted/hooked/emulator devices blocked even if PRO.
        val rasp = RaspManager.fullCheck(ctx)
        if (rasp.tripped) return VaultResult.RaspBlocked
        // 2. Payment gate.
        if (!LicenseValidator.isPro(ctx)) return VaultResult.Locked
        // 3. Decrypt.
        return try {
            val key = vaultKey()
            val iv = Base64.decode(IV_B64, Base64.DEFAULT)
            val ct = Base64.decode(CT_B64, Base64.DEFAULT)
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            VaultResult.Flag(String(c.doFinal(ct)))
        } catch (t: Throwable) {
            VaultResult.Error("decrypt failed: ${t.message}")
        }
    }
}
