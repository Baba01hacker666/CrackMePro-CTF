package com.ctf.crackme

import android.content.Context
import android.util.Log

/**
 * External RASP #1: Talsec FreeRASP Community.
 * Catches root/Magisk, Frida/Xposed hooks, emulator, debugger, tamper,
 * repackaging, unofficial store. Runs alongside our custom RaspManager
 * and Play Integrity so a player must bypass THREE independent stacks.
 *
 * Fully reflective on purpose: never breaks compilation against any
 * FreeRASP version, and the app still boots/plays when the SDK is absent
 * (custom RASP + native gates remain). If the player strips the SDK to
 * silence it, LicenseValidator's native dual-check still gates the vault.
 */
object FreeRaspManager {
    @Volatile var lastThreat: String? = null
        private set

    fun init(ctx: Context) {
        try {
            Class.forName("app.talsec.rasp.security.api.Talsec")
            Log.d("CrackMe", "FreeRASP SDK present — wiring via typed helper")
            TypedStarter.start(ctx) { hit(it) }
        } catch (t: Throwable) {
            Log.w("CrackMe", "FreeRASP absent/incompatible, custom RASP still active: ${t.message}")
        }
    }

    internal fun hit(s: String) {
        lastThreat = s
        Log.w("CrackMe", "threat: $s")
    }
}
