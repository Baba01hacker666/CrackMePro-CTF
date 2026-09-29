package com.ctf.crackme

import android.app.Application
import android.util.Log

/**
 * App entry point. Starts external RASP (Talsec FreeRASP) immediately,
 * then runs our custom RASP checks. CTF players must silence / bypass
 * BOTH layers to use the PRO vault on a rooted/hooked device.
 */
class CrackMeApp : Application() {

    override fun onCreate() {
        super.onCreate()
        try {
            FreeRaspManager.init(this)
        } catch (t: Throwable) {
            Log.w("CrackMe", "freerasp init failed: ${t.message}")
        }
        // Early custom RASP tripwire — no UI here, MainActivity enforces.
        RaspManager.earlyCheck(this)
    }
}
