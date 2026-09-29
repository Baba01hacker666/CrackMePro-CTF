package com.ctf.crackme

import android.app.Application
import android.util.Log
import app.talsec.rasp.security.api.SuspiciousAppInfo
import app.talsec.rasp.security.api.Talsec
import app.talsec.rasp.security.api.TalsecConfig
import app.talsec.rasp.security.api.TalsecMode
import app.talsec.rasp.security.api.ThreatListener

/**
 * Typed FreeRASP wiring (TalsecSecurity-Community 19.x API), isolated so any
 * SDK API drift only touches this file.
 * Docs: https://docs.talsec.app/freerasp/freerasp/integration/android
 */
internal object TypedStarter {
    fun start(ctx: android.content.Context, onThreat: (String) -> Unit) {
        try {
            val app = ctx as Application
            val config = TalsecConfig.Builder(
                ctx.packageName,
                // TODO(author): put YOUR release cert SHA-256 (base64) here before Play upload.
                arrayOf()
            )
                .watcherMail("ctf@example.com")
                .supportedAlternativeStores(arrayOf())
                .prod(false)
                .build()

            val threats = object : ThreatListener.ThreatDetected() {
                override fun onPrivilegedAccess() = onThreat("freerasp:privileged-access")
                override fun onDebug() = onThreat("freerasp:debug")
                override fun onSimulator() = onThreat("freerasp:simulator")
                override fun onAppIntegrity() = onThreat("freerasp:integrity")
                override fun onUnofficialStore() = onThreat("freerasp:store")
                override fun onHooks() = onThreat("freerasp:hooks")
                override fun onDeviceBinding() = onThreat("freerasp:device-binding")
                override fun onObfuscationIssues() = onThreat("freerasp:obfuscation")
                override fun onScreenshot() = onThreat("freerasp:screenshot")
                override fun onScreenRecording() = onThreat("freerasp:screen-recording")
                override fun onMultiInstance() = onThreat("freerasp:multi-instance")
                override fun onUnsecureWifi() = onThreat("freerasp:wifi")
                override fun onTimeSpoofing() = onThreat("freerasp:time")
                override fun onLocationSpoofing() = onThreat("freerasp:location")
                override fun onAutomation() = onThreat("freerasp:automation")
                override fun onBootloader() = onThreat("freerasp:bootloader")
                override fun onMalware(packageInfo: List<SuspiciousAppInfo>) =
                    onThreat("freerasp:malware")
            }
            ThreatListener(threats).registerListener(app)
            Talsec.start(app, config, TalsecMode.BACKGROUND)
        } catch (t: Throwable) {
            Log.w("CrackMe", "FreeRASP typed start skipped: ${t.message}")
        }
    }
}
