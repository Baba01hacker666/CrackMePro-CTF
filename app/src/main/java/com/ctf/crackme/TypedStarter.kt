package com.ctf.crackme

import android.app.Application
import android.util.Log

/**
 * Typed FreeRASP wiring, isolated so any SDK API drift only touches this file.
 * Verified against TalsecSecurity-Community 19.x docs:
 * Talsec.start(app, config, listener : ThreatListener.ThreatDetected).
 */
internal object TypedStarter {
    fun start(ctx: android.content.Context, onThreat: (String) -> Unit) {
        try {
            val app = ctx as Application
            val config = com.aheaditec.talsec.security.TalsecConfig(
                ctx.packageName,
                // TODO(author): put YOUR release cert SHA-256 here before Play upload.
                signingCertHashes = arrayOf(),
                supportedAlternativeStores = arrayOf(),
                watcherMail = "ctf@example.com"
            )
            com.aheaditec.talsec.security.Talsec.start(
                app, config,
                object : com.aheaditec.talsec.security.ThreatListener.ThreatDetected {
                    override fun onRootDetected() = onThreat("freerasp:root")
                    override fun onHookDetected() = onThreat("freerasp:hook")
                    override fun onEmulatorDetected() = onThreat("freerasp:emulator")
                    override fun onTamperDetected() = onThreat("freerasp:tamper")
                    override fun onDeviceBindingDetected() = onThreat("freerasp:device-binding")
                    override fun onUntrustedInstallationSourceDetected() = onThreat("freerasp:store")
                    override fun onDebuggerDetected() = onThreat("freerasp:debugger")
                    override fun onObfuscationIssuesDetected() = onThreat("freerasp:obfuscation")
                    override fun onMalwareDetected(p0: List<com.aheaditec.talsec.security.SuspiciousAppInfo>?) =
                        onThreat("freerasp:malware")
                    override fun onVPNDetected() = onThreat("freerasp:vpn")
                    override fun onDeveloperModeDetected() = onThreat("freerasp:devmode")
                    override fun onADBEnabledDetected() = onThreat("freerasp:adb")
                    override fun onScreenRecordingDetected() = onThreat("freerasp:screen")
                    override fun onScreenshotDetected() = onThreat("freerasp:screenshot")
                    override fun onMultiInstanceDetected() = onThreat("freerasp:multi-instance")
                    override fun onPasscodeDetected() = onThreat("freerasp:passcode")
                    override fun onSecureHardwareNotAvailableDetected() = onThreat("freerasp:hw")
                    override fun onSystemVPNDetected() = onThreat("freerasp:sysvpn")
                    override fun onTimeSpoofingDetected() = onThreat("freerasp:time")
                    override fun onSimulatorDetected() = onThreat("freerasp:simulator")
                }
            )
        } catch (t: Throwable) {
            Log.w("CrackMe", "FreeRASP typed start skipped: ${t.message}")
        }
    }
}
