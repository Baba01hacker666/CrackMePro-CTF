package com.ctf.crackme

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import android.os.Debug
import android.util.Log
import java.io.File

/**
 * Custom (in-house) RASP layer — complements FreeRASP + Play Integrity.
 * Each check is intentionally simple to read for the CTF author, but
 * together they force the player to deal with: root, emulator, debugger,
 * Frida, Xposed, repackaging and hook frameworks.
 */
object RaspManager {
    data class Verdict(val tripped: Boolean, val reasons: List<String>)

    fun earlyCheck(ctx: Context) {
        // No UI — just warm up native lib so attacker can't lazy-load bypass.
        try { NativeBridge.safeGetKeyPart() } catch (t: Throwable) { }
    }

    fun fullCheck(ctx: Context): Verdict {
        val reasons = mutableListOf<String>()
        if (isRooted()) reasons += "root"
        if (isEmulator()) reasons += "emulator"
        if (isDebugged()) reasons += "debugger"
        if (hasFrida()) reasons += "frida"
        if (hasXposed()) reasons += "xposed"
        if (isRepackaged(ctx)) reasons += "tamper"
        if (NativeBridge.safeTraced()) reasons += "ptrace"
        if (NativeBridge.checkPkg(ctx.packageName) == false) reasons += "pkg-native"
        return Verdict(reasons.isNotEmpty(), reasons)
    }

    fun isRooted(): Boolean {
        val tags = Build.TAGS
        if (tags != null && tags.contains("test-keys")) return true
        val paths = arrayOf(
            "/system/app/Superuser.apk", "/system/xbin/su", "/system/bin/su",
            "/sbin/su", "/data/local/xbin/su", "/data/local/bin/su",
            "/system/sd/xbin/su", "/data/local/su",
            "/sbin/.magisk", "/system/bin/.magisk",
            "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap"
        )
        if (paths.any { File(it).exists() }) return true
        try {
            Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su")).inputStream
                .bufferedReader().readText().let { if (it.contains("su")) return true }
        } catch (t: Throwable) { }
        return false
    }

    fun isEmulator(): Boolean {
        val fp = Build.FINGERPRINT ?: ""
        if (fp.startsWith("generic") || fp.contains("vbox") || fp.contains("test-keys")) return true
        val model = (Build.MODEL ?: "") + " " + (Build.MANUFACTURER ?: "") + " " + (Build.PRODUCT ?: "")
        val keys = arrayOf("google_sdk", "Emulator", "Android SDK built for x86", "Genymotion", "generic")
        if (keys.any { model.contains(it, true) }) return true
        if (File("/dev/socket/qemud").exists() || File("/dev/qemu_pipe").exists()) return true
        return false
    }

    fun isDebugged(): Boolean {
        if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) return true
        // TracerPid check — catches gdb/lldb/frida-gadget ptrace even without JDWP.
        try {
            File("/proc/self/status").readLines().forEach {
                if (it.startsWith("TracerPid:")) {
                    val pid = it.substringAfter(":").trim().toIntOrNull() ?: 0
                    if (pid != 0) return true
                }
            }
        } catch (t: Throwable) { }
        return false
    }

    fun hasFrida(): Boolean {
        // 1. default Frida server port
        try {
            java.net.Socket().use { s ->
                s.connect(java.net.InetSocketAddress("127.0.0.1", 27042), 300)
                return true // something listening = frida-server likely
            }
        } catch (t: Throwable) { }
        // 2. frida libs / files in memory maps
        try {
            File("/proc/self/maps").readLines().forEach {
                val l = it.lowercase()
                if (l.contains("frida") || l.contains("gadget") || l.contains("linjector")) return true
            }
        } catch (t: Throwable) { }
        // 3. named pipes / files
        if (File("/data/local/tmp/frida-server").exists() ||
            File("/data/local/tmp/re.frida.server").exists()) return true
        // 4. loaded classes
        try {
            Class.forName("com.frida.server"); return true
        } catch (t: Throwable) { }
        return false
    }

    fun hasXposed(): Boolean {
        try {
            Class.forName("de.robv.android.xposed.XposedBridge"); return true
        } catch (t: Throwable) { }
        try {
            Class.forName("de.robv.android.xposed.XC_MethodHook"); return true
        } catch (t: Throwable) { }
        // stack-trace scan catches LSPosed / EdXposed hooks
        try {
            throw Exception()
        } catch (e: Exception) {
            e.stackTrace.forEach {
                val c = it.className.lowercase()
                if (c.contains("xposed") || c.contains("lsposed") || c.contains("edxp") ||
                    c.contains("substrate") || c.contains("riru") || c.contains("zygisk")) return true
            }
        }
        if (File("/system/framework/XposedBridge.jar").exists()) return true
        return false
    }

    fun isRepackaged(ctx: Context): Boolean {
        // installer check — sideloaded FOSS builds report null; Play builds report vending.
        // For CTF we only hard-fail when native check fails (below), this is advisory.
        try {
            val pm = ctx.packageManager
            val installer = if (Build.VERSION.SDK_INT >= 30) {
                pm.getInstallSourceInfo(ctx.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION") pm.getInstallerPackageName(ctx.packageName)
            }
            Log.d("CrackMe", "installer=$installer")
        } catch (t: Throwable) { }
        // debuggable flag must never ship
        if ((ctx.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0) return true
        return false
    }
}

/** Native package check wrapper with graceful fallback. */
fun NativeBridge.checkPkg(pkg: String): Boolean? = try {
    when (checkPackageNative(pkg)) { 1 -> true; 0 -> false; else -> null }
} catch (t: Throwable) { null }
