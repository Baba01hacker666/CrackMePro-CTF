package com.ctf.crackme

/**
 * JNI bridge. Part of the purchase secret + verification lives here so
 * simple dex decompilation (jadx) is not enough — attacker must also
 * read libnative-lib.so (strings / ghidra / frida hook).
 */
object NativeBridge {
    init {
        try { System.loadLibrary("native-lib") } catch (t: Throwable) { /* CTF emu without NDK abi */ }
    }

    /** Second half of the HMAC secret. Never appears in dex. */
    external fun getKeyPart(): String

    /** Native-side re-verification of the purchase token. 1 = ok. */
    external fun verifyTokenNative(token: String): Int

    /** Native anti-debug: returns 1 if TracerPid != 0 (being ptraced). */
    external fun isTracedNative(): Int

    /** Native package-name check (anti-repackaging). 1 = ok. */
    external fun checkPackageNative(pkg: String): Int

    // ---- Java fallbacks (used only if .so missing; weaker) ----
    fun getKeyPartFallback(): String = "N4t1v3_S3cr3t_p4rt_9xQ2"

    fun safeGetKeyPart(): String = try { getKeyPart() } catch (t: Throwable) { getKeyPartFallback() }
    fun safeVerify(token: String): Boolean = try { verifyTokenNative(token) == 1 } catch (t: Throwable) { false }
    fun safeTraced(): Boolean = try { isTracedNative() == 1 } catch (t: Throwable) { false }
}
