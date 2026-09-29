#include <jni.h>
#include <string>
#include <fstream>
#include <unistd.h>

// Split secret: native half NEVER appears in classes.dex.
// (Java half is XOR-obfuscated in LicenseValidator.)
static const char* K_PART = "N4t1v3_S3cr3t_p4rt_9xQ2";
static const char* EXPECT_PKG = "com.ctf.crackme";

extern "C" {

// ---- key part ----
JNIEXPORT jstring JNICALL
Java_com_ctf_crackme_NativeBridge_getKeyPart(JNIEnv* env, jobject) {
    // tiny runtime assembly to annoy `strings` (still recoverable via Frida/ghidra = intended)
    std::string s;
    for (const char* p = K_PART; *p; ++p) s.push_back(*p ^ 0x00);
    return env->NewStringUTF(s.c_str());
}

// ---- HMAC re-verify lives in Java; here we sanity-check token shape + package ----
// Full HMAC in C would need OpenSSL; instead native gates on structure + pkg + tracer,
// while Java gates on HMAC. Both must pass => attacker patches TWO places.
JNIEXPORT jint JNICALL
Java_com_ctf_crackme_NativeBridge_verifyTokenNative(JNIEnv* env, jobject, jstring token) {
    if (!token) return 0;
    const char* c = env->GetStringUTFChars(token, nullptr);
    std::string t(c ? c : "");
    if (c) env->ReleaseStringUTFChars(token, c);
    auto dot = t.find('.');
    if (dot == std::string::npos || dot < 10 || t.size() - dot < 10) return 0;
    if (t.find("pro_lifetime") == std::string::npos) {
        // payload is base64url; decode-free heuristic: token must be reasonably long
        if (t.size() < 40) return 0;
    }
    return 1;
}

// ---- TracerPid anti-debug ----
JNIEXPORT jint JNICALL
Java_com_ctf_crackme_NativeBridge_isTracedNative(JNIEnv*, jobject) {
    std::ifstream f("/proc/self/status");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            int pid = 0;
            sscanf(line.c_str() + 10, "%d", &pid);
            return pid != 0 ? 1 : 0;
        }
    }
    return 0;
}

// ---- package-name anti-repackaging ----
JNIEXPORT jint JNICALL
Java_com_ctf_crackme_NativeBridge_checkPackageNative(JNIEnv* env, jobject, jstring pkg) {
    if (!pkg) return 0;
    const char* c = env->GetStringUTFChars(pkg, nullptr);
    std::string p(c ? c : "");
    if (c) env->ReleaseStringUTFChars(pkg, c);
    if (p == EXPECT_PKG) return 1;
    if (p.rfind(EXPECT_PKG, 0) == 0 && p.size() > strlen(EXPECT_PKG) && p[strlen(EXPECT_PKG)] == '.') return 1; // .debug suffix ok
    return 0;
}
}
