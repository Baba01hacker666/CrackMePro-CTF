# CrackMePro R8 / ProGuard — maximize obfuscation for CTF hardness
-optimizationpasses 5
-allowaccessmodification
-repackageclasses 'a.a.a'
-overloadaggressively
-dontpreverify

# Keep Android entry points only
-keep public class com.ctf.crackme.MainActivity { *; }
-keep public class com.ctf.crackme.CrackMeApp { *; }
-keepclasseswithmembernames class * {
    native <methods>;
}
-keepclassmembers class * {
    native <methods>;
}
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# Do NOT keep security internals — force them to be obfuscated
# (RaspManager, LicenseValidator, CryptoVault, NativeBridge all get renamed)

# FreeRASP keep rules (required by SDK)
-keep class com.aheaditec.talsec.security.** { *; }
-dontwarn com.aheaditec.talsec.security.**
