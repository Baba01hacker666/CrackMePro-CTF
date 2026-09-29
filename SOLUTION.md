# Author solution (spoilers!)

Flag: `CTF{buy_p4ss_but_pwn3d_4nyw4y_2026}`

## Solve A — Frida bypass (intended, ~10 min)
```js
Java.perform(function () {
  var LV = Java.use("com.ctf.crackme.LicenseValidator"); // obfuscated in release; enumerate
  LV.isValidToken.implementation = function () { return true; };
  var NB = Java.use("com.ctf.crackme.NativeBridge");
  NB.verifyTokenNative.implementation = function () { return 1; };
  NB.isTracedNative.implementation = function () { return 0; };
  var RM = Java.use("com.ctf.crackme.RaspManager");
  // release build renames methods — hook by signature or patch smali instead
});
```
Then tap "Open PRO Vault". (Also silence FreeRASP via airplane/hook if it trips.)

## Solve B — forge a token offline (~20 min)
1. `jadx` → deobfuscate `LicenseValidator.javaPart()` (XOR 0x5A) → `J4v4_0bfusc4t3d_p4rt_7mK5`.
2. `strings libnative-lib.so` → `N4t1v3_S3cr3t_p4rt_9xQ2`.
3. `key = sha256(java + native + "|purchase")`; craft `{"p":"pro_lifetime","ts":...,"n":"abcd1234"}`,
   HMAC-SHA256, `b64u(payload).b64u(sig)`; `adb shell` write into EncryptedSharedPreferences
   or call `SecurePrefs.savePurchase` via Frida; open vault on clean emulator.

## Solve C — patch APK (~15 min)
1. `apktool d app-release.apk`; smali-patch `CryptoVault.open` RASP/license branches to always decrypt,
   or patch `isPro` → `true`.
2. Rebuild, re-sign with own key (native pkg check allows `.debug` suffix; for release, also patch
   `checkPackageNative` → return 1), install, open vault.

All three prove the point: client-side payment gates + RASP raise the bar but never replace
server-side verification (Play Developer API + Integrity verdict decryption on YOUR backend).
