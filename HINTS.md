# Hints (progressive)

1. There is no key input. The token is minted at payment time — find `mintToken` / `BillingManager`.
2. The HMAC key is split: one half XORed in dex, one half in `libnative-lib.so`. You need both.
3. `jadx-gui` on `app-release.apk` + `strings` on `lib/arm64-v8a/libnative-lib.so` reveals a lot.
4. Dynamic is easier: Frida-hook `LicenseValidator.isValidToken` or `NativeBridge.verifyTokenNative` to always return true.
5. RASP blocks hooked devices: hook `RaspManager` checks too, or patch the vault gate. Check `CryptoVault.open` order: RASP → license → decrypt.
6. Easiest CTF path: call `BillingManager.mintToken()` via Frida and `SecurePrefs.savePurchase`, then open the vault on a clean (unrooted, no Frida) device profile.
7. The vault key is `SHA256(javaHalf + nativeHalf + "|vault-v1")` — reimplement `AES/GCM` decrypt offline once you have both halves.
