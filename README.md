# CrackMePro — paid-tier CrackMe CTF (Android)

Free app, **\$4.99 PRO tier**. The flag lives in the PRO-only **Flag Vault**.
No license-key screen exists — PRO unlocks only by completing a **payment flow**.
Steal it without paying. 😈

Flag format: `CTF{...}`

## Protections (what you must beat)

| Layer | Tech |
|---|---|
| Payment | **Google Play Billing 9.x** (`pro_lifetime` in-app product) + signed entitlement token (HMAC-SHA256, dual Java+native secret) |
| Server hook | Optional `POST /verify` purchase check (`/server/server.py` reference, `BuildConfig.SERVER_URL`; empty = offline CTF mode with local HMAC+native check) |
| Device verdict | **Play Integrity API 1.6** (`PlayIntegrityCheck`) — token request at pay/vault time |
| External RASP | **Talsec FreeRASP Community 19.2.1** — root/Magisk, Frida/Xposed hooks, emulator, debugger, tamper, unofficial store |
| Custom RASP | `RaspManager` — su/Magisk files, `test-keys`, emulator fingerprint, `TracerPid`, Frida port `27042` + `/proc/self/maps` scan, Xposed class + stack scan, debuggable flag |
| Native | `libnative-lib.so` — key half, token shape check, `TracerPid`, package-name anti-repackaging |
| Storage | `EncryptedSharedPreferences` for the purchase token |
| Crypto | AES-256-GCM vault; key = `SHA256(javaHalf + nativeHalf + "\|vault-v1")` — need **both** dex + so |
| Obfuscation | R8 full (`repackageclasses`, aggressive overload, no keeps on security classes) + XOR-obfuscated Java secret half |

## Build (GitHub Actions)

Push to `main` → **Actions → Build CTF APKs** → download `crackme-apks` artifact:

- `app-debug.apk` — playable, unobfuscated, logcat-friendly (start here)
- `app-release.apk` — R8-obfuscated final challenge

Local: `gradle assembleDebug` (needs Android SDK 34 + NDK).

Optional online mode: `gradle assembleRelease -PSERVER_URL=https://your-host/verify`.

## Play Console setup (for REAL money, not needed for CTF)

1. Play Console → create app `com.ctf.crackme` → **Monetize → In-app products** → create `pro_lifetime` ($4.99).
2. Add tester emails, upload this AAB to internal testing, install via Play.
3. Set your GCP project number in `PlayIntegrityCheck.kt`, link Cloud ↔ Play, deploy `/server`.
4. Replace `debug.keystore` signing with your release key + put cert SHA-256 into `FreeRaspManager` config.

## Rules / hints

- Static first (jadx + strings on `libnative-lib.so`), then dynamic (Frida / Objection / reflutter).
- The vault needs **PRO *and* clean RASP** — hooked devices get `RaspBlocked` even with a valid token.
- `HINTS.md` has nudges, `SOLUTION.md` has the author's 3 intended solves. Don't open them. 🙂

## Disclaimer

Test gateway makes **no real charge** in CTF builds. Mock checkout exists only because
sideloaded APKs can't reach Play Billing — a Play-installed build uses genuine Google billing.
