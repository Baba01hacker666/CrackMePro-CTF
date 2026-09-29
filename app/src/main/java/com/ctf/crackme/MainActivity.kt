package com.ctf.crackme

import android.os.Bundle
import android.view.View
import android.widget.*
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * CrackMePro — free app with a $4.99 PRO tier.
 *
 * Free:  status screen, RASP self-test.
 * PRO (paid): Flag Vault decrypts the CTF flag.
 *
 * Payment = Google Play Billing if available, else built-in mock checkout
 * (same signed-token crypto) so the GitHub APK is playable offline.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var raspText: TextView
    private lateinit var flagText: TextView
    private lateinit var buyBtn: Button
    private lateinit var vaultBtn: Button
    private lateinit var checkBtn: Button
    private lateinit var progress: ProgressBar

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        statusText = findViewById(R.id.statusText)
        raspText = findViewById(R.id.raspText)
        flagText = findViewById(R.id.flagText)
        buyBtn = findViewById(R.id.buyBtn)
        vaultBtn = findViewById(R.id.vaultBtn)
        checkBtn = findViewById(R.id.checkBtn)
        progress = findViewById(R.id.progress)

        refreshStatus()

        buyBtn.setOnClickListener { startPurchase() }
        vaultBtn.setOnClickListener { openVault() }
        checkBtn.setOnClickListener { runRaspTest() }
    }

    override fun onResume() { super.onResume(); refreshStatus() }

    private fun refreshStatus() {
        val pro = LicenseValidator.isPro(this)
        statusText.text = if (pro) "Status: PRO LIFETIME ✓" else "Status: FREE — Vault locked"
        buyBtn.isEnabled = !pro
        buyBtn.text = if (pro) "PRO ACTIVE" else "Upgrade to PRO — ${BillingManager.PRICE_LABEL} (Play)"
    }

    private fun startPurchase() {
        // Pre-flight: RASP + Integrity (server decides in prod; here advisory).
        lifecycleScope.launch {
            toast("Contacting Play…")
            BillingManager.buyPro(
                activity = this@MainActivity,
                scope = this,
                mockConfirm = { resume -> showMockCheckout(resume) },
                onDone = { res ->
                    when (res) {
                        is BillingManager.PayResult.Success ->
                            toast(if (res.viaPlay) "Play purchase OK — PRO unlocked!" else "Payment OK (test checkout) — PRO unlocked!");
                        is BillingManager.PayResult.Cancelled -> toast("Payment cancelled")
                        is BillingManager.PayResult.Failed -> toast("Payment failed: ${res.reason}")
                    }
                    refreshStatus()
                }
            )
        }
    }

    /** Mock payment sheet — only shown when Play Billing is unreachable (CTF APK). */
    private fun showMockCheckout(resume: (Boolean) -> Unit) {
        val v = layoutInflater.inflate(R.layout.dialog_checkout, null)
        v.findViewById<TextView>(R.id.priceText).text =
            "PRO Lifetime — ${BillingManager.PRICE_LABEL} (test gateway, no real charge)"
        AlertDialog.Builder(this)
            .setTitle("Checkout")
            .setView(v)
            .setNegativeButton("Cancel") { d, _ -> d.dismiss(); resume(false) }
            .setPositiveButton("Pay ${BillingManager.PRICE_LABEL}") { d, _ -> d.dismiss(); resume(true) }
            .setOnCancelListener { resume(false) }
            .show()
    }

    private fun openVault() {
        progress.visibility = View.VISIBLE
        flagText.text = ""
        lifecycleScope.launch(Dispatchers.IO) {
            // Optional server re-verify when SERVER_URL configured.
            val token = SecurePrefs.getToken(this@MainActivity)
            if (token != null && BuildConfig.SERVER_URL.isNotBlank()) {
                if (!ServerVerifier.verify(token)) {
                    withContext(Dispatchers.Main) {
                        progress.visibility = View.GONE
                        flagText.text = "⛔ Server rejected purchase."
                    }
                    return@launch
                }
            }
            val r = CryptoVault.open(this@MainActivity)
            withContext(Dispatchers.Main) {
                progress.visibility = View.GONE
                flagText.text = when (r) {
                    is CryptoVault.VaultResult.Flag -> "🚩 ${r.text}"
                    is CryptoVault.VaultResult.Locked -> "🔒 PRO required — complete payment first."
                    is CryptoVault.VaultResult.RaspBlocked -> "🛡️ RASP blocked this device (root/hook/emu/debug). Bypass it first."
                    is CryptoVault.VaultResult.Error -> "Error: ${r.msg}"
                }
                refreshStatus()
            }
        }
    }

    private fun runRaspTest() {
        val v = RaspManager.fullCheck(this)
        val free = FreeRaspManager.lastThreat
        raspText.text = if (v.tripped)
            "⚠️ TRIPPED: ${v.reasons.joinToString()}${free?.let { " | $it" } ?: ""}"
        else
            "✅ Clean${free?.let { " (freerasp: $it)" } ?: " (no threats)"}"
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_SHORT).show()
}
