package com.ctf.crackme

import android.app.Activity
import android.content.Context
import android.os.SystemClock
import android.util.Log
import com.android.billingclient.api.*
import kotlinx.coroutines.*
import org.json.JSONObject
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * Payment for the PRO tier.
 *
 * Order of attempts:
 *  1. REAL Google Play Billing (BillingClient 9.x, product "pro_lifetime").
 *     Works after YOU create the product in Play Console and install via Play.
 *  2. CTF FALLBACK mock checkout (signed token, same crypto). Used when Play
 *     is unavailable — i.e. the GitHub Actions APK players actually download.
 *
 * There is NO key-entry screen. PRO unlocks only by completing a purchase
 * flow. CTF players must forge/hook/patch the token verification instead.
 */
object BillingManager {
    const val PRICE_LABEL = "\$4.99"

    sealed class PayResult {
        data class Success(val token: String, val viaPlay: Boolean) : PayResult()
        object Cancelled : PayResult()
        data class Failed(val reason: String) : PayResult()
    }

    @Volatile private var client: BillingClient? = null

    private fun getClient(ctx: Context, listener: PurchasesUpdatedListener): BillingClient {
        client?.let { return it }
        val c = BillingClient.newBuilder(ctx)
            .setListener(listener)
            .enablePendingPurchases(
                PendingPurchasesParams.newBuilder().enableOneTimeProducts().build()
            )
            .enableAutoServiceReconnection()
            .build()
        client = c
        return c
    }

    /**
     * @param mockConfirm shown when Play is unavailable: display YOUR mock
     *   checkout UI, call resume(true) to "pay" or resume(false) to cancel.
     */
    fun buyPro(
        activity: Activity,
        scope: CoroutineScope,
        mockConfirm: ((resume: (Boolean) -> Unit) -> Unit)? = null,
        onDone: (PayResult) -> Unit
    ) {
        val listener = PurchasesUpdatedListener { res, purchases ->
            if (res.responseCode == BillingClient.BillingResponseCode.OK && !purchases.isNullOrEmpty()) {
                scope.launch { handlePlayPurchase(activity, purchases.first(), onDone) }
            } else if (res.responseCode == BillingClient.BillingResponseCode.USER_CANCELED) {
                onDone(PayResult.Cancelled)
            } else {
                mockCheckout(activity, mockConfirm, onDone)
            }
        }
        val bc: BillingClient = try { getClient(activity, listener) } catch (t: Throwable) {
            mockCheckout(activity, mockConfirm, onDone); return
        }
        scope.launch(Dispatchers.IO) {
            try {
                if (!connect(bc)) {
                    withContext(Dispatchers.Main) { mockCheckout(activity, mockConfirm, onDone) }
                    return@launch
                }
                // Already owned? Restore without charging again.
                val owned = queryOwned(bc)
                if (owned != null) {
                    withContext(Dispatchers.Main) {
                        scope.launch { handlePlayPurchase(activity, owned, onDone) }
                    }
                    return@launch
                }
                val details = queryPro(bc)
                if (details == null) {
                    withContext(Dispatchers.Main) { mockCheckout(activity, mockConfirm, onDone) }
                    return@launch
                }
                val flowParams = BillingFlowParams.newBuilder().setProductDetailsParamsList(
                    listOf(
                        BillingFlowParams.ProductDetailsParams.newBuilder()
                            .setProductDetails(details).build()
                    )
                ).build()
                withContext(Dispatchers.Main) {
                    val r = bc.launchBillingFlow(activity, flowParams)
                    if (r.responseCode != BillingClient.BillingResponseCode.OK) {
                        mockCheckout(activity, mockConfirm, onDone)
                    }
                    // success continues via listener
                }
            } catch (t: Exception) {
                Log.w("CrackMe", "play billing failed, mock fallback: ${t.message}")
                withContext(Dispatchers.Main) { mockCheckout(activity, mockConfirm, onDone) }
            }
        }
    }

    private suspend fun handlePlayPurchase(ctx: Context, p: Purchase, onDone: (PayResult) -> Unit) {
        try {
            if (p.purchaseState != Purchase.PurchaseState.PURCHASED) {
                onDone(PayResult.Failed("not purchased")); return
            }
            if (!p.isAcknowledged) {
                val bc = client ?: run { onDone(PayResult.Failed("no client")); return }
                val code = acknowledge(bc, p.purchaseToken)
                if (code != BillingClient.BillingResponseCode.OK) {
                    onDone(PayResult.Failed("ack $code")); return
                }
            }
            // Bind Play purchase to our signed entitlement token (server does this in prod).
            val token = mintToken()
            if (ServerVerifier.verify(token)) {
                SecurePrefs.savePurchase(ctx, token)
                onDone(PayResult.Success(token, viaPlay = true))
            } else onDone(PayResult.Failed("server rejected"))
        } catch (t: Exception) {
            onDone(PayResult.Failed(t.message ?: "play error"))
        }
    }

    /** Offline CTF checkout: same HMAC token, no Play needed. */
    private fun mockCheckout(
        activity: Activity,
        mockConfirm: ((resume: (Boolean) -> Unit) -> Unit)?,
        onDone: (PayResult) -> Unit
    ) {
        val pay: (Boolean) -> Unit = { ok ->
            if (!ok) {
                onDone(PayResult.Cancelled)
            } else {
                Thread {
                    SystemClock.sleep(1200)
                    val t = mintToken()
                    activity.runOnUiThread {
                        if (LicenseValidator.isValidToken(t)) {
                            SecurePrefs.savePurchase(activity, t)
                            onDone(PayResult.Success(t, viaPlay = false))
                        } else onDone(PayResult.Failed("issuer check"))
                    }
                }.start()
            }
        }
        if (mockConfirm == null) pay(true) else mockConfirm(pay)
    }

    /** Mints the signed entitlement token (lives server-side in prod). */
    fun mintToken(): String {
        val payload = JSONObject()
            .put("p", BuildConfig.PRO_PRODUCT_ID)
            .put("ts", System.currentTimeMillis() / 1000)
            .put("n", UUID.randomUUID().toString().substring(0, 8))
            .toString().toByteArray()
        val sig = LicenseValidator.hmac(payload, LicenseValidator.purchaseKey())
        return LicenseValidator.b64uEncode(payload) + "." + LicenseValidator.b64uEncode(sig)
    }

    // ---------- BillingClient callback → coroutine bridges ----------

    private suspend fun connect(bc: BillingClient): Boolean =
        suspendCoroutine { cont ->
            bc.startConnection(object : BillingClientStateListener {
                override fun onBillingSetupFinished(r: BillingResult) {
                    cont.resume(r.responseCode == BillingClient.BillingResponseCode.OK)
                }
                override fun onBillingServiceDisconnected() {
                    // auto-reconnect enabled; report failure only if still suspended
                    try { cont.resume(false) } catch (t: Throwable) { }
                }
            })
        }

    private suspend fun queryOwned(bc: BillingClient): Purchase? =
        suspendCoroutine { cont ->
            bc.queryPurchasesAsync(
                QueryPurchasesParams.newBuilder()
                    .setProductType(BillingClient.ProductType.INAPP).build()
            ) { _, list ->
                cont.resume(
                    list.firstOrNull {
                        it.products.contains(BuildConfig.PRO_PRODUCT_ID) &&
                            it.purchaseState == Purchase.PurchaseState.PURCHASED
                    }
                )
            }
        }

    private suspend fun queryPro(bc: BillingClient): ProductDetails? =
        suspendCoroutine { cont ->
            bc.queryProductDetailsAsync(
                QueryProductDetailsParams.newBuilder().setProductList(
                    listOf(
                        QueryProductDetailsParams.Product.newBuilder()
                            .setProductId(BuildConfig.PRO_PRODUCT_ID)
                            .setProductType(BillingClient.ProductType.INAPP).build()
                    )
                ).build()
            ) { res, result ->
                cont.resume(
                    if (res.responseCode == BillingClient.BillingResponseCode.OK) {
                        result.productDetailsList.firstOrNull()
                    } else null
                )
            }
        }

    private suspend fun acknowledge(bc: BillingClient, token: String): Int =
        suspendCoroutine { cont ->
            bc.acknowledgePurchase(
                AcknowledgePurchaseParams.newBuilder().setPurchaseToken(token).build()
            ) { res -> cont.resume(res.responseCode) }
        }
}
