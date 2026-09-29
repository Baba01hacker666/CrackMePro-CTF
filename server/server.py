"""Reference purchase-verification server for CrackMePro CTF.

Real-money builds MUST verify purchases server-side:
  1. Verify our HMAC entitlement token (offline-forgable, so check it here
     with the shared secret instead of trusting the client).
  2. (Prod) Verify the Google Play purchase via Developer API
     Purchases.products.get + check acknowledgement.

Run:  pip install flask && python server.py
Deploy anywhere, then build the app with:
  gradle assembleRelease -PSERVER_URL=https://your-host/verify
"""
import hashlib, hmac, base64, json
from flask import Flask, request, jsonify

JAVA_PART = "J4v4_0bfusc4t3d_p4rt_7mK5"
NATIVE_PART = "N4t1v3_S3cr3t_p4rt_9xQ2"
PURCHASE_KEY = hashlib.sha256((JAVA_PART + NATIVE_PART + "|purchase").encode()).digest()

app = Flask(__name__)

def b64u_decode(s: str) -> bytes:
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)

@app.post("/verify")
def verify():
    data = request.get_json(force=True, silent=True) or {}
    token = data.get("token", "")
    try:
        payload_b64, sig_b64 = token.split(".")
        payload = b64u_decode(payload_b64)
        sig = b64u_decode(sig_b64)
        expect = hmac.new(PURCHASE_KEY, payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expect):
            return jsonify(ok=False, reason="bad hmac"), 200
        body = json.loads(payload)
        if body.get("p") != "pro_lifetime":
            return jsonify(ok=False, reason="bad product"), 200
        # TODO(prod): call Play Developer API here with the Play purchaseToken.
        return jsonify(ok=True), 200
    except Exception as e:
        return jsonify(ok=False, reason=str(e)), 200

@app.get("/")
def index():
    return "CrackMePro verifier alive. POST /verify {token}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
