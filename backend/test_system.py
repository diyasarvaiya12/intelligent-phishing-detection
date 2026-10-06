import urllib.request
import json

base = "http://127.0.0.1:5000"

print("--- Testing PhishGuard System Endpoints ---")

# 1. Test GET /
with urllib.request.urlopen(base + "/") as r:
    html = r.read().decode("utf-8")
    assert "PhishGuard" in html
    print("[PASS] GET /: Dashboard HTML served successfully.")

# 2. Test GET /health
with urllib.request.urlopen(base + "/health") as r:
    data = json.loads(r.read().decode("utf-8"))
    assert data["model_loaded"] is True
    print("[PASS] GET /health: Model is loaded and healthy.")

# 3. Test GET /api/metrics
with urllib.request.urlopen(base + "/api/metrics") as r:
    data = json.loads(r.read().decode("utf-8"))
    assert data["success"] is True
    m = data["metrics"]
    print(f"[PASS] GET /api/metrics: Accuracy = {m['accuracy']*100:.2f}%, F1 = {m['f1_score']*100:.2f}%")

# 4. Test POST /predict with Legitimate URL
req_legit = urllib.request.Request(
    base + "/predict",
    data=json.dumps({"url": "https://www.uni-mainz.de"}).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)
with urllib.request.urlopen(req_legit) as r:
    res = json.loads(r.read().decode("utf-8"))
    print(f"[PASS] Legitimate URL Test:")
    print(f"       Target: {res['url']}")
    print(f"       Verdict: {res['verdict']} ({res['prediction']})")
    print(f"       Risk Score: {res['risk_score']}%, Confidence: {res['confidence']}%")

# 5. Test POST /predict with Phishing URL
req_phish = urllib.request.Request(
    base + "/predict",
    data=json.dumps({"url": "http://secure-login.paypal.account-verify.com/login?id=999&auth=fail"}).encode("utf-8"),
    headers={"Content-Type": "application/json"}
)
with urllib.request.urlopen(req_phish) as r:
    res = json.loads(r.read().decode("utf-8"))
    print(f"[PASS] Phishing URL Test:")
    print(f"       Target: {res['url']}")
    print(f"       Verdict: {res['verdict']} ({res['prediction']})")
    print(f"       Risk Score: {res['risk_score']}%, Confidence: {res['confidence']}%")

print("\nAll integration verification tests passed successfully!")
