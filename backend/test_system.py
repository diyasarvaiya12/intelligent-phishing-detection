import json
import sys
import os

# Ensure backend directory is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CURRENT_DIR)

from app import app

client = app.test_client()

print("=" * 60)
print(" RUNNING PHISHGUARD SYSTEM VERIFICATION TESTS")
print("=" * 60)

# 1. Test GET /
r_index = client.get("/")
assert r_index.status_code == 200, f"Expected 200, got {r_index.status_code}"
assert b"PhishGuard" in r_index.data
print("[PASS] GET / : Dashboard HTML served successfully.")

# 2. Test GET /health
r_health = client.get("/health")
assert r_health.status_code == 200
data_health = r_health.get_json()
assert data_health["model_loaded"] is True
assert data_health["features_count"] == 17
print("[PASS] GET /health : Model is loaded and healthy with 17 features.")

# 3. Test GET /api/metrics
r_metrics = client.get("/api/metrics")
assert r_metrics.status_code == 200
data_metrics = r_metrics.get_json()
assert data_metrics["success"] is True
m = data_metrics["metrics"]
assert m["accuracy"] >= 0.95
print(f"[PASS] GET /api/metrics : Accuracy = {m['accuracy']*100:.2f}%, F1 = {m['f1_score']*100:.2f}%, Engine = {m.get('engine', 'N/A')}")

# 4. Test Legitimate URLs
legit_test_cases = [
    "https://www.uni-mainz.de",
    "google.com",
    "https://github.com",
    "wikipedia.org",
    "https://www.youtube.com"
]

for url in legit_test_cases:
    resp = client.post("/predict", json={"url": url})
    assert resp.status_code == 200, f"Failed on {url}"
    res = resp.get_json()
    assert res["success"] is True
    assert res["verdict"] == "legitimate", f"Expected legitimate for {url}, got {res['verdict']} (risk: {res['risk_score']}%)"
    assert res["risk_score"] < 40.0, f"Expected risk < 40% for {url}, got {res['risk_score']}%"
    print(f"[PASS] Legitimate URL : {url:30} -> Verdict: {res['verdict']} (Risk: {res['risk_score']}%, Conf: {res['confidence']}%)")

# 5. Test Phishing URLs
phish_test_cases = [
    "http://secure-login.paypal.account-verify.com/login?id=999&auth=fail",
    "http://www.teramill.com",
    "http://192.168.1.1/admin-login",
    "http://www.ooguy.com"
]

for url in phish_test_cases:
    resp = client.post("/predict", json={"url": url})
    assert resp.status_code == 200, f"Failed on {url}"
    res = resp.get_json()
    assert res["success"] is True
    assert res["verdict"] == "phishing", f"Expected phishing for {url}, got {res['verdict']} (risk: {res['risk_score']}%)"
    assert res["risk_score"] > 60.0, f"Expected risk > 60% for {url}, got {res['risk_score']}%"
    print(f"[PASS] Phishing URL   : {url:68} -> Verdict: {res['verdict']} (Risk: {res['risk_score']}%, Conf: {res['confidence']}%)")

print("\n" + "=" * 60)
print(" ALL SYSTEM VERIFICATION TESTS PASSED SUCCESSFULLY! ")
print("=" * 60)
