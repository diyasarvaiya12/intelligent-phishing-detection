import json
import sys
import os
import io
import cv2

# Ensure backend directory is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CURRENT_DIR)

from app import app

client = app.test_client()

print("=" * 70)
print(" RUNNING PHISHGUARD AI DEFENSE SUITE INTEGRATION TESTS")
print("=" * 70)

# 1. Test GET /
r_index = client.get("/")
assert r_index.status_code == 200, f"Expected 200, got {r_index.status_code}"
assert b"PHISHGUARD" in r_index.data
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

# 4. Test URL Threat Scanner - Legitimate URLs
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
    assert res["verdict"] == "legitimate", f"Expected legitimate for {url}, got {res['verdict']}"
    assert res["risk_score"] < 40.0, f"Expected risk < 40% for {url}, got {res['risk_score']}%"
    print(f"[PASS] Legitimate URL : {url:30} -> Verdict: {res['verdict']} (Risk: {res['risk_score']}%, Conf: {res['confidence']}%)")

# 5. Test URL Threat Scanner - Phishing URLs
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
    assert res["verdict"] == "phishing", f"Expected phishing for {url}, got {res['verdict']}"
    assert res["risk_score"] > 60.0, f"Expected risk > 60% for {url}, got {res['risk_score']}%"
    print(f"[PASS] Phishing URL   : {url:68} -> Verdict: {res['verdict']} (Risk: {res['risk_score']}%, Conf: {res['confidence']}%)")

# 6. Test Email & SMS Social Engineering Analyzer
print("\n--- Testing Email & SMS Social Engineering Analyzer ---")
phish_email = (
    "URGENT: Your SBI bank account has been suspended due to pending KYC update. "
    "Click http://secure-login.paypal.account-verify.com/login?id=999&auth=fail to verify within 24 hours."
)
r_email_phish = client.post("/api/analyze-message", json={"text": phish_email})
assert r_email_phish.status_code == 200
data_ep = r_email_phish.get_json()
assert data_ep["success"] is True
assert data_ep["overall_threat_score"] >= 70.0, f"Expected score >= 70, got {data_ep['overall_threat_score']}"
assert data_ep["verdict_status"] == "threat"
assert len(data_ep["embedded_links"]) == 1
assert data_ep["malicious_links_count"] == 1
print(f"[PASS] Phishing Email Analysis : Threat Score = {data_ep['overall_threat_score']}%, Status = {data_ep['verdict_status']}, Triggers = {data_ep['social_engineering']['total_triggers']}")

clean_email = (
    "Hi team, please find attached the documentation for our project at https://github.com. "
    "Let us know if you have any questions."
)
r_email_clean = client.post("/api/analyze-message", json={"text": clean_email})
assert r_email_clean.status_code == 200
data_ec = r_email_clean.get_json()
assert data_ec["success"] is True
assert data_ec["overall_threat_score"] < 40.0, f"Expected score < 40, got {data_ec['overall_threat_score']}"
assert data_ec["verdict_status"] == "safe"
assert data_ec["malicious_links_count"] == 0
print(f"[PASS] Clean Email Analysis    : Threat Score = {data_ec['overall_threat_score']}%, Status = {data_ec['verdict_status']}")

# 7. Test Live SSL / DNS Security Inspector
print("\n--- Testing Live SSL/TLS & DNS Security Inspector ---")
r_ssl_good = client.post("/api/inspect-ssl-dns", json={"url": "https://google.com"})
assert r_ssl_good.status_code == 200
data_sg = r_ssl_good.get_json()
assert data_sg["success"] is True
assert data_sg["grade"] in ["A+", "A"], f"Expected grade A or A+, got {data_sg['grade']}"
assert data_sg["dns"]["dns_status"] == "Success"
assert data_sg["ssl"]["has_tls"] is True
print(f"[PASS] SSL/DNS on google.com  : Grade = {data_sg['grade']}, TLS = {data_sg['ssl']['protocol_version']}, Issuer = {data_sg['ssl']['issuer'].get('organization')}")

r_ssl_bad = client.post("/api/inspect-ssl-dns", json={"url": "http://www.teramill.com"})
assert r_ssl_bad.status_code == 200
data_sb = r_ssl_bad.get_json()
assert data_sb["success"] is True
print(f"[PASS] SSL/DNS on teramill.com: Grade = {data_sb['grade']}, Security Flags = {len(data_sb['security_flags'])}")

# 8. Test Quishing (QR Code) Scanner
print("\n--- Testing Quishing (QR Code) Scanner ---")
encoder = cv2.QRCodeEncoder.create()
qr_mat = encoder.encode("https://google.com")
qr_img = cv2.resize(qr_mat, (300, 300), interpolation=cv2.INTER_NEAREST)
_, encoded_png = cv2.imencode(".png", qr_img)
img_bytes = encoded_png.tobytes()

r_qr = client.post(
    "/api/scan-qr",
    data={"qr_image": (io.BytesIO(img_bytes), "sample_qr.png")},
    content_type="multipart/form-data"
)
assert r_qr.status_code == 200
data_qr = r_qr.get_json()
assert data_qr["success"] is True
assert data_qr["has_qr"] is True
assert "google.com" in data_qr["payload"]
assert data_qr["verdict"] == "legitimate"
assert data_qr["risk_score"] < 10.0
print(f"[PASS] QR Code Quishing Scan  : Payload = '{data_qr['payload']}', Verdict = {data_qr['verdict']} (Risk: {data_qr['risk_score']}%)")

# 9. Test Live IP Geolocation & ASN Threat Intelligence
print("\n--- Testing Live IP Geolocation & ASN Threat Intelligence ---")
r_ip = client.post("/api/ip-threat-intel", json={"target": "google.com"})
assert r_ip.status_code == 200
data_ip = r_ip.get_json()
assert data_ip["success"] is True
assert data_ip["primary_ip"] is not None
assert "asn" in data_ip
print(f"[PASS] IP Threat Intel on google.com: IP = {data_ip['primary_ip']}, Country = {data_ip['country']}, Reputation = {data_ip['network_reputation']}")

# 10. Test Forensic Cyber Threat Audit Report Generator
print("\n--- Testing Forensic Cyber Threat Audit Report Generator ---")
r_cert = client.post("/api/generate-audit-report", json={
    "url": "http://secure-login.paypal.account-verify.com/login?id=999&auth=fail",
    "verdict": "phishing",
    "risk_score": 100.0,
    "confidence": 100.0,
    "features": {"URLLength": 75, "IsHTTPS": 0}
})
assert r_cert.status_code == 200
data_cert = r_cert.get_json()
assert data_cert["success"] is True
assert data_cert["incident_id"].startswith("PHISH-SEC-2026-")
assert len(data_cert["sha256_evidence_seal"]) == 64
assert len(data_cert["mitigation_directives"]) > 0
print(f"[PASS] Forensic Audit Certificate: ID = {data_cert['incident_id']}, Severity = {data_cert['severity']}, SHA-256 = {data_cert['sha256_evidence_seal'][:16]}...")

print("\n" + "=" * 70)
print(" ALL 10 DEFENSE SUITE INTEGRATION TESTS PASSED 100% SUCCESSFULLY! ")
print("=" * 70)
