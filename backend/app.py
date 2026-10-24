import os
import sys
import json
import pickle
from flask import Flask, request, jsonify, send_from_directory

# Ensure backend directory is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CURRENT_DIR)

from feature_extraction import extract_features, FEATURE_COLUMNS
from email_analyzer import analyze_message_full
from ssl_dns_inspector import inspect_live_security
from qr_scanner import analyze_quishing_full
from ip_threat_intel import inspect_ip_threat_intel
from audit_report import generate_threat_audit_report

# Import rf_engine so pickle can deserialize PureRandomForestClassifier if used
try:
    from rf_engine import PureRandomForestClassifier, PureDecisionTreeClassifier, PureDecisionNode
except ImportError:
    pass


# Paths
FRONTEND_DIR = os.path.join(CURRENT_DIR, "..", "frontend")
MODEL_PATH = os.path.join(CURRENT_DIR, "model.pkl")
METRICS_PATH = os.path.join(CURRENT_DIR, "model_metrics.json")

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")

# Load trained model
model = None
metrics_data = {}

def load_or_train_model():
    global model, metrics_data
    if os.path.exists(MODEL_PATH):
        try:
            with open(MODEL_PATH, "rb") as f:
                model = pickle.load(f)
            print(f"[OK] Trained model loaded successfully from {MODEL_PATH}")
        except Exception as e:
            print(f"[Warning] Failed to load model ({e}). Auto-retraining...")
            model = None

    if model is None:
        try:
            import subprocess
            train_script = os.path.join(CURRENT_DIR, "train_model.py")
            subprocess.run([sys.executable, train_script], check=True)
            with open(MODEL_PATH, "rb") as f:
                model = pickle.load(f)
            print("[OK] Trained model loaded after auto-retraining.")
        except Exception as e:
            print(f"[Error] Auto-training failed: {e}")

    if os.path.exists(METRICS_PATH):
        try:
            with open(METRICS_PATH, "r", encoding="utf-8") as f:
                metrics_data = json.load(f)
        except Exception as e:
            print(f"[Warning] Failed to load metrics: {e}")

load_or_train_model()


def normalize_url(url: str) -> str:
    """Normalize input URL to standard canonical form matching dataset conventions."""
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = f"https://{url}"

    from urllib.parse import urlparse
    import ipaddress
    parsed = urlparse(url)
    host = parsed.netloc.split(":")[0]

    host_parts = host.split(".")
    # If apex domain (e.g. google.com instead of www.google.com), add www. prefix to align with benchmark schema
    if len(host_parts) == 2:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            new_netloc = f"www.{parsed.netloc}"
            url = url.replace(f"://{parsed.netloc}", f"://{new_netloc}", 1)

    return url



@app.route("/")
def index():
    """Serve the frontend single-page cybersecurity dashboard."""
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "model_loaded": model is not None,
        "features_count": len(FEATURE_COLUMNS)
    })


@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    """Return model evaluation metrics saved during training."""
    if metrics_data:
        return jsonify({"success": True, "metrics": metrics_data})
    return jsonify({"success": False, "error": "Metrics not found. Train the model first."}), 404


@app.route("/predict", methods=["POST"])
def predict():
    """
    Accepts JSON: {"url": "..."}
    Validates URL, extracts lexical features, runs model prediction,
    calculates risk score and returns detailed analysis.
    """
    global model
    if model is None:
        load_or_train_model()

    if model is None:
        return jsonify({
            "success": False,
            "error": "ML model is not loaded on server. Please train the model first."
        }), 503

    data = request.get_json(silent=True)
    if not data or "url" not in data:
        return jsonify({
            "success": False,
            "error": "Please provide a valid URL in the request payload (e.g. {'url': 'https://example.com'})."
        }), 400

    raw_url = str(data["url"]).strip()
    if not raw_url:
        return jsonify({
            "success": False,
            "error": "URL cannot be empty."
        }), 400

    # Normalize URL (e.g. google.com -> https://google.com)
    url = normalize_url(raw_url)

    try:
        # Extract 17 features
        features = extract_features(url)

        # Build feature vector in exact FEATURE_COLUMNS order
        feature_vector = [features[col] for col in FEATURE_COLUMNS]

        # Model inference: supports both scikit-learn and pure-Python models
        # Label Semantics: 0 = Phishing, 1 = Legitimate
        if hasattr(model, "predict_proba"):
            # Probabilities: [P(class=0 / Phishing), P(class=1 / Legitimate)]
            try:
                # Scikit-learn expects 2D array / DataFrame
                import pandas as pd
                X_df = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)
                proba = model.predict_proba(X_df)[0]
            except Exception:
                # Pure-Python or list-based model
                proba = model.predict_proba([feature_vector])[0]

            p_phishing = float(proba[0])
            p_legitimate = float(proba[1])
        else:
            pred_raw = model.predict([feature_vector])[0]
            p_legitimate = 1.0 if pred_raw == 1 else 0.0
            p_phishing = 1.0 - p_legitimate

        # Risk score corresponds to Phishing probability (0% to 100%)
        risk_score = round(p_phishing * 100, 1)

        if p_phishing > 0.50:
            prediction_label = "Potential Phishing"
            confidence = round(p_phishing * 100, 1)
            verdict = "phishing"
            explanation = "Suspicious lexical features detected. High probability of deception or credential harvesting."
        else:
            prediction_label = "Legitimate"
            confidence = round(p_legitimate * 100, 1)
            verdict = "legitimate"
            explanation = "URL lexical patterns conform to standard, benign domain conventions."

        # Enrich with live IP Geolocation & ASN Threat Intel
        try:
            ip_intel = inspect_ip_threat_intel(url)
        except Exception:
            ip_intel = None

        return jsonify({
            "success": True,
            "url": url,
            "prediction": prediction_label,
            "verdict": verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "explanation": explanation,
            "features": features,
            "ip_intel": ip_intel
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to analyze URL: {str(e)}"
        }), 500


@app.route("/api/analyze-message", methods=["POST"])
def api_analyze_message():
    """
    Accepts JSON: {"text": "..."}
    Analyzes message for psychological social engineering lures and evaluates embedded links.
    """
    if model is None:
        return jsonify({"success": False, "error": "ML model is not loaded on server."}), 503

    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"success": False, "error": "Message body cannot be empty."}), 400

    result = analyze_message_full(text, model, normalize_url)
    return jsonify(result)


@app.route("/api/inspect-ssl-dns", methods=["POST"])
def api_inspect_ssl_dns():
    """
    Accepts JSON: {"url": "..."}
    Performs real-time DNS resolution and live cryptographic SSL/TLS certificate inspection.
    """
    data = request.get_json(silent=True) or {}
    target = data.get("url", "").strip()
    if not target:
        return jsonify({"success": False, "error": "Target URL or domain cannot be empty."}), 400

    result = inspect_live_security(target)
    return jsonify(result)


@app.route("/api/scan-qr", methods=["POST"])
def api_scan_qr():
    """
    Accepts multipart/form-data with file 'qr_image' or raw image binary body.
    Decodes QR code and runs full Random Forest + SSL threat analysis on target payload.
    """
    if model is None:
        return jsonify({"success": False, "error": "ML model is not loaded on server."}), 503

    image_bytes = None
    if "qr_image" in request.files:
        file = request.files["qr_image"]
        image_bytes = file.read()
    elif request.data:
        image_bytes = request.data

    if not image_bytes:
        return jsonify({"success": False, "error": "Please provide an image file containing a QR code."}), 400

    result = analyze_quishing_full(image_bytes, model, normalize_url)
    return jsonify(result)


@app.route("/api/ip-threat-intel", methods=["POST"])
def api_ip_threat_intel():
    """
    Accepts JSON: {"target": "..."} or {"url": "..."} or {"domain": "..."}
    Performs real-time IP DNS resolution, BGP ASN lookup, and Geolocation risk analysis.
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target") or data.get("url") or data.get("domain") or data.get("host") or ""
    target = str(target).strip()
    if not target:
        return jsonify({"success": False, "error": "Target URL, host or domain cannot be empty."}), 400

    result = inspect_ip_threat_intel(target)
    return jsonify(result)


@app.route("/api/generate-audit-report", methods=["POST"])
def api_generate_audit_report():
    """
    Accepts JSON with scan telemetry.
    Generates an official cryptographically hashed Cyber Threat Forensic Audit Certificate.
    """
    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"success": False, "error": "No scan data provided for audit certificate."}), 400

    report = generate_threat_audit_report(data)
    return jsonify(report)


if __name__ == "__main__":
    print("\nStarting PhishGuard Detection System server...")
    print("Serving on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
