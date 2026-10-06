import os
import sys
import json
import pickle
from flask import Flask, request, jsonify, send_from_directory

# Ensure backend directory is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, CURRENT_DIR)

from feature_extraction import extract_features, FEATURE_COLUMNS
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
if os.path.exists(MODEL_PATH):
    try:
        with open(MODEL_PATH, "rb") as f:
            model = pickle.load(f)
        print(f"[OK] Trained model loaded successfully from {MODEL_PATH}")
    except Exception as e:
        print(f"[Warning] Failed to load model: {e}")
else:
    print(f"[Warning] model.pkl not found at {MODEL_PATH}. Please run train_model.py first.")

# Load model metrics
metrics_data = {}
if os.path.exists(METRICS_PATH):
    try:
        with open(METRICS_PATH, "r", encoding="utf-8") as f:
            metrics_data = json.load(f)
    except Exception as e:
        print(f"[Warning] Failed to load metrics: {e}")


def normalize_url(url: str) -> str:
    """Normalize input URL to include scheme if omitted."""
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        return f"https://{url}"
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

        return jsonify({
            "success": True,
            "url": url,
            "prediction": prediction_label,
            "verdict": verdict,
            "risk_score": risk_score,
            "confidence": confidence,
            "explanation": explanation,
            "features": features
        })

    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Failed to analyze URL: {str(e)}"
        }), 500


if __name__ == "__main__":
    print("\nStarting PhishGuard Detection System server...")
    print("Serving on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
