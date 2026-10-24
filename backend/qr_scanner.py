"""
PhishGuard AI - Quishing (QR Code Phishing) Detector
Decodes embedded QR codes from images using OpenCV and evaluates
the extracted target URL through our Random Forest ML engine.
"""

import io
import cv2
import numpy as np
from PIL import Image
from typing import Dict, Any
from urllib.parse import urlparse
from feature_extraction import extract_features, FEATURE_COLUMNS
from ssl_dns_inspector import inspect_live_security


def decode_qr_from_bytes(image_bytes: bytes) -> Dict[str, Any]:
    """Decodes QR code from raw uploaded image bytes using OpenCV."""
    if not image_bytes:
        return {"success": False, "error": "No image data received."}

    # Convert bytes to numpy image
    # Convert uploaded image bytes into a NumPy array for OpenCV processing.
    np_arr = np.frombuffer(image_bytes, np.uint8)
    img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)

    # Use Pillow as a fallback when OpenCV cannot decode the uploaded image.
    if img is None:
        # Fallback to Pillow
        try:
            pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
            img = np.array(pil_img)[:, :, ::-1].copy()
        except Exception as e:
            return {"success": False, "error": f"Invalid image format: {str(e)}"}

    # Initialize OpenCV's QR detector to locate and decode the QR code payload.
    detector = cv2.QRCodeDetector()
    decoded_text, points, straight_qrcode = detector.detectAndDecode(img)

    # Improve readability for low-contrast QR codes by applying grayscale
    # conversion and histogram equalization before attempting another decode.
    if not decoded_text:
        # Try grayscale with histogram equalization if low contrast
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        eq = cv2.equalizeHist(gray)

        decoded_text, points, _ = detector.detectAndDecode(eq)

        # Stop processing when neither decoding attempt produces a QR payload.
    if not decoded_text:
        return {
            "success": True,
            "has_qr": False,
            "error": "No QR code detected in the uploaded image. Ensure the QR code is clearly visible."
        }

# Determine whether the decoded payload appears to contain a web address
# so that only URL-based payloads proceed to phishing analysis.
    decoded_text = decoded_text.strip()
    is_url = bool(
        decoded_text.startswith("http://") or
        decoded_text.startswith("https://") or
        decoded_text.startswith("www.") or
        re_is_url(decoded_text)
    )

    return {
        "success": True,
        "has_qr": True,
        "payload": decoded_text,
        "is_url": is_url
    }

# Identify domain-like strings even when the QR payload omits the URL scheme.
def re_is_url(text: str) -> bool:
    """Check if string appears to be a domain/web address."""
    parsed = urlparse(text if "://" in text else f"https://{text}")
    return "." in parsed.netloc and len(parsed.netloc.split(".")[-1]) >= 2


def analyze_quishing_full(image_bytes: bytes, ml_model, normalize_fn) -> Dict[str, Any]:
    """
    Decodes QR code, extracts target URL, and pipes it through
    the 17-feature Random Forest ML engine + live SSL/DNS security inspection.
    """

    # Decode the uploaded QR image and validate the extraction result
    # before performing any threat analysis.
    decode_res = decode_qr_from_bytes(image_bytes)

    if not decode_res.get("success"):
        return decode_res

# Return an error if the image contains no successfully decoded QR code.
    if not decode_res.get("has_qr"):
        return {
            "success": False,
            "error": "No valid QR code could be found in the image. Please upload a clear photo or screenshot containing a QR code."
        }

    payload = decode_res["payload"]
    is_url = decode_res["is_url"]

    if not is_url:
        return {
            "success": True,
            "has_qr": True,
            "is_url": False,
            "payload": payload,
            "verdict": "neutral",
            "risk_score": 0.0,
            "explanation": "Decoded QR code contains plain text or non-URL data."
        }

    # Normalize target URL
    # Standardize the extracted URL before computing features for the classifier.
    normalized_url = normalize_fn(payload)
    features = extract_features(normalized_url)
    feature_vector = [features[col] for col in FEATURE_COLUMNS]

    import pandas as pd

    # Inference using Random Forest
    if hasattr(ml_model, "predict_proba"):
        X_df = pd.DataFrame([feature_vector], columns=FEATURE_COLUMNS)
        proba = ml_model.predict_proba(X_df)[0]
        p_phishing = float(proba[0])
        p_legitimate = float(proba[1])
    else:
        pred_raw = ml_model.predict([feature_vector])[0]
        p_legitimate = 1.0 if pred_raw == 1 else 0.0
        p_phishing = 1.0 - p_legitimate

    risk_score = round(p_phishing * 100, 1)

    if p_phishing > 0.50:
        prediction_label = "Malicious Quishing Link (Phishing)"
        confidence = round(p_phishing * 100, 1)
        verdict = "phishing"
        explanation = "High-risk QR code: Encoded URL exhibits aggressive phishing lexical features."
    else:
        prediction_label = "Legitimate QR Code"
        confidence = round(p_legitimate * 100, 1)
        verdict = "legitimate"
        explanation = "Benign QR code: Encoded target URL conforms to standard safe web domains."

    # Fast SSL & DNS lookup on target host
    ssl_dns = inspect_live_security(normalized_url)

    return {
        "success": True,
        "has_qr": True,
        "is_url": True,
        "payload": payload,
        "normalized_url": normalized_url,
        "prediction": prediction_label,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "explanation": explanation,
        "features": features,
        "ssl_dns": ssl_dns
    }
