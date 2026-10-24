"""
PhishGuard AI - Email & SMS Social Engineering Analyzer
Extracts social engineering psychological triggers and scans embedded URLs
using the 17-feature Random Forest ML engine.
"""

import re
from typing import Dict, Any, List
from feature_extraction import extract_features, FEATURE_COLUMNS

# Social Engineering Keywords and Patterns categorized by psychological exploit vectors
TRIGGER_PATTERNS = {
    "urgency": [
        r"\burgent\b", r"\bimmediately\b", r"\baction required\b", r"\bwithin 24 hours\b",
        r"\bwithin 12 hours\b", r"\bexpires today\b", r"\blast warning\b", r"\bfinal notice\b",
        r"\bact now\b", r"\bimmediate response\b", r"\btime sensitive\b", r"\bdeadline\b"
    ],
    "account_threat": [
        r"\baccount suspended\b", r"\baccount locked\b", r"\bdeactivated\b", r"\bblocked\b",
        r"\bunauthorized access\b", r"\bsuspicious login\b", r"\bsecurity breach\b",
        r"\bverify your account\b", r"\bconfirm your identity\b", r"\bupdate your kyc\b",
        r"\bkyc pending\b", r"\bpassword reset\b", r"\botp\b", r"\bpin code\b"
    ],
    "financial_bait": [
        r"\btax refund\b", r"\blottery\b", r"\bwon\b", r"\bcash prize\b", r"\breward\b",
        r"\bbitcoin\b", r"\bcrypto\b", r"\bwire transfer\b", r"\binheritance\b",
        r"\bunclaimed funds\b", r"\bcongratulations\b", r"\bclaim your bonus\b", r"\bcashback\b"
    ],
    "authority_fear": [
        r"\blegal action\b", r"\bcourt order\b", r"\bpolice department\b", r"\binternal revenue\b",
        r"\bincome tax\b", r"\bbank manager\b", r"\bit support\b", r"\bsystem administrator\b",
        r"\bpenalty\b", r"\bfine of\b", r"\barrest warrant\b"
    ]
}

# Regex to extract standard and defanged URLs (e.g., hxxp://, example[.]com)
URL_REGEX = re.compile(
    r"(?:https?://|hxxps?://|www\.)[^\s<>'\"`]+|(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|io|co|in|xyz|top|online|ru|tk|cn|biz|info)(?:/[^\s<>'\"`]*)?",
    re.IGNORECASE
)


def extract_urls(text: str) -> List[str]:
    """Find and normalize all URLs (including defanged ones) in message text."""
    raw_urls = URL_REGEX.findall(text)
    clean_urls = []

    for raw in raw_urls:
        u = raw.strip().rstrip(".,;:!?)'\"")
        # Re-arm defanged URLs
        u = re.sub(r"^hxxp", "http", u, flags=re.IGNORECASE)
        u = u.replace("[.]", ".").replace("(dot)", ".").replace("{@}", "@")
        if u and u not in clean_urls:
            clean_urls.append(u)

    return clean_urls


def analyze_social_engineering(text: str) -> Dict[str, Any]:
    """Inspect text for psychological urgency, fear, and authority triggers."""
    text_lower = text.lower()
    detected_triggers = []
    category_hits = {cat: 0 for cat in TRIGGER_PATTERNS}

    for cat, patterns in TRIGGER_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text_lower):
                clean_term = pat.replace(r"\b", "").replace(r"\s+", " ")
                detected_triggers.append({
                    "term": clean_term,
                    "category": cat
                })
                category_hits[cat] += 1

    total_hits = len(detected_triggers)

    # Calculate Social Engineering Urgency Score (0 - 100)
    # 1 hit = 30%, 2 hits = 55%, 3 hits = 75%, 4+ hits = 90-100%
    if total_hits == 0:
        se_score = 5.0
    elif total_hits == 1:
        se_score = 35.0
    elif total_hits == 2:
        se_score = 60.0
    elif total_hits == 3:
        se_score = 80.0
    else:
        se_score = min(100.0, 85.0 + (total_hits * 3.0))

    return {
        "score": round(se_score, 1),
        "total_triggers": total_hits,
        "triggers": detected_triggers,
        "category_counts": category_hits
    }


def analyze_message_full(text: str, ml_model, normalize_fn) -> Dict[str, Any]:
    """
    Performs full multi-vector social engineering + embedded link scan.
    Returns composite threat assessment.
    """
    text = (text or "").strip()
    if not text:
        return {
            "success": False,
            "error": "Message content cannot be empty."
        }

    # 1. Social engineering heuristics
    se_data = analyze_social_engineering(text)

    # 2. Extract embedded URLs
    urls = extract_urls(text)
    scanned_links = []
    max_link_risk = 0.0

    import pandas as pd

    for u in urls:
        norm_u = normalize_fn(u)
        feats = extract_features(norm_u)
        vec = [feats[col] for col in FEATURE_COLUMNS]

        if hasattr(ml_model, "predict_proba"):
            X_df = pd.DataFrame([vec], columns=FEATURE_COLUMNS)
            proba = ml_model.predict_proba(X_df)[0]
            link_risk = round(float(proba[0]) * 100, 1)
        else:
            pred = ml_model.predict([vec])[0]
            link_risk = 100.0 if pred == 0 else 0.0

        verdict = "phishing" if link_risk >= 50.0 else "legitimate"
        max_link_risk = max(max_link_risk, link_risk)

        scanned_links.append({
            "original_url": u,
            "normalized_url": norm_u,
            "risk_score": link_risk,
            "verdict": verdict,
            "is_https": feats.get("IsHTTPS", 0) == 1,
            "subdomains": feats.get("NoOfSubDomain", 0),
            "has_obfuscation": feats.get("HasObfuscation", 0) == 1
        })

    # 3. Combined Composite Threat Score
    # If links are present: 65% weight on link risk + 35% on social engineering text score
    # If no links are present: 100% weight on text social engineering score
    if scanned_links:
        overall_score = round((0.65 * max_link_risk) + (0.35 * se_data["score"]), 1)
    else:
        overall_score = se_data["score"]

    # Final verdict
    if overall_score >= 70.0:
        overall_verdict = "HIGH RISK - MALICIOUS PHISHING CAMPAIGN"
        verdict_status = "threat"
        summary = "Critical threat: Strong social engineering lures combined with high-risk deceptive links detected."
    elif overall_score >= 40.0:
        overall_verdict = "SUSPICIOUS - PROCEED WITH CAUTION"
        verdict_status = "warning"
        summary = "Moderate risk: Message exhibits urgency or unusual links. Verify sender before interacting."
    else:
        overall_verdict = "LOW RISK - LIKELY BENIGN"
        verdict_status = "safe"
        summary = "Content exhibits standard non-coercive language and benign domain patterns."

    return {
        "success": True,
        "overall_threat_score": overall_score,
        "overall_verdict": overall_verdict,
        "verdict_status": verdict_status,
        "summary": summary,
        "social_engineering": se_data,
        "embedded_links": scanned_links,
        "links_count": len(scanned_links),
        "malicious_links_count": sum(1 for l in scanned_links if l["verdict"] == "phishing")
    }
