from urllib.parse import urlparse
import re
import ipaddress


# Features that will be used by our ML model (exact match with dataset schema)
FEATURE_COLUMNS = [
    "URLLength",
    "DomainLength",
    "IsDomainIP",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "NoOfLettersInURL",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS"
]


def extract_features(url: str) -> dict:
    """
    Extracts 17 lexical URL features matching the exact preprocessing schema
    of the UCI PhiUSIIL Phishing URL Dataset benchmark.
    """
    url = str(url).strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    domain = parsed.netloc
    domain_without_port = domain.split(":")[0]

    # Benchmark dataset indexes URLs with length - 1 (chopped end-char convention)
    chopped = url[:-1] if len(url) > 1 else url
    url_len = len(chopped)

    # Clean URL without scheme and www prefix used for token/character counts in PhiUSIIL
    clean = re.sub(r"^https?://(www\.)?", "", chopped)

    features = {}

    # 1. URL Length
    features["URLLength"] = url_len

    # 2. Domain Length
    features["DomainLength"] = len(domain)

    # 3. Check whether domain is an IP address
    try:
        ipaddress.ip_address(domain_without_port)
        features["IsDomainIP"] = 1
    except ValueError:
        features["IsDomainIP"] = 0

    # 4. Number of subdomains beyond base domain
    domain_parts = domain_without_port.split(".")
    if len(domain_parts) > 2:
        features["NoOfSubDomain"] = len(domain_parts) - 2
    else:
        features["NoOfSubDomain"] = 0

    # 5, 6, 7. Obfuscation indicators (@, %, and // occurring after protocol scheme)
    url_body = chopped.split("://", 1)[1] if "://" in chopped else chopped
    obf_count = 0
    hex_matches = re.findall(r"%[0-9a-fA-F]{2}", url_body)
    obf_count += len(hex_matches) * 3
    remaining_body = re.sub(r"%[0-9a-fA-F]{2}", "", url_body)
    obf_count += remaining_body.count("%")
    obf_count += remaining_body.count("@")
    obf_count += remaining_body.count("//") * 2

    features["HasObfuscation"] = int(obf_count > 0)
    features["NoOfObfuscatedChar"] = obf_count
    features["ObfuscationRatio"] = round(obf_count / url_len, 3) if url_len > 0 else 0.0

    # 8, 9. Alphabetic letters count and ratio
    letters = sum(c.isalpha() for c in clean)
    features["NoOfLettersInURL"] = letters
    features["LetterRatioInURL"] = round(letters / url_len, 3) if url_len > 0 else 0.0

    # 10, 11. Digits count and ratio
    digits = sum(c.isdigit() for c in clean)
    features["NoOfDegitsInURL"] = digits
    features["DegitRatioInURL"] = round(digits / url_len, 3) if url_len > 0 else 0.0

    # 12, 13, 14. Query delimiter counts
    features["NoOfEqualsInURL"] = clean.count("=")
    features["NoOfQMarkInURL"] = clean.count("?")
    features["NoOfAmpersandInURL"] = clean.count("&")

    # 15, 16. Other special characters (excluding =, ?, &) and ratio
    other_specials = re.findall(r"[^a-zA-Z0-9=?&]", clean)
    features["NoOfOtherSpecialCharsInURL"] = len(other_specials)
    features["SpacialCharRatioInURL"] = round(len(other_specials) / url_len, 3) if url_len > 0 else 0.0

    # 17. HTTPS flag
    features["IsHTTPS"] = int(parsed.scheme.lower() == "https")

    return features


if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://www.uni-mainz.de",
        "https://github.com",
        "http://secure-login.paypal.account-verify.com/login?id=999&auth=fail"
    ]

    for u in test_urls:
        feats = extract_features(u)
        print(f"\n--- Features for {u} ---")
        for k, v in feats.items():
            print(f"  {k}: {v}")