from urllib.parse import urlparse
import re
import ipaddress


# Features that will be used by our ML model
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


def extract_features(url):

    parsed = urlparse(url)

    domain = parsed.netloc

    # Remove port number if present
    domain_without_port = domain.split(":")[0]

    features = {}

    # 1. URL Length
    features["URLLength"] = len(url)

    # 2. Domain Length
    features["DomainLength"] = len(domain_without_port)

    # 3. Check whether domain is an IP address
    try:
        ipaddress.ip_address(domain_without_port)
        features["IsDomainIP"] = 1
    except ValueError:
        features["IsDomainIP"] = 0

    # 4. Number of subdomains
    domain_parts = domain_without_port.split(".")

    if len(domain_parts) > 2:
        features["NoOfSubDomain"] = len(domain_parts) - 2
    else:
        features["NoOfSubDomain"] = 0

    # 5. Check for URL obfuscation (@, %, and // occurring after protocol scheme)
    url_body = url.split("://", 1)[1] if "://" in url else url
    obfuscation_chars = ["@", "%", "//"]

    obfuscated_count = 0

    for char in obfuscation_chars:
        obfuscated_count += url_body.count(char)

    features["HasObfuscation"] = int(obfuscated_count > 0)

    # 6. Number of obfuscated characters
    features["NoOfObfuscatedChar"] = obfuscated_count

    # 7. Obfuscation ratio
    if len(url) > 0:
        features["ObfuscationRatio"] = (
            obfuscated_count / len(url)
        )
    else:
        features["ObfuscationRatio"] = 0

    # 8. Number of letters
    letters = sum(char.isalpha() for char in url)

    features["NoOfLettersInURL"] = letters

    # 9. Letter ratio
    if len(url) > 0:
        features["LetterRatioInURL"] = (
            letters / len(url)
        )
    else:
        features["LetterRatioInURL"] = 0

    # 10. Number of digits
    digits = sum(char.isdigit() for char in url)

    features["NoOfDegitsInURL"] = digits

    # 11. Digit ratio
    if len(url) > 0:
        features["DegitRatioInURL"] = (
            digits / len(url)
        )
    else:
        features["DegitRatioInURL"] = 0

    # 12. Number of '='
    features["NoOfEqualsInURL"] = url.count("=")

    # 13. Number of '?'
    features["NoOfQMarkInURL"] = url.count("?")

    # 14. Number of '&'
    features["NoOfAmpersandInURL"] = url.count("&")

    # 15. Number of other special characters
    special_chars = re.findall(
        r"[^a-zA-Z0-9]",
        url
    )

    excluded_chars = ["=", "?", "&"]

    other_special_chars = [
        char for char in special_chars
        if char not in excluded_chars
    ]

    features["NoOfOtherSpecialCharsInURL"] = len(
        other_special_chars
    )

    # 16. Special character ratio
    if len(url) > 0:
        features["SpacialCharRatioInURL"] = (
            len(special_chars) / len(url)
        )
    else:
        features["SpacialCharRatioInURL"] = 0

    # 17. HTTPS
    features["IsHTTPS"] = int(
        parsed.scheme.lower() == "https"
    )

    return features

if __name__ == "__main__":

    test_url = "https://secure-login.example.com/account?verify=123"

    features = extract_features(test_url)

    print("\nExtracted Features:\n")

    for name, value in features.items():
        print(f"{name}: {value}")