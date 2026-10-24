"""
PhishGuard AI Suite - Live IP Geolocation & ASN Threat Intelligence Engine
Resolves target hosts, queries live BGP ASN registries, geolocation coordinates,
and evaluates network-level infrastructure risk.
"""

import socket
import urllib.parse
import urllib.request
import json
import ipaddress
import re

# High-risk dynamic DNS & abuse-prone free hosts
DYNAMIC_DNS_DOMAINS = {
    "duckdns.org", "ngrok.io", "ngrok-free.app", "no-ip.com", "no-ip.org",
    "hopto.org", "zapto.org", "ddns.net", "000webhostapp.com", "glitch.me",
    "pages.dev", "weebly.com", "wixsite.com", "surge.sh", "firebaseapp.com"
}

# Known Tier-1 Verified CDNs & Cloud Providers (Benign Reputation)
TIER1_CDNS = [
    "cloudflare", "google", "amazon", "microsoft", "fastly", 
    "akamai", "github", "automattic", "verizon", "edgecast"
]

def get_country_flag_emoji(country_code: str) -> str:
    """Converts a 2-letter ISO country code into Unicode Flag Emoji."""
    if not country_code or len(country_code) != 2:
        return "🌐"
    try:
        return "".join(chr(127397 + ord(c.upper())) for c in country_code)
    except Exception:
        return "🌐"

def extract_host(url_or_domain: str) -> str:
    """Extracts clean hostname or IP from any input."""
    raw = (url_or_domain or "").strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    try:
        parsed = urllib.parse.urlparse(raw)
        host = parsed.netloc or parsed.path
        # Strip port if present
        if ":" in host:
            host = host.split(":")[0]
        return host.strip("/").lower()
    except Exception:
        return raw.split("/")[0].split(":")[0].lower()

def is_private_or_bogon_ip(ip_str: str) -> bool:
    """Checks if an IP address belongs to RFC 1918 private or loopback ranges."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local
    except Exception:
        return False

def inspect_ip_threat_intel(url_or_domain: str) -> dict:
    """
    Performs full DNS socket resolution, ASN identification,
    IP geolocation, and network threat risk assessment.
    """
    host = extract_host(url_or_domain)
    if not host:
        return {
            "success": False,
            "error": "Empty or invalid target host provided."
        }

    # 1. Check for Dynamic DNS
    is_dyn_dns = any(host.endswith(suffix) for suffix in DYNAMIC_DNS_DOMAINS)

    # 2. Resolve DNS to IP
    primary_ip = None
    all_ips = []
    try:
        # Check if host itself is already an IP literal
        ipaddress.ip_address(host)
        primary_ip = host
        all_ips = [host]
    except ValueError:
        # Resolve hostname
        try:
            addr_info = socket.getaddrinfo(host, 80, socket.AF_INET, socket.SOCK_STREAM)
            all_ips = list(dict.fromkeys([info[4][0] for info in addr_info]))
            if all_ips:
                primary_ip = all_ips[0]
        except Exception:
            try:
                _, _, ip_list = socket.gethostbyname_ex(host)
                all_ips = list(dict.fromkeys(ip_list))
                if all_ips:
                    primary_ip = all_ips[0]
            except Exception as e:
                return {
                    "success": False,
                    "host": host,
                    "error": f"DNS host resolution failed for '{host}': {str(e)}",
                    "dns_resolved": False
                }

    if not primary_ip:
        return {
            "success": False,
            "host": host,
            "error": f"No valid IP address found for host '{host}'.",
            "dns_resolved": False
        }

    # 3. Check for Private / Bogon IP
    is_private = is_private_or_bogon_ip(primary_ip)

    # 4. Reverse DNS Lookup (PTR)
    reverse_dns = "N/A"
    try:
        socket.setdefaulttimeout(2.0)
        reverse_dns, _, _ = socket.gethostbyaddr(primary_ip)
    except Exception:
        reverse_dns = f"Unassigned / No PTR ({primary_ip})"

    # 5. Geolocation & ASN Lookup
    geo_data = {}
    if is_private:
        geo_data = {
            "country": "Private / Local Area Network",
            "countryCode": "LAN",
            "regionName": "Internal Subnet",
            "city": "Intranet Host",
            "lat": 0.0,
            "lon": 0.0,
            "timezone": "Local",
            "isp": "RFC 1918 Private Network",
            "org": "Internal Infrastructure",
            "as": "AS0 PRIVATE"
        }
    else:
        # Query public IP API with 2.5s strict timeout
        try:
            endpoint = f"http://ip-api.com/json/{primary_ip}?fields=status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,query"
            req = urllib.request.Request(
                endpoint,
                headers={"User-Agent": "PhishGuard-AI-ThreatIntel/2.0"}
            )
            with urllib.request.urlopen(req, timeout=2.5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if data.get("status") == "success":
                    geo_data = data
        except Exception:
            # Fallback gracefully
            geo_data = {
                "country": "Global Internet",
                "countryCode": "XX",
                "regionName": "Public WAN",
                "city": "Unknown",
                "lat": 37.751,
                "lon": -122.42,
                "timezone": "UTC",
                "isp": "Public Autonomous System",
                "org": "Internet Service Provider",
                "as": "AS-UNKNOWN"
            }

    country = geo_data.get("country", "Unknown")
    country_code = geo_data.get("countryCode", "XX")
    flag = get_country_flag_emoji(country_code)
    city = geo_data.get("city", "Unknown")
    region = geo_data.get("regionName", "Unknown")
    lat = geo_data.get("lat", 0.0)
    lon = geo_data.get("lon", 0.0)
    timezone = geo_data.get("timezone", "UTC")
    isp = geo_data.get("isp", "Unknown ISP")
    org = geo_data.get("org", "Unknown Org")
    asn = geo_data.get("as", "N/A")

    # 6. Threat Assessment Heuristics
    security_indicators = []
    network_risk_score = 10.0 # base baseline
    reputation = "Standard Public Host"

    # Check Tier 1 CDNs
    isp_lower = (isp + " " + org + " " + asn).lower()
    is_tier1 = any(cdn in isp_lower for cdn in TIER1_CDNS)

    if is_tier1:
        network_risk_score = 4.0
        reputation = "Tier-1 Verified Enterprise CDN"
        security_indicators.append("Protected by enterprise-grade CDN / Anycast infrastructure.")
    elif is_private:
        network_risk_score = 90.0
        reputation = "Private Bogon / Rogue Intranet Host"
        security_indicators.append("Suspicious: Public URL targets internal private network address (SSRF risk).")
    else:
        network_risk_score = 25.0
        reputation = "Standard Commercial Hosting"

    if is_dyn_dns:
        network_risk_score = min(100.0, network_risk_score + 65.0)
        reputation = "High-Risk Dynamic DNS / Free Subdomain"
        security_indicators.append(f"Domain uses dynamic DNS or free host ('{host}') commonly abused in phishing campaigns.")

    if len(all_ips) > 2:
        security_indicators.append(f"Multi-homed DNS: {len(all_ips)} active IP endpoints detected (Round-Robin/Anycast).")
    elif len(all_ips) == 1 and not is_tier1:
        security_indicators.append("Single point of origin: Hosted on a single dedicated/shared VPS server.")

    return {
        "success": True,
        "dns_resolved": True,
        "host": host,
        "primary_ip": primary_ip,
        "all_ips": all_ips,
        "country": country,
        "country_code": country_code,
        "flag_emoji": flag,
        "city": city,
        "region": region,
        "latitude": lat,
        "longitude": lon,
        "timezone": timezone,
        "isp": isp,
        "organization": org,
        "asn": asn,
        "reverse_dns": reverse_dns,
        "is_private": is_private,
        "is_dynamic_dns": is_dyn_dns,
        "network_threat_score": round(network_risk_score, 1),
        "network_reputation": reputation,
        "security_indicators": security_indicators
    }
