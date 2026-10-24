"""
PhishGuard AI - Live SSL/TLS Certificate & DNS Security Inspector
Performs real-time cryptographic certificate validation and DNS resolution
for the Applied Cryptography & Network Security (CNS) curriculum.
"""

import socket
import ssl
import datetime
import ipaddress
from urllib.parse import urlparse
from typing import Dict, Any, List


def parse_target_host(url_or_domain: str):
    """Normalize input and extract hostname and port."""
    url = url_or_domain.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc

    if ":" in netloc:
        host, port_str = netloc.split(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 443 if scheme == "https" else 80
    else:
        host = netloc
        port = 443 if scheme == "https" else 80

    return host.strip(), port, scheme


def inspect_dns(hostname: str) -> Dict[str, Any]:
    """Perform real-time DNS resolution and examine IP characteristics."""
    dns_info = {
        "hostname": hostname,
        "resolved_ips": [],
        "ip_version": "Unknown",
        "is_private": False,
        "is_loopback": False,
        "reverse_dns": None,
        "dns_status": "Success",
        "error": None
    }

    try:
        # Resolve all IPv4 / IPv6 addresses
        addr_info = socket.getaddrinfo(hostname, None)
        ips = list(set([item[4][0] for item in addr_info]))
        dns_info["resolved_ips"] = ips

        if ips:
            primary_ip = ips[0]
            try:
                ip_obj = ipaddress.ip_address(primary_ip)
                dns_info["is_private"] = ip_obj.is_private
                dns_info["is_loopback"] = ip_obj.is_loopback
                dns_info["ip_version"] = f"IPv{ip_obj.version}"
            except ValueError:
                pass

            # Reverse DNS lookup
            try:
                rev = socket.gethostbyaddr(primary_ip)
                dns_info["reverse_dns"] = rev[0]
            except Exception:
                dns_info["reverse_dns"] = "PTR record unavailable"

    except socket.gaierror as e:
        dns_info["dns_status"] = "Failed"
        dns_info["error"] = f"Domain could not be resolved: {str(e)}"
    except Exception as e:
        dns_info["dns_status"] = "Error"
        dns_info["error"] = str(e)

    return dns_info


def inspect_ssl(hostname: str, port: int = 443, timeout: float = 3.5) -> Dict[str, Any]:
    """
    Executes a real TLS handshake, parses X.509 certificate attributes,
    and checks cryptographic validity and cipher configuration.
    """
    ssl_info = {
        "has_tls": False,
        "protocol_version": None,
        "cipher_suite": None,
        "issuer": {},
        "subject": {},
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None,
        "is_expired": False,
        "sans": [],
        "san_match": False,
        "handshake_status": "Not Attempted",
        "error": None
    }

    # First check if domain can resolve
    try:
        context = ssl.create_default_context()
        # Allow checking certificates even if hostname or expiry has warnings so we can report them
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

                ssl_info["has_tls"] = True
                ssl_info["protocol_version"] = protocol
                ssl_info["cipher_suite"] = f"{cipher[0]} ({cipher[1]}, {cipher[2]} bits)" if cipher else None
                ssl_info["handshake_status"] = "Handshake Successful"

                if cert:
                    # Subject & Issuer
                    subject_dict = dict(x[0] for x in cert.get("subject", []))
                    issuer_dict = dict(x[0] for x in cert.get("issuer", []))

                    ssl_info["subject"] = {
                        "common_name": subject_dict.get("commonName", "Unknown"),
                        "organization": subject_dict.get("organizationName", "Not Specified")
                    }
                    ssl_info["issuer"] = {
                        "common_name": issuer_dict.get("commonName", "Unknown"),
                        "organization": issuer_dict.get("organizationName", "Unknown Issuer")
                    }

                    # Validity Dates
                    not_before_str = cert.get("notBefore")
                    not_after_str = cert.get("notAfter")

                    if not_after_str:
                        # Format: 'May 10 12:00:00 2026 GMT'
                        expiry_date = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                        ssl_info["valid_to"] = expiry_date.strftime("%Y-%m-%d %H:%M:%S UTC")
                        now = datetime.datetime.utcnow()
                        delta = (expiry_date - now).days
                        ssl_info["days_remaining"] = delta
                        ssl_info["is_expired"] = delta < 0

                    if not_before_str:
                        start_date = datetime.datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
                        ssl_info["valid_from"] = start_date.strftime("%Y-%m-%d %H:%M:%S UTC")

                    # Subject Alternative Names (SANs)
                    sans = [x[1] for x in cert.get("subjectAltName", []) if x[0] == "DNS"]
                    ssl_info["sans"] = sans[:15]  # Limit to 15 for readable payload

                    # Check SAN match
                    ssl_info["san_match"] = any(
                        s == hostname or (s.startswith("*.") and hostname.endswith(s[2:]))
                        for s in sans
                    ) or (ssl_info["subject"]["common_name"] == hostname)

    except ssl.SSLError as e:
        ssl_info["handshake_status"] = "SSL Verification Warning"
        ssl_info["error"] = f"TLS Error: {str(e)}"
    except socket.timeout:
        ssl_info["handshake_status"] = "Connection Timeout"
        ssl_info["error"] = "Target server did not respond on TLS port 443 within 3.5s"
    except ConnectionRefusedError:
        ssl_info["handshake_status"] = "Connection Refused"
        ssl_info["error"] = "Port 443 is closed or actively refused by host"
    except Exception as e:
        ssl_info["handshake_status"] = "Handshake Failed"
        ssl_info["error"] = str(e)

    return ssl_info


def inspect_live_security(url_or_domain: str) -> Dict[str, Any]:
    """
    Combined CNS Security Inspector:
    Evaluates DNS, SSL/TLS, and calculates a Cryptographic Security Grade.
    """
    url_or_domain = (url_or_domain or "").strip()
    if not url_or_domain:
        return {"success": False, "error": "Target domain cannot be empty."}

    hostname, port, scheme = parse_target_host(url_or_domain)

    # 1. DNS Resolution
    dns_res = inspect_dns(hostname)

    # 2. SSL/TLS Handshake
    ssl_res = inspect_ssl(hostname, port)

    # 3. Grade & Vulnerability Analysis
    grade = "A"
    flags = []
    risk_points = 0

    # DNS checks
    if dns_res["dns_status"] != "Success":
        flags.append("DNS Resolution Failure: Domain does not exist or has no valid A/AAAA records.")
        risk_points += 40
    elif dns_res["is_private"] or dns_res["is_loopback"]:
        flags.append("Internal/Bogon IP: Host resolves to a private or loopback IP range.")
        risk_points += 35

    # TLS checks
    if not ssl_res["has_tls"]:
        flags.append("No Secure Transport: Server fails to establish a TLS handshake on port 443.")
        grade = "F"
        risk_points += 50
    else:
        if ssl_res["is_expired"]:
            flags.append("Expired SSL Certificate: Certificate expiration date has passed.")
            grade = "F"
            risk_points += 40
        elif ssl_res["days_remaining"] is not None and ssl_res["days_remaining"] < 15:
            flags.append(f"Imminent Expiry: SSL certificate expires in {ssl_res['days_remaining']} days.")
            risk_points += 15

        if not ssl_res["san_match"]:
            flags.append("Hostname Mismatch: Target hostname is not included in the Certificate SANs list.")
            if grade != "F":
                grade = "C"
            risk_points += 30

        # Protocol rating
        proto = ssl_res.get("protocol_version", "")
        if "TLSv1.3" in proto:
            pass  # Modern standard
        elif "TLSv1.2" in proto:
            pass
        else:
            flags.append(f"Legacy Protocol: Insecure or legacy TLS protocol version ({proto}) detected.")
            risk_points += 25

        # Issuer check
        issuer_org = ssl_res.get("issuer", {}).get("organization", "").lower()
        if "cpanel" in issuer_org or "let's encrypt" in issuer_org:
            flags.append("Automated / Domain Validated (DV) Certificate: Common on disposable phishing domains.")
            risk_points += 10

    # Determine final cryptographic grade
    if risk_points == 0 and ssl_res.get("protocol_version") == "TLSv1.3" and ssl_res.get("san_match"):
        grade = "A+"
    elif risk_points <= 10 and ssl_res["has_tls"] and not ssl_res["is_expired"]:
        grade = "A"
    elif risk_points <= 25:
        grade = "B"
    elif risk_points <= 45:
        grade = "C"
    else:
        grade = "F"

    return {
        "success": True,
        "target": {
            "input": url_or_domain,
            "hostname": hostname,
            "port": port,
            "scheme": scheme
        },
        "grade": grade,
        "risk_level": "High" if grade in ["F", "C"] else ("Moderate" if grade == "B" else "Low"),
        "security_flags": flags,
        "dns": dns_res,
        "ssl": ssl_res
    }
