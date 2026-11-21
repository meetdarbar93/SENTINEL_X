"""
SENTINEL-X | Subdomain Enumeration & Attack Surface Discovery Engine
Performs passive Certificate Transparency (crt.sh) queries combined with
active non-intrusive DNS resolution to uncover hidden staging, VPN, portal,
and administrative assets across target domain attack surfaces.
"""

import re
import socket
import urllib.parse
import requests
from config import Config
from modules.security_utils import sanitize_url, resolve_and_validate_host, SecurityValidationError

HIGH_VALUE_SUBDOMAINS = [
    "api", "dev", "staging", "admin", "vpn", "mail", "portal", "app", 
    "auth", "login", "sso", "corp", "test", "git", "jenkins", "status", 
    "dashboard", "cloud", "secure", "remote", "intranet", "beta", "cdn", 
    "gateway", "mx", "ns1", "ns2", "webmail", "support", "billing"
]

def clean_domain_input(raw_input):
    """Normalizes input to clean root domain/FQDN."""
    if not raw_input:
        return ""
    cleaned = sanitize_url(raw_input)
    parsed = urllib.parse.urlparse(cleaned)
    host = parsed.hostname or raw_input.strip().lower()
    # Remove leading wildcards if any
    host = re.sub(r"^\*\.", "", host)
    return host

def query_crt_sh(domain, timeout=6.0):
    """
    Queries crt.sh Certificate Transparency logs for historical and active
    certificates registered under %.domain.
    """
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {
        "User-Agent": getattr(Config, "USER_AGENT", "SentinelX-Intelligence/5.0"),
        "Accept": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=timeout)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get("name_value", "")
                # name_value can contain newlines with multiple domains
                for line in name_value.split("\n"):
                    line = line.strip().lower()
                    if line.endswith(domain) and not line.startswith("*"):
                        subdomains.add(line)
    except Exception:
        # crt.sh frequently times out or rate limits - fallback to DNS probes
        pass

    return list(subdomains)

def probe_subdomain_dns(subdomain, timeout=1.5):
    """Probes if a subdomain actively resolves to an IPv4 address."""
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        ip = socket.gethostbyname(subdomain)
        # Check SSRF safety
        try:
            resolve_and_validate_host(subdomain)
            is_internal = False
        except SecurityValidationError:
            is_internal = True

        return {
            "resolves": True,
            "ip": ip,
            "is_internal": is_internal
        }
    except Exception:
        return {
            "resolves": False,
            "ip": None,
            "is_internal": False
        }
    finally:
        socket.setdefaulttimeout(old_timeout)

def enumerate_subdomains(target_input, max_probes=60):
    """
    Main enumeration orchestrator.
    Combines passive CT logs and curated high-frequency dictionary probes.
    """
    domain = clean_domain_input(target_input)
    if not domain or "." not in domain:
        return {
            "success": False,
            "error": "A valid domain (e.g. example.com) is required for subdomain enumeration."
        }

    # SSRF check on base domain
    try:
        resolve_and_validate_host(domain)
    except SecurityValidationError as sve:
        return {
            "success": False,
            "error": f"Target domain violates perimeter isolation: {str(sve)}"
        }
    except Exception:
        pass  # If domain doesn't resolve directly, still allow CT lookup

    discovered = set()

    # 1. Passive CT log query
    ct_subdomains = query_crt_sh(domain)
    for sub in ct_subdomains:
        discovered.add(sub)

    # 2. Add high-value words if discovered list is small
    if len(discovered) < 15:
        for prefix in HIGH_VALUE_SUBDOMAINS:
            candidate = f"{prefix}.{domain}"
            discovered.add(candidate)

    # Sort & cap
    candidate_list = sorted(list(discovered))[:max_probes]

    results = []
    live_count = 0

    for sub in candidate_list:
        probe = probe_subdomain_dns(sub)
        is_live = probe["resolves"]
        if is_live:
            live_count += 1

        results.append({
            "subdomain": sub,
            "ip": probe["ip"] or "Unresolved",
            "status": "LIVE" if is_live else "HISTORICAL / DORMANT",
            "is_live": is_live,
            "is_internal": probe["is_internal"],
            "source": "Certificate Transparency" if sub in ct_subdomains else "Target Probe",
            "risk_tag": "INTERNAL PERIMETER" if probe["is_internal"] else ("EXPOSED STAGING" if any(w in sub for w in ["dev", "staging", "test", "corp", "jenkins"]) else "PUBLIC ASSET")
        })

    # Sort live first
    results.sort(key=lambda x: (not x["is_live"], x["subdomain"]))

    return {
        "success": True,
        "domain": domain,
        "total_discovered": len(results),
        "live_count": live_count,
        "dormant_count": len(results) - live_count,
        "subdomains": results
    }
