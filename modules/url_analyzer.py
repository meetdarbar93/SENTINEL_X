import re
import base64
from urllib.parse import urlparse, parse_qs
from config import Config
from modules.security_utils import is_ip_address, sanitize_url, resolve_and_validate_host, SecurityValidationError
from modules.redirect_analyzer import inspect_redirects
from modules.risk_engine import RiskEngine
from modules.domain_intelligence import get_ssl_details

# Known high-value targets frequently spoofed in phishing/typosquatting
WELL_KNOWN_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", 
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica", 
    "coinbase", "binance", "metamask", "whatsapp", "dropbox", "dhl", "fedex"
]

def analyze_url_structure(raw_url):
    """
    Parses and decomposes URL components into detailed structural attributes.
    """
    clean_url = sanitize_url(raw_url)
    parsed = urlparse(clean_url)
    
    hostname = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None)
    
    # Subdomain parsing
    domain_labels = hostname.split(".") if hostname else []
    subdomain_count = max(0, len(domain_labels) - 2) if len(domain_labels) > 2 else 0
    
    # Query parameters
    query_params = parse_qs(parsed.query)
    formatted_params = [{"key": k, "values": v} for k, v in query_params.items()]
    
    return {
        "full_url": clean_url,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "netloc": parsed.netloc,
        "port": port,
        "is_default_port": (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80),
        "path": parsed.path or "/",
        "query": parsed.query,
        "fragment": parsed.fragment,
        "total_length": len(clean_url),
        "path_length": len(parsed.path or ""),
        "query_params": formatted_params,
        "query_params_count": len(formatted_params),
        "domain_labels": domain_labels,
        "subdomain_depth": subdomain_count
    }

def detect_suspicious_patterns(structure, raw_url):
    """
    Evaluates URL against known threat heuristics and structural anomalies.
    Returns list of triggered indicator dictionaries for RiskEngine.
    """
    indicators = []
    hostname = structure["hostname"]
    path = structure["path"].lower()
    query = structure["query"].lower()
    full_url = structure["full_url"]
    
    # 1. IP address instead of domain
    if is_ip_address(hostname):
        indicators.append({
            "id": "IP_AS_HOST",
            "title": "Raw IP Address Used in Place of Domain Name",
            "severity": "High",
            "points": 25,
            "description": f"The URL directly targets an IP address ({hostname}) rather than a registered domain name. Legitimate web services rarely present raw IP addresses to users.",
            "recommendation": "Avoid interacting with IP-based endpoints unless working within a verified private lab or internal testing perimeter."
        })
        
    # 2. Punycode Domain (Homograph Attack)
    if "xn--" in hostname:
        indicators.append({
            "id": "PUNYCODE_HOMOGRAPH",
            "title": "Punycode (IDN) Internationalized Domain Detected",
            "severity": "High",
            "points": 20,
            "description": f"Domain '{hostname}' utilizes Punycode encoding (xn--). Cyber adversaries frequently exploit Internationalized Domain Names for homograph impersonation attacks (using Cyrillic or Greek characters that look identical to Latin).",
            "recommendation": "Inspect the decoded Unicode characters carefully to verify the domain is not mimicking a reputable service."
        })
        
    # 3. '@' Symbol in URL (Destination / Credential Spoofing)
    if "@" in raw_url:
        indicators.append({
            "id": "AT_SYMBOL_SPOOFING",
            "title": "Embedded '@' Symbol in URL (Credential Spoofing)",
            "severity": "Critical",
            "points": 30,
            "description": "The URL contains an '@' character. Browsers treat content before '@' as user credentials and route traffic to the hostname after the '@', which can easily deceive victims into misidentifying the true destination.",
            "recommendation": "Do not navigate to URLs containing '@' characters in browser address bars."
        })
        
    # 4. URL Shortener Service
    for shortener in Config.URL_SHORTENERS:
        if hostname == shortener or hostname.endswith("." + shortener):
            indicators.append({
                "id": "URL_SHORTENER",
                "title": f"Known URL Shortening Service Detected ({shortener})",
                "severity": "Medium",
                "points": 15,
                "description": f"The target URL is routed through '{shortener}', an intermediate link shortening gateway that conceals the ultimate landing page destination.",
                "recommendation": "Always review the full redirect inspection chain to verify the ultimate destination before trusting the link."
            })
            break
            
    # 5. Excessive Subdomain Depth
    if structure["subdomain_depth"] >= 3:
        indicators.append({
            "id": "EXCESSIVE_SUBDOMAINS",
            "title": f"Excessive Subdomain Depth ({structure['subdomain_depth']} levels)",
            "severity": "Medium",
            "points": 15,
            "description": f"The domain employs {structure['subdomain_depth']} nested subdomain levels. Threat actors often chain arbitrary subdomains on dynamic DNS or free hosting services to evade domain-level reputation filters.",
            "recommendation": "Verify whether the root parent domain is an authoritative organization or a public cloud wildcard host."
        })
        
    # 6. Misleading Brand Impersonation / Typosquatting
    for brand in WELL_KNOWN_BRANDS:
        if brand in hostname:
            # Check if it's the real brand or impersonation
            is_real_brand = (hostname == f"{brand}.com" or 
                             hostname.endswith(f".{brand}.com") or 
                             hostname == f"{brand}.org" or 
                             hostname.endswith(f".{brand}.org"))
            if not is_real_brand:
                indicators.append({
                    "id": "BRAND_TYPOSQUATTING",
                    "title": f"Suspected Brand Impersonation / Typosquatting ('{brand}')",
                    "severity": "High",
                    "points": 25,
                    "description": f"The hostname '{hostname}' references the recognized brand '{brand}', but does not originate from the official authoritative domain. This is a common indicator of credential harvesting or brand spoofing.",
                    "recommendation": "Navigate directly to the verified official portal of the brand rather than clicking through external links."
                })
                break
                
    # 7. Non-standard Ports
    if not structure["is_default_port"] and structure["port"] not in [8080, 8443]:
        indicators.append({
            "id": "NON_STANDARD_PORT",
            "title": f"Non-Standard Service Port Specified (Port {structure['port']})",
            "severity": "Medium",
            "points": 15,
            "description": f"The URL directs connections to non-standard port {structure['port']} instead of standard web ports (80 HTTP, 443 HTTPS). Unusual ports are commonly seen in command-and-control (C2) callbacks or rogue backdoors.",
            "recommendation": "Confirm whether the port is an authorized corporate web proxy or staging endpoint before connecting."
        })
        
    # 8. Dangerous / Executable File Extensions
    for ext in Config.SUSPICIOUS_EXTENSIONS:
        if path.endswith(ext) or f"{ext}?" in full_url.lower():
            indicators.append({
                "id": "SUSPICIOUS_FILE_EXTENSION",
                "title": f"Potentially Dangerous File Download Extension ('{ext}')",
                "severity": "Critical",
                "points": 30,
                "description": f"The URL path directly references an executable or script payload with extension '{ext}'. Visiting this link may prompt automatic file download or payload delivery.",
                "recommendation": "Do not execute downloaded files from untrusted links. Inspect suspicious payloads in an isolated sandbox."
            })
            break
            
    # 9. Phishing Keywords in Path or Query
    matched_keywords = []
    for kw in Config.SUSPICIOUS_KEYWORDS:
        if kw in path or kw in query:
            matched_keywords.append(kw)
            
    if matched_keywords:
        indicators.append({
            "id": "PHISHING_KEYWORDS",
            "title": f"Credential / Financial Keywords Present ({', '.join(matched_keywords[:3])})",
            "severity": "Medium",
            "points": 15,
            "description": f"The URL contains sensitive authentication or account keywords: {', '.join(matched_keywords)}. Phishing landing pages heavily incorporate these terms in their URI paths to deceive users.",
            "recommendation": "Ensure you are authenticated on an officially verified domain before entering login credentials or financial information."
        })
        
    # 10. Obfuscated Encoding or Anomalous Characters
    has_double_encoding = "%25" in full_url
    has_null_byte = "%00" in full_url
    has_hex_obfuscation = bool(re.search(r'%[0-9a-fA-F]{2}', path))
    
    if has_double_encoding or has_null_byte:
        indicators.append({
            "id": "ENCODING_ANOMALY",
            "title": "Obfuscated / Double URL Percent-Encoding Detected",
            "severity": "High",
            "points": 20,
            "description": "The URL incorporates nested percent-encoding (%25) or null-byte characters (%00), frequently utilized to bypass Web Application Firewall (WAF) filters or input sanitizers.",
            "recommendation": "Analyze the fully decoded target to verify whether it attempts directory traversal or command injection."
        })
        
    # 11. Plain Unencrypted HTTP
    if structure["scheme"] == "http":
        indicators.append({
            "id": "UNENCRYPTED_HTTP",
            "title": "Unencrypted HTTP Protocol (Cleartext Transmission)",
            "severity": "Low",
            "points": 10,
            "description": "The URL transmits information over unencrypted HTTP. Data sent across this connection is susceptible to eavesdropping, tampering, and Man-in-the-Middle (MitM) attacks.",
            "recommendation": "Prefer HTTPS connections to guarantee transport layer confidentiality and cryptographic integrity."
        })
        
    # 12. Excessive URL Length
    if structure["total_length"] > 140:
        indicators.append({
            "id": "EXCESSIVE_URL_LENGTH",
            "title": f"Excessive URL Length ({structure['total_length']} characters)",
            "severity": "Low",
            "points": 10,
            "description": "The URL length exceeds standard thresholds. Long URLs can be utilized to push the true destination or malicious parameters off the visible portion of the address bar.",
            "recommendation": "Deconstruct query parameters to inspect whether tracking tokens or serialized payloads are embedded."
        })
        
    return indicators

def analyze_url_comprehensive(raw_url):
    """
    Master URL Security Analyzer.
    Conducts structural parsing, suspicious pattern detection, safe redirect inspection,
    domain resolution, SSL verification, and transparent risk scoring.
    """
    clean_url = sanitize_url(raw_url)
    
    # 1. Structure Analysis
    structure = analyze_url_structure(clean_url)
    hostname = structure["hostname"]
    
    # SSRF & Safe Host Check
    resolved_ips = []
    is_blocked = False
    block_reason = None
    
    try:
        resolved_ips = resolve_and_validate_host(hostname)
    except SecurityValidationError as e:
        is_blocked = True
        block_reason = str(e)
        
    # 2. Suspicious Pattern Detection
    indicators = detect_suspicious_patterns(structure, raw_url)
    
    # If blocked by SSRF
    if is_blocked:
        indicators.append({
            "id": "SSRF_BLOCKED",
            "title": "Blocked by SSRF Protection Policy",
            "severity": "Critical",
            "points": 75,
            "description": f"Connection blocked: {block_reason}. The destination target resolves to a private, loopback, or cloud metadata address.",
            "recommendation": "Sentinel-X strictly blocks connections to internal network assets to prevent Server-Side Request Forgery."
        })
        
    # 3. Redirect Analysis (Safe)
    redirect_info = None
    if not is_blocked:
        try:
            redirect_info = inspect_redirects(clean_url)
            # Evaluate redirect indicators
            if redirect_info.get("has_downgrade"):
                indicators.append({
                    "id": "REDIRECT_DOWNGRADE",
                    "title": "HTTPS to HTTP Downgrade During Redirect Chain",
                    "severity": "High",
                    "points": 25,
                    "description": "The redirect chain downgraded an encrypted HTTPS connection to cleartext HTTP, exposing subsequent communications to interception.",
                    "recommendation": "Investigate why the server routes secure sessions to unencrypted endpoints."
                })
            if redirect_info.get("has_loop"):
                indicators.append({
                    "id": "REDIRECT_LOOP",
                    "title": "Redirect Loop Detected",
                    "severity": "Medium",
                    "points": 15,
                    "description": "The URL redirects circularly back into itself, causing a denial of service for the client connection.",
                    "recommendation": "Check web server routing and rewrite rules."
                })
            if redirect_info.get("excessive_redirects"):
                indicators.append({
                    "id": "EXCESSIVE_REDIRECTS",
                    "title": "Excessive Redirect Chain Exceeded Threshold",
                    "severity": "Medium",
                    "points": 15,
                    "description": "The URL traversed multiple consecutive redirect hops, a tactic frequently used by evasion campaigns to complicate telemetry tracking.",
                    "recommendation": "Review the final destination URL directly."
                })
        except Exception as e:
            redirect_info = {"error": str(e), "total_hops": 0, "chain": []}
            
    # 4. Domain & SSL Details
    ssl_summary = None
    if not is_blocked and not is_ip_address(hostname):
        ssl_summary = get_ssl_details(hostname)
        if ssl_summary.get("is_expired"):
            indicators.append({
                "id": "EXPIRED_SSL",
                "title": "Expired SSL/TLS Certificate",
                "severity": "High",
                "points": 20,
                "description": f"The host's SSL certificate expired on {ssl_summary.get('valid_to')}.",
                "recommendation": "Renew the certificate or discontinue entering sensitive data on this host."
            })
            
    # 5. Risk Assessment Engine Evaluation
    risk_evaluation = RiskEngine.evaluate(indicators)
    
    # 6. Domain details bundle
    domain_details = {
        "hostname": hostname,
        "resolved_ip": resolved_ips[0] if resolved_ips else "Unavailable",
        "all_ips": resolved_ips,
        "is_ip_host": is_ip_address(hostname),
        "is_blocked": is_blocked,
        "block_reason": block_reason,
        "ssl_available": ssl_summary.get("available", False) if ssl_summary else False,
        "ssl_info": ssl_summary
    }
    
    # High-level summary string
    summary = f"Analyzed {structure['hostname']} - Risk: {risk_evaluation['level']} ({risk_evaluation['score']}/100) with {len(indicators)} detected indicators."
    
    return {
        "target_url": clean_url,
        "url_structure": structure,
        "domain_details": domain_details,
        "redirect_analysis": redirect_info,
        "risk_assessment": risk_evaluation,
        "summary": summary
    }
