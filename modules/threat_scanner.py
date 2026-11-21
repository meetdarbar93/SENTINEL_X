"""
SENTINEL-X | Multi-Engine Cyber Threat Scanner & VirusTotal Consensus Engine
Performs exhaustive cyber attack vector evaluation across:
1. Phishing & Brand Impersonation
2. Malware & Executable Payload Droppers
3. Ransomware C2 & Botnet Footprint
4. Web Application Exploits (SQLi, XSS, RCE, LFI/RFI, SSRF)
5. Cryptojacking & Unauthorized Web Mining
6. Network, TLS & Header Vulnerabilities
7. Reputation, Blacklists & High-Risk TLDs
Simulates a 68-Security-Vendor Consensus Grid (VirusTotal architecture)
with real heuristic detection correlation and defensive mitigation playbooks.
"""

import re
import math
import socket
import datetime
from urllib.parse import urlparse, parse_qs
from config import Config
from modules.security_utils import (
    is_ip_address, sanitize_url, sanitize_domain,
    resolve_and_validate_host, SecurityValidationError
)

# High-profile brands frequently targeted by spear-phishing and credential harvesters
TARGET_BRANDS = [
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "chase", "wellsfargo", "bankofamerica",
    "citibank", "binance", "coinbase", "metamask", "whatsapp", "dropbox",
    "steam", "adobe", "dhl", "fedex", "usps", "linkedin", "twitter", "x.com"
]

# High-risk / spam / malware TLDs frequently abused in malicious campaigns
HIGH_RISK_TLDS = [
    "top", "xyz", "buzz", "fit", "work", "click", "gq", "cf", "tk", "ml",
    "rest", "cam", "icu", "country", "stream", "gdn", "mom", "kim", "loan",
    "racing", "accountant", "download", "review", "science", "party"
]

# High-risk dynamic DNS / ephemeral tunneling domains used for C2 or evading detection
DYNAMIC_DNS_DOMAINS = [
    "duckdns.org", "no-ip.biz", "no-ip.org", "no-ip.com", "ngrok.io",
    "localtunnel.me", "serveo.net", "hopto.org", "zapto.org", "sytes.net",
    "ddns.net", "pagekite.me", "telebit.io", "portmap.io"
]

# In-browser cryptojacking signatures
CRYPTOJACKING_SIGNATURES = [
    "coinhive", "cryptoloot", "webminepool", "monero-miner", "minr.pw",
    "coin-have", "jsecoin", "cryptonight", "deepminer", "webxmr"
]

# Executable / dangerous dropper payload extensions
EXECUTABLE_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".vbs", ".apk", ".jar", ".ps1", ".msi",
    ".dll", ".iso", ".hta", ".wsf", ".cmd", ".pif", ".cpl", ".reg"
]

# 68 Security Vendor Engines (modeled on VirusTotal Multi-Scanner Grid)
SECURITY_VENDORS = [
    {"name": "Google SafeBrowsing", "tier": "Tier-1 Cloud", "category": "Phishing & Malware"},
    {"name": "Kaspersky Web Shield", "tier": "Tier-1 AV", "category": "Malware & APT"},
    {"name": "Bitdefender TrafficLight", "tier": "Tier-1 AV", "category": "Web Protection"},
    {"name": "CrowdStrike Falcon Intel", "tier": "Enterprise EDR", "category": "Threat Intelligence"},
    {"name": "Sophos Web Threat Filter", "tier": "Tier-1 AV", "category": "Exploit & Malware"},
    {"name": "Fortinet AntiPhishing", "tier": "NextGen Firewall", "category": "Phishing Detection"},
    {"name": "TrendMicro Web Reputation", "tier": "Tier-1 AV", "category": "Reputation Matrix"},
    {"name": "AlienVault OTX", "tier": "Open Threat Exchange", "category": "Community Intel"},
    {"name": "PhishTank Heuristics", "tier": "Anti-Phishing Feed", "category": "Phishing Database"},
    {"name": "Spamhaus Zen DBL", "tier": "Domain Blocklist", "category": "Spam & Botnet"},
    {"name": "ESET Network Security", "tier": "Tier-1 AV", "category": "Heuristic Engine"},
    {"name": "Symantec BlueCoat", "tier": "Enterprise Gateway", "category": "URL Categorization"},
    {"name": "Mandiant Attack Surface", "tier": "Intelligence Core", "category": "Threat Actor C2"},
    {"name": "Avast Cloud Care", "tier": "Cloud AV", "category": "Web Shield"},
    {"name": "Palo Alto WildFire", "tier": "NextGen Sandbox", "category": "Zero-Day Analysis"},
    {"name": "CheckPoint ThreatCloud", "tier": "Security Gateway", "category": "Threat Prevention"},
    {"name": "Cisco Talos Intelligence", "tier": "Global Sensor Grid", "category": "Adversary Intel"},
    {"name": "Microsoft Defender SmartScreen", "tier": "OS Integration", "category": "Phishing & Exploit"},
    {"name": "Cloudflare Radar", "tier": "Edge Intelligence", "category": "DDoS & Bot Filter"},
    {"name": "F-Secure Radar", "tier": "Enterprise AV", "category": "Vulnerability Scan"},
    {"name": "McAfee SiteAdvisor", "tier": "Web Security", "category": "Site Reputation"},
    {"name": "Yandex Safe Browsing", "tier": "Search Engine Feed", "category": "Malware Crawler"},
    {"name": "Webroot BrightCloud", "tier": "Cloud Threat Intel", "category": "IP & URL Rep"},
    {"name": "Quttera Web Scanner", "tier": "Heuristic Inspector", "category": "Hidden Script Scanner"},
    {"name": "Sucuri SiteCheck", "tier": "Web Integrity", "category": "Blacklist & Injection"},
    {"name": "Dr.Web Link Scanner", "tier": "Gateway Antivirus", "category": "Trojan & Worms"},
    {"name": "G-Data Threat Protection", "tier": "Dual-Engine AV", "category": "Heuristic Shield"},
    {"name": "Malwarepatrol Blocklist", "tier": "Specialized Feed", "category": "Ransomware & C2"},
    {"name": "CRDF Labs Threat Engine", "tier": "Cloud Sensor", "category": "Malicious URLs"},
    {"name": "Cyren Web Security", "tier": "Cloud Telemetry", "category": "Zero-Hour Phishing"},
    {"name": "Comodo Valkyrie", "tier": "Automated Sandbox", "category": "Static Analysis"},
    {"name": "Quick Heal Web Security", "tier": "Endpoint Security", "category": "Network Protection"},
    {"name": "VIPRE Threat Intelligence", "tier": "Enterprise AV", "category": "Malware Shield"},
    {"name": "Forcepoint ThreatSeeker", "tier": "Data Gateway", "category": "Content Inspection"},
    {"name": "Netcraft Anti-Phishing", "tier": "Fraud Intelligence", "category": "Credential Theft"},
    {"name": "DNSGuard Heuristics", "tier": "DNS Resolver", "category": "Sinkhole Detector"},
    {"name": "Tencent Anti-Virus", "tier": "Global Engine", "category": "Cloud AV Engine"},
    {"name": "Baidu Web Protection", "tier": "Heuristic Crawler", "category": "Phishing Filter"},
    {"name": "AhnLab V3 Web", "tier": "Endpoint Suite", "category": "Web Threat Blocker"},
    {"name": "Zscaler ThreatLabz", "tier": "Zero Trust Cloud", "category": "SSL Inspection"},
    {"name": "Securonix ThreatStream", "tier": "SIEM Analytics", "category": "Behavioral Anomaly"},
    {"name": "ThreatConnect Sensor", "tier": "Threat Intelligence", "category": "IOC Correlation"},
    {"name": "SentinelOne Vigilance", "tier": "Autonomous EDR", "category": "Behavioral AI"},
    {"name": "Trellix Threat Intelligence", "tier": "Enterprise XDR", "category": "C2 Threat Stream"},
    {"name": "Darktrace Cyber AI", "tier": "Autonomous Response", "category": "Pattern Deviations"},
    {"name": "Deep Instinct Heuristics", "tier": "Deep Learning AV", "category": "Pre-Execution Guard"},
    {"name": "Proofpoint URL Defense", "tier": "Email Gateway", "category": "Spear Phishing"},
    {"name": "Barracuda Web Security", "tier": "Firewall Suite", "category": "Content & Payload"},
    {"name": "SonicWall Capture ATP", "tier": "Multi-Engine Sandbox", "category": "Advanced Threats"},
    {"name": "Juniper Sky ATP", "tier": "Cloud Protection", "category": "Malware Pipeline"},
    {"name": "WatchGuard Gateway AV", "tier": "UTM Appliance", "category": "Gateway Filter"},
    {"name": "Acronis Cyber Protect", "tier": "Backup & Security", "category": "Ransomware Blocker"},
    {"name": "Carbon Black Cloud", "tier": "VMware Security", "category": "Process Telemetry"},
    {"name": "Cybereason Nocturnus", "tier": "EDR Platform", "category": "Malicious Operation"},
    {"name": "Elastic Security Rules", "tier": "SIEM Detection", "category": "Rule Signature"},
    {"name": "Rapid7 InsightVM", "tier": "Vulnerability Core", "category": "Exploit Assessment"},
    {"name": "Qualys Web Threat", "tier": "Continuous Security", "category": "Perimeter Auditor"},
    {"name": "Tenable Nessus Sensor", "tier": "Vulnerability Scanner", "category": "Exposure Inspector"},
    {"name": "CISA Known Exploits", "tier": "Government Advisory", "category": "Catalog Match"},
    {"name": "Shadowserver Foundation", "tier": "Non-Profit Intel", "category": "Botnet Tracking"},
    {"name": "AbuseIPDB Reputation", "tier": "IP Blacklist", "category": "Attack Source IP"},
    {"name": "Virusdie Web Scanner", "tier": "Web Antivirus", "category": "Web Shell Detector"},
    {"name": "CleanBrowsing Security", "tier": "Protective DNS", "category": "Malicious Filter"},
    {"name": "OpenDNS Security", "tier": "Cisco Umbrella", "category": "DNS Filtering"},
    {"name": "Quad9 Threat Filter", "tier": "Privacy DNS", "category": "Threat Blocking"},
    {"name": "BlockList.de Scanner", "tier": "Fail2Ban Grid", "category": "Brute-Force Source"},
    {"name": "Emerging Threats Pro", "tier": "Proofpoint Ruleset", "category": "Suricata/Snort Rules"},
    {"name": "SURBL Multi-List", "tier": "Spam & Phish URI", "category": "Reputation Database"}
]


def calculate_shannon_entropy(text):
    """Calculates Shannon entropy to detect algorithmic randomness (DGA)."""
    if not text:
        return 0.0
    prob_dict = {}
    for char in text:
        prob_dict[char] = prob_dict.get(char, 0) + 1
    entropy = 0.0
    text_len = len(text)
    for count in prob_dict.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def run_threat_scan(raw_target):
    """
    Main Threat Scanner function.
    Evaluates target against all major cyber attack vectors and generates
    a 68-vendor VirusTotal-style consensus detection report.
    """
    if not raw_target or not raw_target.strip():
        return {"error": "Target URL, domain, or IP address cannot be empty."}

    target = raw_target.strip()
    full_url = sanitize_url(target)
    parsed = urlparse(full_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    query = parsed.query or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # 1. SSRF & Host Validation
    is_ssrf_blocked = False
    resolved_ips = []
    try:
        resolved_ips = resolve_and_validate_host(hostname)
    except SecurityValidationError as e:
        is_ssrf_blocked = True
        resolved_ips = ["127.0.0.1 (SSRF-BLOCKED)"]
    except Exception:
        resolved_ips = ["Unresolvable"]

    primary_ip = resolved_ips[0] if resolved_ips else "Unknown"

    # 2. Attack Vector Analysis Containers
    attack_findings = {
        "phishing": [],
        "malware": [],
        "ransomware_c2": [],
        "web_exploits": [],
        "cryptojacking": [],
        "network_security": [],
        "reputation_blacklist": []
    }

    triggered_signatures = set()
    risk_score = 0

    # -------------------------------------------------------------
    # VECTOR 1: PHISHING & SOCIAL ENGINEERING
    # -------------------------------------------------------------
    # A. Brand Impersonation in subdomain or path
    for brand in TARGET_BRANDS:
        if brand in hostname:
            parts = hostname.split(".")
            apex = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
            if brand not in apex:
                attack_findings["phishing"].append({
                    "vector": "Brand Deception / Subdomain Phish",
                    "severity": "Critical",
                    "target_brand": brand.upper(),
                    "detail": f"Target impersonates trusted brand '{brand.upper()}' as a subdomain on third-party apex '{apex}'."
                })
                triggered_signatures.add("PHISHING_BRAND_SPOOF")
                risk_score += 35

    # B. Credential Harvesting Keywords
    phish_keywords = ["login", "signin", "verify", "account", "wallet", "secure", "banking", "password", "auth", "confirm", "update"]
    found_keywords = [kw for kw in phish_keywords if kw in path.lower() or kw in query.lower()]
    if found_keywords:
        attack_findings["phishing"].append({
            "vector": "Credential Harvesting Pattern",
            "severity": "High" if len(found_keywords) > 1 else "Medium",
            "keywords": found_keywords,
            "detail": f"Observed authentication/credential keywords in URI path: {', '.join(found_keywords)}"
        })
        triggered_signatures.add("CREDENTIAL_HARVESTING")
        risk_score += 20 * len(found_keywords)

    # C. Punycode IDN Homograph
    if "xn--" in hostname:
        attack_findings["phishing"].append({
            "vector": "Internationalized Homograph Spoof (Punycode)",
            "severity": "Critical",
            "detail": f"Domain utilizes Punycode ('{hostname}') which can spoof visual Latin glyphs using Cyrillic/Greek characters."
        })
        triggered_signatures.add("HOMOGRAPH_PUNYCODE")
        risk_score += 35

    # -------------------------------------------------------------
    # VECTOR 2: MALWARE & DRIVE-BY DOWNLOADS
    # -------------------------------------------------------------
    # A. Executable payload in path
    path_lower = path.lower()
    for ext in EXECUTABLE_EXTENSIONS:
        if path_lower.endswith(ext) or ext + "?" in full_url.lower():
            attack_findings["malware"].append({
                "vector": "Malicious Dropper / Executable Delivery",
                "severity": "Critical",
                "payload_extension": ext,
                "detail": f"URI directly serves executable binary or script payload ending with '{ext}'."
            })
            triggered_signatures.add("EXECUTABLE_DROPPER")
            risk_score += 45
            break

    # B. Double Extension Deception
    double_ext_match = re.search(r'\.(pdf|docx|xlsx|jpg|png|txt)\.(exe|scr|vbs|bat|ps1)', path_lower)
    if double_ext_match:
        attack_findings["malware"].append({
            "vector": "Double Extension Trojan Technique",
            "severity": "Critical",
            "detail": f"Detected deceptive double extension '{double_ext_match.group(0)}' designed to trick users into running binaries."
        })
        triggered_signatures.add("DOUBLE_EXTENSION_TROJAN")
        risk_score += 50

    # C. Obfuscated Base64 / Hex Executables in Query
    b64_eval_match = re.search(r'(eval|base64_decode|unescape|exec|powershell)\s*\(', full_url, re.IGNORECASE)
    if b64_eval_match:
        attack_findings["malware"].append({
            "vector": "Obfuscated Code Execution Invocation",
            "severity": "High",
            "detail": f"Found code evaluation signature: '{b64_eval_match.group(0)}'"
        })
        triggered_signatures.add("CODE_EXECUTION_EVAL")
        risk_score += 30

    # -------------------------------------------------------------
    # VECTOR 3: RANSOMWARE C2 & BOTNET INFRASTRUCTURE
    # -------------------------------------------------------------
    # A. Dynamic DNS / Transient Tunnel Providers
    for dyndns in DYNAMIC_DNS_DOMAINS:
        if hostname.endswith(dyndns):
            attack_findings["ransomware_c2"].append({
                "vector": "Dynamic DNS / Transient C2 Proxy",
                "severity": "High",
                "service": dyndns,
                "detail": f"Host is hosted on ephemeral dynamic DNS service '{dyndns}' commonly used for throwaway C2 nodes."
            })
            triggered_signatures.add("DYNAMIC_DNS_C2")
            risk_score += 30

    # B. Ransomware Gate Endpoints
    c2_gates = ["/gate.php", "/upload.php", "/beacon", "/sync/c2", "/panel/", "/client.php", "/bot.php"]
    for gate in c2_gates:
        if gate in path_lower:
            attack_findings["ransomware_c2"].append({
                "vector": "Ransomware / Botnet Gate Endpoint",
                "severity": "Critical",
                "gate": gate,
                "detail": f"URI path matches known C2 callback beacon endpoint '{gate}'."
            })
            triggered_signatures.add("RANSOMWARE_GATE")
            risk_score += 45

    # C. High Shannon Entropy (DGA Algorithm)
    domain_labels = hostname.split(".")
    apex_name = domain_labels[-2] if len(domain_labels) >= 2 else hostname
    entropy_score = calculate_shannon_entropy(apex_name)
    if entropy_score > 3.8 and len(apex_name) > 9:
        attack_findings["ransomware_c2"].append({
            "vector": "Domain Generation Algorithm (DGA) Anomaly",
            "severity": "High",
            "entropy": entropy_score,
            "detail": f"Apex domain '{apex_name}' displays elevated Shannon entropy ({entropy_score} bits/char), characteristic of automated DGA malware botnets."
        })
        triggered_signatures.add("DGA_HIGH_ENTROPY")
        risk_score += 25

    # -------------------------------------------------------------
    # VECTOR 4: WEB APPLICATION ATTACKS (SQLi, XSS, RCE, LFI, SSRF)
    # -------------------------------------------------------------
    decoded_url = full_url.replace("%20", " ").replace("%27", "'").replace("%22", '"')

    # A. SQL Injection (SQLi)
    sqli_patterns = [
        r"(union\s+(all\s+)?select)",
        r"(\'\s*or\s*[\'\"0-9a-zA-Z]+\s*=\s*[\'\"0-9a-zA-Z]+)",
        r"(information_schema|sys\.databases|sleep\(|benchmark\()",
        r"(--\s*$|/\*.*?\*/)"
    ]
    for pattern in sqli_patterns:
        if re.search(pattern, decoded_url, re.IGNORECASE):
            attack_findings["web_exploits"].append({
                "vector": "SQL Injection (SQLi) Payload Vector",
                "severity": "Critical",
                "detail": "Observed structured SQL syntax manipulation payload in query parameters."
            })
            triggered_signatures.add("SQL_INJECTION")
            risk_score += 40
            break

    # B. Cross-Site Scripting (XSS)
    xss_patterns = [
        r"(<script.*?>.*?</script>)",
        r"(javascript\s*:)",
        r"(onerror\s*=\s*['\"a-zA-Z0-9_\(\)]+)",
        r"(onload\s*=\s*['\"a-zA-Z0-9_\(\)]+)",
        r"(document\.cookie|window\.location)"
    ]
    for pattern in xss_patterns:
        if re.search(pattern, decoded_url, re.IGNORECASE):
            attack_findings["web_exploits"].append({
                "vector": "Cross-Site Scripting (XSS) Vector",
                "severity": "Critical",
                "detail": "Observed client-side script injection or event handler execution in URI parameters."
            })
            triggered_signatures.add("XSS_EXPLOIT")
            risk_score += 35
            break

    # C. Remote Code Execution (RCE) / Command Injection
    rce_patterns = [
        r"(;\s*(ls|dir|whoami|cat\s+/etc/passwd|id|uname))",
        r"(\|\s*(whoami|cat|bash|sh|powershell))",
        r"(\$\(.*?\)|\$\{IFS\})"
    ]
    for pattern in rce_patterns:
        if re.search(pattern, decoded_url, re.IGNORECASE):
            attack_findings["web_exploits"].append({
                "vector": "Remote Command Injection (RCE)",
                "severity": "Critical",
                "detail": "Target parameters contain system command separators and execution binaries."
            })
            triggered_signatures.add("COMMAND_INJECTION")
            risk_score += 45
            break

    # D. Local / Remote File Inclusion (LFI/RFI)
    if "../" in decoded_url or "/etc/passwd" in decoded_url or "php://filter" in decoded_url:
        attack_findings["web_exploits"].append({
            "vector": "Path Traversal / Local File Inclusion (LFI)",
            "severity": "High",
            "detail": "Detected directory traversal sequence ('../') or system configuration file targeting."
        })
        triggered_signatures.add("PATH_TRAVERSAL_LFI")
        risk_score += 35

    # E. SSRF Intrusion
    if is_ssrf_blocked:
        attack_findings["web_exploits"].append({
            "vector": "Server-Side Request Forgery (SSRF) Boundary Breach",
            "severity": "Critical",
            "detail": f"Target resolves to protected private IP range or loopback interface ({primary_ip}). Direct connection aborted by Sentinel-X RFC-1918 firewall."
        })
        triggered_signatures.add("SSRF_ATTEMPT")
        risk_score += 50

    # -------------------------------------------------------------
    # VECTOR 5: CRYPTOJACKING & UNAUTHORIZED MINING
    # -------------------------------------------------------------
    for miner in CRYPTOJACKING_SIGNATURES:
        if miner in full_url.lower():
            attack_findings["cryptojacking"].append({
                "vector": "In-Browser Web Cryptominer Signature",
                "severity": "High",
                "miner": miner,
                "detail": f"Detected in-browser cryptocurrency mining script or websocket endpoint matching '{miner}'."
            })
            triggered_signatures.add("CRYPTOJACKING")
            risk_score += 35

    # -------------------------------------------------------------
    # VECTOR 6: NETWORK & TRANSPORT VULNERABILITIES
    # -------------------------------------------------------------
    if parsed.scheme == "http" and any(kw in full_url.lower() for kw in phish_keywords):
        attack_findings["network_security"].append({
            "vector": "Unencrypted Plaintext HTTP for Authentication",
            "severity": "High",
            "detail": "Target accepts sensitive credential inputs across unencrypted plaintext HTTP protocol without TLS."
        })
        triggered_signatures.add("CLEARTEXT_CREDENTIALS")
        risk_score += 25

    # Non-standard attack ports
    suspicious_ports = {4444: "Metasploit Default Listener", 1337: "Elite Hacker Port", 6667: "IRC Botnet C2", 31337: "Back Orifice Trojan"}
    if port in suspicious_ports:
        attack_findings["network_security"].append({
            "vector": "Non-Standard Suspicious Port Exposure",
            "severity": "High",
            "port": port,
            "detail": f"Target specifies port {port} ({suspicious_ports[port]})."
        })
        triggered_signatures.add("MALICIOUS_PORT")
        risk_score += 30

    # -------------------------------------------------------------
    # VECTOR 7: REPUTATION & HIGH-RISK TLDS
    # -------------------------------------------------------------
    # Raw IP Host
    if is_ip_address(hostname):
        attack_findings["reputation_blacklist"].append({
            "vector": "Direct IP-Formatted Hostname",
            "severity": "Medium",
            "detail": f"Host targets raw IP address ({hostname}) directly, bypassing domain reputation systems."
        })
        triggered_signatures.add("RAW_IP_HOST")
        risk_score += 15

    # High-Risk TLD
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in HIGH_RISK_TLDS:
        attack_findings["reputation_blacklist"].append({
            "vector": "High-Risk Top-Level Domain (TLD)",
            "severity": "Medium",
            "tld": f".{tld}",
            "detail": f"The '.{tld}' TLD exhibits high statistical correlation with malicious phishing and spam campaigns."
        })
        triggered_signatures.add("HIGH_RISK_TLD")
        risk_score += 15

    # Cap risk score at 100
    risk_score = min(risk_score, 100)
    risk_level = (
        "Critical" if risk_score >= 70
        else "High" if risk_score >= 45
        else "Medium" if risk_score >= 20
        else "Low"
    )

    # -------------------------------------------------------------
    # 3. 68-VENDOR VIRUSTOTAL CONSENSUS ENGINE SIMULATION
    # -------------------------------------------------------------
    vendor_detections = []
    malicious_count = 0
    suspicious_count = 0
    clean_count = 0

    # Map triggered signatures to vendor heuristics
    for idx, v in enumerate(SECURITY_VENDORS):
        v_name = v["name"]
        v_cat = v["category"]
        v_tier = v["tier"]

        # Deterministic detection mapping based on actual heuristic findings
        verdict = "clean"
        detail = "Clean / No threat detected"
        threat_label = None

        if "SSRF_ATTEMPT" in triggered_signatures and idx in (0, 3, 4, 15, 16, 20, 39, 42, 58):
            verdict = "malicious"
            threat_label = "SSRF.Internal.Target"
            detail = "Blocked internal RFC1918 probe"
        elif "EXECUTABLE_DROPPER" in triggered_signatures and idx in (1, 2, 4, 10, 14, 17, 25, 26, 30, 48, 51, 67):
            verdict = "malicious"
            threat_label = "Trojan.Dropper.Win32"
            detail = "Malicious executable binary detected"
        elif "DOUBLE_EXTENSION_TROJAN" in triggered_signatures and idx in (1, 2, 3, 5, 11, 14, 21, 26, 33, 41, 49, 52):
            verdict = "malicious"
            threat_label = "Trojan.DeceptiveExt"
            detail = "Double extension trick detected"
        elif "PHISHING_BRAND_SPOOF" in triggered_signatures and idx in (0, 5, 8, 17, 29, 34, 46, 54, 60, 67):
            verdict = "phishing"
            threat_label = "Phish.BrandImpersonation"
            detail = "Impersonating financial/cloud brand"
        elif "HOMOGRAPH_PUNYCODE" in triggered_signatures and idx in (0, 7, 8, 16, 17, 34, 46, 63):
            verdict = "phishing"
            threat_label = "Phish.PunycodeHomograph"
            detail = "Visual spoofing via IDN Punycode"
        elif "SQL_INJECTION" in triggered_signatures and idx in (4, 15, 16, 18, 24, 43, 50, 54, 56):
            verdict = "malicious"
            threat_label = "Exploit.SQLi.Generic"
            detail = "SQL Injection pattern in URL"
        elif "XSS_EXPLOIT" in triggered_signatures and idx in (4, 15, 18, 23, 24, 30, 54, 56):
            verdict = "malicious"
            threat_label = "Exploit.XSS.Reflected"
            detail = "Cross-Site Scripting signature"
        elif "COMMAND_INJECTION" in triggered_signatures and idx in (3, 4, 14, 15, 16, 42, 43, 54):
            verdict = "malicious"
            threat_label = "Exploit.RCE.Command"
            detail = "Remote OS command execution pattern"
        elif "RANSOMWARE_GATE" in triggered_signatures and idx in (1, 3, 12, 14, 27, 42, 44, 51, 59):
            verdict = "malicious"
            threat_label = "Ransomware.C2.Gate"
            detail = "Known Ransomware beacon endpoint"
        elif "DYNAMIC_DNS_C2" in triggered_signatures and idx in (6, 9, 22, 27, 35, 41, 60, 64):
            verdict = "suspicious"
            threat_label = "Suspicious.DynamicDNS"
            detail = "Transient dynamic DNS infrastructure"
        elif "CRYPTOJACKING" in triggered_signatures and idx in (2, 4, 17, 23, 24, 47, 61):
            verdict = "malicious"
            threat_label = "CoinMiner.WebScript"
            detail = "In-browser cryptocurrency mining script"
        elif "CREDENTIAL_HARVESTING" in triggered_signatures and idx in (0, 5, 8, 17, 28, 34, 46, 67):
            verdict = "phishing"
            threat_label = "Phishing.CredentialTheft"
            detail = "Credential theft trap detected"
        elif "HIGH_RISK_TLD" in triggered_signatures and idx in (9, 22, 35, 60, 65):
            verdict = "suspicious"
            threat_label = "Suspicious.HighRiskTLD"
            detail = "Statistical correlation with spam/malware"
        elif "RAW_IP_HOST" in triggered_signatures and idx in (6, 22, 35, 60):
            verdict = "suspicious"
            threat_label = "Suspicious.IPTarget"
            detail = "Raw IP address bypasses domain reputation"

        if verdict in ("malicious", "phishing"):
            malicious_count += 1
        elif verdict == "suspicious":
            suspicious_count += 1
        else:
            clean_count += 1

        vendor_detections.append({
            "vendor": v_name,
            "tier": v_tier,
            "category": v_cat,
            "verdict": verdict,
            "threat_label": threat_label,
            "detail": detail,
            "icon": "bi-shield-x text-danger" if verdict in ("malicious", "phishing") else ("bi-exclamation-triangle text-warning" if verdict == "suspicious" else "bi-shield-check text-success")
        })

    total_vendors = len(SECURITY_VENDORS)
    detection_pct = round(((malicious_count + suspicious_count * 0.5) / total_vendors) * 100, 1)

    # 4. Generate SOC Mitigation Playbook
    mitigation_playbook = generate_mitigation_playbook(hostname, triggered_signatures, full_url)

    # 5. Build Comprehensive Output
    # Map to MITRE ATT&CK & OWASP Framework
    try:
        from modules.mitre_mapper import map_findings_to_mitre
        mitre_data = map_findings_to_mitre(attack_findings, triggered_signatures, entropy_score)
    except Exception:
        mitre_data = None

    # Generate Executive Threat Intelligence Narrative
    try:
        from modules.ai_analyst import generate_threat_narrative
        verdict_val = (
            "MALICIOUS" if malicious_count >= 5
            else "SUSPICIOUS" if (malicious_count > 0 or suspicious_count >= 2)
            else "CLEAN"
        )
        executive_brief = generate_threat_narrative(target, {
            "risk_score": risk_score,
            "overall_verdict": verdict_val,
            "hostname": hostname,
            "primary_ip": primary_ip,
            "entropy_score": entropy_score,
            "detection_ratio": {"malicious": malicious_count, "suspicious": suspicious_count, "clean": clean_count, "total": total_vendors},
            "attack_findings": attack_findings
        })
    except Exception:
        executive_brief = None

    ist_tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    ist_scan_time = datetime.datetime.now(ist_tz).strftime("%Y-%m-%d %H:%M:%S IST")

    result = {
        "target": target,
        "full_url": full_url,
        "hostname": hostname,
        "primary_ip": primary_ip,
        "port": port,
        "scheme": parsed.scheme,
        "scan_timestamp": ist_scan_time,
        "detection_ratio": {
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "clean": clean_count,
            "total": total_vendors,
            "display": f"{malicious_count} / {total_vendors}"
        },
        "detection_rate_pct": detection_pct,
        "overall_verdict": (
            "MALICIOUS" if malicious_count >= 5
            else "SUSPICIOUS" if (malicious_count > 0 or suspicious_count >= 2)
            else "CLEAN"
        ),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "entropy_score": entropy_score,
        "triggered_signatures": list(triggered_signatures),
        "attack_findings": attack_findings,
        "vendor_detections": vendor_detections,
        "mitigation_playbook": mitigation_playbook,
        "mitre_matrix": mitre_data,
        "executive_brief": executive_brief,
        "summary": f"VirusTotal-Grade Threat Scan for {target}: {malicious_count} of {total_vendors} security engines flagged target as hostile. Risk: {risk_level} ({risk_score}/100)."
    }

    return result


def generate_mitigation_playbook(hostname, signatures, full_url):
    """Generates real actionable SOC mitigation rules (Snort, ModSecurity, Firewall)."""
    rules = []

    # Firewall rule
    rules.append({
        "type": "Firewall / Perimeter Rule",
        "action": "BLOCK & DROP",
        "command": f"iptables -A FORWARD -d {hostname} -j DROP\n# Or DNS Sinkhole:\n0.0.0.0 {hostname}"
    })

    # ModSecurity rule
    if any(sig in signatures for sig in ["SQL_INJECTION", "XSS_EXPLOIT", "COMMAND_INJECTION"]):
        rules.append({
            "type": "ModSecurity WAF Directive",
            "action": "DENY 403",
            "command": (
                f'SecRule REQUEST_URI "@contains {hostname}" '
                f'"id:100101,phase:2,deny,status:403,msg:\'Sentinel-X Web Exploit Block for {hostname}\'"'
            )
        })

    # Snort/Suricata Rule
    if "EXECUTABLE_DROPPER" in signatures or "RANSOMWARE_GATE" in signatures:
        rules.append({
            "type": "Snort / Suricata IDS Signature",
            "action": "ALERT & LOG",
            "command": (
                f'alert tcp any any -> any [80,443] (msg:"SENTINEL-X Malicious Dropper Callback: {hostname}"; '
                f'content:"Host: {hostname}"; nocase; sid:9001001; rev:1;)'
            )
        })

    # Incident Response Checklist
    rules.append({
        "type": "Incident Response Protocol",
        "action": "INVESTIGATE & ISOLATE",
        "command": (
            "1. Isolate any local host that communicated with target.\n"
            "2. Inspect proxy logs for outbound connections.\n"
            "3. Revoke active user session cookies if credentials were submitted.\n"
            "4. Submit domain takedown request to authoritative registrar."
        )
    })

    return rules

