"""
SENTINEL-X | MITRE ATT&CK & OWASP Matrix Alignment Engine
Correlates observed cyber attack findings, heuristic anomalies, and security vendor
verdicts against official MITRE ATT&CK Enterprise Matrix (Tactics & Techniques)
and OWASP Top 10 (2021) Web Security Standards.
"""

MITRE_TECHNIQUE_DATABASE = {
    "phishing": {
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "subtechnique": True,
        "description": "Adversaries send malicious links to entice targets into navigating to malicious sites or fake credential harvesting login portals.",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
        "owasp": "A07:2021 - Identification and Authentication Failures"
    },
    "credential_harvesting": {
        "technique_id": "T1056.003",
        "technique_name": "Input Capture: Web Portal Capture",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "subtechnique": True,
        "description": "Adversaries install or mimic web login portals with password prompt inputs to capture user credentials.",
        "url": "https://attack.mitre.org/techniques/T1056/003/",
        "owasp": "A07:2021 - Identification and Authentication Failures"
    },
    "dropper": {
        "technique_id": "T1204.001",
        "technique_name": "User Execution: Malicious Link",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "subtechnique": True,
        "description": "Adversaries rely on user actions to execute malicious payload binaries, scripts, or executables delivered via direct download.",
        "url": "https://attack.mitre.org/techniques/T1204/001/",
        "owasp": "A08:2021 - Software and Data Integrity Failures"
    },
    "executable": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "subtechnique": False,
        "description": "Adversaries transfer tools or other files from an external system into a compromised environment.",
        "url": "https://attack.mitre.org/techniques/T1105/",
        "owasp": "A08:2021 - Software and Data Integrity Failures"
    },
    "c2_channel": {
        "technique_id": "T1071.001",
        "technique_name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "subtechnique": True,
        "description": "Adversaries communicate using application layer protocols (HTTP/HTTPS) to avoid detection and mimic legitimate user traffic.",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
        "owasp": "A05:2021 - Security Misconfiguration"
    },
    "dga": {
        "technique_id": "T1568.002",
        "technique_name": "Dynamic Resolution: Domain Generation Algorithms",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "subtechnique": True,
        "description": "Adversaries make use of Domain Generation Algorithms (DGAs) to dynamically produce rendezvous domains for command and control.",
        "url": "https://attack.mitre.org/techniques/T1568/002/",
        "owasp": "A05:2021 - Security Misconfiguration"
    },
    "injection": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "subtechnique": False,
        "description": "Adversaries attempt to exploit vulnerabilities such as SQL injection, XSS, or command injection in public-facing web applications.",
        "url": "https://attack.mitre.org/techniques/T1190/",
        "owasp": "A03:2021 - Injection"
    },
    "cryptojacking": {
        "technique_id": "T1496",
        "technique_name": "Resource Hijacking",
        "tactic": "Impact",
        "tactic_id": "TA0040",
        "subtechnique": False,
        "description": "Adversaries leverage compromised host compute resources to mine cryptocurrencies without authorization.",
        "url": "https://attack.mitre.org/techniques/T1496/",
        "owasp": "A04:2021 - Insecure Design"
    },
    "typosquatting": {
        "technique_id": "T1583.001",
        "technique_name": "Acquire Infrastructure: Domains",
        "tactic": "Resource Development",
        "tactic_id": "TA0042",
        "subtechnique": True,
        "description": "Adversaries acquire deceptive domains (typosquatting, homographs, punycode) to masquerade as trusted entities.",
        "url": "https://attack.mitre.org/techniques/T1583/001/",
        "owasp": "A07:2021 - Identification and Authentication Failures"
    },
    "open_redirect": {
        "technique_id": "T1566.002",
        "technique_name": "Phishing: Open Redirect Abuse",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "subtechnique": True,
        "description": "Adversaries abuse unvalidated redirect cascades to route users from trusted domains to malicious landing pages.",
        "url": "https://attack.mitre.org/techniques/T1566/002/",
        "owasp": "A01:2021 - Broken Access Control"
    },
    "ssrf_probe": {
        "technique_id": "T1090.003",
        "technique_name": "Proxy: Multi-hop / Internal Pivot",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "subtechnique": True,
        "description": "Adversaries attempt to leverage server-side request forgery (SSRF) to access internal metadata and RFC-1918 networks.",
        "url": "https://attack.mitre.org/techniques/T1090/003/",
        "owasp": "A10:2021 - Server-Side Request Forgery (SSRF)"
    }
}

def map_findings_to_mitre(attack_findings, triggered_signatures=None, entropy_score=0.0):
    """
    Analyzes findings and builds a structured MITRE ATT&CK Matrix & OWASP alignment.
    """
    triggered_signatures = triggered_signatures or []
    matched_keys = set()

    # Heuristic signature checks
    sig_str = " ".join([str(s).lower() for s in triggered_signatures])
    finding_str = ""
    if isinstance(attack_findings, list):
        finding_str = " ".join([f.get("finding", "") + " " + f.get("description", "") for f in attack_findings]).lower()
    elif isinstance(attack_findings, dict):
        for k, v in attack_findings.items():
            if isinstance(v, list):
                finding_str += " " + " ".join([str(x) for x in v]).lower()

    combined = f"{sig_str} {finding_str}"

    if "phish" in combined or "credential" in combined or "login" in combined or "password" in combined:
        matched_keys.add("phishing")
        matched_keys.add("credential_harvesting")
    if "dropper" in combined or "malware_dropper" in combined:
        matched_keys.add("dropper")
        matched_keys.add("executable")
    if "exe" in combined or "executable" in combined or "payload" in combined:
        matched_keys.add("executable")
    if "c2" in combined or "botnet" in combined or "command" in combined:
        matched_keys.add("c2_channel")
    if "dga" in combined or entropy_score >= 3.6:
        matched_keys.add("dga")
    if "injection" in combined or "sqli" in combined or "xss" in combined:
        matched_keys.add("injection")
    if "crypto" in combined or "miner" in combined:
        matched_keys.add("cryptojacking")
    if "typo" in combined or "punycode" in combined or "brand" in combined or "spoof" in combined:
        matched_keys.add("typosquatting")
    if "redirect" in combined:
        matched_keys.add("open_redirect")
    if "ssrf" in combined or "internal_ip" in combined:
        matched_keys.add("ssrf_probe")

    # If completely clean, map reconnaissance baseline
    if not matched_keys:
        return {
            "has_threat_mappings": False,
            "overall_mitre_posture": "BENIGN / RECONNAISSANCE ONLY",
            "tactics": [],
            "techniques": [],
            "owasp_top10": [],
            "mitigation_framework": "No active adversarial tactics or techniques observed. Maintain standard zero-trust perimeter telemetry."
        }

    techniques = []
    tactics_map = {}
    owasp_set = set()

    for key in matched_keys:
        item = MITRE_TECHNIQUE_DATABASE.get(key)
        if not item:
            continue
        techniques.append(item)
        owasp_set.add(item["owasp"])
        tactic_name = item["tactic"]
        if tactic_name not in tactics_map:
            tactics_map[tactic_name] = {
                "tactic": tactic_name,
                "tactic_id": item["tactic_id"],
                "techniques": []
            }
        tactics_map[tactic_name]["techniques"].append({
            "id": item["technique_id"],
            "name": item["technique_name"],
            "url": item["url"]
        })

    return {
        "has_threat_mappings": True,
        "overall_mitre_posture": f"{len(tactics_map)} TACTICS &bull; {len(techniques)} TECHNIQUES IDENTIFIED",
        "tactics": list(tactics_map.values()),
        "techniques": techniques,
        "owasp_top10": sorted(list(owasp_set)),
        "mitigation_framework": "Enforce endpoint application control (M1038), perimeter DNS sinkholing (M1040), and multi-factor authentication enforcement (M1032)."
    }
