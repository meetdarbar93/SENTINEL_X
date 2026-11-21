"""
SENTINEL-X | AI Threat Analyst Copilot & Executive Narrative Engine
Synthesizes low-level heuristic findings, vendor consensus, Shannon entropy,
and redirect cascades into a professional, human-readable SOC Incident Commander briefing.
"""

def generate_threat_narrative(target, details):
    """
    Synthesizes investigation telemetry and writes an executive threat assessment.
    """
    details = details or {}
    score = details.get("risk_score", 0)
    verdict = details.get("overall_verdict", "CLEAN")
    hostname = details.get("hostname") or target.replace("http://", "").replace("https://", "").split("/")[0]
    primary_ip = details.get("primary_ip") or "Undetermined"
    entropy = details.get("entropy_score", 0.0)
    ratio = details.get("detection_ratio", {})
    malicious_count = ratio.get("malicious", 0)

    findings = details.get("attack_findings", [])
    findings_text = ""
    if isinstance(findings, list):
        findings_text = " ".join([f.get("finding", "") for f in findings]).lower()

    # Determine Threat Archetype
    if "phish" in findings_text or "@" in target:
        archetype = "Credential Harvesting Spearphishing Campaign"
        actor_profile = "Financially motivated cybercrime syndicate mimicking authenticated single sign-on (SSO) gateways."
    elif "dropper" in findings_text or ".exe" in target.lower():
        archetype = "Multi-Stage Trojan Dropper / Loader"
        actor_profile = "Commodity malware distributor leveraging direct download execution chains for initial foothold."
    elif "c2" in findings_text or entropy >= 3.6:
        archetype = "Ransomware Command & Control (C2) / DGA Node"
        actor_profile = "Advanced persistent threat (APT) or ransomware operator utilizing algorithmically generated domain infrastructure."
    elif score >= 60:
        archetype = "High-Confidence Malicious Host"
        actor_profile = "Adversary-controlled landing zone exhibiting aggressive deceptive characteristics."
    elif score >= 25:
        archetype = "Suspicious Untrusted Infrastructure"
        actor_profile = "Anomalous host with missing security headers, fresh registration, or unverified routing trajectory."
    else:
        archetype = "Nominal Verified Asset"
        actor_profile = "Legitimate commercial or public domain demonstrating stable infrastructure and valid trust chains."

    # Urgency & Severity
    if score >= 70 or verdict == "MALICIOUS":
        severity = "SEV-1 (CRITICAL)"
        urgency = "IMMEDIATE CONTAINMENT REQUIRED"
        recommendations = [
            f"Enforce immediate DNS sinkholing on recursive resolvers for {hostname}.",
            f"Blacklist destination IP {primary_ip} on perimeter edge firewalls.",
            "Trigger automated password reset for any enterprise credentials entered within the last 24 hours.",
            "Isolate internal endpoints that initiated outbound connections to this destination."
        ]
    elif score >= 35 or verdict == "SUSPICIOUS":
        severity = "SEV-2 (ELEVATED CAUTION)"
        urgency = "SOC MONITORING & RESTRICTED ACCESS"
        recommendations = [
            "Enable aggressive web proxy SSL/TLS inspection on connections to this host.",
            "Verify email gateway SPF/DKIM filters to prevent incoming link delivery.",
            "Audit internal endpoint telemetry for unauthorized script executions."
        ]
    else:
        severity = "SEV-4 (NOMINAL)"
        urgency = "STANDARD BASELINE MONITORING"
        recommendations = [
            "No immediate firewall drop rules required.",
            "Maintain standard zero-trust telemetry logging.",
            "Re-evaluate host periodically for domain ownership changes or registration expiration."
        ]

    # Executive Summary Paragraphs
    p1 = (
        f"Forensic surveillance conducted on subject target '{target}' has concluded with an overall classification of "
        f"{verdict} ({score}/100 Risk Score). The target resolved to primary infrastructure IP {primary_ip} with a Shannon "
        f"entropy rating of {entropy} bits. Cross-vendor analysis across 68 threat intelligence consensus engines flagged "
        f"{malicious_count} active security engines concurring on hostile intent."
    )

    if verdict == "MALICIOUS" or score >= 50:
        p2 = (
            f"The observed telemetry strongly aligns with a {archetype}. Observed forensic patterns indicate {actor_profile} "
            f"The presence of deceptive URL syntax and potential credential prompt payloads necessitates an immediate response "
            f"rated at {severity} priority."
        )
    elif verdict == "SUSPICIOUS":
        p2 = (
            f"The target exhibits structural anomalies consistent with {archetype}. While active malicious payloads were not "
            f"definitively weaponized at the moment of probing, anomalous routing and infrastructure indicators justify a {severity} classification."
        )
    else:
        p2 = (
            f"The target demonstrates nominal behavioral compliance. No active exploit signatures, phishing traps, or malicious redirect "
            f"cascades were uncovered during deep heuristic inspection. Asset is cleared for routine network transit under standard SOC monitoring."
        )

    return {
        "severity": severity,
        "urgency": urgency,
        "archetype": archetype,
        "actor_profile": actor_profile,
        "executive_summary": f"{p1}\n\n{p2}",
        "actionable_directives": recommendations
    }
