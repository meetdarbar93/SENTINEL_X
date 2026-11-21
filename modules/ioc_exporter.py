"""
SENTINEL-X | SOC IOC Export Engine
Converts forensic investigation findings into industry standard SOC formats:
- STIX 2.1 JSON Bundle (OASIS Cyber Threat Intelligence standard)
- Snort / Suricata Network Intrusion Detection Rules (IDS/IPS)
- Splunk SPL Threat Hunting Query Strings
- Normalized CSV Threat Indicator Sheets
"""

import json
import uuid
import datetime

def generate_stix_bundle(target, ip=None, threat_level="Low", indicators=None, verdict="CLEAN"):
    """Generates an OASIS STIX 2.1 compliant Cyber Threat Intelligence JSON bundle."""
    bundle_id = f"bundle--{str(uuid.uuid4())}"
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    stix_objects = []

    # 1. Identity Object
    identity_id = f"identity--{str(uuid.uuid4())}"
    stix_objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now_iso,
        "modified": now_iso,
        "name": "Sentinel-X Cyber Intelligence Platform",
        "identity_class": "system"
    })

    # 2. Indicator for URL / Domain
    ind_url_id = f"indicator--{str(uuid.uuid4())}"
    pattern_url = f"[url:value = '{target}']"
    stix_objects.append({
        "type": "indicator",
        "spec_version": "2.1",
        "id": ind_url_id,
        "created": now_iso,
        "modified": now_iso,
        "name": f"Adversarial Target: {target}",
        "description": f"Target evaluated with verdict {verdict} and risk severity {threat_level}.",
        "indicator_types": ["malicious-activity"] if verdict != "CLEAN" else ["benign"],
        "pattern": pattern_url,
        "pattern_type": "stix",
        "valid_from": now_iso,
        "confidence": 85 if verdict == "MALICIOUS" else 50
    })

    # 3. Indicator for IP if present
    if ip and ip != "0.0.0.0" and ip != "Unresolved":
        ind_ip_id = f"indicator--{str(uuid.uuid4())}"
        stix_objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_ip_id,
            "created": now_iso,
            "modified": now_iso,
            "name": f"Infrastructure Host IP: {ip}",
            "description": f"Resolved infrastructure IPv4 address for target {target}.",
            "indicator_types": ["anomalous-activity"],
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix",
            "valid_from": now_iso,
            "confidence": 75
        })

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": stix_objects
    }

def generate_snort_rules(target, ip=None, verdict="MALICIOUS", sid_start=1008001):
    """Generates actionable Snort / Suricata IDS/IPS packet filter rules."""
    rules = []
    clean_host = target.replace("http://", "").replace("https://", "").split("/")[0]

    if ip and ip != "0.0.0.0" and ip != "Unresolved":
        rule_ip = (
            f'alert tcp $HOME_NET any -> {ip} any '
            f'(msg:"SENTINEL-X [BLOCKED HOSTILE C2] Connection to {ip}"; '
            f'flow:to_server,established; classtype:trojan-activity; sid:{sid_start}; rev:1;)'
        )
        rules.append(rule_ip)
        sid_start += 1

    rule_domain = (
        f'drop dns $HOME_NET any -> any 53 '
        f'(msg:"SENTINEL-X [DNS SINKHOLE] Query for suspicious host {clean_host}"; '
        f'content:"{clean_host}"; nocase; classtype:bad-unknown; sid:{sid_start}; rev:1;)'
    )
    rules.append(rule_domain)

    return "\n".join(rules)

def generate_splunk_spl(target, ip=None):
    """Generates ready-to-run Splunk SPL search query for SIEM analyst investigation."""
    clean_host = target.replace("http://", "").replace("https://", "").split("/")[0]
    spl_lines = [
        f'// SENTINEL-X SIEM Hunting Query for {clean_host}',
        f'index=* (dest="{clean_host}" OR dest_ip="{ip or clean_host}" OR url="*{clean_host}*")',
        f'| stats count earliest(_time) as first_seen latest(_time) as last_seen values(action) as firewall_action by src_ip, dest, dest_ip',
        f'| eval duration_hrs = round((last_seen - first_seen) / 3600, 2)',
        f'| sort - count'
    ]
    return "\n".join(spl_lines)

def generate_ioc_csv(target, ip=None, verdict="CLEAN", score=0, timestamp=None):
    """Generates standard CSV comma-separated IOC sheet."""
    ist_tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    timestamp = timestamp or datetime.datetime.now(ist_tz).strftime("%Y-%m-%d %H:%M:%S IST")
    clean_host = target.replace("http://", "").replace("https://", "").split("/")[0]

    rows = [
        "indicator,indicator_type,verdict,risk_score,confidence,feed_source,timestamp",
        f'"{target}","URL","{verdict}",{score},85,"Sentinel-X Intelligence","{timestamp}"',
        f'"{clean_host}","DOMAIN","{verdict}",{score},80,"Sentinel-X Intelligence","{timestamp}"'
    ]
    if ip and ip != "0.0.0.0" and ip != "Unresolved":
        rows.append(f'"{ip}","IPV4","{verdict}",{score},90,"Sentinel-X Intelligence","{timestamp}"')

    return "\n".join(rows)
