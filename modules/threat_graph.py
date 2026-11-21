"""
SENTINEL-X | Interactive Threat Graph & Visual Topology Engine
Generates structured multi-tier node-link graph data representing:
Target Root -> Redirect Trajectory Hops -> DNS Infrastructure (IPs, NS, MX)
-> Detected Attack Vectors -> Flagged Threat Vendor Consensuses.
"""

import urllib.parse
from modules.security_utils import sanitize_url, is_ip_address, resolve_and_validate_host, SecurityValidationError
from modules.domain_intelligence import query_dns_records
from modules.redirect_analyzer import inspect_redirects

def generate_threat_graph(raw_target, details=None):
    """
    Builds an interactive force-directed graph schema (nodes and edges)
    for a given target and optional existing forensic details.
    """
    clean_url = sanitize_url(raw_target)
    parsed = urllib.parse.urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    nodes = []
    edges = []
    node_ids = set()

    def add_node(node_id, label, node_type, sublabel="", color=None, icon=None, size=24, extra=None):
        if node_id in node_ids:
            return
        node_ids.add(node_id)
        nodes.append({
            "id": node_id,
            "label": label,
            "type": node_type,
            "sublabel": sublabel,
            "color": color,
            "icon": icon,
            "size": size,
            "data": extra or {}
        })

    def add_edge(source, target, label="", edge_type="default", color=None, dashed=False):
        edges.append({
            "source": source,
            "target": target,
            "label": label,
            "type": edge_type,
            "color": color,
            "dashed": dashed
        })

    # 1. Central Root Node
    root_risk = (details or {}).get("risk_level", "Medium") if details else "Target"
    root_score = (details or {}).get("risk_score", 0) if details else 0
    root_color = "#EF4444" if root_score >= 60 else "#F59E0B" if root_score >= 25 else "#3B82F6"

    add_node(
        node_id="root",
        label=hostname or clean_url[:28],
        node_type="target",
        sublabel=f"{parsed.scheme.upper()}:{port}",
        color=root_color,
        icon="bi-bullseye",
        size=32,
        extra={"full_url": clean_url, "risk": root_risk, "score": root_score}
    )

    # 2. Redirect Trajectory Hops
    redirect_chain = []
    if details and "redirect_analysis" in details:
        redirect_chain = details["redirect_analysis"].get("chain", [])
    elif details and "chain" in details:
        redirect_chain = details.get("chain", [])
    else:
        # Fast safe redirect trace if not provided
        try:
            red_res = inspect_redirects(clean_url)
            redirect_chain = red_res.get("chain", [])
        except Exception:
            redirect_chain = []

    last_hop_id = "root"
    if redirect_chain and len(redirect_chain) > 1:
        for idx, hop in enumerate(redirect_chain[1:], start=1):
            hop_id = f"hop_{idx}"
            hop_url = hop.get("url", "")
            hop_parsed = urllib.parse.urlparse(hop_url)
            hop_status = hop.get("status_code", 302)
            hop_ip = hop.get("ip", "")

            add_node(
                node_id=hop_id,
                label=f"Hop {idx}: {hop_parsed.hostname or 'Endpoint'}",
                node_type="redirect",
                sublabel=f"HTTP {hop_status}",
                color="#F97316" if hop.get("has_downgrade") else "#8B5CF6",
                icon="bi-signpost-split",
                size=22,
                extra={"url": hop_url, "status": hop_status, "ip": hop_ip}
            )
            add_edge(
                source=last_hop_id,
                target=hop_id,
                label=f"HTTP {hop_status}",
                edge_type="redirect",
                color="#8B5CF6"
            )
            last_hop_id = hop_id

    # 3. DNS Resolution Nodes (A / AAAA records)
    resolved_ips = []
    try:
        resolved_ips = resolve_and_validate_host(hostname)
    except SecurityValidationError:
        resolved_ips = ["127.0.0.1 (SSRF-BLOCKED)"]
    except Exception:
        resolved_ips = []

    if resolved_ips:
        for idx, ip in enumerate(resolved_ips[:4]):
            ip_id = f"ip_{idx}"
            is_ssrf = "SSRF" in ip
            add_node(
                node_id=ip_id,
                label=ip,
                node_type="ip",
                sublabel="IPv4" if ":" not in ip else "IPv6",
                color="#EF4444" if is_ssrf else "#10B981",
                icon="bi-hdd-network",
                size=20,
                extra={"ip": ip, "is_private": is_ssrf}
            )
            add_edge(
                source=last_hop_id,
                target=ip_id,
                label="RESOLVES TO",
                color="#10B981" if not is_ssrf else "#EF4444"
            )

    # 4. Authoritative Nameservers & MX Records
    if hostname and not is_ip_address(hostname):
        try:
            dns_recs = query_dns_records(hostname)
            # NS Records
            for idx, ns in enumerate(dns_recs.get("NS", [])[:3]):
                ns_id = f"ns_{idx}"
                add_node(
                    node_id=ns_id,
                    label=ns,
                    node_type="nameserver",
                    sublabel="Auth NS",
                    color="#0EA5E9",
                    icon="bi-globe2",
                    size=18,
                    extra={"nameserver": ns}
                )
                add_edge(
                    source=last_hop_id,
                    target=ns_id,
                    label="DELEGATED NS",
                    color="#0EA5E9",
                    dashed=True
                )

            # MX Records
            for idx, mx in enumerate(dns_recs.get("MX", [])[:2]):
                mx_id = f"mx_{idx}"
                mx_host = mx.get("exchange", "mail") if isinstance(mx, dict) else str(mx)
                add_node(
                    node_id=mx_id,
                    label=mx_host,
                    node_type="mail",
                    sublabel="Mail Exchange",
                    color="#6366F1",
                    icon="bi-envelope-at",
                    size=18,
                    extra={"exchange": mx_host}
                )
                add_edge(
                    source=last_hop_id,
                    target=mx_id,
                    label="MAIL MX",
                    color="#6366F1",
                    dashed=True
                )
        except Exception:
            pass

    # 5. Detected Cyber Attack Vectors Nodes
    findings = []
    if details:
        if isinstance(details.get("attack_findings"), list):
            findings = details["attack_findings"]
        elif isinstance(details.get("attack_findings"), dict):
            for cat, items in details["attack_findings"].items():
                if isinstance(items, list):
                    for itm in items:
                        findings.append({
                            "category": cat.replace("_", " ").title(),
                            "finding": itm.get("vector", "Threat Anomaly"),
                            "severity": itm.get("severity", "Medium")
                        })
        elif "risk_assessment" in details and "indicators" in details["risk_assessment"]:
            for ind in details["risk_assessment"]["indicators"]:
                findings.append({
                    "category": "Heuristic",
                    "finding": ind.get("title", "Indicator"),
                    "severity": ind.get("severity", "Medium")
                })

    for idx, f in enumerate(findings[:6]):
        atk_id = f"threat_{idx}"
        sev = f.get("severity", "Medium")
        atk_color = "#EF4444" if sev in ("Critical", "High") else "#F59E0B"
        add_node(
            node_id=atk_id,
            label=f.get("finding", f.get("vector", "Attack Vector")),
            node_type="threat",
            sublabel=f.get("category", "Exploit").upper(),
            color=atk_color,
            icon="bi-shield-slash",
            size=22,
            extra={"severity": sev, "category": f.get("category", "Threat")}
        )
        add_edge(
            source="root",
            target=atk_id,
            label=f"EXPLOIT: {sev.upper()}",
            edge_type="threat",
            color=atk_color
        )

    # 6. Consensus Security Vendor Flags (Top vendors flagging malicious)
    vendors = (details or {}).get("vendor_detections", [])
    flagged = [v for v in vendors if v.get("verdict") in ("malicious", "phishing")][:4]
    for idx, v in enumerate(flagged):
        v_id = f"vendor_{idx}"
        add_node(
            node_id=v_id,
            label=v.get("vendor", "Engine"),
            node_type="vendor",
            sublabel=v.get("threat_label", "Malware"),
            color="#DC2626",
            icon="bi-exclamation-octagon",
            size=18,
            extra={"vendor": v.get("vendor"), "verdict": v.get("verdict")}
        )
        # Link to first threat node if available, else root
        threat_link = f"threat_0" if findings else "root"
        add_edge(
            source=threat_link,
            target=v_id,
            label="FLAGGED BY",
            color="#DC2626",
            dashed=True
        )

    return {
        "success": True,
        "target": clean_url,
        "hostname": hostname,
        "nodes": nodes,
        "edges": edges,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "threat_nodes": len(findings),
            "resolved_ips_count": len(resolved_ips),
            "redirect_hops_count": len(redirect_chain)
        }
    }
