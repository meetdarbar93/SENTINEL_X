"""
SENTINEL-X | Multi-Target Batch Threat Matrix Engine
Enables bulk threat intelligence processing for SOC analysts. Scans up to 25 targets
concurrently, aggregates detection consensus, and produces unified risk comparison matrices.
"""

import concurrent.futures
import datetime
from modules.security_utils import sanitize_url, resolve_and_validate_host, SecurityValidationError
from modules.threat_scanner import run_threat_scan

def run_single_scan_worker(target):
    """Worker function for single target scanning in batch thread pool."""
    clean_target = target.strip()
    if not clean_target:
        return None
    try:
        res = run_threat_scan(clean_target)
        findings = res.get("attack_findings", [])
        top_finding = findings[0].get("finding") if (findings and isinstance(findings, list)) else "Nominal Profile"
        ratio = res.get("detection_ratio", {})

        return {
            "target": clean_target,
            "hostname": res.get("hostname", clean_target),
            "primary_ip": res.get("primary_ip", "Undetermined"),
            "risk_score": res.get("risk_score", 0),
            "overall_verdict": res.get("overall_verdict", "CLEAN"),
            "malicious_engines": ratio.get("malicious", 0),
            "suspicious_engines": ratio.get("suspicious", 0),
            "clean_engines": ratio.get("clean", 68),
            "top_finding": top_finding,
            "investigation_id": res.get("investigation_id"),
            "status": "COMPLETED"
        }
    except Exception as e:
        return {
            "target": clean_target,
            "hostname": clean_target,
            "primary_ip": "Error",
            "risk_score": 0,
            "overall_verdict": "ERROR",
            "malicious_engines": 0,
            "suspicious_engines": 0,
            "clean_engines": 0,
            "top_finding": str(e)[:60],
            "investigation_id": None,
            "status": "FAILED"
        }

def process_batch_targets(raw_targets, max_workers=5):
    """
    Parses and processes multiple targets in parallel thread pool.
    """
    if isinstance(raw_targets, str):
        # Split by comma or newline
        lines = [line.strip() for line in raw_targets.replace(",", "\n").split("\n")]
    elif isinstance(raw_targets, list):
        lines = [str(t).strip() for t in raw_targets]
    else:
        return {"success": False, "error": "Invalid targets format. Expected list or text."}

    # Filter empty lines and de-duplicate while preserving order, cap at 20
    seen = set()
    valid_targets = []
    for line in lines:
        if line and line not in seen:
            seen.add(line)
            valid_targets.append(line)
            if len(valid_targets) >= 20:
                break

    if not valid_targets:
        return {"success": False, "error": "No valid URLs or hostnames provided in batch request."}

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(run_single_scan_worker, t): t for t in valid_targets}
        for future in concurrent.futures.as_completed(future_to_target):
            try:
                res = future.result()
                if res:
                    results.append(res)
            except Exception:
                pass

    # Sort results: Malicious first, then Suspicious, then Clean
    def sort_key(item):
        v = item.get("overall_verdict", "")
        if v == "MALICIOUS":
            return (0, -item.get("risk_score", 0))
        elif v == "SUSPICIOUS":
            return (1, -item.get("risk_score", 0))
        return (2, -item.get("risk_score", 0))

    results.sort(key=sort_key)

    total = len(results)
    malicious = sum(1 for r in results if r.get("overall_verdict") == "MALICIOUS")
    suspicious = sum(1 for r in results if r.get("overall_verdict") == "SUSPICIOUS")
    clean = sum(1 for r in results if r.get("overall_verdict") == "CLEAN")

    ist_tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    return {
        "success": True,
        "batch_id": datetime.datetime.now(ist_tz).strftime("BATCH-%Y%m%d%H%M%S"),
        "total_targets": total,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "clean_count": clean,
        "results": results,
        "scanned_at": datetime.datetime.now(ist_tz).strftime("%Y-%m-%d %H:%M:%S IST")
    }
