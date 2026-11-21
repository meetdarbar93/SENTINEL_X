import os
import json
import urllib3
from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash, Response
from config import Config
from database.db import (
    init_db, save_investigation, get_investigations, get_investigation_by_id,
    delete_investigation, clear_all_investigations, get_statistics,
    log_activity, get_recent_activities, get_setting, set_setting
)
from modules.osint_generator import generate_osint_queries
from modules.domain_intelligence import analyze_domain_intelligence
from modules.url_analyzer import analyze_url_comprehensive
from modules.redirect_analyzer import inspect_redirects
from modules.threat_scanner import run_threat_scan
from modules.preview_generator import capture_safe_preview
from modules.threat_graph import generate_threat_graph
from modules.subdomain_scanner import enumerate_subdomains
from modules.batch_scanner import process_batch_targets
from modules.ioc_exporter import generate_stix_bundle, generate_snort_rules, generate_splunk_spl, generate_ioc_csv
from modules.report_generator import generate_pdf_report, generate_json_report
from modules.security_utils import sanitize_domain, sanitize_url, SecurityValidationError

# Disable TLS verification warnings for security scanning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
app.config.from_object(Config)

# Ensure database tables exist
init_db()

# Context processor for global template variables
@app.context_processor
def inject_global_vars():
    return {
        "app_name": Config.APP_NAME,
        "app_subtitle": Config.APP_SUBTITLE,
        "app_tagline": Config.APP_TAGLINE,
        "app_version": Config.APP_VERSION
    }

# -------------------------------------------------------------
# PAGE ROUTES
# -------------------------------------------------------------

@app.route("/")
def dashboard():
    return render_template("dashboard.html", active_page="dashboard")

@app.route("/osint")
def osint_page():
    return render_template("osint.html", active_page="osint")

@app.route("/domain")
def domain_page():
    return render_template("domain.html", active_page="domain")

@app.route("/analyzer")
def analyzer_page():
    return render_template("analyzer.html", active_page="analyzer")

@app.route("/redirects")
def redirects_page():
    return render_template("redirects.html", active_page="redirects")

@app.route("/scanner")
def scanner_page():
    return render_template("scanner.html", active_page="scanner")

@app.route("/history")
def history_page():
    return render_template("history.html", active_page="history")

@app.route("/reports")
def reports_page():
    return render_template("reports.html", active_page="reports")

@app.route("/about")
def about_page():
    return render_template("about.html", active_page="about")

@app.route("/subdomains")
def subdomains_page():
    return render_template("subdomains.html", active_page="subdomains")

@app.route("/settings")
def settings_page():
    return render_template("settings.html", active_page="settings")

# -------------------------------------------------------------
# REST API ENDPOINTS
# -------------------------------------------------------------

@app.route("/api/dashboard/stats", methods=["GET"])
def api_dashboard_stats():
    """Returns aggregated real-time statistics and timeline data from DB."""
    try:
        stats = get_statistics()
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/activity/recent", methods=["GET"])
def api_recent_activity():
    """Returns recent log entries for the SOC notification panel."""
    limit = request.args.get("limit", 10, type=int)
    activities = get_recent_activities(limit=limit)
    return jsonify({"success": True, "activities": activities})

@app.route("/api/osint/generate", methods=["POST"])
def api_osint_generate():
    """Generates categorized OSINT search operator queries for a target domain."""
    data = request.get_json() or {}
    domain = data.get("domain", "").strip()
    
    if not domain:
        return jsonify({"success": False, "error": "Target domain cannot be empty."}), 400
        
    try:
        result = generate_osint_queries(domain)
        if "error" in result:
            return jsonify({"success": False, "error": result["error"]}), 400
            
        # Record into investigation database
        inv_id = save_investigation(
            target=result["domain"],
            inv_type="osint_query",
            risk_score=0,
            risk_level="Info",
            summary=f"Generated {result['total_queries']} OSINT research queries across 10 security categories.",
            details=result
        )
        
        result["investigation_id"] = inv_id
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": f"OSINT query generation failed: {str(e)}"}), 500

@app.route("/api/domain/analyze", methods=["POST"])
def api_domain_analyze():
    """Performs comprehensive domain intelligence (DNS, SSL, HTTP, WHOIS)."""
    data = request.get_json() or {}
    domain = data.get("domain", "").strip()
    
    if not domain:
        return jsonify({"success": False, "error": "Domain name cannot be empty."}), 400
        
    try:
        result = analyze_domain_intelligence(domain)
        if "error" in result:
            status = 403 if result.get("is_blocked") else 400
            return jsonify({"success": False, "error": result["error"]}), status
            
        # Determine risk assessment
        risk_score = 0
        risk_level = "Low"
        summary_notes = []
        
        # Check SSL
        ssl_info = result.get("ssl", {})
        if ssl_info.get("is_expired"):
            risk_score += 25
            summary_notes.append("Expired SSL Certificate")
        elif not ssl_info.get("available"):
            risk_score += 15
            summary_notes.append("No active SSL detected on port 443")
            
        # Check security headers
        sec_summary = result.get("security_score_summary", {})
        present_headers = sec_summary.get("present_security_headers", 0)
        if present_headers < 2:
            risk_score += 10
            summary_notes.append("Minimal HTTP security headers")
            
        risk_score = min(risk_score, 100)
        if risk_score >= 50:
            risk_level = "High"
        elif risk_score >= 25:
            risk_level = "Medium"
            
        summary = f"Domain Audit: {result['domain']} - Primary IP: {result.get('primary_ip', 'N/A')}. " + (", ".join(summary_notes) if summary_notes else "Standard profile.")
        
        # Record into investigation database
        inv_id = save_investigation(
            target=result["domain"],
            inv_type="domain_intelligence",
            risk_score=risk_score,
            risk_level=risk_level,
            summary=summary,
            details=result
        )
        
        result["investigation_id"] = inv_id
        result["risk_score"] = risk_score
        result["risk_level"] = risk_level
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": f"Domain intelligence failed: {str(e)}"}), 500

@app.route("/api/url/analyze", methods=["POST"])
def api_url_analyze():
    """Performs deep URL structure analysis, heuristic anomaly detection, and safe redirect trace."""
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    
    if not url:
        return jsonify({"success": False, "error": "URL parameter cannot be empty."}), 400
        
    try:
        result = analyze_url_comprehensive(url)
        risk = result["risk_assessment"]

        # Generate visual threat topology graph
        try:
            result["threat_graph"] = generate_threat_graph(result["target_url"], details=result)
        except Exception:
            result["threat_graph"] = None

        # Record into database
        inv_id = save_investigation(
            target=result["target_url"],
            inv_type="url_analysis",
            risk_score=risk["score"],
            risk_level=risk["level"],
            summary=result["summary"],
            details=result
        )
        
        result["investigation_id"] = inv_id
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": f"URL analysis error: {str(e)}"}), 500

@app.route("/api/redirects/inspect", methods=["POST"])
def api_redirects_inspect():
    """Audits HTTP/HTTPS redirect chains with SSRF protections and hop telemetry."""
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    
    if not url:
        return jsonify({"success": False, "error": "URL parameter cannot be empty."}), 400
        
    try:
        result = inspect_redirects(url)
        
        # Calculate risk points for redirects
        risk_score = 0
        if result.get("has_downgrade"):
            risk_score += 35
        if result.get("has_loop"):
            risk_score += 25
        if result.get("excessive_redirects"):
            risk_score += 20
        if any(h.get("is_ssrf_blocked") for h in result.get("chain", [])):
            risk_score += 50
            
        risk_score = min(risk_score, 100)
        risk_level = "High" if risk_score >= 60 else "Medium" if risk_score >= 25 else "Low"
        
        summary = f"Redirect trace completed: {result['total_hops']} hop(s). " + (f"Final: {result['final_url']}" if result['total_hops'] > 1 else "Direct endpoint (no redirects).")
        
        inv_id = save_investigation(
            target=result["start_url"],
            inv_type="redirect_inspection",
            risk_score=risk_score,
            risk_level=risk_level,
            summary=summary,
            details=result
        )
        
        result["investigation_id"] = inv_id
        result["risk_score"] = risk_score
        result["risk_level"] = risk_level
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": f"Redirect inspection failed: {str(e)}"}), 500

@app.route("/api/scanner/analyze", methods=["POST"])
def api_threat_scanner_analyze():
    """VirusTotal-grade multi-engine cyber threat and exploit scan."""
    data = request.get_json() or {}
    target = (data.get("target") or data.get("url") or "").strip()

    if not target:
        return jsonify({"success": False, "error": "Target parameter cannot be empty."}), 400

    try:
        result = run_threat_scan(target)

        # Generate visual threat topology graph
        try:
            result["threat_graph"] = generate_threat_graph(target, details=result)
        except Exception:
            result["threat_graph"] = None

        # Save to database
        inv_id = save_investigation(
            target=result["target"],
            inv_type="threat_scan",
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            summary=result["summary"],
            details=result
        )

        result["investigation_id"] = inv_id

        # Log to SOC activity stream
        log_activity(
            "THREAT_SCAN",
            result["target"][:60],
            f"VirusTotal-grade consensus scan: {result['detection_ratio']['display']} engines flagged. Verdict: {result['overall_verdict']}."
        )

        return jsonify({"success": True, "data": result})
    except SecurityValidationError as sve:
        return jsonify({"success": False, "error": str(sve)}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Cyber threat scan failed: {str(e)}"}), 500

@app.route("/api/preview/capture", methods=["POST"])
def api_preview_capture():
    """Captures safe headless DOM preview, strips active scripts, and extracts forms/metadata."""
    data = request.get_json() or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"success": False, "error": "Target parameter cannot be empty."}), 400
    try:
        preview = capture_safe_preview(target)
        if not preview.get("success", False):
            return jsonify({"success": False, "error": preview.get("error", "Safe preview failed.")})
        return jsonify({"success": True, "data": preview})
    except Exception as e:
        return jsonify({"success": False, "error": f"Preview capture failed: {str(e)}"}), 500

@app.route("/api/topology/graph", methods=["POST"])
def api_topology_graph():
    """Generates structured node-link threat graph topology for visualization."""
    data = request.get_json() or {}
    target = (data.get("target") or data.get("url") or "").strip()
    if not target:
        return jsonify({"success": False, "error": "Target parameter cannot be empty."}), 400
    try:
        graph = generate_threat_graph(target, details=data.get("details"))
        if not graph.get("success", False):
            return jsonify({"success": False, "error": graph.get("error", "Graph generation failed.")})
        return jsonify({"success": True, "data": graph})
    except Exception as e:
        return jsonify({"success": False, "error": f"Graph generation failed: {str(e)}"}), 500

@app.route("/api/history", methods=["GET"])
def api_get_history():
    """Returns paginated, filterable investigation history."""
    limit = request.args.get("limit", 50, type=int)
    offset = request.args.get("offset", 0, type=int)
    inv_type = request.args.get("type", "all")
    risk_level = request.args.get("risk", "all")
    search = request.args.get("search", "").strip()
    sort_order = request.args.get("sort", "desc")
    
    records = get_investigations(
        limit=limit,
        offset=offset,
        inv_type=inv_type,
        risk_level=risk_level,
        search=search,
        sort_order=sort_order
    )
    return jsonify({"success": True, "records": records, "count": len(records)})

@app.route("/api/history/<int:inv_id>", methods=["GET"])
def api_get_history_item(inv_id):
    """Retrieves full investigation dossier by ID."""
    record = get_investigation_by_id(inv_id)
    if not record:
        return jsonify({"success": False, "error": "Investigation record not found."}), 404
    return jsonify({"success": True, "record": record})

@app.route("/api/history/<int:inv_id>", methods=["DELETE"])
def api_delete_history_item(inv_id):
    """Deletes an individual investigation record."""
    deleted = delete_investigation(inv_id)
    if deleted:
        log_activity("RECORD_DELETED", f"ID #{inv_id}", f"Investigation record #{inv_id} removed by user.")
        return jsonify({"success": True, "message": f"Record #{inv_id} deleted."})
    return jsonify({"success": False, "error": "Record not found."}), 404

@app.route("/api/history/clear", methods=["POST"])
def api_clear_history():
    """Clears all investigation records with confirmation."""
    clear_all_investigations()
    log_activity("DATABASE_CLEARED", "ALL", "Investigation history database reset.")
    return jsonify({"success": True, "message": "All investigation history has been purged."})

@app.route("/api/reports/pdf/<int:inv_id>", methods=["GET"])
def api_export_pdf(inv_id):
    """Generates and serves downloadable PDF report for a given investigation."""
    record = get_investigation_by_id(inv_id)
    if not record:
        return jsonify({"success": False, "error": "Record not found."}), 404
        
    try:
        pdf_path = generate_pdf_report(record)
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=os.path.basename(pdf_path),
            mimetype="application/pdf"
        )
    except Exception as e:
        return jsonify({"success": False, "error": f"PDF generation error: {str(e)}"}), 500

@app.route("/api/reports/json/<int:inv_id>", methods=["GET"])
def api_export_json(inv_id):
    """Exports standardized JSON report for a given investigation."""
    record = get_investigation_by_id(inv_id)
    if not record:
        return jsonify({"success": False, "error": "Record not found."}), 404
        
    report = generate_json_report(record)
    return jsonify(report)

@app.route("/api/subdomains/scan", methods=["POST"])
def api_subdomains_scan():
    """Discovers subdomains via passive CT logs and active DNS resolution."""
    data = request.get_json() or {}
    domain = (data.get("domain") or data.get("target") or "").strip()
    if not domain:
        return jsonify({"success": False, "error": "Target domain cannot be empty."}), 400
    try:
        result = enumerate_subdomains(domain)
        if not result.get("success", False):
            return jsonify({"success": False, "error": result.get("error", "Subdomain enumeration failed.")})
        log_activity("SUBDOMAIN_SCAN", domain, f"Discovered {result['total_discovered']} subdomains ({result['live_count']} live).")
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": f"Subdomain enumeration error: {str(e)}"}), 500

@app.route("/api/scanner/batch", methods=["POST"])
def api_scanner_batch():
    """Processes multiple targets in parallel thread pool and returns comparative threat matrix."""
    data = request.get_json() or {}
    targets = data.get("targets") or data.get("urls") or []
    if not targets:
        return jsonify({"success": False, "error": "No targets provided for batch analysis."}), 400
    try:
        result = process_batch_targets(targets)
        if not result.get("success", False):
            return jsonify({"success": False, "error": result.get("error", "Batch analysis failed.")})
        log_activity("BATCH_SCAN", f"{result['total_targets']} Targets", f"Completed batch scan: {result['malicious_count']} malicious.")
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": f"Batch threat scan error: {str(e)}"}), 500

@app.route("/api/reports/ioc/<int:inv_id>", methods=["GET"])
def api_export_ioc(inv_id):
    """Exports structured SOC IOC formats (STIX 2.1, Snort, Splunk, CSV) for an investigation."""
    record = get_investigation_by_id(inv_id)
    if not record:
        return jsonify({"success": False, "error": "Record not found."}), 404
        
    fmt = request.args.get("format", "stix").lower()
    details = record.get("details", {}) or {}
    target = record.get("target", "")
    ip = details.get("primary_ip") or details.get("resolved_ip") or "0.0.0.0"
    verdict = details.get("overall_verdict") or record.get("risk_level", "Low").upper()
    score = record.get("risk_score", 0)

    if fmt == "snort" or fmt == "suricata":
        rules = generate_snort_rules(target, ip=ip, verdict=verdict)
        return Response(rules, mimetype="text/plain", headers={"Content-Disposition": f"attachment; filename=sentinelx_ioc_{inv_id}.rules"})
    elif fmt == "splunk":
        spl = generate_splunk_spl(target, ip=ip)
        return Response(spl, mimetype="text/plain", headers={"Content-Disposition": f"attachment; filename=sentinelx_splunk_{inv_id}.spl"})
    elif fmt == "csv":
        csv_data = generate_ioc_csv(target, ip=ip, verdict=verdict, score=score)
        return Response(csv_data, mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename=sentinelx_iocs_{inv_id}.csv"})
    else: # stix 2.1 default
        bundle = generate_stix_bundle(target, ip=ip, threat_level=record.get("risk_level", "Low"), verdict=verdict)
        return jsonify(bundle)

@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    """Gets or updates application settings."""
    if request.method == "POST":
        data = request.get_json() or {}
        for key, val in data.items():
            set_setting(key, val)
        return jsonify({"success": True, "message": "Settings updated."})
    else:
        theme = get_setting("theme", "dark")
        audio_alerts = get_setting("audio_alerts", "false")
        auto_redirect = get_setting("auto_redirect", "true")
        return jsonify({
            "theme": theme,
            "audio_alerts": audio_alerts,
            "auto_redirect": auto_redirect
        })

# -------------------------------------------------------------
# ERROR HANDLERS
# -------------------------------------------------------------

@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Endpoint not found."}), 404
    return render_template("base.html", error_title="404 - Sensor Endpoint Not Found", error_message="The requested investigation module or resource does not exist."), 404

@app.errorhandler(500)
def internal_error(error):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Internal platform error occurred."}), 500
    return render_template("base.html", error_title="500 - Internal Security Sensor Error", error_message="A server-side anomaly was encountered during telemetry processing."), 500

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)

