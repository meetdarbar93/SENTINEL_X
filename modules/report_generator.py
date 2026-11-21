import os
import json
import datetime
import hashlib

# Python 3.8 hashlib compatibility shim for ReportLab 4.x
_orig_md5 = hashlib.md5
def safe_md5(*args, **kwargs):
    kwargs.pop('usedforsecurity', None)
    return _orig_md5(*args, **kwargs)
hashlib.md5 = safe_md5

try:
    import reportlab.pdfbase.pdfdoc as pdfdoc
    pdfdoc.md5 = safe_md5
except Exception:
    pass

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas
from config import Config

class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and print 'Page X of Y' in footer."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_footer(num_pages)
            super().showPage()
        super().save()

    def draw_footer(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#7A889B"))
        
        # Draw top divider in subtle cyan
        self.setStrokeColor(colors.HexColor("#00F5FF"))
        self.setLineWidth(0.6)
        self.line(36, 40, 576, 40)
        
        # Footer text
        footer_text = f"SENTINEL-X Cyber Intelligence Platform  |  BEYOND THE FIREWALL.  |  GRID: ONLINE"
        self.drawString(36, 28, footer_text)
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 28, page_text)
        self.restoreState()

def generate_pdf_report(inv_record, output_filepath=None):
    """
    Renders an executive-grade cybersecurity analysis dossier in PDF format
    using the Cyberpunk Cyber-Intelligence aesthetic.
    """
    if not output_filepath:
        os.makedirs(Config.REPORTS_DIR, exist_ok=True)
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        target_slug = inv_record.get("target", "target").replace("://", "_").replace("/", "_").replace(":", "_")[:25]
        output_filepath = os.path.join(Config.REPORTS_DIR, f"sentinelx_{target_slug}_{timestamp_str}.pdf")
        
    doc = SimpleDocTemplate(
        output_filepath,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=36,
        bottomMargin=54
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0D1020")
    )
    
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=13,
        textColor=colors.HexColor("#008B99")
    )
    
    section_h1 = ParagraphStyle(
        "SectionH1",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=15,
        textColor=colors.HexColor("#0D1020"),
        spaceBefore=12,
        spaceAfter=5
    )
    
    body_text = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#2B3347")
    )
    
    code_text = ParagraphStyle(
        "DocCode",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#006B77")
    )
    
    table_cell_bold = ParagraphStyle(
        "CellBold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0D1020")
    )
    
    table_cell = ParagraphStyle(
        "CellNormal",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#2B3347")
    )
    
    story = []
    
    # 1. Header Banner Box
    target = inv_record.get("target", "N/A")
    inv_type = inv_record.get("investigation_type", "url_analysis").replace("_", " ").title()
    ist_tz = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
    created_at = inv_record.get("created_at", datetime.datetime.now(ist_tz).strftime("%Y-%m-%d %H:%M:%S IST"))
    risk_score = inv_record.get("risk_score", 0)
    risk_level = inv_record.get("risk_level", "Low")
    details = inv_record.get("details", {})
    
    header_data = [
        [
            Paragraph("<b>SENTINEL-X</b> &bull; CYBER INTELLIGENCE DOSSIER", subtitle_style),
            Paragraph(f"<b>CLEARANCE:</b> LEVEL-5<br/><b>DATE:</b> {created_at}", table_cell)
        ],
        [
            Paragraph(f"<b>TARGET:</b> {target}<br/><b>VECTOR:</b> {inv_type}", code_text),
            Paragraph(f"<b>STATUS:</b> COMPLETED<br/><b>PLATFORM:</b> v{Config.APP_VERSION}", table_cell)
        ]
    ]
    header_table = Table(header_data, colWidths=[340, 200])
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F0F8FF")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#00F5FF")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#B2EBF2")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(header_table)
    story.append(Spacer(1, 14))
    
    # 2. Risk Assessment Summary
    story.append(Paragraph("1. EXECUTIVE RISK ASSESSMENT", section_h1))
    
    # Cyberpunk Risk Colors: Low #00A876, Med #D99B00, High/Critical #D91E44
    risk_color = colors.HexColor("#00A876")
    if risk_level in ("High", "Critical"):
        risk_color = colors.HexColor("#D91E44")
    elif risk_level == "Medium":
        risk_color = colors.HexColor("#D99B00")
        
    risk_data = [
        [
            Paragraph(f"<font size=16 color='{risk_color.hexval()}'><b>{risk_score} / 100</b></font><br/><b>ASSESSED RISK SCORE</b>", table_cell_bold),
            Paragraph(f"<font size=14 color='{risk_color.hexval()}'><b>RATING: {risk_level.upper()} RISK</b></font><br/>{inv_record.get('summary', 'Heuristic risk analysis complete.')}", table_cell)
        ]
    ]
    risk_table = Table(risk_data, colWidths=[160, 380])
    risk_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#FFFFFF")),
        ('BOX', (0, 0), (-1, -1), 1.5, risk_color),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(risk_table)
    story.append(Spacer(1, 12))
    
    # 3. URL Structure Breakdown
    structure = details.get("url_structure")
    if structure:
        story.append(Paragraph("2. URL STRUCTURAL DECOMPOSITION", section_h1))
        struct_rows = [
            [Paragraph("<b>Component</b>", table_cell_bold), Paragraph("<b>Value</b>", table_cell_bold), Paragraph("<b>Security Observations</b>", table_cell_bold)],
            [Paragraph("Protocol / Scheme", table_cell), Paragraph(structure.get("scheme", "-"), code_text), Paragraph("HTTPS encrypted" if structure.get("scheme") == "https" else "Unencrypted plain HTTP", table_cell)],
            [Paragraph("Hostname / FQDN", table_cell), Paragraph(structure.get("hostname", "-"), code_text), Paragraph("Resolvable domain host", table_cell)],
            [Paragraph("Port Number", table_cell), Paragraph(str(structure.get("port", "-")), code_text), Paragraph("Standard service port" if structure.get("is_default_port") else "Non-standard port alert", table_cell)],
            [Paragraph("Path Segment", table_cell), Paragraph(structure.get("path", "-")[:45], code_text), Paragraph(f"Length: {structure.get('path_length', 0)} chars", table_cell)],
            [Paragraph("Query Parameters", table_cell), Paragraph(f"{structure.get('query_params_count', 0)} detected", table_cell), Paragraph(structure.get("query", "-")[:45] if structure.get("query") else "None", code_text)],
            [Paragraph("Subdomain Depth", table_cell), Paragraph(str(structure.get("subdomain_depth", 0)), table_cell), Paragraph("Standard depth" if structure.get("subdomain_depth", 0) < 3 else "Excessive depth warning", table_cell)],
            [Paragraph("Total URL Length", table_cell), Paragraph(f"{structure.get('total_length', 0)} chars", table_cell), Paragraph("Within standard RFC range" if structure.get("total_length", 0) <= 120 else "Anomalously long URL", table_cell)],
        ]
        struct_table = Table(struct_rows, colWidths=[130, 200, 210])
        struct_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#12172A")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#00F5FF")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#00F5FF")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E8F5")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F4F7FF")]),
        ]))
        story.append(struct_table)
        story.append(Spacer(1, 12))
        
    # 4. Detected Indicators Table
    risk_assessment = details.get("risk_assessment", {})
    indicators = risk_assessment.get("indicators", [])
    if indicators:
        story.append(Paragraph("3. SUSPICIOUS THREAT INDICATORS & HEURISTICS", section_h1))
        ind_rows = [
            [Paragraph("<b>Severity</b>", table_cell_bold), Paragraph("<b>Indicator / Detection</b>", table_cell_bold), Paragraph("<b>Points</b>", table_cell_bold), Paragraph("<b>Technical Context & Impact</b>", table_cell_bold)]
        ]
        for ind in indicators:
            sev = ind.get("severity", "Info")
            sev_color = "#D91E44" if sev in ("High", "Critical") else "#D99B00" if sev == "Medium" else "#008B99"
            ind_rows.append([
                Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", table_cell_bold),
                Paragraph(ind.get("title", "Indicator"), table_cell_bold),
                Paragraph(f"+{ind.get('points', 0)}", code_text),
                Paragraph(ind.get("description", "-"), table_cell)
            ])
            
        ind_table = Table(ind_rows, colWidths=[65, 145, 45, 285])
        ind_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#12172A")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#00F5FF")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#00F5FF")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E8F5")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F4F7FF")]),
        ]))
        story.append(ind_table)
        story.append(Spacer(1, 12))
        
    # 5. Redirect Trajectory
    redirects = details.get("redirect_analysis")
    if redirects and redirects.get("chain"):
        story.append(Paragraph("4. REDIRECT TRAJECTORY SEQUENCE", section_h1))
        chain_rows = [
            [Paragraph("<b>Hop</b>", table_cell_bold), Paragraph("<b>HTTP Status</b>", table_cell_bold), Paragraph("<b>Destination URL</b>", table_cell_bold), Paragraph("<b>Resolved IP</b>", table_cell_bold), Paragraph("<b>Latency</b>", table_cell_bold)]
        ]
        for hop in redirects.get("chain", []):
            chain_rows.append([
                Paragraph(str(hop.get("hop", 1)), table_cell),
                Paragraph(f"<b>{hop.get('status_code', '-')}</b>", code_text),
                Paragraph(hop.get("url", "-")[:45], code_text),
                Paragraph(hop.get("ip", "Unknown"), table_cell),
                Paragraph(f"{hop.get('response_time_ms', 0)}ms", table_cell)
            ])
        chain_table = Table(chain_rows, colWidths=[35, 75, 240, 110, 80])
        chain_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#12172A")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#00F5FF")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#00F5FF")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E8F5")),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F4F7FF")]),
        ]))
        story.append(chain_table)
        story.append(Spacer(1, 12))

    # Threat Scanner Consensus Grid (VirusTotal-Grade Multi-Engine Scan)
    detection_ratio = details.get("detection_ratio")
    if detection_ratio:
        story.append(Paragraph("2. MULTI-ENGINE SECURITY CONSENSUS (VIRUSTOTAL GRID)", section_h1))
        ratio_rows = [
            [
                Paragraph("<b>Consensus Detection Ratio</b>", table_cell_bold),
                Paragraph("<b>Overall Verdict</b>", table_cell_bold),
                Paragraph("<b>Malicious Engines</b>", table_cell_bold),
                Paragraph("<b>Suspicious Engines</b>", table_cell_bold),
                Paragraph("<b>Clean Engines</b>", table_cell_bold)
            ],
            [
                Paragraph(f"<b>{detection_ratio.get('display', '0 / 68')}</b>", code_text),
                Paragraph(f"<b>{details.get('overall_verdict', 'CLEAN')}</b>", table_cell_bold),
                Paragraph(str(detection_ratio.get("malicious", 0)), code_text),
                Paragraph(str(detection_ratio.get("suspicious", 0)), code_text),
                Paragraph(str(detection_ratio.get("clean", 68)), code_text)
            ]
        ]
        ratio_table = Table(ratio_rows, colWidths=[140, 100, 100, 100, 100])
        ratio_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#12172A")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#00F5FF")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#00F5FF")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E8F5")),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF")]),
        ]))
        story.append(ratio_table)
        story.append(Spacer(1, 12))

        # Attack Vectors Forensics
        raw_findings = details.get("attack_findings", [])
        if isinstance(raw_findings, dict):
            attack_findings = []
            for k, v in raw_findings.items():
                if isinstance(v, list):
                    for item in v:
                        attack_findings.append({
                            "category": k.replace("_", " ").title(),
                            "severity": item.get("severity", "Medium"),
                            "finding": item.get("vector", "Security Anomaly"),
                            "description": item.get("detail", "-")
                        })
        elif isinstance(raw_findings, list):
            attack_findings = raw_findings
        else:
            attack_findings = []

        if attack_findings:
            story.append(Paragraph("3. ATTACK VECTOR FORENSIC EVALUATION", section_h1))
            atk_rows = [
                [
                    Paragraph("<b>Attack Vector</b>", table_cell_bold),
                    Paragraph("<b>Severity</b>", table_cell_bold),
                    Paragraph("<b>Threat Finding</b>", table_cell_bold),
                    Paragraph("<b>Technical Context & Impact</b>", table_cell_bold)
                ]
            ]
            for atk in attack_findings:
                sev = atk.get("severity", "Info")
                sev_color = "#D91E44" if sev in ("High", "Critical") else "#D99B00" if sev == "Medium" else "#008B99"
                atk_rows.append([
                    Paragraph(atk.get("category", "General"), table_cell_bold),
                    Paragraph(f"<font color='{sev_color}'><b>{sev}</b></font>", table_cell_bold),
                    Paragraph(atk.get("finding", "-"), table_cell_bold),
                    Paragraph(atk.get("description", "-"), table_cell)
                ])
            atk_table = Table(atk_rows, colWidths=[120, 60, 140, 220])
            atk_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#12172A")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#00F5FF")),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#00F5FF")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E8F5")),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F4F7FF")]),
            ]))
            story.append(atk_table)
            story.append(Spacer(1, 12))

        # Flagged Security Vendors Grid (up to top 15 flagged)
        vendor_detections = details.get("vendor_detections", [])
        flagged_vendors = [v for v in vendor_detections if v.get("verdict") in ("malicious", "phishing", "suspicious")]
        if flagged_vendors:
            story.append(Paragraph("4. FLAGGED SECURITY ENGINES TELEMETRY", section_h1))
            v_rows = [
                [
                    Paragraph("<b>Security Vendor Engine</b>", table_cell_bold),
                    Paragraph("<b>Architecture Tier</b>", table_cell_bold),
                    Paragraph("<b>Verdict</b>", table_cell_bold),
                    Paragraph("<b>Threat Signature Label</b>", table_cell_bold)
                ]
            ]
            for v in flagged_vendors[:16]:
                v_verdict = v.get("verdict", "").upper()
                v_color = "#D91E44" if v_verdict in ("MALICIOUS", "PHISHING") else "#D99B00"
                v_rows.append([
                    Paragraph(v.get("vendor", "Engine"), table_cell_bold),
                    Paragraph(v.get("tier", "Cloud Sensor"), table_cell),
                    Paragraph(f"<font color='{v_color}'><b>{v_verdict}</b></font>", table_cell_bold),
                    Paragraph(v.get("threat_label", "Malware"), code_text)
                ])
            v_table = Table(v_rows, colWidths=[150, 110, 80, 200])
            v_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#12172A")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#00F5FF")),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#00F5FF")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E8F5")),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F4F7FF")]),
            ]))
            story.append(v_table)
            story.append(Spacer(1, 12))

        # SOC Mitigation Playbook
        mitigation_playbook = details.get("mitigation_playbook", [])
        if mitigation_playbook:
            story.append(Paragraph("5. SOC MITIGATION PLAYBOOK & FIREWALL DIRECTIVES", section_h1))
            m_rows = [
                [
                    Paragraph("<b>Directive Type</b>", table_cell_bold),
                    Paragraph("<b>Action</b>", table_cell_bold),
                    Paragraph("<b>Technical Syntax / Command Rule</b>", table_cell_bold)
                ]
            ]
            for rule in mitigation_playbook:
                m_rows.append([
                    Paragraph(rule.get("type", "Rule"), table_cell_bold),
                    Paragraph(f"<b>{rule.get('action', 'BLOCK')}</b>", table_cell_bold),
                    Paragraph(rule.get("command", "").replace("\n", "<br/>")[:200], code_text)
                ])
            m_table = Table(m_rows, colWidths=[140, 100, 300])
            m_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#12172A")),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#00F5FF")),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#00F5FF")),
                ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#E0E8F5")),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F4F7FF")]),
            ]))
            story.append(m_table)
            story.append(Spacer(1, 12))
        
    # 6. Actionable Precautions & Disclaimer
    precautions = risk_assessment.get("precautions", [])
    if precautions:
        story.append(Paragraph("5. ACTIONABLE SECURITY PRECAUTIONS", section_h1))
        prec_data = []
        for p in precautions:
            prec_data.append([
                Paragraph("&bull;", table_cell_bold),
                Paragraph(p, table_cell)
            ])
        prec_table = Table(prec_data, colWidths=[15, 525])
        prec_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(prec_table)
        story.append(Spacer(1, 14))
        
    # Heuristic Disclaimer Box
    disclaimer_text = (
        "<b>CYBER THREAT INTELLIGENCE HEURISTIC NOTICE:</b> This intelligence dossier is generated using structural pattern "
        "recognition, automated RFC network queries, and heuristic security rules. Assessed risk ratings represent "
        "defensive indicators rather than conclusive verification of hostile compromise. Always execute verification "
        "in compliance with institutional policies."
    )
    disc_table = Table([[Paragraph(disclaimer_text, body_text)]], colWidths=[540])
    disc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F0F8FF")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#00F5FF")),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(disc_table)
    
    # Build Document
    doc.build(story, canvasmaker=NumberedCanvas)
    return output_filepath


def generate_json_report(inv_record):
    """Formats an investigation record into a standardized cyber JSON intelligence dossier."""
    return {
        "metadata": {
            "platform": Config.APP_NAME,
            "tagline": Config.APP_TAGLINE,
            "version": Config.APP_VERSION,
            "classification": "LEVEL-5 CLASSIFIED // CYBER THREAT DOSSIER",
            "generated_at": datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=5, minutes=30))).strftime("%Y-%m-%d %H:%M:%S IST")
        },
        "investigation": {
            "id": inv_record.get("id"),
            "target": inv_record.get("target"),
            "investigation_type": inv_record.get("investigation_type"),
            "risk_score": inv_record.get("risk_score"),
            "risk_level": inv_record.get("risk_level"),
            "summary": inv_record.get("summary"),
            "created_at": inv_record.get("created_at"),
            "details": inv_record.get("details", {})
        }
    }