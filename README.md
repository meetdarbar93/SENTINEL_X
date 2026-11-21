# SENTINEL-X | Security Analysis & URL Intelligence Platform

```
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     ██╗  ██╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ╚██╗██╔╝
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║      ╚███╔╝ 
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║      ██╔██╗ 
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██╔╝ ██╗
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
```

> **Tagline:** *"Investigate Smarter. Detect Earlier. Stay Secure."*  
> **Version:** 2.5.0  
> **Classification:** Security Operations Center (SOC) / Defensive Telemetry Platform

---

## 1. Executive Summary

**SENTINEL-X** is an enterprise-grade cybersecurity investigation and threat telemetry platform. It unifies Open Source Intelligence (OSINT) query generation, real-time DNS zone reconnaissance, cryptographic SSL/TLS inspection, deep URL structural parsing, hop-by-hop HTTP redirect tracking, and heuristic risk scoring into a single Security Operations Center (SOC) dashboard.

Built strictly with safe, passive defensive controls, **SENTINEL-X** features an active Server-Side Request Forgery (SSRF) firewall that automatically prevents connections to loopback interfaces, RFC 1918 private subnets, and cloud instance metadata services.

---

## 2. Technology Stack

### Backend
- **Python 3.8+**
- **Flask 3.0+**: Lightweight, high-concurrency micro-framework
- **Requests & urllib3**: Sandboxed HTTP/HTTPS telemetry probing
- **dnspython 2.6+**: Direct RFC DNS zone querying (A, AAAA, MX, NS, TXT, SOA)
- **Standard Library `ssl` & `socket`**: Deep TLS certificate analysis and negotiated cipher inspection
- **ReportLab 4.x**: Executive PDF dossier compiler with custom vector graphics and tables
- **SQLite3**: Local encrypted-ready transaction journal for investigation logs

### Frontend
- **HTML5 & CSS3**: Glassmorphism cards with cyber glowing accents
- **JavaScript (ES6+)**: Custom async controllers without external JS frameworks
- **Bootstrap 5.3 & Bootstrap Icons**: Responsive layout grid and dark aesthetic
- **Chart.js 4.4**: Hardware-accelerated telemetry charts (Doughnut & 7-day velocity bar charts)
- **Cinematic Cyber Canvas & Video Stream**: Fullscreen HTML5 video background with dynamic node network canvas fallback
- **Web Audio API**: Real-time synthesizer audio alert generation on critical threat detection

---

## 3. System Architecture & Project Structure

```
sentinel_x/
│
├── app.py                      # Master Flask application & REST API controller
├── config.py                   # Platform configuration, CIDR blocklists, timeouts
├── requirements.txt            # Python dependencies
├── test_app.py                 # Automated end-to-end verification test suite
│
├── modules/                    # Modular Cybersecurity Engines
│   ├── security_utils.py       # SSRF boundary firewall & IP/Domain sanitizers
│   ├── osint_generator.py      # 10-Category Google search operator engine
│   ├── domain_intelligence.py  # DNS, SSL/TLS, HTTP header, and WHOIS auditor
│   ├── url_analyzer.py         # URL decomposition, typosquatting & heuristic scanner
│   ├── redirect_analyzer.py    # Sandboxed hop-by-hop HTTP redirect tracer
│   ├── risk_engine.py          # Transparent 0-100 rule-based threat scoring engine
│   └── report_generator.py     # ReportLab vector PDF & JSON dossier exporter
│
├── database/                   # SQLite Persistent Layer
│   ├── db.py                   # Thread-safe database access object & statistics
│   └── history.db              # SQLite database file (auto-generated)
│
├── templates/                  # SOC Glassmorphism Jinja2 Views
│   ├── base.html               # Master layout with video/canvas background & topbar
│   ├── dashboard.html          # Main SOC command center with real statistics
│   ├── osint.html              # 10-Category OSINT query generator
│   ├── domain.html             # Domain intelligence & DNS/SSL inspection
│   ├── analyzer.html           # Deep URL security analyzer
│   ├── redirects.html          # Hop-by-hop redirect inspector
│   ├── history.html            # Searchable investigation dossier log
│   ├── reports.html            # PDF & JSON dossier export center
│   ├── about.html              # Security architecture & ethical usage charter
│   └── settings.html           # Sensor settings & SSRF policy management
│
├── static/                     # Static Assets
│   ├── css/
│   │   ├── style.css           # Glassmorphism, colors, cards, and responsiveness
│   │   └── animations.css      # Radar spinners, scanlines, and glow keyframes
│   ├── js/
│   │   ├── main.js             # Canvas particle controller, UTC clock, toasts
│   │   ├── dashboard.js        # Live SQLite metrics & Chart.js instances
│   │   └── analyzer.js         # URL scanner async controller
│   ├── images/
│   │   └── logo.svg            # Cyber hex-shield vector logo
│   └── videos/
│       └── cyber_background.mp4 # Cinematic background video loop
│
└── reports/                    # Generated PDF & JSON export dossiers
```

---

## 4. Key Functional Modules

### 1. SOC Command Center Dashboard (`/`)
- Real-time animated telemetry counters: URLs Analyzed, Domains Audited, OSINT Queries Compiled, Suspicious Threats Detected.
- Real SQLite metrics aggregated without hardcoded or simulated statistics.
- Interactive Chart.js visualizations:
  - **Risk Distribution**: Doughnut breakdown (Low, Medium, High).
  - **7-Day Velocity**: Multi-dataset trajectory of scans over time.
- Rapid Reconnaissance Launchpad: One-click routing to any engine.
- Interactive investigation history table with filtering, search, and live PDF downloads.

### 2. OSINT Search Operator Generator (`/osint`)
Generates 10 specialized Google Dork query categories for authorized passive reconnaissance:
1. **Publicly Indexed Files**: Spreadsheets, Word documents, text notes (`filetype:xls`, `filetype:doc`).
2. **PDF and Document Discovery**: Manuals, confidential notices (`filetype:pdf intext:"confidential"`).
3. **Login and Authentication Pages**: Admin consoles, SSO gateways, recovery links (`inurl:login`, `inurl:admin`).
4. **Publicly Indexed Directories**: Open Apache/Nginx directory listings (`intitle:"index of /"`).
5. **Subdomain Discovery**: Staging, dev, QA, and API subdomains (`site:*.target.com -site:www.target.com`).
6. **Exposed Configuration References**: Dotenv files, docker manifests, server configs (`inurl:".env"`).
7. **Error Messages and Debug Information**: Stack traces, unhandled SQL exceptions (`intext:"fatal error"`).
8. **Public Contact Information**: Staff directories, domain-specific emails (`intext:"@domain.com"`).
9. **Technology and Platform Discovery**: WordPress plugins, Swagger API specs, S3 buckets.
10. **Publicly Indexed Backup References**: SQL dumps, archive files, editor swap files (`filetype:sql`, `filetype:bak`).

### 3. Domain Infrastructure Intelligence (`/domain`)
- Resolves primary IPv4 and IPv6 addresses.
- Queries DNS zone records: `A`, `AAAA`, `MX` (with priority), `NS`, `TXT` (SPF/DKIM), and `SOA` (Zone Authority).
- Cryptographic SSL/TLS inspection: Common Name, Issuer CA, Validity dates, Expiration countdown, TLS protocol version, cipher suite, and Subject Alternative Names (SANs).
- HTTP response latency in milliseconds and server software banner.
- Security Headers Matrix: Tests presence and values for `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.
- WHOIS and RDAP registry data: Registrar, Creation date, Expiration date, Status codes, and Nameservers.

### 4. Deep URL Security Analyzer (`/analyzer`)
- **Deconstruction**: Scheme, Hostname, Netloc, Port, Subdomain depth, Path, and parsed Query parameters.
- **Threat Heuristic Detections**:
  - Direct IP address used as hostname.
  - Punycode / IDN homograph attack characters (`xn--`).
  - Credential spoofing using embedded `@` characters (`http://target.com@evil.com`).
  - Known link shortener services (`bit.ly`, `tinyurl.com`, `t.co`).
  - Excessive subdomain depth (> 3 levels).
  - Misleading brand typosquatting (heuristics detecting spoofed brands like `paypal`, `microsoft`, `apple`, `google`).
  - Non-standard service ports.
  - Dangerous executable / script download extensions (`.exe`, `.scr`, `.bat`, `.ps1`, `.apk`).
  - Sensitive authentication and banking keywords in URI path.
  - Double percent-encoding (`%25`) and null-byte anomalies (`%00`).
- **Integrated Redirect & SSL Trace**: Automatically audits redirect trajectory and certificates.

### 5. Safe Redirect Inspector (`/redirects`)
- Follows HTTP redirects (301, 302, 303, 307, 308) up to 5 hops.
- Re-evaluates SSRF policy on **every individual hop destination** before connecting.
- Detects HTTPS to cleartext HTTP protocol downgrades (SSL stripping vulnerability).
- Detects circular redirect loops and excessive chain depths.

### 6. Transparent Rule-Based Risk Engine
- Calculates transparent, bounded numerical scores from **0 to 100**:
  - **Low Risk (0–29)**: Standard baseline precautions.
  - **Medium Risk (30–69)**: Security anomalies or non-standard configs detected.
  - **High Risk (70–100)**: Multiple significant threat patterns or SSRF violations detected.
- Every triggered indicator includes score weight, severity badge, technical context, and recommended precaution.
- Clear disclaimer: Analytical heuristic evaluation, not a definitive malware verdict.

### 7. Executive Dossier Generation (`/reports`)
- **PDF Export**: Built with ReportLab 4.x featuring custom header banners, executive summary, risk score gauges, structural decomposition tables, threat indicator matrices, and page-numbered footers.
- **JSON Export**: Standardized machine-readable REST schema for integration with SIEMs or external pipelines.

---

## 5. Security & SSRF Protection Architecture

SENTINEL-X incorporates strict defensive controls designed to protect host environments:
1. **Pre-flight DNS & IP Resolution**: Targets are resolved via `socket.getaddrinfo()` before any HTTP or socket connection is initiated.
2. **Automatic RFC 1918 & Private Subnet Blocking**:
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
   - Loopback: `127.0.0.0/8`, `::1/128`, `localhost`
   - Link-Local & Cloud Metadata: `169.254.0.0/16` (including `169.254.169.254`)
   - Carrier-Grade NAT & Reserved: `100.64.0.0/10`, `0.0.0.0/8`, `224.0.0.0/4`, `240.0.0.0/4`
3. **Hop-by-Hop Destination Inspection**: Redirect targets cannot route back to internal services.
4. **Request Sandboxing**: Strict timeouts (3–5 seconds), headers-only streaming (`stream=True`), and disabled file execution.
5. **SQL Injection Defense**: Parameterized queries across all SQLite interactions.
6. **XSS Defense**: Jinja2 contextual HTML auto-escaping and sanitized input normalization.

---

## 6. Installation & Execution Guide

### Prerequisites
- Python 3.8 or higher
- Modern web browser (Chrome, Firefox, Edge, Safari)

### Step 1: Install Dependencies
Open a PowerShell or Terminal window in the project directory:

```bash
pip install -r requirements.txt
```

*Required packages: `Flask>=3.0.0`, `requests>=2.31.0`, `dnspython>=2.6.0`, `reportlab>=4.0.0`, `urllib3>=2.0.0`*

### Step 2: Run Verification Test Suite
Verify that all engines, APIs, SSRF firewalls, and PDF generators function properly:

```bash
python test_app.py
```

*Expected output: `Ran 6 tests ... OK`*

### Step 3: Launch the Application
Start the Flask web server:

```bash
python app.py
```

*Console output:*
```
 * Serving Flask app 'app'
 * Debug mode: on
 * Running on http://127.0.0.1:5000
```

### Step 4: Open in Web Browser
Navigate to:
```
http://127.0.0.1:5000
```

---

## 7. Ethical Usage Policy & Legal Disclaimers

> **IMPORTANT:**  
> SENTINEL-X is developed strictly for authorized security auditing, threat intelligence gathering, defensive perimeter monitoring, and educational research.  
> 
> The platform performs **passive observation and structural analysis**. It does not perform invasive vulnerability scanning, denial of service attacks, authentication bypasses, or exploit payload injection.  
> 
> Security analysts and researchers must possess documented authorization prior to investigating third-party domains or network endpoints. The creators and developers assume no liability for misuse of this tool.

"# SENTINEL_X" 
"# SENTINEL_X" 
