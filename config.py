import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    APP_NAME = "SENTINEL-X"
    APP_SUBTITLE = "Classified Website Intelligence & URL Investigation Terminal"
    APP_TAGLINE = "EVERY URL HIDES A STORY."
    APP_VERSION = "5.0.0"
    
    SECRET_KEY = os.environ.get("SENTINELX_SECRET_KEY", "sentinelx-horror-investigation-sec-key-666x")
    
    # Storage paths
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "history.db")
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")
    STATIC_DIR = os.path.join(BASE_DIR, "static")
    TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
    
    # Network Security Controls
    REQUEST_TIMEOUT = 5.0  # seconds
    MAX_REDIRECTS = 5
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelX-ParanormalScanner/5.0 (Investigation-Terminal; +https://sentinelx.local)"
    
    # SSRF Protection: Deny local/private/link-local/metadata address ranges
    BLOCKED_IP_RANGES = [
        "0.0.0.0/8",         # "This host on this network"
        "10.0.0.0/8",        # Private Class A
        "127.0.0.0/8",       # Loopback
        "169.254.0.0/16",    # Link-Local (including cloud metadata: 169.254.169.254)
        "172.16.0.0/12",     # Private Class B
        "192.168.0.0/16",    # Private Class C
        "100.64.0.0/10",     # Shared Address Space (Carrier-grade NAT)
        "192.0.0.0/24",      # IETF Protocol Assignments
        "192.0.2.0/24",      # TEST-NET-1
        "198.18.0.0/15",     # Benchmarking
        "198.51.100.0/24",   # TEST-NET-2
        "203.0.113.0/24",    # TEST-NET-3
        "224.0.0.0/4",       # Multicast
        "240.0.0.0/4",       # Reserved for Future Use
        "255.255.255.255/32",# Broadcast
        "::/128",            # Unspecified IPv6
        "::1/128",           # IPv6 Loopback
        "fc00::/7",          # IPv6 Unique Local Address
        "fe80::/10",         # IPv6 Link-Local
        "ff00::/8",          # IPv6 Multicast
    ]
    
    # Common DNS servers
    DEFAULT_DNS_SERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    
    # Heuristic Rule Weights (0-100 scale)
    RISK_WEIGHTS = {
        "RAW_IP": 30,
        "PUNYCODE": 35,
        "SHORTENER": 25,
        "AT_SYMBOL": 35,
        "EXCESSIVE_SUBDOMAINS": 20,
        "SPECIAL_CHARS": 15,
        "NON_STANDARD_PORT": 25,
        "SUSPICIOUS_EXTENSION": 40,
        "SUSPICIOUS_KEYWORDS": 25,
        "OBFUSCATED_ENCODING": 20,
        "EXCESSIVE_REDIRECTS": 20,
        "PROTOCOL_DOWNGRADE": 40,
        "EXPIRED_SSL": 30,
        "NO_SSL": 15,
        "MISSING_SECURITY_HEADERS": 10,
        "REDIRECT_LOOP": 25,
        "SSRF_BLOCKED": 75
    }

    # Recognized URL Shortener Services
    URL_SHORTENERS = [
        "bit.ly", "goo.gl", "tinyurl.com", "t.co", "is.gd", "cli.gs", "yfrog.com",
        "migre.me", "ff.im", "tiny.cc", "url4.eu", "twit.ac", "su.pr", "twurl.nl",
        "snipurl.com", "budurl.com", "short.to", "ping.fm", "post.ly", "just.as",
        "bkite.com", "snipr.com", "fic.kr", "loopt.us", "doiop.com", "short.ie",
        "kl.am", "wp.me", "rubyurl.com", "om.ly", "to.ly", "bit.do", "t.ly",
        "lnkd.in", "db.tt", "qr.ae", "adf.ly", "cur.lv", "ity.im", "q.gs", "po.st",
        "bc.vc", "twitthis.com", "u.to", "j.mp", "buzurl.com", "cutt.ly", "rb.gy",
        "rebrand.ly", "ow.ly"
    ]

    # Dangerous / Executable Payload Extensions
    SUSPICIOUS_EXTENSIONS = [
        ".exe", ".scr", ".bat", ".cmd", ".msi", ".vbs", ".js", ".wsf", ".hta",
        ".jar", ".ps1", ".psm1", ".pif", ".application", ".gadget", ".msp", ".com",
        ".sh", ".bash", ".bin", ".elf", ".apk", ".dmg", ".iso", ".img", ".vhd"
    ]

    # Sensitive / Phishing / Credential Harvesting Keywords
    SUSPICIOUS_KEYWORDS = [
        "login", "signin", "sign-in", "log-in", "verify", "verification", "secure",
        "security", "account", "update", "banking", "billing", "authenticate",
        "password", "credential", "confirm", "wallet", "recover", "suspension",
        "support", "service", "appleid", "paypal", "microsoft", "invoice",
        "payment", "checkout", "alert", "notification"
    ]
