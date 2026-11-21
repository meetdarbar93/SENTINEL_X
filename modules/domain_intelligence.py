import socket
import ssl
import re
import datetime
import requests
import dns.resolver
from config import Config
from modules.security_utils import sanitize_domain, resolve_and_validate_host, SecurityValidationError

def query_dns_records(domain):
    """
    Query DNS records (A, AAAA, MX, NS, TXT, SOA, CNAME) using dnspython.
    Gracefully handles missing records and timeouts.
    """
    records = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "SOA": [],
        "CNAME": []
    }
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.5
    resolver.lifetime = 3.0
    resolver.nameservers = Config.DEFAULT_DNS_SERVERS
    
    for rtype in records.keys():
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                if rtype == "MX":
                    records[rtype].append({
                        "preference": rdata.preference,
                        "exchange": str(rdata.exchange).rstrip('.')
                    })
                elif rtype == "SOA":
                    records[rtype].append({
                        "mname": str(rdata.mname).rstrip('.'),
                        "rname": str(rdata.rname).rstrip('.'),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum
                    })
                else:
                    text_val = str(rdata).strip('"')
                    if rtype in ("NS", "CNAME"):
                        text_val = text_val.rstrip('.')
                    records[rtype].append(text_val)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception:
            continue
            
    # Fallback for A records if dnspython timed out
    if not records["A"]:
        try:
            ips = socket.gethostbyname_ex(domain)[2]
            records["A"] = ips
        except Exception:
            pass
            
    return records

def get_ssl_details(domain):
    """
    Connect via SSL/TLS socket to retrieve certificate parameters, validity dates,
    subject alternative names, and negotiated TLS version.
    """
    ssl_info = {
        "available": False,
        "error": None,
        "subject": {},
        "issuer": {},
        "valid_from": None,
        "valid_to": None,
        "days_remaining": None,
        "is_expired": False,
        "tls_version": None,
        "cipher": None,
        "sans": [],
        "serial_number": None
    }
    
    try:
        resolve_and_validate_host(domain)
        
        ctx_ver = ssl.create_default_context()
        ctx_ver.check_hostname = True
        ctx_ver.verify_mode = ssl.CERT_REQUIRED
        
        with socket.create_connection((domain, 443), timeout=3.5) as sock:
            with ctx_ver.wrap_socket(sock, server_hostname=domain) as ssl_sock:
                ssl_info["tls_version"] = ssl_sock.version()
                cipher_info = ssl_sock.cipher()
                if cipher_info:
                    ssl_info["cipher"] = cipher_info[0]
                    
                cert = ssl_sock.getpeercert()
                ssl_info["available"] = True
                
                # Subject parsing
                if "subject" in cert:
                    for sub in cert["subject"]:
                        for key, val in sub:
                            ssl_info["subject"][key] = val
                            
                # Issuer parsing
                if "issuer" in cert:
                    for iss in cert["issuer"]:
                        for key, val in iss:
                            ssl_info["issuer"][key] = val
                            
                # Validity dates
                if "notBefore" in cert:
                    ssl_info["valid_from"] = cert["notBefore"]
                if "notAfter" in cert:
                    ssl_info["valid_to"] = cert["notAfter"]
                    try:
                        expiry_date = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_left = (expiry_date - datetime.datetime.utcnow()).days
                        ssl_info["days_remaining"] = days_left
                        ssl_info["is_expired"] = days_left < 0
                    except Exception:
                        pass
                        
                # SANs
                if "subjectAltName" in cert:
                    ssl_info["sans"] = [san[1] for san in cert["subjectAltName"] if len(san) > 1]
                    
                ssl_info["serial_number"] = cert.get("serialNumber")
                
    except ssl.SSLCertVerificationError as e:
        ssl_info["available"] = True
        ssl_info["error"] = f"Certificate Verification Warning: {str(e)}"
        ssl_info["is_self_signed"] = "self signed" in str(e).lower()
    except Exception as e:
        ssl_info["available"] = False
        ssl_info["error"] = str(e)
        
    return ssl_info

def get_http_headers_and_security(domain):
    """
    Sends safe HTTP and HTTPS GET/HEAD requests to analyze server banner,
    protocol availability, response latency, and security headers.
    """
    results = {
        "http_status": None,
        "https_status": None,
        "https_available": False,
        "server_banner": "Undisclosed",
        "raw_headers": {},
        "response_time_ms": None,
        "security_headers": {
            "Strict-Transport-Security": {"present": False, "value": None, "recommendation": "Enforces HTTPS connections and prevents SSL-stripping attacks."},
            "Content-Security-Policy": {"present": False, "value": None, "recommendation": "Restricts execution of unauthorized scripts and prevents XSS/injection attacks."},
            "X-Frame-Options": {"present": False, "value": None, "recommendation": "Protects against clickjacking attacks by controlling iframe rendering."},
            "X-Content-Type-Options": {"present": False, "value": None, "recommendation": "Prevents MIME-type sniffing of uploaded or returned assets (nosniff)."},
            "Referrer-Policy": {"present": False, "value": None, "recommendation": "Controls how much referrer information is included with requests."},
            "Permissions-Policy": {"present": False, "value": None, "recommendation": "Restricts browser feature usage (camera, microphone, geolocation)."}
        }
    }
    
    headers = {"User-Agent": Config.USER_AGENT}
    
    # 1. Test HTTPS
    try:
        t0 = datetime.datetime.now()
        r = requests.get(
            f"https://{domain}",
            headers=headers,
            timeout=Config.REQUEST_TIMEOUT,
            allow_redirects=False,
            verify=False
        )
        elapsed = (datetime.datetime.now() - t0).total_seconds() * 1000
        results["https_available"] = True
        results["https_status"] = r.status_code
        results["response_time_ms"] = round(elapsed, 1)
        results["server_banner"] = r.headers.get("Server", "Undisclosed")
        results["raw_headers"] = dict(r.headers)
        
        # Check security headers
        for h_key in results["security_headers"].keys():
            val = r.headers.get(h_key)
            if val:
                results["security_headers"][h_key]["present"] = True
                results["security_headers"][h_key]["value"] = val
    except Exception as e:
        results["https_available"] = False
        results["https_error"] = str(e)
        
    # 2. Test HTTP
    try:
        r_http = requests.get(
            f"http://{domain}",
            headers=headers,
            timeout=3.0,
            allow_redirects=False
        )
        results["http_status"] = r_http.status_code
        if not results["raw_headers"]:
            results["raw_headers"] = dict(r_http.headers)
            results["server_banner"] = r_http.headers.get("Server", "Undisclosed")
    except Exception:
        results["http_status"] = None
        
    return results

def _raw_whois_query(server, query):
    """Low-level socket query on port 43 with timeout."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.5)
        s.connect((server, 43))
        s.send((query + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data)
        s.close()
        return b"".join(chunks).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def get_whois_information(domain):
    """
    Robust WHOIS lookup using RFC 3912 socket queries (IANA -> Registrar referral)
    with RDAP JSON fallback. Never crashes on missing fields.
    """
    whois_info = {
        "available": False,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "name_servers": [],
        "status": [],
        "registrant_country": None
    }
    
    # 1. Native Socket WHOIS
    try:
        iana_resp = _raw_whois_query("whois.iana.org", domain)
        refer_server = None
        for line in iana_resp.splitlines():
            if line.lower().startswith("refer:"):
                refer_server = line.split(":", 1)[1].strip()
                break
                
        server_to_query = refer_server or "whois.internic.net"
        raw_output = _raw_whois_query(server_to_query, domain)
        
        # If internic refers to another registrar whois
        if "Registrar WHOIS Server:" in raw_output:
            for line in raw_output.splitlines():
                if "Registrar WHOIS Server:" in line:
                    sub_server = line.split(":", 1)[1].strip()
                    if sub_server:
                        detailed = _raw_whois_query(sub_server, domain)
                        if detailed:
                            raw_output = detailed
                            break
                            
        if raw_output:
            for line in raw_output.splitlines():
                line_str = line.strip()
                lower = line_str.lower()
                
                # Registrar
                if not whois_info["registrar"] and any(lower.startswith(k) for k in ["registrar:", "sponsoring registrar:"]):
                    whois_info["registrar"] = line_str.split(":", 1)[1].strip()
                    whois_info["available"] = True
                    
                # Creation Date
                if not whois_info["creation_date"] and any(lower.startswith(k) for k in ["creation date:", "created:", "registration time:"]):
                    whois_info["creation_date"] = line_str.split(":", 1)[1].strip()
                    whois_info["available"] = True
                    
                # Expiration Date
                if not whois_info["expiration_date"] and any(lower.startswith(k) for k in ["registry expiry date:", "expiration date:", "registrar registration expiration date:"]):
                    whois_info["expiration_date"] = line_str.split(":", 1)[1].strip()
                    whois_info["available"] = True
                    
                # Updated Date
                if not whois_info["updated_date"] and any(lower.startswith(k) for k in ["updated date:", "last updated:"]):
                    whois_info["updated_date"] = line_str.split(":", 1)[1].strip()
                    
                # Name Server
                if any(lower.startswith(k) for k in ["name server:", "nserver:"]):
                    ns_val = line_str.split(":", 1)[1].strip().lower()
                    if ns_val and ns_val not in whois_info["name_servers"]:
                        whois_info["name_servers"].append(ns_val)
                        whois_info["available"] = True
                        
                # Status
                if lower.startswith("domain status:") or lower.startswith("status:"):
                    status_val = line_str.split(":", 1)[1].strip().split()[0]
                    if status_val and status_val not in whois_info["status"]:
                        whois_info["status"].append(status_val)
                        
                # Country
                if not whois_info["registrant_country"] and any(lower.startswith(k) for k in ["registrant country:", "country:"]):
                    whois_info["registrant_country"] = line_str.split(":", 1)[1].strip()
                    
            if whois_info["available"]:
                return whois_info
    except Exception:
        pass
        
    # 2. RDAP Fallback over HTTPS
    try:
        rdap_url = f"https://rdap.org/domain/{domain}"
        resp = requests.get(rdap_url, timeout=3.0, headers={"Accept": "application/json"})
        if resp.status_code == 200:
            data = resp.json()
            whois_info["available"] = True
            whois_info["registrar"] = data.get("port43", "RDAP Registry")
            
            for event in data.get("events", []):
                action = event.get("eventAction")
                edate = event.get("eventDate")
                if action == "registration":
                    whois_info["creation_date"] = edate
                elif action == "expiration":
                    whois_info["expiration_date"] = edate
                elif action == "last changed":
                    whois_info["updated_date"] = edate
                    
            if "status" in data:
                whois_info["status"] = data["status"][:5]
                
            nameservers = []
            for ns in data.get("nameservers", []):
                ldh = ns.get("ldhName")
                if ldh:
                    nameservers.append(ldh.lower())
            if nameservers:
                whois_info["name_servers"] = nameservers
    except Exception:
        pass
        
    return whois_info

def analyze_domain_intelligence(target_input):
    """
    Comprehensive domain intelligence orchestrator.
    Gathers DNS records, IP resolution, SSL inspection, HTTP status & security headers,
    and WHOIS registration details.
    """
    clean_domain = sanitize_domain(target_input)
    if not clean_domain:
        return {"error": "Invalid domain name specified."}
        
    try:
        resolved_ips = resolve_and_validate_host(clean_domain)
    except SecurityValidationError as e:
        return {"error": str(e), "is_blocked": True}
        
    dns_data = query_dns_records(clean_domain)
    ssl_data = get_ssl_details(clean_domain)
    http_data = get_http_headers_and_security(clean_domain)
    whois_data = get_whois_information(clean_domain)
    
    present_sec_headers = sum(1 for h in http_data["security_headers"].values() if h["present"])
    total_sec_headers = len(http_data["security_headers"])
    
    return {
        "domain": clean_domain,
        "resolved_ips": resolved_ips,
        "primary_ip": resolved_ips[0] if resolved_ips else None,
        "dns_records": dns_data,
        "ssl": ssl_data,
        "http": http_data,
        "whois": whois_data,
        "security_score_summary": {
            "present_security_headers": present_sec_headers,
            "total_security_headers": total_sec_headers,
            "https_enforced": http_data["https_available"],
            "ssl_valid": ssl_data["available"] and not ssl_data.get("is_expired", False)
        },
        "analyzed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
