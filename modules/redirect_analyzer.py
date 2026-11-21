import requests
import datetime
from urllib.parse import urlparse, urljoin
from config import Config
from modules.security_utils import resolve_and_validate_host, SecurityValidationError, sanitize_url

def inspect_redirects(start_url, max_redirects=Config.MAX_REDIRECTS, timeout=Config.REQUEST_TIMEOUT):
    """
    Safely follows and audits HTTP/HTTPS redirect chains hop-by-hop.
    Enforces SSRF validation on every destination, detects loops, protocol downgrades,
    and excessive redirect chains.
    """
    clean_url = sanitize_url(start_url)
    
    chain = []
    visited_urls = set()
    current_url = clean_url
    
    warning_flags = []
    has_downgrade = False
    has_loop = False
    excessive_redirects = False
    
    session = requests.Session()
    session.headers.update({"User-Agent": Config.USER_AGENT})
    
    for hop_index in range(max_redirects + 1):
        parsed = urlparse(current_url)
        hostname = parsed.hostname
        
        if not hostname:
            return {
                "start_url": clean_url,
                "final_url": current_url,
                "total_hops": len(chain),
                "chain": chain,
                "error": "Invalid URL structure: missing hostname."
            }
            
        # SSRF Check on this hop
        try:
            resolved_ips = resolve_and_validate_host(hostname)
        except SecurityValidationError as e:
            chain.append({
                "hop": hop_index + 1,
                "url": current_url,
                "status_code": "BLOCKED",
                "error": str(e),
                "is_ssrf_blocked": True,
                "timestamp": datetime.datetime.now().strftime("%H:%M:%S")
            })
            warning_flags.append(f"Redirect destination blocked by SSRF policy: {str(e)}")
            break
            
        # Loop detection
        if current_url in visited_urls:
            has_loop = True
            warning_flags.append(f"Redirect loop detected at hop {hop_index + 1}: {current_url}")
            break
        visited_urls.add(current_url)
        
        # Stop if we exceeded max_redirects
        if hop_index == max_redirects:
            excessive_redirects = True
            warning_flags.append(f"Exceeded maximum allowed redirect hops ({max_redirects}).")
            break
            
        try:
            t0 = datetime.datetime.now()
            # Request headers only with stream=True, no body download
            response = session.get(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                stream=True,
                verify=False
            )
            elapsed_ms = round((datetime.datetime.now() - t0).total_seconds() * 1000, 1)
            
            status_code = response.status_code
            server_header = response.headers.get("Server", "Undisclosed")
            location = response.headers.get("Location")
            
            hop_data = {
                "hop": hop_index + 1,
                "url": current_url,
                "hostname": hostname,
                "ip": resolved_ips[0] if resolved_ips else "Unknown",
                "scheme": parsed.scheme,
                "status_code": status_code,
                "response_time_ms": elapsed_ms,
                "server": server_header,
                "next_location": location,
                "headers": dict(list(response.headers.items())[:12])  # capture key headers
            }
            chain.append(hop_data)
            
            # If redirect status code
            if status_code in (301, 302, 303, 307, 308) and location:
                next_url = urljoin(current_url, location)
                next_parsed = urlparse(next_url)
                
                # Check for HTTPS -> HTTP downgrade
                if parsed.scheme == "https" and next_parsed.scheme == "http":
                    has_downgrade = True
                    warning_flags.append(f"Security Alert: HTTPS to HTTP downgrade detected between hop {hop_index + 1} and {hop_index + 2}!")
                    
                current_url = next_url
            else:
                # Terminal response reached
                break
                
        except requests.exceptions.Timeout:
            chain.append({
                "hop": hop_index + 1,
                "url": current_url,
                "status_code": "TIMEOUT",
                "error": f"Request timed out after {timeout} seconds."
            })
            warning_flags.append(f"Hop {hop_index + 1} timed out.")
            break
        except requests.exceptions.RequestException as e:
            chain.append({
                "hop": hop_index + 1,
                "url": current_url,
                "status_code": "ERROR",
                "error": str(e)
            })
            warning_flags.append(f"Connection error at hop {hop_index + 1}: {str(e)}")
            break
            
    final_destination = chain[-1]["url"] if chain else current_url
    
    return {
        "start_url": clean_url,
        "final_url": final_destination,
        "total_hops": len(chain),
        "is_redirected": len(chain) > 1,
        "chain": chain,
        "warnings": warning_flags,
        "has_downgrade": has_downgrade,
        "has_loop": has_loop,
        "excessive_redirects": excessive_redirects,
        "inspected_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

