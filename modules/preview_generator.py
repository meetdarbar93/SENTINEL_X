"""
SENTINEL-X | Safe Headless Sandbox Visual Preview & DOM Dissector
Enforces strict RFC-1918 SSRF boundaries, safely queries target endpoints,
neutralizes malicious active scripts/iframes, analyzes forms for credential
harvesting, and produces safe sandboxed DOM previews for SOC analysts.
"""

import re
import urllib.parse
import requests
from modules.security_utils import sanitize_url, resolve_and_validate_host, SecurityValidationError
from config import Config

def capture_safe_preview(raw_target):
    """
    Safely probes target URL, fetches DOM, strips malicious active code,
    extracts metadata/forms, and returns sanitized sandbox payload.
    """
    if not raw_target or not raw_target.strip():
        return {"success": False, "error": "Target URL cannot be empty."}

    clean_url = sanitize_url(raw_target)
    parsed = urllib.parse.urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()

    # 1. Enforce SSRF Boundary
    try:
        resolve_and_validate_host(hostname)
    except SecurityValidationError as sve:
        return {
            "success": False,
            "error": f"Safe preview aborted by SSRF firewall: {str(sve)}",
            "is_ssrf_blocked": True,
            "target": raw_target
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"Host validation failed: {str(e)}",
            "target": raw_target
        }

    # 2. Safe HTTP Fetch
    headers = {
        "User-Agent": getattr(Config, "USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SentinelX/5.0"),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "DNT": "1",
        "Connection": "close"
    }

    try:
        response = requests.get(
            clean_url,
            headers=headers,
            timeout=getattr(Config, "REQUEST_TIMEOUT", 5.0),
            verify=False,
            allow_redirects=True
        )
        content_type = response.headers.get("Content-Type", "").lower()
        status_code = response.status_code
        final_url = response.url
        raw_html = response.text if "text" in content_type or "html" in content_type else ""
    except requests.exceptions.Timeout:
        return {
            "success": False,
            "error": f"Target endpoint timed out after {getattr(Config, 'REQUEST_TIMEOUT', 5.0)}s.",
            "target": raw_target
        }
    except requests.exceptions.SSLError as ssl_err:
        return {
            "success": False,
            "error": f"TLS/SSL Handshake failure: {str(ssl_err)[:120]}",
            "target": raw_target
        }
    except Exception as req_err:
        return {
            "success": False,
            "error": f"Safe probe failed: {str(req_err)[:140]}",
            "target": raw_target
        }

    # 3. Parse Metadata
    title_match = re.search(r"<title[^>]*>(.*?)</title>", raw_html, re.IGNORECASE | re.DOTALL)
    page_title = title_match.group(1).strip() if title_match else "Untitled Document"
    page_title = re.sub(r"\s+", " ", page_title)[:120]

    # Meta description
    meta_desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\'](.*?)["\']', raw_html, re.IGNORECASE)
    meta_desc = meta_desc_match.group(1).strip() if meta_desc_match else "No meta description defined."

    # OpenGraph title / image
    og_img_match = re.search(r'<meta[^>]*property=["\']og:image["\'][^>]*content=["\'](.*?)["\']', raw_html, re.IGNORECASE)
    og_image = og_img_match.group(1).strip() if og_img_match else None
    if og_image and not og_image.startswith("http"):
        og_image = urllib.parse.urljoin(final_url, og_image)

    # Favicon
    favicon_match = re.search(r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\'](.*?)["\']', raw_html, re.IGNORECASE)
    favicon_url = favicon_match.group(1).strip() if favicon_match else None
    if favicon_url and not favicon_url.startswith("http"):
        favicon_url = urllib.parse.urljoin(final_url, favicon_url)

    # 4. Form Telemetry (Credential Harvesting Detection)
    forms_found = re.findall(r"<form[^>]*>(.*?)</form>", raw_html, re.IGNORECASE | re.DOTALL)
    has_password_field = bool(re.search(r'<input[^>]*type=["\']password["\']', raw_html, re.IGNORECASE))
    has_credit_card_field = bool(re.search(r'(card[_\-]?number|cvv|exp[_\-]?date|cardholder)', raw_html, re.IGNORECASE))
    has_text_inputs = bool(re.search(r'<input[^>]*type=["\'](text|email|tel|number)["\']', raw_html, re.IGNORECASE))

    detailed_forms = []
    for form_match in re.finditer(r'<form([^>]*)>(.*?)</form>', raw_html, re.IGNORECASE | re.DOTALL):
        form_attrs = form_match.group(1)
        form_body = form_match.group(2)
        
        action_m = re.search(r'action=["\'](.*?)["\']', form_attrs, re.IGNORECASE)
        action = urllib.parse.urljoin(final_url, action_m.group(1)) if action_m else final_url
        method_m = re.search(r'method=["\'](.*?)["\']', form_attrs, re.IGNORECASE)
        method = method_m.group(1).upper() if method_m else "GET"
        
        inputs = []
        for inp in re.finditer(r'<input([^>]+)>', form_body, re.IGNORECASE):
            attrs = inp.group(1)
            t_m = re.search(r'type=["\'](.*?)["\']', attrs, re.IGNORECASE)
            n_m = re.search(r'name=["\'](.*?)["\']', attrs, re.IGNORECASE)
            inputs.append({
                "type": t_m.group(1).lower() if t_m else "text",
                "name": n_m.group(1) if n_m else ""
            })
        detailed_forms.append({
            "action": action,
            "method": method,
            "inputs": inputs
        })

    form_actions = [f["action"] for f in detailed_forms]

    # 5. External Third-Party Script Dependencies
    scripts_found = re.findall(r'<script[^>]*src=["\'](.*?)["\']', raw_html, re.IGNORECASE)
    external_scripts = []
    for s in scripts_found[:12]:
        abs_s = urllib.parse.urljoin(final_url, s)
        external_scripts.append(abs_s)

    # 6. Sanitize HTML for Zero-Trust Sandbox Isolation
    # Neutralize script tags completely
    sanitized = re.sub(r"<script.*?>.*?</script>", "<!-- [ACTIVE SCRIPT STRIPPED BY SENTINEL-X] -->", raw_html, flags=re.IGNORECASE | re.DOTALL)
    # Strip iframes, embeds, objects, applets
    sanitized = re.sub(r"<(iframe|embed|object|applet).*?>.*?</\1>", "<!-- [EMBEDDED CONTAINER REMOVED] -->", sanitized, flags=re.IGNORECASE | re.DOTALL)
    sanitized = re.sub(r"<(iframe|embed|object|applet)[^>]*>", "<!-- [EMBEDDED TAG REMOVED] -->", sanitized, flags=re.IGNORECASE)
    # Strip inline event handlers (onclick, onload, onerror, etc.)
    sanitized = re.sub(r'\son\w+\s*=\s*["\'][^"\']*["\']', '', sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r'\son\w+\s*=\s*[^\s>]+', '', sanitized, flags=re.IGNORECASE)
    # Strip javascript: URLs
    sanitized = re.sub(r'href\s*=\s*["\']javascript:[^"\']*["\']', 'href="#"', sanitized, flags=re.IGNORECASE)
    # Strip meta refreshes / redirects
    sanitized = re.sub(r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*>', '<!-- [REFRESH HEADER REMOVED] -->', sanitized, flags=re.IGNORECASE)

    # Rebase relative image and CSS paths to absolute so the visual styling remains intact
    def rebase_attr(match):
        attr = match.group(1)
        val = match.group(2)
        if val.startswith("http://") or val.startswith("https://") or val.startswith("data:"):
            return f'{attr}="{val}"'
        rebased = urllib.parse.urljoin(final_url, val)
        return f'{attr}="{rebased}"'

    sanitized = re.sub(r'(src|href)=["\']([^"\']+)["\']', rebase_attr, sanitized, flags=re.IGNORECASE)

    # Injected Security Warning Banner inside DOM
    sandbox_banner = (
        '<div style="position: sticky; top: 0; left: 0; width: 100%; background: #161F30; color: #3B82F6; '
        'border-bottom: 2px solid #2563EB; font-family: monospace; font-size: 11px; padding: 6px 12px; '
        'display: flex; justify-content: space-between; align-items: center; z-index: 999999; box-shadow: 0 4px 10px rgba(0,0,0,0.5);">'
        '<span>🛡️ <b>SENTINEL-X ZERO-TRUST SANDBOX</b> &bull; ACTIVE JS NEUTRALIZED &bull; RECON ISOLATION</span>'
        f'<span style="color: #94A3B8;">HTTP {status_code} &bull; {len(raw_html):,} BYTES</span>'
        '</div>'
    )
    if "<body" in sanitized.lower():
        sanitized = re.sub(r"(<body[^>]*>)", r"\1" + sandbox_banner, sanitized, count=1, flags=re.IGNORECASE)
    else:
        sanitized = sandbox_banner + sanitized

    return {
        "success": True,
        "target": clean_url,
        "final_url": final_url,
        "status_code": status_code,
        "content_type": content_type,
        "page_size_bytes": len(raw_html),
        "html_bytes": len(raw_html),
        "title": page_title,
        "server": response.headers.get("Server", "Undisclosed"),
        "phishing_risk": has_password_field or has_credit_card_field,
        "forms": detailed_forms,
        "headers": {
            "server": response.headers.get("Server", "Undisclosed"),
            "content_type": content_type,
            "x_frame_options": response.headers.get("X-Frame-Options", "Not Set"),
            "content_security_policy": "Present" if "Content-Security-Policy" in response.headers else "Missing",
            "strict_transport_security": "Present" if "Strict-Transport-Security" in response.headers else "Missing"
        },
        "metadata": {
            "title": page_title,
            "description": meta_desc[:250],
            "og_image": og_image,
            "favicon": favicon_url
        },
        "form_telemetry": {
            "form_count": len(forms_found),
            "has_password": has_password_field,
            "has_credit_card": has_credit_card_field,
            "has_inputs": has_text_inputs,
            "actions": form_actions[:5],
            "is_phishing_indicator": has_password_field or has_credit_card_field
        },
        "scripts_telemetry": {
            "total_inline_stripped": len(re.findall(r"<script", raw_html, re.IGNORECASE)),
            "external_count": len(scripts_found),
            "external_samples": external_scripts
        },
        "sanitized_html": sanitized
    }
