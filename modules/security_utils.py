import ipaddress
import socket
import re
from urllib.parse import urlparse
from config import Config

class SecurityValidationError(Exception):
    """Exception raised when an address or target violates SSRF or security boundaries."""
    pass

def is_ip_address(target):
    """Check if target string is an IPv4 or IPv6 address."""
    target = target.strip()
    # Remove port if present
    if ":" in target and not target.startswith("["):
        # Could be IPv4 with port or IPv6
        parts = target.split(":")
        if len(parts) == 2:
            target = parts[0]
            
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def is_private_or_restricted_ip(ip_str):
    """
    Check if an IP address belongs to RFC 1918, loopback, link-local,
    multicast, or cloud metadata addresses.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        
        # Built-in standard checks
        if (ip_obj.is_private or 
            ip_obj.is_loopback or 
            ip_obj.is_link_local or 
            ip_obj.is_multicast or 
            ip_obj.is_reserved or 
            ip_obj.is_unspecified):
            return True
            
        # Extra subnet checks from Config
        for cidr in Config.BLOCKED_IP_RANGES:
            net = ipaddress.ip_network(cidr)
            if ip_obj in net:
                return True
                
        return False
    except ValueError:
        return True  # If invalid, treat as unsafe

def resolve_and_validate_host(hostname):
    """
    Resolves hostname to IP addresses and verifies that NONE of them
    resolve to a private, loopback, link-local, or cloud metadata address.
    Returns list of safe resolved IP addresses.
    Raises SecurityValidationError if unsafe or unresolvable.
    """
    hostname = hostname.strip().lower()
    
    # Check for direct localhost strings
    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise SecurityValidationError(f"Access to '{hostname}' is blocked by Sentinel-X SSRF protection policy.")
        
    # If the hostname is already an IP address
    if is_ip_address(hostname):
        if is_private_or_restricted_ip(hostname):
            raise SecurityValidationError(f"Direct connection to private/internal IP '{hostname}' is blocked.")
        return [hostname]
        
    # DNS Resolution
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        resolved_ips = []
        for item in addr_info:
            ip = item[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)
                
        if not resolved_ips:
            raise SecurityValidationError(f"Could not resolve host '{hostname}'.")
            
        for ip in resolved_ips:
            if is_private_or_restricted_ip(ip):
                raise SecurityValidationError(
                    f"Host '{hostname}' resolved to private/restricted IP ({ip}). Connection blocked for SSRF prevention."
                )
                
        return resolved_ips
    except socket.gaierror as e:
        raise SecurityValidationError(f"DNS resolution failed for '{hostname}': {str(e)}")
    except Exception as e:
        if isinstance(e, SecurityValidationError):
            raise e
        raise SecurityValidationError(f"Target validation failed for '{hostname}': {str(e)}")

def sanitize_domain(domain_input):
    """
    Cleans domain input by stripping protocols, paths, query strings, and whitespace.
    """
    if not domain_input:
        return ""
    d = domain_input.strip()
    if "://" in d:
        parsed = urlparse(d)
        d = parsed.netloc or parsed.path
    else:
        # Strip path or trailing characters
        d = d.split("/")[0].split("?")[0].split("#")[0]
        
    # Remove port if present
    if ":" in d and not d.startswith("["):
        d = d.split(":")[0]
        
    return d.strip().lower()

def sanitize_url(url_input):
    """
    Validates and normalizes URL string.
    Ensures scheme (defaults to https:// if missing).
    """
    if not url_input:
        return ""
    u = url_input.strip()
    if not re.match(r'^[a-zA-Z]+://', u):
        u = "https://" + u
    return u

