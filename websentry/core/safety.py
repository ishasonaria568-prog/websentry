"""
WebSentry Safety and Authorization Guardrails
Enforces safe scanning defaults, private-target validation, and refuses
public internet targets unless --allow-public flag is explicitly passed.
Developer: Isha Sonaria
"""

import socket
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, List, Optional
from websentry.core.colors import bright_red, yellow, cyan, gray, bold, crimson

class SafetyError(Exception):
    """Base class for safety verification errors."""
    pass

class TargetSafetyRefusalError(SafetyError):
    """Raised when target is public internet without --allow-public flag."""
    pass

class InvalidTargetURLError(SafetyError):
    """Raised when URL is malformed or unsupported scheme."""
    pass

def is_private_or_local_ip(ip_str: str) -> bool:
    """Checks whether an IP address belongs to RFC 1918 private, loopback, or link-local ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or
            ip.is_loopback or
            ip.is_link_local or
            ip.is_reserved or
            ip.is_multicast
        )
    except ValueError:
        return False

def resolve_target_host(hostname: str, timeout: float = 4.0) -> List[str]:
    """Resolves target hostname to IPv4/IPv6 addresses."""
    # Special hostnames
    if hostname.lower() in ("localhost", "127.0.0.1", "::1"):
        return ["127.0.0.1"]
    
    ips: List[str] = []
    try:
        # Resolve address info
        orig_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for item in addr_info:
                sockaddr = item[4]
                ip = sockaddr[0]
                if ip not in ips:
                    ips.append(ip)
        finally:
            socket.setdefaulttimeout(orig_timeout)
    except socket.gaierror as e:
        raise InvalidTargetURLError(f"DNS resolution failed for '{hostname}': {e}")
    except Exception as e:
        raise InvalidTargetURLError(f"Could not resolve host '{hostname}': {e}")
        
    if not ips:
        raise InvalidTargetURLError(f"No IP addresses found for '{hostname}'.")
    return ips

def normalize_target_url(raw_url: str) -> str:
    """Normalizes target URL ensuring valid http/https scheme."""
    raw = raw_url.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "http://" + raw
    parsed = urlparse(raw)
    if not parsed.hostname:
        raise InvalidTargetURLError(f"Invalid target URL: missing hostname in '{raw_url}'")
    if parsed.scheme not in ("http", "https"):
        raise InvalidTargetURLError(f"Unsupported scheme '{parsed.scheme}'. Only http and https are supported.")
    # Clean trailing slashes for standard root
    path = parsed.path if parsed.path else "/"
    normalized = f"{parsed.scheme}://{parsed.netloc}{path}".rstrip("/")
    if not normalized.startswith(("http://", "https://")):
        normalized = f"{parsed.scheme}://{parsed.netloc}/"
    return normalized

def validate_target_safety(url: str, allow_public: bool = False) -> Tuple[str, List[str], bool]:
    """
    Validates target URL and enforces authorization gatekeeper.
    Returns: (normalized_url, resolved_ips, is_private)
    Raises TargetSafetyRefusalError if public and not allow_public.
    """
    normalized = normalize_target_url(url)
    parsed = urlparse(normalized)
    hostname = parsed.hostname
    
    if not hostname:
        raise InvalidTargetURLError(f"Cannot extract hostname from '{url}'")

    # Local / test domain suffixes
    local_suffixes = (".local", ".internal", ".test", ".example", ".invalid", ".localhost")
    if any(hostname.lower().endswith(suffix) for suffix in local_suffixes) or hostname.lower() == "localhost":
        # Resolve to 127.0.0.1 or local
        try:
            ips = resolve_target_host(hostname)
        except Exception:
            ips = ["127.0.0.1"]
        return normalized, ips, True

    # Resolve IPs
    ips = resolve_target_host(hostname)
    
    # Check if ALL resolved IPs are private/local
    is_private = all(is_private_or_local_ip(ip) for ip in ips)
    
    if not is_private and not allow_public:
        msg = (
            f"\n{crimson(bold('[!] SAFETY REFUSAL: Public Target Detected!'))}\n\n"
            f"  Target: {cyan(normalized)}\n"
            f"  Resolved IP(s): {yellow(', '.join(ips))}\n\n"
            f"  WebSentry strictly prohibits scanning public internet infrastructure\n"
            f"  without explicit authorization. Testing unauthorized external targets\n"
            f"  violates computer misuse statutes and security ethics.\n\n"
            f"  {bold('To authorize scanning an external system you own or have permission to test:')}\n"
            f"  Re-run with the {bold(bright_red('--allow-public'))} flag:\n\n"
            f"    {cyan(f'websentry scan -u {normalized} --allow-public')}\n"
        )
        raise TargetSafetyRefusalError(msg)
        
    return normalized, ips, is_private
