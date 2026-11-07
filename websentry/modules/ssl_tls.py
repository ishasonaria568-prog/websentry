"""
WebSentry SSL/TLS Security Assessment Module
Validates HTTPS availability, certificate validity, expiration, self-signing, and legacy TLS protocols.
Developer: Isha Sonaria
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import List, Optional, Dict, Any, Tuple
from websentry.modules.base import BaseScanner, ProgressCallback
from websentry.core.finding import Finding, Severity
from websentry.core.http_client import HttpClient
from websentry.core.config import ScanConfig

class SslTlsScanner(BaseScanner):
    name = "SSL/TLS Assessment"
    description = "Checks HTTPS availability, certificate expiration/validity, and TLS protocol configurations."
    category = "SSL/TLS Security"

    def _get_cert_and_cipher(self, hostname: str, port: int, timeout: float = 6.0) -> Tuple[Optional[Dict[str, Any]], Optional[Tuple[str, str, int]], Optional[str]]:
        """Connects via SSL and retrieves peer certificate and negotiated cipher."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # inspect even invalid/self-signed certs

        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    # If CERT_NONE, binary cert can be parsed via ssl.DER_cert_to_PEM_cert or getpeercert()
                    # Try with CERT_REQUIRED to get structured dict if valid
                    cipher = ssock.cipher()
                    version = ssock.version()
                    return cert, (cipher[0], version, cipher[2]), None
        except Exception as e:
            return None, None, str(e)

    def _check_strict_cert(self, hostname: str, port: int, timeout: float = 6.0) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Attempts strict validation to check trust chain and hostname matching."""
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return cert, None
        except ssl.SSLCertVerificationError as e:
            return None, f"Certificate verification error: {e.verify_message} (Code {e.verify_code})"
        except Exception as e:
            return None, str(e)

    def _check_legacy_tls(self, hostname: str, port: int, proto_version, proto_name: str, timeout: float = 4.0) -> bool:
        """Tests if a deprecated legacy TLS version is accepted."""
        try:
            ctx = ssl.SSLContext(proto_version)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True
        except Exception:
            return False

    def run(
        self,
        target_url: str,
        client: HttpClient,
        config: ScanConfig,
        progress_callback: ProgressCallback = None
    ) -> List[Finding]:
        findings: List[Finding] = []
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if not hostname:
            return findings

        is_target_https = parsed.scheme.lower() == "https"
        port = parsed.port or (443 if is_target_https else 80)

        # 1. If target is HTTP, check if HTTPS is supported on port 443
        if not is_target_https:
            if progress_callback:
                progress_callback("Checking HTTPS availability on port 443...", 1, 4)
            https_url = f"https://{hostname}:443/"
            resp_https = client.get(https_url)
            if not resp_https.ok and resp_https.status_code == 0:
                findings.append(Finding(
                    id="WS-SSL-NO-HTTPS",
                    title="HTTPS Not Available / Plain HTTP in Use",
                    severity=Severity.HIGH,
                    url=target_url,
                    status_code=None,
                    evidence=f"Target is served over unencrypted HTTP. Connection to {https_url} failed.",
                    description="The web server serves traffic in cleartext HTTP without transport layer encryption, exposing data in transit to interception and tampering.",
                    remediation="Obtain a valid TLS certificate (e.g., Let's Encrypt) and redirect all HTTP traffic to HTTPS.",
                    category=self.category,
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
                ))
                return findings
            else:
                findings.append(Finding(
                    id="WS-SSL-HTTP-DEFAULT",
                    title="Target Scanned Over Plain HTTP (HTTPS Available)",
                    severity=Severity.MEDIUM,
                    url=target_url,
                    status_code=None,
                    evidence="Target URL is http://, but port 443 accepts TLS connections.",
                    description="Plain HTTP is active while HTTPS is available. Ensure HTTP automatically redirects to HTTPS with HTTP 301.",
                    remediation="Configure an automatic HTTP 301 redirect to HTTPS for all incoming requests.",
                    category=self.category
                ))
                port = 443

        if progress_callback:
            progress_callback("Connecting to TLS port and fetching certificate...", 2, 4)

        # 2. Strict certificate validation
        strict_cert, strict_err = self._check_strict_cert(hostname, port, timeout=config.timeout)
        if strict_err:
            sev = Severity.HIGH if "self-signed" in strict_err.lower() or "expired" in strict_err.lower() else Severity.MEDIUM
            findings.append(Finding(
                id="WS-SSL-CERT-VERIFY-FAILED",
                title=f"SSL Certificate Trust Issue ({'Self-Signed or Untrusted' if 'self-signed' in strict_err.lower() else 'Validation Error'})",
                severity=sev,
                url=f"https://{hostname}:{port}",
                evidence=strict_err,
                description="The SSL certificate presented by the server failed strict trust verification against standard CA roots.",
                remediation="Replace self-signed or invalid certificates with a certificate signed by a recognized Certificate Authority (CA).",
                category=self.category,
                reference="https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
            ))

        if strict_cert:
            # Check expiration date
            not_after_str = strict_cert.get("notAfter")
            if not_after_str:
                try:
                    # Format: 'May 15 12:00:00 2026 GMT'
                    exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    days_remaining = (exp_date - now).days

                    if days_remaining < 0:
                        findings.append(Finding(
                            id="WS-SSL-CERT-EXPIRED",
                            title="SSL/TLS Certificate Has Expired",
                            severity=Severity.CRITICAL,
                            url=f"https://{hostname}:{port}",
                            evidence=f"Certificate expired on {not_after_str} ({abs(days_remaining)} days ago).",
                            description="The SSL certificate is expired, triggering browser security warnings and broken trust.",
                            remediation="Immediately renew and deploy a valid SSL certificate.",
                            category=self.category
                        ))
                    elif days_remaining < 30:
                        findings.append(Finding(
                            id="WS-SSL-CERT-EXPIRING-SOON",
                            title=f"SSL/TLS Certificate Expiring Soon ({days_remaining} Days Remaining)",
                            severity=Severity.MEDIUM,
                            url=f"https://{hostname}:{port}",
                            evidence=f"Certificate expires on {not_after_str} (in {days_remaining} days).",
                            description="Certificate validity will lapse within 30 days.",
                            remediation="Schedule automated certificate renewal before expiration.",
                            category=self.category
                        ))
                    else:
                        findings.append(Finding(
                            id="WS-SSL-CERT-VALID",
                            title=f"SSL/TLS Certificate Valid ({days_remaining} Days Remaining)",
                            severity=Severity.INFORMATIONAL,
                            url=f"https://{hostname}:{port}",
                            evidence=f"Expires: {not_after_str} (Subject: {dict(x[0] for x in strict_cert.get('subject', []))})",
                            description="Certificate is actively trusted and within valid lifetime.",
                            remediation="Maintain certificate lifecycle automation.",
                            category=self.category
                        ))
                except Exception:
                    pass

        if progress_callback:
            progress_callback("Probing for deprecated TLSv1.0 / TLSv1.1 protocols...", 3, 4)

        # 3. Check Deprecated Legacy TLS Protocols
        # Check TLSv1.0
        if hasattr(ssl, "PROTOCOL_TLSv1"):
            if self._check_legacy_tls(hostname, port, ssl.PROTOCOL_TLSv1, "TLSv1.0"):
                findings.append(Finding(
                    id="WS-TLS-DEPRECATED-V10",
                    title="Deprecated TLSv1.0 Protocol Supported",
                    severity=Severity.HIGH,
                    url=f"https://{hostname}:{port}",
                    evidence="Server completed TLS handshake using deprecated protocol TLSv1.0.",
                    description="TLSv1.0 was officially deprecated by NIST and RFC 8996 due to known cryptographic weaknesses (e.g., BEAST, POODLE).",
                    remediation="Disable TLSv1.0 in web server configuration; enforce TLSv1.2 and TLSv1.3 only.",
                    category=self.category,
                    reference="https://datatracker.ietf.org/doc/rfc8996/"
                ))

        # Check TLSv1.1
        if hasattr(ssl, "PROTOCOL_TLSv1_1"):
            if self._check_legacy_tls(hostname, port, ssl.PROTOCOL_TLSv1_1, "TLSv1.1"):
                findings.append(Finding(
                    id="WS-TLS-DEPRECATED-V11",
                    title="Deprecated TLSv1.1 Protocol Supported",
                    severity=Severity.HIGH,
                    url=f"https://{hostname}:{port}",
                    evidence="Server completed TLS handshake using deprecated protocol TLSv1.1.",
                    description="TLSv1.1 lacks modern cipher suites and has been deprecated under RFC 8996.",
                    remediation="Disable TLSv1.1 and mandate minimum protocol TLSv1.2.",
                    category=self.category,
                    reference="https://datatracker.ietf.org/doc/rfc8996/"
                ))

        if progress_callback:
            progress_callback("SSL/TLS assessment complete.", 4, 4)

        return findings
