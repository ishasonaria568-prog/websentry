"""
WebSentry HTTP Header Analysis Module
Detects missing security headers, server information leakage, and insecure header policies.
Developer: Isha Sonaria
"""

from typing import List
from urllib.parse import urlparse
from websentry.modules.base import BaseScanner, ProgressCallback
from websentry.core.finding import Finding, Severity
from websentry.core.http_client import HttpClient
from websentry.core.config import ScanConfig

class HeaderScanner(BaseScanner):
    name = "Header Analysis"
    description = "Analyzes HTTP headers for security defenses and information disclosure."
    category = "HTTP Headers"

    # Crucial security headers to verify
    SECURITY_HEADERS = {
        "Content-Security-Policy": {
            "severity": Severity.MEDIUM,
            "title": "Missing Content-Security-Policy (CSP) Header",
            "description": "The Content-Security-Policy response header restricts the sources of scripts, images, and other assets, mitigating Cross-Site Scripting (XSS) and data injection attacks.",
            "remediation": "Define and deploy a restrictive Content-Security-Policy header (e.g., default-src 'self').",
            "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
        },
        "Strict-Transport-Security": {
            "severity": Severity.MEDIUM,
            "title": "Missing HTTP Strict-Transport-Security (HSTS) Header",
            "description": "HSTS instructs modern browsers to only connect to the domain using HTTPS, preventing SSL-stripping attacks and man-in-the-middle downgrade attempts.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
            "ref": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
        },
        "X-Frame-Options": {
            "severity": Severity.LOW,
            "title": "Missing X-Frame-Options Header (Clickjacking)",
            "description": "Without X-Frame-Options or CSP frame-ancestors, the application may be embedded in an attacker's iframe, exposing users to clickjacking.",
            "remediation": "Send 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors' directive.",
            "ref": "https://owasp.org/www-community/attacks/Clickjacking"
        },
        "X-Content-Type-Options": {
            "severity": Severity.LOW,
            "title": "Missing X-Content-Type-Options Header",
            "description": "Without 'X-Content-Type-Options: nosniff', browsers may attempt to MIME-sniff the response content, potentially executing untrusted uploads as HTML/JavaScript.",
            "remediation": "Set 'X-Content-Type-Options: nosniff' across all HTTP responses.",
            "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
        },
        "Referrer-Policy": {
            "severity": Severity.INFORMATIONAL,
            "title": "Missing Referrer-Policy Header",
            "description": "A missing Referrer-Policy may cause browsers to leak sensitive path or query parameters in the Referer header when navigating to external origins.",
            "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
            "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
        },
        "Permissions-Policy": {
            "severity": Severity.INFORMATIONAL,
            "title": "Missing Permissions-Policy Header",
            "description": "Permissions-Policy allows site administrators to disable or restrict browser features such as geolocation, camera, microphone, and payment APIs.",
            "remediation": "Implement a Permissions-Policy header restricting unused browser hardware and APIs.",
            "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
        },
        "Cross-Origin-Opener-Policy": {
            "severity": Severity.INFORMATIONAL,
            "title": "Missing Cross-Origin-Opener-Policy (COOP)",
            "description": "COOP ensures top-level documents do not share a browsing context group with cross-origin documents, protecting against Spectre-style side-channel attacks.",
            "remediation": "Set 'Cross-Origin-Opener-Policy: same-origin'.",
            "ref": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
        }
    }

    # Information disclosure headers
    DISCLOSURE_HEADERS = [
        ("Server", "Web Server Version Disclosure", "The Server header discloses the underlying web server software and potentially version or OS details."),
        ("X-Powered-By", "Technology Framework Disclosure (X-Powered-By)", "The X-Powered-By header reveals backend technology stacks (e.g. PHP, ASP.NET, Express)."),
        ("X-AspNet-Version", "ASP.NET Version Disclosed", "Reveals exact Microsoft ASP.NET framework version."),
        ("X-AspNetMvc-Version", "ASP.NET MVC Version Disclosed", "Reveals exact Microsoft ASP.NET MVC version."),
        ("X-Runtime", "Application Execution Time Disclosed", "Reveals request processing timing, aiding timing attacks."),
        ("Via", "Proxy / Gateway Disclosure (Via)", "Discloses internal proxy or gateway infrastructure."),
        ("X-Generator", "Content Management System Disclosed", "Reveals CMS platform and version.")
    ]

    def run(
        self,
        target_url: str,
        client: HttpClient,
        config: ScanConfig,
        progress_callback: ProgressCallback = None
    ) -> List[Finding]:
        findings: List[Finding] = []
        is_https = target_url.lower().startswith("https://")

        if progress_callback:
            progress_callback("Analyzing root response headers...", 1, 3)

        resp = client.get(target_url, allow_redirects=True)
        if not resp.ok and resp.status_code == 0:
            return findings

        headers = resp.headers

        # 1. Check Missing Security Headers
        for header_name, meta in self.SECURITY_HEADERS.items():
            # Only check HSTS if target is HTTPS
            if header_name == "Strict-Transport-Security" and not is_https:
                continue

            if header_name not in headers:
                findings.append(Finding(
                    id=f"WS-HDR-MISSING-{header_name.upper().replace('-', '_')}",
                    title=meta["title"],
                    severity=meta["severity"],
                    url=target_url,
                    status_code=resp.status_code,
                    evidence=f"Header '{header_name}' was not returned in HTTP {resp.status_code} response.",
                    description=meta["description"],
                    remediation=meta["remediation"],
                    category=self.category,
                    reference=meta["ref"]
                ))

        if progress_callback:
            progress_callback("Checking header information disclosure...", 2, 3)

        # 2. Check Information Disclosure Headers
        for header_name, title, desc in self.DISCLOSURE_HEADERS:
            if header_name in headers:
                val = headers.get(header_name, "")
                # Only flag Server if it contains version numbers or detailed OS
                is_detailed = any(c.isdigit() for c in val) or "/" in val or "(" in val
                sev = Severity.LOW if (is_detailed and header_name in ("Server", "X-Powered-By", "X-AspNet-Version")) else Severity.INFORMATIONAL
                
                findings.append(Finding(
                    id=f"WS-HDR-DISCLOSE-{header_name.upper().replace('-', '_')}",
                    title=title,
                    severity=sev,
                    url=target_url,
                    status_code=resp.status_code,
                    evidence=f"{header_name}: {val}",
                    description=f"{desc} Disclosed value: '{val}'.",
                    remediation=f"Disable or sanitize the '{header_name}' header in server/framework configuration to prevent fingerprinting.",
                    category="Information Disclosure",
                    reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
                ))

        if progress_callback:
            progress_callback("Inspecting CSP and CORS configurations...", 3, 3)

        # 3. Analyze CSP configuration if present
        if "Content-Security-Policy" in headers:
            csp_val = headers["Content-Security-Policy"]
            if "'unsafe-inline'" in csp_val and "nonce-" not in csp_val and "sha256-" not in csp_val:
                findings.append(Finding(
                    id="WS-CSP-UNSAFE-INLINE",
                    title="Insecure Content-Security-Policy: 'unsafe-inline' Detected",
                    severity=Severity.MEDIUM,
                    url=target_url,
                    status_code=resp.status_code,
                    evidence=f"Content-Security-Policy contains 'unsafe-inline' without nonces/hashes.",
                    description="Allowing 'unsafe-inline' scripts in CSP significantly weakens cross-site scripting (XSS) defenses.",
                    remediation="Refactor inline JavaScript to external files and use cryptographically secure nonces or hashes.",
                    category=self.category,
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src"
                ))
            if "'unsafe-eval'" in csp_val:
                findings.append(Finding(
                    id="WS-CSP-UNSAFE-EVAL",
                    title="Insecure Content-Security-Policy: 'unsafe-eval' Detected",
                    severity=Severity.LOW,
                    url=target_url,
                    status_code=resp.status_code,
                    evidence="Content-Security-Policy contains 'unsafe-eval'.",
                    description="'unsafe-eval' permits dynamic string execution (e.g., eval(), Function()), increasing XSS impact.",
                    remediation="Remove 'unsafe-eval' and eliminate dynamic string evaluation.",
                    category=self.category
                ))

        # 4. Check Insecure CORS (Access-Control-Allow-Origin: *)
        if "Access-Control-Allow-Origin" in headers:
            acao = headers["Access-Control-Allow-Origin"]
            acac = headers.get("Access-Control-Allow-Credentials", "false").lower()
            if acao == "*":
                findings.append(Finding(
                    id="WS-CORS-WILDCARD",
                    title="Permissive CORS Policy (Access-Control-Allow-Origin: *)",
                    severity=Severity.LOW,
                    url=target_url,
                    status_code=resp.status_code,
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    description="Wildcard CORS allows any third-party domain to read resources from this endpoint.",
                    remediation="Restrict Access-Control-Allow-Origin to explicit trusted domains instead of '*'.",
                    category=self.category,
                    reference="https://portswigger.net/web-security/cors"
                ))

        return findings
