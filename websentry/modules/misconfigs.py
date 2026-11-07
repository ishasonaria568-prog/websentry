"""
WebSentry Common Web Misconfigurations Module
Checks directory listing, default welcome pages, stack trace leaks, and insecure cookie flags.
Developer: Isha Sonaria
"""

import re
from typing import List
from urllib.parse import urljoin
from websentry.modules.base import BaseScanner, ProgressCallback
from websentry.core.finding import Finding, Severity
from websentry.core.http_client import HttpClient
from websentry.core.config import ScanConfig

class MisconfigScanner(BaseScanner):
    name = "Misconfiguration Analysis"
    description = "Checks directory index exposure, default landing pages, cookie flags, and error disclosures."
    category = "Misconfiguration"

    DIRECTORY_LISTING_PATTERNS = [
        r"<title>Index of /[^<]*</title>",
        r"<h1>Index of /[^<]*</h1>",
        r"<a href=\"\?C=N;O=D\">Name</a>",
        r"\[To Parent Directory\]",
        r"Directory Listing for",
        r"<pre><A HREF=\"/.*\">\[DIR\]</A>",
    ]

    DEFAULT_PAGE_SIGNATURES = [
        ("Apache Default Page", r"Apache2 Ubuntu Default Page|It works!|Apache2 Debian Default Page"),
        ("Nginx Welcome Page", r"Welcome to nginx!|Thank you for using nginx\."),
        ("IIS Welcome Page", r"<title>IIS Windows Server</title>|iisstart\.htm|IIS7|IIS8|IIS10"),
        ("LiteSpeed Default Page", r"LiteSpeed Web Server.*?Default Page"),
        ("Tomcat Default Page", r"Apache Tomcat/[0-9\.]+.*?If you're seeing this, you've successfully installed Tomcat"),
    ]

    def _check_cookies(self, target_url: str, resp) -> List[Finding]:
        findings: List[Finding] = []
        is_https = target_url.lower().startswith("https://")

        # In urllib or requests, Set-Cookie can appear in headers
        set_cookie_raw = resp.headers.get("Set-Cookie", "")
        if not set_cookie_raw:
            return findings

        # Split multiple cookies if present
        cookies = [c.strip() for c in set_cookie_raw.split(",") if "=" in c]
        for cookie_str in cookies:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue
            name_val = parts[0]
            cookie_name = name_val.split("=")[0].strip()
            flags = [p.lower() for p in parts[1:]]

            # Insecure cookie missing Secure on HTTPS
            if is_https and "secure" not in flags:
                findings.append(Finding(
                    id=f"WS-COOKIE-NO-SECURE-{cookie_name}",
                    title=f"Cookie Missing 'Secure' Attribute ('{cookie_name}')",
                    severity=Severity.MEDIUM,
                    url=target_url,
                    status_code=resp.status_code,
                    evidence=f"Set-Cookie: {cookie_str[:120]}...",
                    description=f"Cookie '{cookie_name}' was set over HTTPS without the 'Secure' flag, allowing transmission over cleartext HTTP if redirected.",
                    remediation=f"Add the '; Secure' directive to the Set-Cookie header for '{cookie_name}'.",
                    category="Session Security",
                    reference="https://owasp.org/www-community/controls/SecureFlag"
                ))

            # Missing HttpOnly (prevents XSS cookie theft)
            if "httponly" not in flags:
                # Prioritize session cookies (session, token, auth, jwt, id)
                is_session_like = any(s in cookie_name.lower() for s in ("session", "sess", "token", "auth", "jwt", "id"))
                sev = Severity.MEDIUM if is_session_like else Severity.LOW
                findings.append(Finding(
                    id=f"WS-COOKIE-NO-HTTPONLY-{cookie_name}",
                    title=f"Cookie Missing 'HttpOnly' Attribute ('{cookie_name}')",
                    severity=sev,
                    url=target_url,
                    status_code=resp.status_code,
                    evidence=f"Set-Cookie: {cookie_str[:120]}...",
                    description=f"Cookie '{cookie_name}' is accessible to client-side scripts, increasing risk of credential/session theft via Cross-Site Scripting (XSS).",
                    remediation=f"Add '; HttpOnly' to prevent JavaScript access to cookie '{cookie_name}'.",
                    category="Session Security",
                    reference="https://owasp.org/www-community/HttpOnly"
                ))

            # Missing SameSite (CSRF mitigation)
            if not any(f.startswith("samesite") for f in flags):
                findings.append(Finding(
                    id=f"WS-COOKIE-NO-SAMESITE-{cookie_name}",
                    title=f"Cookie Missing 'SameSite' Attribute ('{cookie_name}')",
                    severity=Severity.LOW,
                    url=target_url,
                    status_code=resp.status_code,
                    evidence=f"Set-Cookie: {cookie_str[:120]}...",
                    description=f"Cookie '{cookie_name}' lacks a SameSite attribute, exposing cross-site requests to Cross-Site Request Forgery (CSRF).",
                    remediation=f"Set '; SameSite=Lax' or '; SameSite=Strict' for cookie '{cookie_name}'.",
                    category="Session Security",
                    reference="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite"
                ))

        return findings

    def run(
        self,
        target_url: str,
        client: HttpClient,
        config: ScanConfig,
        progress_callback: ProgressCallback = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        if progress_callback:
            progress_callback("Analyzing root response for default pages & cookie flags...", 1, 3)

        root_resp = client.get(target_url)
        if root_resp.status_code != 0:
            # 1. Cookie security checks
            findings.extend(self._check_cookies(target_url, root_resp))

            # 2. Default Welcome Page Detection
            for page_name, regex_pattern in self.DEFAULT_PAGE_SIGNATURES:
                if re.search(regex_pattern, root_resp.text, re.IGNORECASE):
                    findings.append(Finding(
                        id=f"WS-DEFAULT-PAGE-{page_name.upper().replace(' ', '_')}",
                        title=f"Default Web Server Welcome Page Detected ({page_name})",
                        severity=Severity.LOW,
                        url=target_url,
                        status_code=root_resp.status_code,
                        evidence=f"Matched default page signature for {page_name}.",
                        description="Default installation or test page remains exposed, indicating incomplete server hardening or deployment.",
                        remediation="Remove or replace default welcome pages and disable default virtual host landing sites.",
                        category=self.category,
                        reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration"
                    ))
                    break

        if progress_callback:
            progress_callback("Checking for exposed directory listings...", 2, 3)

        # 3. Directory listing check on common folder paths
        dir_candidates = ["/", "/images/", "/uploads/", "/static/", "/css/", "/js/", "/files/", "/assets/"]
        for dpath in dir_candidates:
            d_url = urljoin(target_url, dpath)
            d_resp = client.get(d_url)
            if d_resp.status_code == 200:
                for pattern in self.DIRECTORY_LISTING_PATTERNS:
                    if re.search(pattern, d_resp.text, re.IGNORECASE):
                        findings.append(Finding(
                            id=f"WS-DIR-LISTING-{dpath.replace('/', '_')}",
                            title=f"Directory Listing Enabled ({dpath})",
                            severity=Severity.MEDIUM,
                            url=d_url,
                            status_code=d_resp.status_code,
                            evidence=f"Matched directory index pattern: '{pattern}' in response.",
                            description=f"Directory browsing is enabled at {dpath}, exposing file hierarchy and private assets to enumeration.",
                            remediation="Disable directory browsing (e.g. 'Options -Indexes' in Apache, 'autoindex off' in Nginx).",
                            category=self.category,
                            reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure"
                        ))
                        break

        if progress_callback:
            progress_callback("Checking error pages for stack trace disclosure...", 3, 3)

        # 4. Check for stack trace or debug leak on malformed path
        err_url = urljoin(target_url, "/non_existent_page_triggering_404_error_test")
        err_resp = client.get(err_url)
        stack_trace_signatures = [
            (r"Traceback \(most recent call last\):", "Python Stack Trace"),
            (r"Exception in thread \"main\"|java\.[a-z\.]+(?:Exception|Error):", "Java Stack Trace"),
            (r"Fatal error:.*in /.*\.php on line [0-9]+", "PHP Fatal Error Leak"),
            (r"Microsoft VBScript runtime error|Server Error in '/' Application", "ASP.NET Stack Trace Disclosure"),
            (r"at [a-zA-Z0-9_\.]+\([a-zA-Z0-9_\.\/]+:[0-9]+:[0-9]+\)", "Node.js Stack Trace")
        ]
        for pattern, leak_type in stack_trace_signatures:
            if re.search(pattern, err_resp.text):
                findings.append(Finding(
                    id="WS-STACK-TRACE-LEAK",
                    title=f"Application Stack Trace / Error Disclosure ({leak_type})",
                    severity=Severity.MEDIUM,
                    url=err_url,
                    status_code=err_resp.status_code,
                    evidence=f"Disclosed: '{pattern}' in HTTP {err_resp.status_code} error page.",
                    description=f"The application returned an unhandled {leak_type} disclosing internal file paths and code execution flow.",
                    remediation="Configure a generic custom error handler (e.g. 404/500 handler) and disable debug mode in production.",
                    category=self.category,
                    reference="https://owasp.org/www-community/vulnerabilities/Improper_Error_Handling"
                ))
                break

        return findings
