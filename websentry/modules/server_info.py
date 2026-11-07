"""
WebSentry Server Information & Technology Fingerprinting Module
Identifies web servers, backend runtimes, frameworks, and CMS engines.
Developer: Isha Sonaria
"""

import re
from typing import List, Dict, Tuple, Any
from websentry.modules.base import BaseScanner, ProgressCallback
from websentry.core.finding import Finding, Severity
from websentry.core.http_client import HttpClient
from websentry.core.config import ScanConfig

class ServerInfoScanner(BaseScanner):
    name = "Server Fingerprinting"
    description = "Detects underlying web server software, versions, and framework fingerprints."
    category = "Server Fingerprinting"

    SERVER_PATTERNS: List[Tuple[str, str, str]] = [
        ("Apache", r"Apache(?:/([0-9\.]+))?", "Apache HTTP Server"),
        ("Nginx", r"nginx(?:/([0-9\.]+))?", "Nginx Web Server"),
        ("Microsoft-IIS", r"Microsoft-IIS(?:/([0-9\.]+))?", "Microsoft Internet Information Services"),
        ("Caddy", r"Caddy(?:/([0-9\.]+))?", "Caddy Web Server"),
        ("Cloudflare", r"cloudflare", "Cloudflare Edge Proxy"),
        ("LiteSpeed", r"LiteSpeed(?:/([0-9\.]+))?", "LiteSpeed Web Server"),
        ("openresty", r"openresty(?:/([0-9\.]+))?", "OpenResty Nginx bundle"),
        ("Envoy", r"envoy", "Envoy Proxy"),
        ("gunicorn", r"gunicorn(?:/([0-9\.]+))?", "Gunicorn Python WSGI Server"),
        ("Werkzeug", r"Werkzeug(?:/([0-9\.]+))?", "Werkzeug Python WSGI / Flask Dev Server"),
        ("Uvicorn", r"uvicorn", "Uvicorn ASGI Server"),
        ("Express", r"Express", "Node.js Express Framework")
    ]

    FRAMEWORK_SIGNATURES: List[Dict[str, Any]] = [
        {
            "name": "PHP",
            "header": "X-Powered-By",
            "regex": r"PHP(?:/([0-9\.]+))?",
            "cookie": "PHPSESSID",
            "desc": "PHP Hypertext Preprocessor"
        },
        {
            "name": "ASP.NET",
            "header": "X-Powered-By",
            "regex": r"ASP\.NET",
            "cookie": "ASP.NET_SessionId",
            "desc": "Microsoft ASP.NET Framework"
        },
        {
            "name": "Java / Spring",
            "header": "Server",
            "regex": r"Tomcat|Jetty|WildFly|JBoss",
            "cookie": "JSESSIONID",
            "desc": "Java Enterprise / Spring Framework"
        },
        {
            "name": "Python / Django",
            "header": "Server",
            "regex": r"WSGIServer",
            "cookie": "csrftoken",
            "desc": "Django Web Framework"
        },
        {
            "name": "Ruby on Rails",
            "header": "X-Powered-By",
            "regex": r"Phusion_Passenger",
            "cookie": "_session_id",
            "desc": "Ruby on Rails Framework"
        }
    ]

    def run(
        self,
        target_url: str,
        client: HttpClient,
        config: ScanConfig,
        progress_callback: ProgressCallback = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        if progress_callback:
            progress_callback("Probing server banner and headers...", 1, 3)

        resp = client.get(target_url)
        if resp.status_code == 0:
            return findings

        server_hdr = resp.headers.get("Server", "")
        powered_hdr = resp.headers.get("X-Powered-By", "")
        set_cookie = resp.headers.get("Set-Cookie", "")
        html_body = resp.text

        # 1. Match Web Server software
        detected_server = None
        server_version = None

        for key, pattern, full_name in self.SERVER_PATTERNS:
            match = re.search(pattern, server_hdr, re.IGNORECASE)
            if match:
                detected_server = full_name
                if match.groups() and match.group(1):
                    server_version = match.group(1)
                break

        if detected_server:
            if server_version:
                findings.append(Finding(
                    id="WS-SERVER-VERSION",
                    title=f"Detailed Web Server Version Disclosed ({detected_server} {server_version})",
                    severity=Severity.LOW,
                    url=target_url,
                    status_code=resp.status_code,
                    evidence=f"Server: {server_hdr}",
                    description=f"The web server openly disclosed its exact version number ({server_version}). Disclosing exact versions helps attackers query vulnerability databases for known CVEs.",
                    remediation="Configure web server to suppress granular version banners (e.g. 'ServerTokens Prod' in Apache, 'server_tokens off' in Nginx).",
                    category=self.category,
                    reference="https://cheatsheetseries.owasp.org/cheatsheets/Web_Service_Security_Cheat_Sheet.html"
                ))
            else:
                findings.append(Finding(
                    id="WS-SERVER-DETECTED",
                    title=f"Web Server Technology Identified: {detected_server}",
                    severity=Severity.INFORMATIONAL,
                    url=target_url,
                    status_code=resp.status_code,
                    evidence=f"Server: {server_hdr}",
                    description=f"Identified web server banner as {detected_server}.",
                    remediation="Mask or suppress the Server header if required by organizational hardening policies.",
                    category=self.category
                ))

        if progress_callback:
            progress_callback("Analyzing application framework fingerprints...", 2, 3)

        # 2. Match Framework signatures
        for fw in self.FRAMEWORK_SIGNATURES:
            detected = False
            evidence_parts = []

            # Check header
            if fw["header"] in resp.headers:
                val = resp.headers.get(fw["header"], "")
                if re.search(fw["regex"], val, re.IGNORECASE):
                    detected = True
                    evidence_parts.append(f"{fw['header']}: {val}")

            # Check cookie
            if fw["cookie"] and fw["cookie"] in set_cookie:
                detected = True
                evidence_parts.append(f"Cookie: {fw['cookie']}")

            if detected:
                findings.append(Finding(
                    id=f"WS-FRAMEWORK-{fw['name'].upper().replace(' ', '_')}",
                    title=f"Application Framework Detected: {fw['name']}",
                    severity=Severity.INFORMATIONAL,
                    url=target_url,
                    status_code=resp.status_code,
                    evidence="; ".join(evidence_parts),
                    description=f"Detected technology footprint for {fw['desc']}.",
                    remediation="Ensure the framework is kept up-to-date with security patches and suppress framework branding headers.",
                    category=self.category
                ))

        if progress_callback:
            progress_callback("Inspecting meta generator tags...", 3, 3)

        # 3. Check HTML meta generator tag
        gen_match = re.search(r'<meta[^>]+name=[\'"]generator[\'"][^>]+content=[\'"]([^\'"]+)[\'"]', html_body, re.IGNORECASE)
        if gen_match:
            gen_val = gen_match.group(1)
            findings.append(Finding(
                id="WS-META-GENERATOR",
                title=f"CMS / Site Generator Disclosed: {gen_val}",
                severity=Severity.INFORMATIONAL,
                url=target_url,
                status_code=resp.status_code,
                evidence=f'<meta name="generator" content="{gen_val}">',
                description=f"HTML source explicitly discloses the site CMS or site generator: {gen_val}.",
                remediation="Remove or customize the generator meta tag in your template/theme settings.",
                category=self.category
            ))

        return findings
