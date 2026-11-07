"""
WebSentry HTTP Methods Detection Module
Discovers enabled HTTP verbs and flags potentially dangerous methods (TRACE, PUT, DELETE, WebDAV).
Developer: Isha Sonaria
"""

from typing import List, Set
from websentry.modules.base import BaseScanner, ProgressCallback
from websentry.core.finding import Finding, Severity
from websentry.core.http_client import HttpClient
from websentry.core.config import ScanConfig

class MethodScanner(BaseScanner):
    name = "HTTP Methods Detection"
    description = "Probes enabled HTTP methods and checks for dangerous verbs."
    category = "HTTP Methods"

    DANGEROUS_METHODS = {
        "TRACE": {
            "severity": Severity.MEDIUM,
            "title": "HTTP TRACE Method Enabled (Cross-Site Tracing / XST)",
            "description": "The TRACE method reflects the client request back in the response body. In conjunction with XSS, attackers can steal HttpOnly authentication cookies.",
            "remediation": "Disable the HTTP TRACE method in web server configuration (e.g., 'TraceEnable off' in Apache).",
            "ref": "https://owasp.org/www-community/attacks/Cross_Site_Tracing"
        },
        "PUT": {
            "severity": Severity.MEDIUM,
            "title": "HTTP PUT Method Advertised",
            "description": "The PUT method allows uploading or replacing resources. If access controls are misconfigured, unauthenticated users could upload arbitrary malicious files.",
            "remediation": "Disable the PUT method if not required by an authorized API, or enforce strict authentication and upload validation.",
            "ref": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
        },
        "DELETE": {
            "severity": Severity.MEDIUM,
            "title": "HTTP DELETE Method Advertised",
            "description": "The DELETE method allows deleting resources from the server. Without strict authentication, it presents an integrity risk.",
            "remediation": "Ensure DELETE is disabled for public static endpoints and restricted to authenticated API users.",
            "ref": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
        },
        "CONNECT": {
            "severity": Severity.HIGH,
            "title": "HTTP CONNECT Method Enabled",
            "description": "The CONNECT method can turn a web server into an open forward proxy, allowing attackers to tunnel arbitrary TCP connections through the server.",
            "remediation": "Disable HTTP CONNECT proxying on the web server.",
            "ref": "https://portswigger.net/web-security/http-host-header"
        },
        "PROPFIND": {
            "severity": Severity.LOW,
            "title": "WebDAV PROPFIND Method Enabled",
            "description": "PROPFIND is part of WebDAV and can be abused to enumerate internal directory structures, usernames, and file metadata.",
            "remediation": "Disable WebDAV modules (mod_dav, IIS WebDAV Publishing) if not required.",
            "ref": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods"
        }
    }

    def run(
        self,
        target_url: str,
        client: HttpClient,
        config: ScanConfig,
        progress_callback: ProgressCallback = None
    ) -> List[Finding]:
        findings: List[Finding] = []
        enabled_methods: Set[str] = set()

        if progress_callback:
            progress_callback("Sending OPTIONS probe...", 1, 3)

        # 1. Send OPTIONS request
        resp_options = client.options(target_url)
        allow_header = resp_options.headers.get("Allow") or resp_options.headers.get("Public")

        if allow_header:
            parsed = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
            enabled_methods.update(parsed)

        if progress_callback:
            progress_callback("Actively testing dangerous HTTP verbs...", 2, 3)

        # 2. Actively probe TRACE to confirm if server actually responds with 200 reflecting body
        trace_resp = client.request("TRACE", target_url)
        if trace_resp.status_code == 200 and "TRACE" in trace_resp.text:
            enabled_methods.add("TRACE")
            findings.append(Finding(
                id="WS-METHOD-TRACE-ACTIVE",
                title="Active HTTP TRACE Verification Confirmed",
                severity=Severity.HIGH,
                url=target_url,
                status_code=trace_resp.status_code,
                evidence=f"HTTP TRACE returned status 200 reflecting request headers:\n{trace_resp.text[:200]}...",
                description="Server actively echoed request headers in response to HTTP TRACE verb.",
                remediation="Immediately disable TRACE method in web server configuration ('TraceEnable off').",
                category=self.category,
                reference="https://owasp.org/www-community/attacks/Cross_Site_Tracing"
            ))

        # 3. Check discovered methods from Allow/Public headers
        for method, info in self.DANGEROUS_METHODS.items():
            if method in enabled_methods and not (method == "TRACE" and any(f.id == "WS-METHOD-TRACE-ACTIVE" for f in findings)):
                findings.append(Finding(
                    id=f"WS-METHOD-{method}",
                    title=info["title"],
                    severity=info["severity"],
                    url=target_url,
                    status_code=resp_options.status_code if resp_options.status_code else None,
                    evidence=f"Disclosed in Allow/Public header: '{allow_header}'",
                    description=info["description"],
                    remediation=info["remediation"],
                    category=self.category,
                    reference=info.get("ref")
                ))

        if progress_callback:
            progress_callback("Compiling method findings...", 3, 3)

        # Informational finding detailing all discovered methods
        if enabled_methods:
            sorted_methods = ", ".join(sorted(enabled_methods))
            findings.append(Finding(
                id="WS-METHOD-LIST",
                title="Discovered HTTP Methods",
                severity=Severity.INFORMATIONAL,
                url=target_url,
                status_code=resp_options.status_code if resp_options.status_code else None,
                evidence=f"Allowed methods: {sorted_methods}",
                description=f"The target advertised support for the following HTTP methods: {sorted_methods}.",
                remediation="Verify that only required methods (typically GET, POST, HEAD) are exposed to public endpoints.",
                category=self.category
            ))

        return findings
