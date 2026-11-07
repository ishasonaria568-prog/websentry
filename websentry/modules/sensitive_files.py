"""
WebSentry Sensitive File & Directory Detection Module
High-precision probe for exposed configuration, version control, backups, and diagnostic paths.
Includes intelligent soft-404 / catch-all false-positive suppression.
Developer: Isha Sonaria
"""

import concurrent.futures
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from websentry.modules.base import BaseScanner, ProgressCallback
from websentry.core.finding import Finding, Severity
from websentry.core.http_client import HttpClient
from websentry.core.config import ScanConfig

class SensitiveFilesScanner(BaseScanner):
    name = "Sensitive Files Detection"
    description = "Discovers exposed source repositories, configurations, backups, and administrative endpoints."
    category = "Exposed Files"

    # Targeted high-value test definitions
    TARGET_PATHS: List[Dict[str, Any]] = [
        # Git / VCS exposure (CRITICAL / HIGH)
        {
            "path": "/.git/HEAD",
            "title": "Exposed Git Repository (/.git/HEAD)",
            "severity": Severity.CRITICAL,
            "match": "ref: refs/",
            "desc": "The root .git/HEAD file is publicly accessible, allowing potential full source code reconstruction.",
            "remediation": "Block access to all dotfiles and dotfolders (.git, .svn, .env) in web server config.",
            "ref": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure"
        },
        {
            "path": "/.git/config",
            "title": "Exposed Git Configuration (/.git/config)",
            "severity": Severity.HIGH,
            "match": "[core]",
            "desc": "The Git repository configuration file is exposed, disclosing repository remotes and branch names.",
            "remediation": "Deny web access to /.git/ directory.",
            "ref": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure"
        },
        {
            "path": "/.env",
            "title": "Exposed Environment Configuration File (/.env)",
            "severity": Severity.CRITICAL,
            "match_any": ["DB_PASSWORD", "APP_KEY", "SECRET", "API_KEY", "DATABASE_URL", "AWS_", "PASSWORD="],
            "desc": "Exposed .env file containing environment credentials, database passwords, or application secrets.",
            "remediation": "Store .env files outside the web root and configure web server rules to deny access to .env* files.",
            "ref": "https://cwe.mitre.org/data/definitions/200.html"
        },
        {
            "path": "/.env.local",
            "title": "Exposed Local Environment File (/.env.local)",
            "severity": Severity.CRITICAL,
            "match_any": ["=", "KEY", "SECRET", "DB_"],
            "desc": "Publicly readable .env.local file containing local secret overrides.",
            "remediation": "Move configuration files out of document root and deny access.",
            "ref": "https://cwe.mitre.org/data/definitions/200.html"
        },
        {
            "path": "/.DS_Store",
            "title": "Exposed Apple macOS Metadata File (/.DS_Store)",
            "severity": Severity.LOW,
            "match_bytes": b"\x00\x00\x00\x01Bud1",
            "desc": "macOS Finder metadata file exposed. May disclose hidden file and folder names.",
            "remediation": "Remove .DS_Store files and add them to .gitignore; block them in web server config.",
            "ref": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure"
        },
        # Configuration & Application Files
        {
            "path": "/web.config",
            "title": "Exposed IIS Configuration (web.config)",
            "severity": Severity.HIGH,
            "match": "<configuration>",
            "desc": "IIS web.config file exposed, potentially revealing database connection strings, handlers, and security rules.",
            "remediation": "Verify IIS Request Filtering is actively blocking web.config.",
            "ref": "https://cwe.mitre.org/data/definitions/200.html"
        },
        {
            "path": "/docker-compose.yml",
            "title": "Exposed Docker Compose File",
            "severity": Severity.HIGH,
            "match_any": ["services:", "version:", "image:"],
            "desc": "Docker compose specification file exposed, disclosing internal container network topology and environment variables.",
            "remediation": "Do not place infrastructure files inside the web document root.",
            "ref": "https://cwe.mitre.org/data/definitions/200.html"
        },
        {
            "path": "/config.json",
            "title": "Exposed JSON Application Configuration",
            "severity": Severity.MEDIUM,
            "match_any": ["{", "api", "database", "host"],
            "desc": "Publicly accessible configuration JSON file.",
            "remediation": "Restrict access to sensitive internal configuration files.",
            "ref": "https://cwe.mitre.org/data/definitions/200.html"
        },
        # Backups & Archives
        {
            "path": "/backup.zip",
            "title": "Exposed Backup Archive (backup.zip)",
            "severity": Severity.HIGH,
            "match_bytes": b"PK\x03\x04",
            "desc": "A ZIP archive named backup.zip is publicly downloadable.",
            "remediation": "Remove backup files from the web root and store backups securely in dedicated cold storage.",
            "ref": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files"
        },
        {
            "path": "/backup.sql",
            "title": "Exposed Database Dump (backup.sql)",
            "severity": Severity.CRITICAL,
            "match_any": ["CREATE TABLE", "INSERT INTO", "MySQL dump", "PostgreSQL database dump"],
            "desc": "A raw SQL database dump is publicly downloadable.",
            "remediation": "Never store SQL backups inside the web root.",
            "ref": "https://cwe.mitre.org/data/definitions/200.html"
        },
        {
            "path": "/dump.sql",
            "title": "Exposed Database Dump (dump.sql)",
            "severity": Severity.CRITICAL,
            "match_any": ["CREATE TABLE", "INSERT INTO", "MySQL dump", "-- Dump"],
            "desc": "Database dump exposed to unauthenticated download.",
            "remediation": "Remove SQL dump immediately from web root.",
            "ref": "https://cwe.mitre.org/data/definitions/200.html"
        },
        # Diagnostics & Actuators
        {
            "path": "/phpinfo.php",
            "title": "Exposed PHP Information Script (phpinfo.php)",
            "severity": Severity.MEDIUM,
            "match": "phpinfo()",
            "desc": "phpinfo() diagnostic page is publicly accessible, leaking full PHP configuration, environment variables, and module paths.",
            "remediation": "Delete diagnostic scripts (phpinfo.php, test.php) from production environments.",
            "ref": "https://owasp.org/www-community/vulnerabilities/Information_leak"
        },
        {
            "path": "/actuator/env",
            "title": "Exposed Spring Boot Actuator /env Endpoint",
            "severity": Severity.CRITICAL,
            "match_any": ["propertySources", "activeProfiles"],
            "desc": "Spring Boot Actuator environment endpoint is exposed without authentication, disclosing system properties and credentials.",
            "remediation": "Secure Actuator endpoints using Spring Security or disable exposure: management.endpoints.web.exposure.exclude=env.",
            "ref": "https://cwe.mitre.org/data/definitions/200.html"
        },
        {
            "path": "/actuator/health",
            "title": "Spring Boot Actuator Health Endpoint Exposed",
            "severity": Severity.LOW,
            "match": '"status"',
            "desc": "Spring Boot /actuator/health endpoint is exposed, revealing health indicators and internal service dependencies.",
            "remediation": "Restrict health details to authorized monitoring systems only.",
            "ref": "https://cwe.mitre.org/data/definitions/200.html"
        },
        {
            "path": "/server-status",
            "title": "Exposed Apache server-status Page",
            "severity": Severity.MEDIUM,
            "match": "Apache Server Status",
            "desc": "Apache mod_status page is publicly accessible, displaying active client IPs, requests, and server performance metrics.",
            "remediation": "Restrict mod_status to localhost only: Require local.",
            "ref": "https://httpd.apache.org/docs/2.4/mod/mod_status.html"
        },
        # Informational & Policy Endpoints
        {
            "path": "/robots.txt",
            "title": "robots.txt File Disclosed",
            "severity": Severity.INFORMATIONAL,
            "match": "User-agent:",
            "desc": "The robots.txt file discloses disallowed paths which may point attackers toward sensitive administrative or hidden endpoints.",
            "remediation": "Review robots.txt to ensure confidential or administrative URLs are not explicitly advertised.",
            "ref": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles"
        },
        {
            "path": "/.well-known/security.txt",
            "title": "security.txt File Disclosed",
            "severity": Severity.INFORMATIONAL,
            "match": "Contact:",
            "desc": "RFC 9116 security.txt vulnerability disclosure policy file detected.",
            "remediation": "Ensure contact details and expiration dates remain up-to-date.",
            "ref": "https://securitytxt.org/"
        }
    ]

    def _probe_path(self, target_url: str, item: Dict[str, Any], client: HttpClient, baseline_size: int, baseline_status: int) -> Optional[Finding]:
        test_url = urljoin(target_url, item["path"])
        resp = client.get(test_url, allow_redirects=False)

        # Must be 200 OK or 403 Forbidden for certain interesting files
        if resp.status_code != 200:
            # If 403, might be protected directory or file
            if resp.status_code == 403 and any(k in item["path"] for k in (".git", ".env")):
                return Finding(
                    id=f"WS-FORBIDDEN-{item['path'].replace('/', '_').replace('.', '_')}",
                    title=f"Protected Resource Detected (HTTP 403 Forbidden: {item['path']})",
                    severity=Severity.INFORMATIONAL,
                    url=test_url,
                    status_code=403,
                    evidence=f"HTTP 403 Forbidden returned for {item['path']}.",
                    description=f"Resource {item['path']} exists and is protected by server access controls.",
                    remediation="Confirm access controls remain strictly enforced.",
                    category=self.category
                )
            return None

        # Check against baseline soft-404
        content_len = len(resp.content)
        if baseline_status == 200 and abs(content_len - baseline_size) < 50:
            # Catch-all soft 404
            return None

        # Content signature verification
        is_match = False
        evidence_snippet = ""

        if "match_bytes" in item:
            if item["match_bytes"] in resp.content:
                is_match = True
                evidence_snippet = f"Binary magic bytes confirmed ({len(resp.content)} bytes)."
        elif "match" in item:
            if item["match"] in resp.text:
                is_match = True
                evidence_snippet = f"Matched signature: '{item['match']}' (HTTP 200, {len(resp.content)} bytes)."
        elif "match_any" in item:
            for m in item["match_any"]:
                if m in resp.text:
                    is_match = True
                    evidence_snippet = f"Matched signature: '{m}' in response."
                    break

        if is_match:
            return Finding(
                id=f"WS-FILE-{item['path'].replace('/', '_').replace('.', '_')}",
                title=item["title"],
                severity=item["severity"],
                url=test_url,
                status_code=resp.status_code,
                evidence=evidence_snippet,
                description=item["desc"],
                remediation=item["remediation"],
                category=self.category,
                reference=item.get("ref")
            )

        return None

    def run(
        self,
        target_url: str,
        client: HttpClient,
        config: ScanConfig,
        progress_callback: ProgressCallback = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        if progress_callback:
            progress_callback("Performing baseline soft-404 calibration...", 1, len(self.TARGET_PATHS) + 2)

        # Baseline request for non-existent path to detect soft-404 catch-alls
        baseline_url = urljoin(target_url, "/__websentry_404_calibration_test_token_87234__")
        base_resp = client.get(baseline_url, allow_redirects=False)
        baseline_status = base_resp.status_code
        baseline_size = len(base_resp.content)

        paths_to_test = self.TARGET_PATHS
        # If in quick mode, only test top 8 highest severity paths
        if config.mode == "quick":
            paths_to_test = [p for p in self.TARGET_PATHS if p["severity"] in (Severity.CRITICAL, Severity.HIGH)]

        total_paths = len(paths_to_test)
        completed = 0

        # Concurrent scanning with ThreadPoolExecutor
        workers = min(config.threads, 8)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_item = {
                executor.submit(self._probe_path, target_url, item, client, baseline_size, baseline_status): item
                for item in paths_to_test
            }

            for future in concurrent.futures.as_completed(future_to_item):
                completed += 1
                if progress_callback and completed % 2 == 0:
                    progress_callback(f"Checking sensitive files ({completed}/{total_paths})...", completed, total_paths)
                try:
                    f = future.result()
                    if f:
                        findings.append(f)
                except Exception:
                    pass

        return findings
