# WebSentry — Web Server Security Assessment Tool

```text
 __      __      ___.    _________               __                       
/  \    /  \ ____\_ |__ /   _____/____   _______/  |________ ___.__.      
\   \/\/   // __ \| __ \\_____  \/ __ \ /    /\   __\_  __ <   |  |      
 \        /\  ___/| \_\ \        \  ___/|   |  \|  |  |  | \/\___  |      
  \__/\  /  \___  >___  /_______  /\___  >___|  /|__|  |__|   / ____|      
       \/       \/    \/        \/     \/     \/             \/           
```

> **BUILT BY ISHA SONARIA**  
> GitHub: [https://github.com/ishasonaria568-prog](https://github.com/ishasonaria568-prog)  
> Version: `1.2.0` | License: `MIT`

---

## 1. Project Introduction

**WebSentry** is a high-performance, modular, open-source CLI-based web server security scanning tool inspired by the capabilities and scanning methodology of **Nikto**. Engineered with offensive security standards and strict defensive guardrails, WebSentry audits target web infrastructure for missing security defenses, information leakage, exposed configurations, sensitive endpoints, dangerous HTTP methods, and known server misconfigurations.

WebSentry is completely CLI-driven, lightweight, and engineered with **zero required external binary dependencies** while supporting modern Python environments, virtual environments, and global installation via `pipx` on **Kali Linux**, Debian, Ubuntu, macOS, and Linux distributions.

---

## 2. Core Features

### 🛡️ HTTP Header Analysis
- **Defensive Headers Check**: Audits existence and configuration of `Content-Security-Policy`, `Strict-Transport-Security` (HSTS), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and Cross-Origin policies (`COOP`/`COEP`/`CORP`).
- **Information Leakage**: Detects verbose software versions in `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`, `Via`, and `X-Generator`.
- **Policy Hardening**: Identifies weak CSP directives (`'unsafe-inline'` without nonces, `'unsafe-eval'`) and wildcard CORS policies (`Access-Control-Allow-Origin: *`).

### 🔌 HTTP Methods Detection
- Identifies allowed and advertised verbs using `OPTIONS`, `Allow`, and `Public` headers.
- Actively tests and verifies dangerous methods such as `TRACE` (Cross-Site Tracing / XST vulnerability), `PUT` (unauthenticated upload risk), `DELETE`, `CONNECT` (proxy tunnel risk), and WebDAV methods (`PROPFIND`, `MKCOL`).

### 🔍 Server & Technology Fingerprinting
- Fingerprints leading web servers: Apache, Nginx, Microsoft-IIS, Caddy, Cloudflare Edge, LiteSpeed, OpenResty, Envoy, Gunicorn, Uvicorn, and Werkzeug.
- Analyzes software version numbers and reports patch risk.
- Detects backend runtime engines and CMS platforms (PHP, ASP.NET, Java/Spring, Python/Django, Ruby on Rails, Node/Express, WordPress).

### 📁 Sensitive File & Directory Detection
- Discovers exposed source code repositories: `/.git/HEAD`, `/.git/config`, `/.svn/entries`.
- Detects exposed environment credentials: `/.env`, `/.env.local`, `/.env.production`.
- Identifies downloadable database dumps and archives: `/backup.sql`, `/dump.sql`, `/backup.zip`, `/site.tar.gz`.
- Detects exposed diagnostic and administration endpoints: `/server-status`, `/server-info`, `/actuator/env`, `/actuator/health`, `/phpinfo.php`, `/.well-known/security.txt`, `/robots.txt`.
- **Intelligent False-Positive Calibration**: Calibrates against soft-404 / catch-all endpoints to eliminate false reports.

### 🔒 SSL/TLS Configuration Assessment
- Checks HTTPS availability on port 443.
- Inspects certificate validity, trust chain, common name (CN), subject alt names (SANs), and issuer.
- Computes exact days remaining until expiration (flags expiring soon or expired certificates).
- Flags untrusted or self-signed certificates.
- Probes for deprecated and insecure legacy protocols (`TLSv1.0` and `TLSv1.1`).

### ⚙️ Common Web Misconfiguration Checks
- **Directory Browsing**: Detects active directory indexing (`Index of /`, `Parent Directory`).
- **Default Installation Pages**: Identifies default Apache, Nginx, IIS, and LiteSpeed landing pages.
- **Session Security**: Audits `Set-Cookie` directives for missing `Secure`, `HttpOnly`, and `SameSite` flags.
- **Application Error Disclosure**: Detects raw stack traces leaking internal paths (Python, Java, PHP, ASP.NET, Node.js).

### 🎯 Nikto-Inspired Signature Engine
- Maintainable local signature database (`websentry/signatures/default_signatures.json`).
- Checks for known dangerous scripts (`test.cgi`, `printenv`, `phpmyadmin`, `elmah.axd`, `swagger-ui.html`, `solr/`, `jmx-console/`).
- Supports user-defined custom signature files via `--signatures <file.json>`.
- Generates reproducible technical evidence for every finding.

---

## 3. Installation on Kali Linux

WebSentry is 100% compatible with **Kali Linux 2023.x / 2024.x / 2025.x / 2026.x**.

### Recommended: Global Isolated Installation via `pipx`

```bash
# 1. Update system and ensure pipx is installed
sudo apt update && sudo apt install -y git python3 python3-pip pipx
pipx ensurepath

# 2. Clone the repository
git clone https://github.com/ishasonaria568-prog/websentry.git
cd websentry

# 3. Install globally using pipx
pipx install .

# 4. Verify installation
websentry --help
websentry version
```

### Alternative: Virtual Environment Installation

```bash
# Clone the repository
git clone https://github.com/ishasonaria568-prog/websentry.git
cd websentry

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies and editable package
pip install -r requirements.txt
pip install -e .

# Run WebSentry
websentry --help
```

### Standalone Direct Execution (Zero Installation Required)

WebSentry includes an automatic fallback to Python's standard library (`urllib.request`), allowing direct execution without installing third-party packages:

```bash
git clone https://github.com/ishasonaria568-prog/websentry.git
cd websentry
chmod +x websentry.py bin/websentry

# Execute directly
./websentry.py version
./bin/websentry scan -u http://127.0.0.1:8080
```

---

## 4. Usage & Command Reference

### Basic Commands

```bash
# View startup banner and help
websentry --help

# View version, author, and build metadata
websentry version

# Verify signature database and local rules count
websentry update
```

### Scanning Targets

```bash
# Standard scan against a local or private target
websentry scan -u http://127.0.0.1:8080

# Fast scan of critical issues and high-risk paths
websentry scan -u http://127.0.0.1:8080 --quick

# Full deep scan across all modules and complete signature database
websentry scan -u http://127.0.0.1:8080 --full

# Scan specific modules only
websentry scan -u http://127.0.0.1:8080 --headers
websentry scan -u http://127.0.0.1:8080 --ssl
websentry scan -u http://127.0.0.1:8080 --methods
websentry scan -u http://127.0.0.1:8080 --files
websentry scan -u http://127.0.0.1:8080 --nikto

# Authorized public target scan (requires explicit --allow-public flag)
websentry scan -u https://authorized-target.com --allow-public
```

### Reporting & Output Options

```bash
# Generate standalone interactive HTML report
websentry scan -u http://127.0.0.1:8080 --format html

# Generate structured JSON report
websentry scan -u http://127.0.0.1:8080 --format json

# Generate plain text report
websentry scan -u http://127.0.0.1:8080 --format txt

# Generate all report formats at once
websentry scan -u http://127.0.0.1:8080 --format all

# Specify custom output path
websentry scan -u http://127.0.0.1:8080 --output reports/target_audit.json
```

### Advanced Performance & Tuning

```bash
# Configure worker thread concurrency (default: 6)
websentry scan -u http://127.0.0.1:8080 -t 10

# Set custom request timeout (seconds)
websentry scan -u http://127.0.0.1:8080 --timeout 12.0

# Rate-limit requests (delay in seconds between requests)
websentry scan -u http://127.0.0.1:8080 --delay 0.2

# Ignore self-signed TLS errors on test targets
websentry scan -u https://127.0.0.1:8443 --insecure

# Load custom signature rules database
websentry scan -u http://127.0.0.1:8080 --signatures custom_rules.json

# Disable colored terminal output
websentry scan -u http://127.0.0.1:8080 --no-color
```

---

## 5. Risk Classification System

Every finding in WebSentry is classified into a 5-tier severity hierarchy based on actual exploitability and impact:

| Severity | Color Code | Description | Examples |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | `Crimson / Red [CRITICAL]` | Direct compromise vector, leaked credentials, or full source code disclosure | Exposed `/.env` with credentials, exposed `/.git/HEAD`, downloadable raw SQL dump, unauthenticated JMX console |
| **HIGH** | `Bright Red [HIGH]` | Severe infrastructure flaw or active dangerous capability | Enabled `TRACE` method (XST), active `CONNECT` tunneling, expired SSL certificate, deprecated `TLSv1.0`/`TLSv1.1`, exposed `/.git/config` |
| **MEDIUM** | `Orange / Yellow [MEDIUM]` | Significant defense gap, clickjacking, or sensitive panel exposure | Missing `Content-Security-Policy`, missing `HSTS`, directory indexing enabled, cookie missing `Secure`/`HttpOnly`, `phpinfo.php` exposed |
| **LOW** | `Yellow [LOW]` | Weak configuration, MIME sniffing, or minor information disclosure | Missing `X-Content-Type-Options`, `X-Frame-Options`, verbose server version, wildcard CORS |
| **INFORMATIONAL** | `Blue / Cyan [INFO]` | Non-exploitable technology discovery or architectural detail | Valid SSL certificate lifetime, discovered HTTP methods, detected framework, `robots.txt` present |

---

## 6. Example Terminal Output

```text
 __      __      ___.    _________               __                       
/  \    /  \ ____\_ |__ /   _____/____   _______/  |________ ___.__.      
\   \/\/   // __ \| __ \\_____  \/ __ \ /    /\   __\_  __ <   |  |      
 \        /\  ___/| \_\ \        \  ___/|   |  \|  |  |  | \/\___  |      
  \__/\  /  \___  >___  /_______  /\___  >___|  /|__|  |__|   / ____|      
       \/       \/    \/        \/     \/     \/             \/           

  [ BUILT BY ISHA SONARIA ]   Web Server Security Assessment Tool
  Version: v1.2.0  |  GitHub: https://github.com/ishasonaria568-prog  |  Engine: Nikto-Inspired v1.2
  ──────────────────────────────────────────────────────────────────────────
  [!] LEGAL DISCLAIMER: This tool is intended for authorized security
  assessments, penetration tests, and defensive audits only. Scanning targets
  without explicit prior written consent is strictly illegal and prohibited.
  ──────────────────────────────────────────────────────────────────────────

[*] Target Validation & Safety Gatekeeper...
  [+] Target URL:    http://127.0.0.1:8080
  [+] Resolved IP(s): 127.0.0.1
  [+] Scope Mode:     Private/Internal RFC1918 Scope
  [+] Scan Profile:   STANDARD (Concurrency: 6 threads)
  [+] Engine Delay:   0.05s | Timeout: 8.0s
  ──────────────────────────────────────────────────────────────────────────

[*] Starting Security Assessment Modules...

[*] Module: Header Analysis (Analyzes HTTP headers for security defenses and information disclosure.)
  [MEDIUM] Missing Content-Security-Policy (CSP) Header [200]
    Target: http://127.0.0.1:8080
    Category: HTTP Headers
    Detail: The Content-Security-Policy response header restricts the sources of scripts, images, and other assets.
    Evidence: Header 'Content-Security-Policy' was not returned in HTTP 200 response.
    Remediation: Define and deploy a restrictive Content-Security-Policy header.

[*] Module: HTTP Methods Detection (Probes enabled HTTP methods and checks for dangerous verbs.)
  [HIGH] Active HTTP TRACE Verification Confirmed [200]
    Target: http://127.0.0.1:8080
    Category: HTTP Methods
    Detail: Server actively echoed request headers in response to HTTP TRACE verb.
    Evidence: HTTP TRACE returned status 200 reflecting request headers.
    Remediation: Immediately disable TRACE method in web server configuration ('TraceEnable off').

[*] Module: Sensitive Files Detection (Discovers exposed source repositories, configurations, backups, and administrative endpoints.)
  [CRITICAL] Exposed Git Repository (/.git/HEAD) [200]
    Target: http://127.0.0.1:8080/.git/HEAD
    Category: Exposed Files
    Detail: The root .git/HEAD file is publicly accessible, allowing potential full source code reconstruction.
    Evidence: Matched signature: 'ref: refs/' (HTTP 200, 21 bytes).
    Remediation: Block access to all dotfiles and dotfolders (.git, .svn, .env) in web server config.

  [CRITICAL] Exposed Environment Configuration File (/.env) [200]
    Target: http://127.0.0.1:8080/.env
    Category: Exposed Files
    Detail: Exposed .env file containing environment credentials, database passwords, or application secrets.
    Evidence: Matched signature: 'DB_PASSWORD' in response.
    Remediation: Store .env files outside the web root and configure web server rules to deny access to .env* files.

  ──────────────────────────────────────────────────────────────────────────
  SCAN SUMMARY & RISK BREAKDOWN:
  ──────────────────────────────────────────────────────────────────────────
  Target:            http://127.0.0.1:8080
  Duration:          2.14 seconds
  HTTP Requests:     48
  Total Findings:    7

    [CRITICAL]:        2
    [HIGH]:            1
    [MEDIUM]:          2
    [LOW]:             1
    [INFORMATIONAL]:   1
  ──────────────────────────────────────────────────────────────────────────
  Developer Credit: Built by ISHA SONARIA | WebSentry v1.2.0

[+] Report(s) successfully generated:
    reports/websentry_scan_20261107_063000.json
```

---

## 7. Safety, Ethics & Authorization

WebSentry is built with defensive and professional assessment principles:

1. **Authorization Gatekeeper**: By default, WebSentry refuses to scan public internet targets unless the operator explicitly passes `--allow-public`. Localhost (`127.0.0.1`), private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), and test environments are permitted without `--allow-public`.
2. **Non-Destructive Testing**: WebSentry never injects SQL injection payloads, never launches exploit code, never attempts remote code execution, and never conducts denial-of-service tests.
3. **No Brute-Forcing**: WebSentry does not brute-force passwords, authentication logins, or user credentials.
4. **Data Privacy**: WebSentry operates 100% locally. No scan results, hostnames, or target data are ever transmitted to third-party cloud services or telemetry servers.

---

## 8. Uninstallation & Troubleshooting

### Uninstallation

#### If installed via `pipx`:
```bash
pipx uninstall websentry
```

#### If installed via `pip`:
```bash
pip uninstall websentry -y
```

### Troubleshooting

- **`command not found: websentry`**: Ensure `~/.local/bin` is in your environment `PATH`. Run `pipx ensurepath` and restart your shell (`source ~/.bashrc` or `source ~/.zshrc`).
- **`[!] SAFETY REFUSAL: Public Target Detected!`**: WebSentry detected a public internet IP. Confirm you have written authorization to test the target, then re-run with `--allow-public`.
- **`SSL Certificate Verification Error`**: If assessing a staging server or local development environment with self-signed TLS certificates, supply the `--insecure` (or `-k`) flag.
- **Connection timeouts**: If the target server has aggressive rate limiting or slow network latency, increase `--timeout 15` and lower concurrency with `-t 2` and `--delay 0.3`.

---

## 9. Running Tests

WebSentry includes a complete automated test suite featuring unit tests and an in-process local HTTP test server:

```bash
# Run all tests
python3 -m unittest discover -s tests -v
```

All 15 automated test cases validate safety guardrails, URL normalization, finding serialization, report generation, and realistic server vulnerability discovery.

---

## 10. Developer Information

- **Developer:** Isha Sonaria
- **GitHub:** [https://github.com/ishasonaria568-prog](https://github.com/ishasonaria568-prog)
- **Email:** ishasonaria568@gmail.com
- **Project:** WebSentry — Web Server Security Assessment Tool
- **Inspiration:** Nikto Web Server Scanner
