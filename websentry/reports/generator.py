"""
WebSentry Report Generation Subsystem
Generates comprehensive JSON, plain-text (TXT), and standalone interactive HTML reports.
Developer: Isha Sonaria
GitHub: https://github.com/ishasonaria568-prog
"""

import json
import os
import html
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
from websentry.core.finding import Finding, Severity

class ReportGenerator:
    def __init__(
        self,
        target_url: str,
        findings: List[Finding],
        duration_seconds: float,
        total_requests: int,
        version: str = "1.2.0",
        author: str = "Isha Sonaria",
        github: str = "https://github.com/ishasonaria568-prog"
    ):
        self.target_url = target_url
        self.findings = findings
        self.duration = duration_seconds
        self.total_requests = total_requests
        self.version = version
        self.author = author
        self.github = github
        self.timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Calculate severity summary
        self.severity_counts = {
            "CRITICAL": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "HIGH": sum(1 for f in findings if f.severity == Severity.HIGH),
            "MEDIUM": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "LOW": sum(1 for f in findings if f.severity == Severity.LOW),
            "INFORMATIONAL": sum(1 for f in findings if f.severity == Severity.INFORMATIONAL),
        }
        self.total_findings = len(findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_meta": {
                "tool": "WebSentry",
                "version": self.version,
                "author": self.author,
                "github": self.github,
                "target_url": self.target_url,
                "timestamp": self.timestamp,
                "duration_seconds": round(self.duration, 2),
                "total_requests": self.total_requests,
                "total_findings": self.total_findings,
                "summary": self.severity_counts,
            },
            "findings": [f.to_dict() for f in self.findings]
        }

    def generate_json(self) -> str:
        """Serializes scan findings into structured JSON."""
        return json.dumps(self.to_dict(), indent=2)

    def generate_txt(self) -> str:
        """Formats scan findings into clean plain-text report."""
        lines = []
        divider = "=" * 76
        subdiv = "-" * 76

        lines.append(divider)
        lines.append("  WEBSENTRY — WEB SERVER SECURITY ASSESSMENT REPORT")
        lines.append(f"  Developer: {self.author}  |  GitHub: {self.github}")
        lines.append(f"  Version: v{self.version}  |  Scan Date: {self.timestamp}")
        lines.append(divider)
        lines.append(f"Target URL:       {self.target_url}")
        lines.append(f"Scan Duration:    {self.duration:.2f} seconds")
        lines.append(f"Total Requests:   {self.total_requests}")
        lines.append(f"Total Findings:   {self.total_findings}")
        lines.append(subdiv)
        lines.append("FINDINGS BY SEVERITY:")
        for sev, count in self.severity_counts.items():
            lines.append(f"  - {sev.ljust(15)}: {count}")
        lines.append(divider)
        lines.append("")

        if not self.findings:
            lines.append("No security vulnerabilities or misconfigurations detected.")
        else:
            for i, f in enumerate(self.findings, 1):
                lines.append(f"[{i:02d}] [{f.severity.value}] {f.title}")
                lines.append(f"     Target URL:    {f.url}")
                if f.status_code:
                    lines.append(f"     Status Code:   HTTP {f.status_code}")
                lines.append(f"     Category:      {f.category}")
                lines.append(f"     Description:   {f.description}")
                if f.evidence:
                    lines.append(f"     Evidence:      {f.evidence}")
                lines.append(f"     Remediation:   {f.remediation}")
                if f.reference:
                    lines.append(f"     Reference:     {f.reference}")
                lines.append(subdiv)

        lines.append("")
        lines.append("END OF WEBSENTRY REPORT — BUILT BY ISHA SONARIA")
        lines.append(divider)
        return "\n".join(lines)

    def generate_html(self) -> str:
        """Renders self-contained responsive HTML report with dark red/black cyberpunk theme."""
        # Convert findings to JSON for client-side search/filter
        findings_json = json.dumps([f.to_dict() for f in self.findings])
        
        crit_count = self.severity_counts["CRITICAL"]
        high_count = self.severity_counts["HIGH"]
        med_count = self.severity_counts["MEDIUM"]
        low_count = self.severity_counts["LOW"]
        info_count = self.severity_counts["INFORMATIONAL"]

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WebSentry Security Report — {html.escape(self.target_url)}</title>
  <style>
    :root {{
      --bg-dark: #0a0b0e;
      --card-bg: #12151c;
      --card-border: #1f2430;
      --crimson: #e50914;
      --crimson-glow: rgba(229, 9, 20, 0.25);
      --red: #ef4444;
      --orange: #f97316;
      --yellow: #eab308;
      --green: #22c55e;
      --blue: #38bdf8;
      --text: #f1f5f9;
      --text-muted: #94a3b8;
      --code-bg: #060709;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg-dark);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      line-height: 1.5;
      padding: 24px;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{
      background: linear-gradient(135deg, #18090a 0%, #12151c 100%);
      border: 1px solid #381216;
      border-radius: 12px;
      padding: 28px;
      margin-bottom: 24px;
      box-shadow: 0 4px 24px var(--crimson-glow);
    }}
    .badge-dev {{
      display: inline-block;
      background: var(--crimson);
      color: #fff;
      font-weight: 800;
      font-size: 11px;
      letter-spacing: 1px;
      padding: 4px 10px;
      border-radius: 4px;
      margin-bottom: 12px;
      text-transform: uppercase;
    }}
    h1 {{ font-size: 28px; font-weight: 700; color: #fff; margin-bottom: 6px; }}
    .subtitle {{ color: var(--text-muted); font-size: 14px; margin-bottom: 18px; }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      background: var(--card-bg);
      padding: 16px;
      border-radius: 8px;
      border: 1px solid var(--card-border);
      font-size: 13px;
    }}
    .meta-item span {{ color: var(--text-muted); display: block; font-size: 11px; text-transform: uppercase; }}
    .meta-item strong {{ color: #fff; font-family: monospace; font-size: 13px; }}
    
    .stats-row {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 14px;
      margin-bottom: 24px;
    }}
    .stat-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 18px;
      text-align: center;
      transition: transform 0.2s;
    }}
    .stat-card:hover {{ transform: translateY(-2px); }}
    .stat-val {{ font-size: 32px; font-weight: 800; line-height: 1.1; margin-bottom: 4px; }}
    .stat-label {{ font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; font-weight: 600; color: var(--text-muted); }}
    
    .crit {{ color: var(--crimson); }}
    .high {{ color: var(--red); }}
    .med {{ color: var(--orange); }}
    .low {{ color: var(--yellow); }}
    .info {{ color: var(--blue); }}

    .controls {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 20px;
    }}
    .filter-tabs {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    .tab-btn {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      color: var(--text-muted);
      padding: 8px 16px;
      border-radius: 6px;
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      transition: all 0.2s;
    }}
    .tab-btn:hover, .tab-btn.active {{
      background: #251214;
      border-color: var(--crimson);
      color: #fff;
    }}
    .search-box {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      color: #fff;
      padding: 9px 16px;
      border-radius: 6px;
      font-size: 13px;
      min-width: 260px;
    }}
    .search-box:focus {{ outline: none; border-color: var(--crimson); }}

    .finding-card {{
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      margin-bottom: 16px;
      overflow: hidden;
      border-left: 4px solid var(--card-border);
    }}
    .finding-card.CRITICAL {{ border-left-color: var(--crimson); }}
    .finding-card.HIGH {{ border-left-color: var(--red); }}
    .finding-card.MEDIUM {{ border-left-color: var(--orange); }}
    .finding-card.LOW {{ border-left-color: var(--yellow); }}
    .finding-card.INFORMATIONAL {{ border-left-color: var(--blue); }}

    .finding-header {{
      padding: 16px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      border-bottom: 1px solid var(--card-border);
    }}
    .finding-title-group {{ display: flex; align-items: center; gap: 12px; flex-wrap: wrap; }}
    .badge {{
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .badge.CRITICAL {{ background: rgba(229, 9, 20, 0.2); color: var(--crimson); border: 1px solid var(--crimson); }}
    .badge.HIGH {{ background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); }}
    .badge.MEDIUM {{ background: rgba(249, 115, 22, 0.2); color: var(--orange); border: 1px solid var(--orange); }}
    .badge.LOW {{ background: rgba(234, 179, 8, 0.2); color: var(--yellow); border: 1px solid var(--yellow); }}
    .badge.INFORMATIONAL {{ background: rgba(56, 189, 248, 0.2); color: var(--blue); border: 1px solid var(--blue); }}

    .finding-title {{ font-weight: 600; font-size: 16px; color: #fff; }}
    .finding-body {{ padding: 18px 20px; font-size: 14px; }}
    .field-row {{ margin-bottom: 10px; }}
    .field-label {{ color: var(--text-muted); font-size: 12px; font-weight: 600; text-transform: uppercase; margin-bottom: 4px; }}
    .field-content {{ color: #e2e8f0; }}
    .evidence-box {{
      background: var(--code-bg);
      border: 1px solid #242938;
      border-radius: 6px;
      padding: 10px 14px;
      font-family: monospace;
      font-size: 12px;
      color: #f87171;
      white-space: pre-wrap;
      word-break: break-all;
      margin-top: 4px;
    }}
    .remediation-box {{
      background: #0f1c14;
      border: 1px solid #144626;
      border-radius: 6px;
      padding: 10px 14px;
      color: #86efac;
      font-size: 13px;
      margin-top: 4px;
    }}
    footer {{
      text-align: center;
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid var(--card-border);
      color: var(--text-muted);
      font-size: 13px;
    }}
    footer a {{ color: var(--crimson); text-decoration: none; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="badge-dev">BUILT BY {html.escape(self.author)}</div>
      <h1>WebSentry Security Assessment Report</h1>
      <div class="subtitle">Modular Web Server Vulnerability & Misconfiguration Audit Engine</div>
      <div class="meta-grid">
        <div class="meta-item"><span>Target URL</span><strong>{html.escape(self.target_url)}</strong></div>
        <div class="meta-item"><span>Scan Timestamp</span><strong>{self.timestamp}</strong></div>
        <div class="meta-item"><span>Duration & Requests</span><strong>{self.duration:.2f}s ({self.total_requests} reqs)</strong></div>
        <div class="meta-item"><span>Scanner Version</span><strong>WebSentry v{self.version}</strong></div>
      </div>
    </header>

    <div class="stats-row">
      <div class="stat-card"><div class="stat-val crit">{crit_count}</div><div class="stat-label">Critical</div></div>
      <div class="stat-card"><div class="stat-val high">{high_count}</div><div class="stat-label">High</div></div>
      <div class="stat-card"><div class="stat-val med">{med_count}</div><div class="stat-label">Medium</div></div>
      <div class="stat-card"><div class="stat-val low">{low_count}</div><div class="stat-label">Low</div></div>
      <div class="stat-card"><div class="stat-val info">{info_count}</div><div class="stat-label">Info</div></div>
    </div>

    <div class="controls">
      <div class="filter-tabs">
        <button class="tab-btn active" onclick="filterSeverity('ALL')">All ({self.total_findings})</button>
        <button class="tab-btn" onclick="filterSeverity('CRITICAL')">Critical ({crit_count})</button>
        <button class="tab-btn" onclick="filterSeverity('HIGH')">High ({high_count})</button>
        <button class="tab-btn" onclick="filterSeverity('MEDIUM')">Medium ({med_count})</button>
        <button class="tab-btn" onclick="filterSeverity('LOW')">Low ({low_count})</button>
        <button class="tab-btn" onclick="filterSeverity('INFORMATIONAL')">Info ({info_count})</button>
      </div>
      <input type="text" id="search" class="search-box" placeholder="Search findings..." oninput="handleSearch()">
    </div>

    <div id="findings-container"></div>

    <footer>
      Report generated by <strong>WebSentry v{self.version}</strong> &bull;
      Developer: <strong>{html.escape(self.author)}</strong> &bull;
      <a href="{self.github}" target="_blank">GitHub Repository</a>
    </footer>
  </div>

  <script>
    const findingsData = {findings_json};
    let currentFilter = 'ALL';
    let searchQuery = '';

    function renderFindings() {{
      const container = document.getElementById('findings-container');
      const filtered = findingsData.filter(f => {{
        const matchesSev = (currentFilter === 'ALL' || f.severity === currentFilter);
        const text = (f.title + ' ' + f.description + ' ' + f.url + ' ' + f.category).toLowerCase();
        const matchesSearch = (!searchQuery || text.includes(searchQuery.toLowerCase()));
        return matchesSev && matchesSearch;
      }});

      if (filtered.length === 0) {{
        container.innerHTML = '<div style="padding: 40px; text-align: center; color: #64748b; background: #12151c; border-radius: 8px;">No findings match your criteria.</div>';
        return;
      }}

      container.innerHTML = filtered.map(f => `
        <div class="finding-card ${{f.severity}}">
          <div class="finding-header">
            <div class="finding-title-group">
              <span class="badge ${{f.severity}}">${{f.severity}}</span>
              <span class="finding-title">${{escapeHtml(f.title)}}</span>
            </div>
            ${{f.status_code ? `<span style="font-family: monospace; font-size: 12px; color: #94a3b8;">HTTP ${{f.status_code}}</span>` : ''}}
          </div>
          <div class="finding-body">
            <div class="field-row">
              <div class="field-label">Target Resource & Category</div>
              <div class="field-content" style="font-family: monospace; font-size: 13px;">${{escapeHtml(f.url)}} &bull; <span style="color: #cbd5e1;">${{escapeHtml(f.category)}}</span></div>
            </div>
            <div class="field-row">
              <div class="field-label">Description</div>
              <div class="field-content">${{escapeHtml(f.description)}}</div>
            </div>
            ${{f.evidence ? `
              <div class="field-row">
                <div class="field-label">Technical Evidence</div>
                <div class="evidence-box">${{escapeHtml(f.evidence)}}</div>
              </div>` : ''}}
            <div class="field-row">
              <div class="field-label">Remediation Recommendation</div>
              <div class="remediation-box">${{escapeHtml(f.remediation)}}</div>
            </div>
            ${{f.reference ? `
              <div class="field-row" style="margin-top: 10px;">
                <span class="field-label">Reference: </span>
                <a href="${{escapeHtml(f.reference)}}" target="_blank" style="color: #38bdf8; font-size: 12px; text-decoration: none;">${{escapeHtml(f.reference)}}</a>
              </div>` : ''}}
          </div>
        </div>
      `).join('');
    }}

    function filterSeverity(sev) {{
      currentFilter = sev;
      document.querySelectorAll('.tab-btn').forEach(btn => {{
        btn.classList.toggle('active', btn.textContent.startsWith(sev === 'ALL' ? 'All' : sev.charAt(0) + sev.slice(1).toLowerCase()));
      }});
      renderFindings();
    }}

    function handleSearch() {{
      searchQuery = document.getElementById('search').value;
      renderFindings();
    }}

    function escapeHtml(str) {{
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }}

    renderFindings();
  </script>
</body>
</html>
"""

    def save_reports(self, output_path: str = None, fmt: str = "json") -> List[str]:
        """Saves reports to file(s) and returns saved file paths."""
        reports_dir = Path("reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        saved_paths: List[str] = []

        # If user did not provide a specific output path, build timestamped name
        base_name = f"websentry_scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        if output_path:
            out_p = Path(output_path)
            out_p.parent.mkdir(parents=True, exist_ok=True)
            ext = out_p.suffix.lower()

            if ext == ".json":
                out_p.write_text(self.generate_json(), encoding="utf-8")
                saved_paths.append(str(out_p))
            elif ext == ".html":
                out_p.write_text(self.generate_html(), encoding="utf-8")
                saved_paths.append(str(out_p))
            elif ext == ".txt":
                out_p.write_text(self.generate_txt(), encoding="utf-8")
                saved_paths.append(str(out_p))
            else:
                # Default to JSON
                out_p.write_text(self.generate_json(), encoding="utf-8")
                saved_paths.append(str(out_p))
            return saved_paths

        # Generate based on --format
        fmt_lower = fmt.lower()
        if fmt_lower in ("json", "all"):
            p = reports_dir / f"{base_name}.json"
            p.write_text(self.generate_json(), encoding="utf-8")
            saved_paths.append(str(p))

        if fmt_lower in ("html", "all"):
            p = reports_dir / f"{base_name}.html"
            p.write_text(self.generate_html(), encoding="utf-8")
            saved_paths.append(str(p))

        if fmt_lower in ("txt", "all"):
            p = reports_dir / f"{base_name}.txt"
            p.write_text(self.generate_txt(), encoding="utf-8")
            saved_paths.append(str(p))

        return saved_paths
