"""
WebSentry Core Scan Orchestration Engine
Coordinates module execution, progress reporting, finding deduplication, and safe Ctrl+C recovery.
Developer: Isha Sonaria
"""

import time
import sys
from typing import List, Dict, Set, Optional, Callable
from websentry.core.config import ScanConfig
from websentry.core.finding import Finding, Severity
from websentry.core.http_client import HttpClient
from websentry.core.safety import validate_target_safety, TargetSafetyRefusalError, InvalidTargetURLError
from websentry.core.colors import (
    crimson, bright_red, dark_red, bold, dim, yellow, cyan, green, white, gray,
    sym_plus, sym_minus, sym_star, sym_warn, sym_err, format_severity
)
from websentry.modules.headers import HeaderScanner
from websentry.modules.methods import MethodScanner
from websentry.modules.server_info import ServerInfoScanner
from websentry.modules.sensitive_files import SensitiveFilesScanner
from websentry.modules.ssl_tls import SslTlsScanner
from websentry.modules.misconfigs import MisconfigScanner
from websentry.modules.nikto_signatures import NiktoSignatureScanner

class ScanEngine:
    def __init__(self, config: ScanConfig):
        self.config = config
        self.client = HttpClient(
            user_agent=config.user_agent,
            timeout=config.timeout,
            retries=config.retries,
            delay=config.delay,
            verify_ssl=config.verify_ssl,
            custom_headers=config.custom_headers
        )
        self.findings: List[Finding] = []
        self._seen_finding_keys: Set[str] = set()
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.interrupted: bool = False

    def _progress_logger(self, module_name: str) -> Callable[[str, int, int], None]:
        def cb(msg: str, current: int, total: int):
            if self.config.verbose:
                print(f"    {dim(gray(f'[{module_name}]'))} {gray(msg)}")
        return cb

    def _add_finding(self, finding: Finding) -> None:
        """Adds finding preventing duplicates."""
        key = f"{finding.id or ''}:{finding.title}:{finding.url}"
        if key not in self._seen_finding_keys:
            self._seen_finding_keys.add(key)
            self.findings.append(finding)
            # Live stream print of high-severity or all findings
            print(finding.format_cli(show_evidence=True))
            print()

    def run(self) -> List[Finding]:
        """
        Executes the full scan pipeline across selected modules.
        Handles Ctrl+C safely to preserve collected findings.
        """
        self.start_time = time.time()

        # 1. Safety & Target Validation
        print(f"\n{sym_star()} {bold('Target Validation & Safety Gatekeeper...')}")
        try:
            normalized_url, ips, is_private = validate_target_safety(
                self.config.url, allow_public=self.config.allow_public
            )
            self.config.url = normalized_url
        except TargetSafetyRefusalError as e:
            print(str(e))
            raise
        except InvalidTargetURLError as e:
            print(f"{sym_err()} {bright_red(f'Error: {e}')}")
            raise

        scope_type = green("Private/Internal RFC1918 Scope") if is_private else yellow("Authorized Public Internet Scope")
        print(f"  {sym_plus()} Target URL:    {bold(cyan(self.config.url))}")
        print(f"  {sym_plus()} Resolved IP(s): {yellow(', '.join(ips))}")
        print(f"  {sym_plus()} Scope Mode:     {scope_type}")
        print(f"  {sym_plus()} Scan Profile:   {bold(white(self.config.mode.upper()))} (Concurrency: {self.config.threads} threads)")
        print(f"  {sym_plus()} Engine Delay:   {self.config.delay}s | Timeout: {self.config.timeout}s")
        print(f"  {gray('──────────────────────────────────────────────────────────────────────────')}\n")

        # 2. Select Modules
        modules_to_run = []
        mod_selection = self.config.modules

        if "ssl" in mod_selection or "ssl_tls" in mod_selection:
            modules_to_run.append(SslTlsScanner())

        if "headers" in mod_selection:
            modules_to_run.append(HeaderScanner())

        if "methods" in mod_selection:
            modules_to_run.append(MethodScanner())

        if "server_info" in mod_selection or "server" in mod_selection:
            modules_to_run.append(ServerInfoScanner())

        if "misconfigs" in mod_selection:
            modules_to_run.append(MisconfigScanner())

        if "sensitive_files" in mod_selection or "files" in mod_selection:
            modules_to_run.append(SensitiveFilesScanner())

        if "nikto" in mod_selection:
            modules_to_run.append(NiktoSignatureScanner(signatures_path=self.config.signatures_path))

        print(f"{sym_star()} {bold(crimson('Starting Security Assessment Modules...'))}\n")

        try:
            for scanner in modules_to_run:
                print(f"{sym_star()} {bold(white(f'Module: {scanner.name}'))} {gray(f'({scanner.description})')}")
                cb = self._progress_logger(scanner.name)
                module_findings = scanner.run(self.config.url, self.client, self.config, progress_callback=cb)
                
                for f in module_findings:
                    self._add_finding(f)

        except KeyboardInterrupt:
            self.interrupted = True
            print(f"\n{sym_warn()} {yellow(bold('Scan interrupted by user (Ctrl+C). Saving partial results...'))}\n")

        finally:
            self.end_time = time.time()

        # Sort findings by severity (Critical first)
        self.findings.sort(key=lambda x: x.severity.score, reverse=True)
        return self.findings

    @property
    def duration(self) -> float:
        if self.end_time == 0.0:
            return time.time() - self.start_time
        return self.end_time - self.start_time

    @property
    def total_requests(self) -> int:
        return self.client.total_requests

    def print_summary(self) -> None:
        """Prints terminal summary table with black/red aesthetic."""
        dur = self.duration
        total_reqs = self.total_requests

        crit = sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in self.findings if f.severity == Severity.HIGH)
        med = sum(1 for f in self.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in self.findings if f.severity == Severity.LOW)
        info = sum(1 for f in self.findings if f.severity == Severity.INFORMATIONAL)

        print(f"  {gray('──────────────────────────────────────────────────────────────────────────')}")
        print(f"  {bold(white('SCAN SUMMARY & RISK BREAKDOWN:'))}")
        print(f"  {gray('──────────────────────────────────────────────────────────────────────────')}")
        print(f"  Target:            {cyan(self.config.url)}")
        print(f"  Duration:          {dur:.2f} seconds")
        print(f"  HTTP Requests:     {total_reqs}")
        print(f"  Total Findings:    {bold(white(str(len(self.findings))))}")
        print()
        print(f"    {format_severity('CRITICAL')}:    {bold(crimson(str(crit)))}")
        print(f"    {format_severity('HIGH')}:        {bold(bright_red(str(high)))}")
        print(f"    {format_severity('MEDIUM')}:      {bold(yellow(str(med)))}")
        print(f"    {format_severity('LOW')}:         {bold(cyan(str(low)))}")
        print(f"    {format_severity('INFORMATIONAL')}: {bold(gray(str(info)))}")
        print(f"  {gray('──────────────────────────────────────────────────────────────────────────')}")
        print(f"  {dim(gray('Developer Credit: Built by ISHA SONARIA | WebSentry v1.2.0'))}\n")
