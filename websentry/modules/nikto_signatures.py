"""
WebSentry Nikto-Inspired Signature Detection Engine
Modular signature-based vulnerability and misconfiguration detector.
Developer: Isha Sonaria
"""

import json
import os
import concurrent.futures
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from websentry.modules.base import BaseScanner, ProgressCallback
from websentry.core.finding import Finding, Severity
from websentry.core.http_client import HttpClient
from websentry.core.config import ScanConfig

class NiktoSignatureScanner(BaseScanner):
    name = "Nikto Signatures"
    description = "Checks endpoints against a maintained signature database of known exposures and server flaws."
    category = "Nikto Signatures"

    def __init__(self, signatures_path: Optional[str] = None):
        self.signatures_path = signatures_path
        self._signatures: List[Dict[str, Any]] = []
        self.loaded_path: Optional[str] = None
        self._load_signatures()

    def _load_signatures(self) -> None:
        """Loads signature database from disk or package data."""
        path_to_load = None
        if self.signatures_path and os.path.exists(self.signatures_path):
            path_to_load = self.signatures_path
        else:
            try:
                from websentry.signatures import DEFAULT_SIGNATURES_FILE
                if DEFAULT_SIGNATURES_FILE.exists():
                    path_to_load = str(DEFAULT_SIGNATURES_FILE)
            except Exception:
                pass

            if not path_to_load:
                default_path = Path(__file__).parent.parent / "signatures" / "default_signatures.json"
                if default_path.exists():
                    path_to_load = str(default_path)

        if path_to_load:
            self.loaded_path = path_to_load
            try:
                with open(path_to_load, "r", encoding="utf-8") as f:
                    self._signatures = json.load(f)
            except Exception:
                self._signatures = []

    def get_signatures_count(self) -> int:
        return len(self._signatures)

    def _test_signature(
        self,
        target_url: str,
        sig: Dict[str, Any],
        client: HttpClient,
        baseline_size: int,
        baseline_status: int
    ) -> Optional[Finding]:
        test_url = urljoin(target_url, sig.get("uri", "/"))
        method = sig.get("method", "GET").upper()

        resp = client.request(method, test_url, allow_redirects=False)

        # 1. Status code check
        match_statuses = sig.get("match_status", [200])
        if resp.status_code not in match_statuses:
            return None

        # 2. Check for soft-404 match
        if baseline_status == 200 and abs(len(resp.content) - baseline_size) < 60:
            return None

        # 3. Negative match string (if present, must NOT appear in response)
        neg_match = sig.get("negative_match")
        if neg_match and neg_match in resp.text:
            return None

        # 4. Positive match string (if present, MUST appear in response or headers)
        match_str = sig.get("match_string")
        if match_str:
            in_body = match_str in resp.text
            in_headers = any(match_str in v for v in resp.headers.values())
            if not in_body and not in_headers:
                return None

        # Confirmed match!
        evidence_snippet = f"HTTP {resp.status_code} ({len(resp.content)} bytes)"
        if match_str:
            evidence_snippet += f" matching keyword '{match_str}'"

        sev = Severity.from_string(sig.get("severity", "LOW"))

        return Finding(
            id=sig.get("id", "NIKTO-UNKNOWN"),
            title=sig.get("title", f"Exposed Endpoint {sig.get('uri')}"),
            severity=sev,
            url=test_url,
            status_code=resp.status_code,
            evidence=evidence_snippet,
            description=sig.get("description", "Exposed sensitive file or misconfigured service."),
            remediation=sig.get("remediation", "Restrict access or remove the exposed file."),
            category=self.category,
            reference=sig.get("reference")
        )

    def run(
        self,
        target_url: str,
        client: HttpClient,
        config: ScanConfig,
        progress_callback: ProgressCallback = None
    ) -> List[Finding]:
        findings: List[Finding] = []

        if not self._signatures:
            return findings

        # In quick mode, only run first 10 core signatures
        sigs_to_run = self._signatures
        if config.mode == "quick":
            sigs_to_run = [s for s in self._signatures if s.get("severity") in ("CRITICAL", "HIGH")][:8]

        total = len(sigs_to_run)
        if progress_callback:
            progress_callback(f"Running {total} Nikto signatures against target...", 1, total)

        # Baseline calibration
        baseline_url = urljoin(target_url, "/__nikto_baseline_probe_912839218__")
        base_resp = client.get(baseline_url, allow_redirects=False)
        baseline_status = base_resp.status_code
        baseline_size = len(base_resp.content)

        completed = 0
        workers = min(config.threads, 8)
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_sig = {
                executor.submit(self._test_signature, target_url, sig, client, baseline_size, baseline_status): sig
                for sig in sigs_to_run
            }

            for future in concurrent.futures.as_completed(future_to_sig):
                completed += 1
                if progress_callback and completed % 5 == 0:
                    progress_callback(f"Evaluated Nikto signatures ({completed}/{total})...", completed, total)
                try:
                    f = future.result()
                    if f:
                        findings.append(f)
                except Exception:
                    pass

        return findings
