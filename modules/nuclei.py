#!/usr/bin/env python3
"""
CSCAN — Nuclei Template Scanner Integration
Adds a fast template-based vulnerability scan to CSCAN using a locally installed
nuclei binary. The module is intentionally lightweight and safe: it only runs
when the binary is present and uses a single target URL.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any

from modules.ui import section, ok, warn, alert, info, G, Y, C, M, W, BR, DM, RS


def nuclei_available() -> bool:
    return shutil.which("nuclei") is not None


def run_nuclei_scan(target: str, templates: str | None = None, severity: str = "info,low,medium,high,critical") -> dict[str, Any]:
    """
    Run a nuclei scan against a target URL and return parsed JSON results.

    Args:
        target: Target URL or hostname to scan
        templates: Optional template path or template name filter
        severity: Comma-separated severities to include

    Returns:
        {"ok": bool, "target": str, "findings": [...], "raw": ...}
    """
    section("NUCLEI TEMPLATE SCAN")

    if not nuclei_available():
        return {
            "ok": False,
            "target": target,
            "findings": [],
            "raw": "Nuclei is not installed or not on PATH.",
            "error": "nuclei_missing",
        }

    target = target.rstrip("/")
    cmd = ["nuclei", "-t", templates] if templates else ["nuclei"]
    cmd.extend([
        "-u", target,
        "-severity", severity,
        "-json",
        "-silent",
    ])

    info(f"Launching Nuclei scan for: {BR}{C}{target}{RS}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()

        findings: list[dict[str, Any]] = []
        if stdout:
            try:
                for line in stdout.splitlines():
                    if not line.strip():
                        continue
                    try:
                        findings.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
            except Exception:
                pass

        if result.returncode == 0 or findings:
            ok(f"Nuclei completed with {len(findings)} result(s).")
            if findings:
                for item in findings[:5]:
                    name = item.get("info", {}).get("name", "unknown")
                    matcher = item.get("matched-at") or item.get("host") or "unknown"
                    severity = item.get("info", {}).get("severity", "info")
                    print(f"  {BR}{Y}[{severity.upper()}]{RS}  {name}  {DM}{matcher}{RS}")
            return {
                "ok": True,
                "target": target,
                "findings": findings,
                "raw": stdout,
                "stderr": stderr,
            }

        warn(f"Nuclei returned exit code {result.returncode}.")
        if stderr:
            warn(stderr)
        return {
            "ok": False,
            "target": target,
            "findings": [],
            "raw": stdout,
            "stderr": stderr,
            "error": "nuclei_scan_failed",
        }
    except subprocess.TimeoutExpired:
        alert("Nuclei scan timed out after 180s.")
        return {
            "ok": False,
            "target": target,
            "findings": [],
            "raw": "",
            "error": "nuclei_timeout",
        }
    except Exception as exc:
        alert(f"Nuclei execution error: {exc}")
        return {
            "ok": False,
            "target": target,
            "findings": [],
            "raw": "",
            "error": str(exc),
        }


def install_nuclei_instructions() -> str:
    return """
  Install Nuclei on a supported system:
    - Linux/macOS: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    - Or use the projectdiscovery package manager / release binary
    - Then ensure 'nuclei' is on PATH
"""


if __name__ == "__main__":
    print(run_nuclei_scan("https://example.com", templates=None))
