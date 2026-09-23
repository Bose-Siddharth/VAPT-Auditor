"""WordPress scanner: WPScan (core/plugin/theme enumeration + known-vuln DB lookup)."""
from __future__ import annotations

import json
import os

from app.models import Finding, Severity, TargetType, ToolRunResult
from app.scanners.base import run_command


def scan(url: str, timeout: int = 900) -> tuple[list[Finding], ToolRunResult]:
    args = [
        "wpscan",
        "--url", url,
        "--enumerate", "vp,vt,u",  # vulnerable plugins/themes, users
        "--format", "json",
        "--no-banner",
        "--random-user-agent",
    ]
    api_token = os.environ.get("WPSCAN_API_TOKEN")
    if api_token:
        args += ["--api-token", api_token]

    result, stdout = run_command("wpscan", args, timeout=timeout)
    findings: list[Finding] = []
    if not stdout.strip():
        return findings, result

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return findings, result

    if not api_token:
        findings.append(Finding(
            category=TargetType.WORDPRESS,
            source_tool="wpscan",
            severity=Severity.INFO,
            title="Scanned without a WPScan API token",
            description="No WPSCAN_API_TOKEN was configured, so plugin/theme/core versions were "
                         "enumerated but not cross-checked against the WPVulnDB. Set WPSCAN_API_TOKEN "
                         "for CVE-level findings on this target.",
            affected=url,
            remediation="Register a free WPScan API token and set WPSCAN_API_TOKEN in the environment.",
        ))

    version_info = data.get("version") or {}
    if version_info.get("number"):
        _add_component_findings(findings, url, "WordPress core",
                                 version_info.get("number"), version_info.get("vulnerabilities", []))

    for plugin_name, plugin in (data.get("plugins") or {}).items():
        version = (plugin.get("version") or {}).get("number", "unknown")
        _add_component_findings(findings, url, f"Plugin: {plugin_name}",
                                 version, plugin.get("vulnerabilities", []))

    for theme_name, theme in (data.get("themes") or {}).items():
        version = (theme.get("version") or {}).get("number", "unknown")
        _add_component_findings(findings, url, f"Theme: {theme_name}",
                                 version, theme.get("vulnerabilities", []))

    users = data.get("users") or {}
    if users:
        usernames = ", ".join(users.keys())
        findings.append(Finding(
            category=TargetType.WORDPRESS,
            source_tool="wpscan",
            severity=Severity.LOW,
            title="WordPress usernames enumerable",
            description=f"The following usernames were enumerated: {usernames}. "
                         "Valid usernames narrow brute-force/credential-stuffing attacks.",
            affected=url,
            remediation="Avoid exposing usernames via author archives/REST API; enforce MFA and lockout policies.",
        ))

    return findings, result


def _add_component_findings(findings: list[Finding], url: str, component: str,
                              version: str, vulns: list[dict]) -> None:
    if not vulns:
        return
    for vuln in vulns:
        refs = vuln.get("references", {}) or {}
        cves = refs.get("cve", [])
        reference = ", ".join(f"CVE-{c}" if not c.startswith("CVE") else c for c in cves) if cves else None
        findings.append(Finding(
            category=TargetType.WORDPRESS,
            source_tool="wpscan",
            severity=Severity.HIGH,
            title=f"{component} {version}: {vuln.get('title', 'known vulnerability')}",
            description=f"WPScan/WPVulnDB lists a known vulnerability affecting {component} "
                         f"version {version}.",
            affected=url,
            reference=reference,
            remediation="Update the component to a patched version, or remove it if unmaintained.",
        ))
