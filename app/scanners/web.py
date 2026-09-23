"""Web app scanner: Nuclei (templated vuln/exposure checks) + Nikto (server misconfig)."""
from __future__ import annotations

import json

from app.models import Finding, Severity, TargetType, ToolRunResult
from app.scanners.base import run_command

NUCLEI_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "unknown": Severity.INFO,
}


def scan_nuclei(url: str, timeout: int = 900) -> tuple[list[Finding], ToolRunResult]:
    args = [
        "nuclei",
        "-u", url,
        "-jsonl",
        "-silent",
        "-severity", "info,low,medium,high,critical",
    ]
    result, stdout = run_command("nuclei", args, timeout=timeout)
    findings: list[Finding] = []
    if not stdout.strip():
        return findings, result

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = rec.get("info", {})
        sev = NUCLEI_SEVERITY.get((info.get("severity") or "unknown").lower(), Severity.INFO)
        classification = info.get("classification") or {}
        cve_ids = classification.get("cve-id") or []

        raw_reference = info.get("reference")
        if cve_ids:
            reference = ", ".join(cve_ids)
        elif isinstance(raw_reference, list):
            reference = raw_reference[0] if raw_reference else None
        else:
            reference = raw_reference

        findings.append(Finding(
            category=TargetType.WEB,
            source_tool="nuclei",
            severity=sev,
            title=info.get("name", rec.get("template-id", "Nuclei finding")),
            description=info.get("description") or "See matched request/response for detail.",
            evidence=rec.get("matched-at") or rec.get("host"),
            affected=rec.get("host", url),
            reference=reference,
            cvss=classification.get("cvss-score"),
            remediation=info.get("remediation") or "Review the matched template and apply the vendor's fix/patch.",
        ))

    return findings, result


NIKTO_SEVERITY_DEFAULT = Severity.MEDIUM


def scan_nikto(url: str, timeout: int = 900) -> tuple[list[Finding], ToolRunResult]:
    args = ["nikto", "-h", url, "-Format", "json", "-output", "-", "-ask", "no"]
    result, stdout = run_command("nikto", args, timeout=timeout)
    findings: list[Finding] = []
    if not stdout.strip():
        return findings, result

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return findings, result

    vulnerabilities = data.get("vulnerabilities", []) if isinstance(data, dict) else []
    for vuln in vulnerabilities:
        findings.append(Finding(
            category=TargetType.WEB,
            source_tool="nikto",
            severity=NIKTO_SEVERITY_DEFAULT,
            title=vuln.get("msg", "Nikto finding")[:200],
            description=vuln.get("msg", ""),
            evidence=vuln.get("url"),
            affected=url,
            reference=vuln.get("references"),
            remediation="Review the flagged path/header and reconfigure or patch the web server accordingly.",
        ))

    return findings, result
