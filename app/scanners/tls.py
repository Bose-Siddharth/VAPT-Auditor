"""TLS/SSL configuration scanner: testssl.sh."""
from __future__ import annotations

import json

from app.models import Finding, Severity, TargetType, ToolRunResult
from app.scanners.base import run_command

TESTSSL_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "WARN": Severity.MEDIUM,
    "INFO": Severity.INFO,
    "OK": None,  # not a finding
}


def scan(url_or_host: str, timeout: int = 600) -> tuple[list[Finding], ToolRunResult]:
    args = [
        "testssl.sh",
        "--jsonfile-pretty", "/dev/stdout",
        "--quiet",
        "--color", "0",
        url_or_host,
    ]
    result, stdout = run_command("testssl.sh", args, timeout=timeout)
    findings: list[Finding] = []
    if not stdout.strip():
        return findings, result

    # testssl prints some banner text before the JSON array; find the first '['
    start = stdout.find("[")
    if start == -1:
        return findings, result

    try:
        records = json.loads(stdout[start:])
    except json.JSONDecodeError:
        return findings, result

    for rec in records:
        severity_raw = (rec.get("severity") or "").upper()
        severity = TESTSSL_SEVERITY.get(severity_raw)
        if severity is None:
            continue  # OK / unrecognized -> not a finding

        findings.append(Finding(
            category=TargetType.WEB,
            source_tool="testssl.sh",
            severity=severity,
            title=f"TLS: {rec.get('id', 'finding')}",
            description=rec.get("finding", ""),
            affected=rec.get("ip") or url_or_host,
            remediation="Disable weak protocols/ciphers and fix certificate issues per the finding detail.",
        ))

    return findings, result
