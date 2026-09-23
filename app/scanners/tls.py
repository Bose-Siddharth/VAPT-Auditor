"""TLS/SSL configuration scanner: testssl.sh.

testssl.sh's --jsonfile-pretty output is a nested, category-keyed structure
(protocols/ciphers/vulnerabilities/headerResponse/...) that varies with what
was tested, plus the odd flat top-level record mixed in -- not a flat list of
findings. Rather than depend on that shape (which has known upstream bugs:
drwetter/testssl.sh#822, #1699, #2198), this walks the whole tree and treats
any dict carrying {id, severity, finding} as one result, which is stable
across testssl.sh versions and however deep a given check is nested.
"""
from __future__ import annotations

import json
import os
import tempfile

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
    "DEBUG": None,
}


def scan(url_or_host: str, timeout: int = 900) -> tuple[list[Finding], ToolRunResult]:
    fd, out_path = tempfile.mkstemp(suffix=".json", prefix="testssl_")
    os.close(fd)
    try:
        args = [
            "testssl.sh",
            "--jsonfile-pretty", out_path,
            "--quiet",
            "--color", "0",
            url_or_host,
        ]
        result, _ = run_command("testssl.sh", args, timeout=timeout)
        findings: list[Finding] = []

        try:
            with open(out_path) as f:
                raw = f.read()
        except OSError:
            return findings, result

        if not raw.strip():
            return findings, result

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return findings, result

        records: list[tuple[dict, str | None]] = []
        _collect_records(data, None, records)

        for rec, host in records:
            severity_raw = (rec.get("severity") or "").upper()
            severity = TESTSSL_SEVERITY.get(severity_raw)
            if severity is None:
                continue  # OK/DEBUG/unrecognized -> not a finding

            findings.append(Finding(
                category=TargetType.WEB,
                source_tool="testssl.sh",
                severity=severity,
                title=f"TLS: {rec.get('id', 'finding')}",
                description=rec.get("finding", ""),
                affected=host or url_or_host,
                remediation="Disable weak protocols/ciphers and fix certificate issues per the finding detail.",
            ))

        return findings, result
    finally:
        try:
            os.unlink(out_path)
        except OSError:
            pass


def _collect_records(node, current_host: str | None, out: list[tuple[dict, str | None]]) -> None:
    if isinstance(node, dict):
        host = node.get("ip") or node.get("targetHost") or current_host
        if {"id", "severity", "finding"} <= node.keys():
            out.append((node, host))
        for value in node.values():
            _collect_records(value, host, out)
    elif isinstance(node, list):
        for item in node:
            _collect_records(item, current_host, out)
