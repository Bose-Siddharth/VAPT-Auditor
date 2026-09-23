"""Unit tests for scanner output parsing, using canned tool output so these
run without nmap/nuclei/etc actually being installed."""
import json
from datetime import datetime, timezone

from app.models import Severity
from app.models import ToolRunResult

SAMPLE_NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <os><osmatch name="Linux 5.X" accuracy="95"/></os>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="7.4"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.4.6"/>
        <script id="http-vuln-cve2017-5638" output="State: VULNERABLE&#10;CVE-2017-5638 detail here"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

SAMPLE_NUCLEI_JSONL = "\n".join([
    json.dumps({
        "template-id": "exposed-env-file",
        "info": {
            "name": "Exposed .env File",
            "severity": "critical",
            "description": "A .env file is publicly accessible.",
            "classification": {"cve-id": ["CVE-2021-0001"], "cvss-score": 9.1},
        },
        "host": "https://example.com",
        "matched-at": "https://example.com/.env",
    }),
    json.dumps({
        "template-id": "missing-header",
        "info": {"name": "Missing Security Header", "severity": "low", "description": "..."},
        "host": "https://example.com",
        "matched-at": "https://example.com",
    }),
])


def _fake_ok_result(tool):
    now = datetime.now(timezone.utc)
    return ToolRunResult(tool=tool, command="fake", exit_code=0, started_at=now, finished_at=now, ok=True)


def test_nmap_parses_ports_os_and_vuln_script(monkeypatch):
    from app.scanners import network

    def fake_run_command(tool, args, timeout=600):
        return _fake_ok_result(tool), SAMPLE_NMAP_XML

    monkeypatch.setattr("app.scanners.base.run_command", fake_run_command)
    findings, result = network.scan("10.0.0.5")

    titles = [f.title for f in findings]
    assert any("OS fingerprint" in t for t in titles)
    assert any("Open port 22/tcp" in t for t in titles)
    assert any("Open port 80/tcp" in t for t in titles)

    vuln_findings = [f for f in findings if f.source_tool.startswith("nmap:http-vuln")]
    assert len(vuln_findings) == 1
    assert vuln_findings[0].severity == Severity.HIGH
    assert vuln_findings[0].affected == "10.0.0.5:80"


def test_nuclei_parses_severity_and_cve(monkeypatch):
    from app.scanners import web

    def fake_run_command(tool, args, timeout=600):
        return _fake_ok_result(tool), SAMPLE_NUCLEI_JSONL

    monkeypatch.setattr(web, "run_command", fake_run_command)
    findings, result = web.scan_nuclei("https://example.com")

    assert len(findings) == 2
    critical = next(f for f in findings if f.severity == Severity.CRITICAL)
    assert critical.reference == "CVE-2021-0001"
    assert critical.cvss == 9.1
    low = next(f for f in findings if f.severity == Severity.LOW)
    assert low.title == "Missing Security Header"


def test_missing_tool_reports_error_not_crash(monkeypatch):
    """If nmap isn't installed, scan() must return an empty finding list and a
    ToolRunResult explaining why -- never raise."""
    from app.scanners import network
    findings, result = network.scan("127.0.0.1")
    assert findings == []
    assert result.ok is False
    assert "not installed" in result.error
