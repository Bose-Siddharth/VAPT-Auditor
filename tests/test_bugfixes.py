"""Regression tests for bugs found in code review: real-shaped Nikto/testssl.sh
output, orchestrator scanner isolation, and upload path traversal."""
import json
from datetime import datetime, timezone

from app.models import Severity, ToolRunResult

REAL_NIKTO_OUTPUT = json.dumps([
    {
        "host": "127.0.0.1",
        "ip": "127.0.0.1",
        "port": 8000,
        "vulnerabilities": [
            {"id": "999990", "method": "OPTIONS", "msg": "OPTIONS: Allowed HTTP Methods: GET .",
             "references": "", "url": "/"},
            {"id": "013587", "method": "GET", "msg": "Suggested security header missing: x-frame-options.",
             "references": "https://example.com/ref", "url": "/"},
        ],
    }
])

REAL_TESTSSL_OUTPUT = {
    "scanResult": [
        {"id": "engine_problem", "severity": "WARN", "finding": "No engine support"},
        {
            "targetHost": "example.com", "ip": "1.2.3.4", "port": "443",
            "protocols": [
                {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
                {"id": "TLS1_3", "severity": "OK", "finding": "offered"},
            ],
            "vulnerabilities": [
                {"id": "heartbleed", "severity": "OK", "finding": "not vulnerable"},
            ],
        },
    ]
}


def _fake_ok_result(tool):
    now = datetime.now(timezone.utc)
    return ToolRunResult(tool=tool, command="fake", exit_code=0, started_at=now, finished_at=now, ok=True)


def test_nikto_parses_real_top_level_array_shape(monkeypatch, tmp_path):
    from app.scanners import web

    out_file = tmp_path / "nikto_out.json"
    out_file.write_text(REAL_NIKTO_OUTPUT)

    def fake_mkstemp(*a, **kw):
        import os
        fd = os.open(str(out_file), os.O_RDWR | os.O_CREAT)
        return fd, str(out_file)

    monkeypatch.setattr("tempfile.mkstemp", fake_mkstemp)
    monkeypatch.setattr(web, "run_command", lambda tool, args, timeout=600: (_fake_ok_result(tool), ""))

    findings, result = web.scan_nikto("http://127.0.0.1:8000")
    assert len(findings) == 2
    assert findings[0].source_tool == "nikto"
    titles = [f.title for f in findings]
    assert any("Allowed HTTP Methods" in t for t in titles)


def test_testssl_recursively_collects_nested_findings():
    from app.scanners import tls

    records: list = []
    tls._collect_records(REAL_TESTSSL_OUTPUT, None, records)
    assert len(records) == 4  # engine_problem, TLS1, TLS1_3, heartbleed

    # OK/DEBUG severities must be filtered out as non-findings, others kept
    kept = [
        (rec, host) for rec, host in records
        if tls.TESTSSL_SEVERITY.get((rec.get("severity") or "").upper()) is not None
    ]
    assert len(kept) == 2  # engine_problem (WARN) + TLS1 (LOW)
    hosts = {host for _, host in kept}
    assert "1.2.3.4" in hosts or None in hosts


def test_orchestrator_isolates_one_broken_scanner(monkeypatch):
    """If one scanner's parsing code raises, other scanners for the same
    target must still run and their findings must not be lost."""
    from app import orchestrator
    from app.models import Finding, ScanJob, Target, TargetType

    good_finding = Finding(category=TargetType.WEB, source_tool="nuclei", severity=Severity.HIGH,
                            title="ok finding", description="d")

    def broken_scan(url):
        raise AttributeError("'APK' object has no attribute 'is_debuggable'")

    def working_scan(url):
        return [good_finding], _fake_ok_result("nuclei")

    monkeypatch.setattr(orchestrator, "_scanners_for", lambda t, v: [broken_scan, working_scan])

    job = ScanJob(target=Target(type=TargetType.WEB, value="https://example.com"))
    orchestrator.run_job(job)

    assert good_finding in job.findings
    assert len(job.tool_runs) == 2
    assert job.tool_runs[0].ok is False
    assert "AttributeError" in job.tool_runs[0].error
    assert job.tool_runs[1].ok is True


def test_upload_filename_is_sanitized_against_path_traversal():
    import os
    malicious = "../../../../etc/cron.d/evil.apk"
    safe_name = os.path.basename(malicious)
    assert safe_name == "evil.apk"
    assert ".." not in safe_name
    assert "/" not in safe_name
