"""Smoke test: build a synthetic ScanJob and confirm HTML+PDF report generation works
end-to-end, independent of whether nmap/nuclei/etc are installed on this machine."""
from datetime import datetime, timezone
from pathlib import Path

from app.models import Finding, ScanJob, Severity, Target, TargetType, ToolRunResult
from app.report import generate as report_generate


def _sample_job() -> ScanJob:
    job = ScanJob(target=Target(type=TargetType.WEB, value="https://example.com", label="Test target"))
    job.status = "completed"
    job.started_at = datetime.now(timezone.utc)
    job.finished_at = datetime.now(timezone.utc)
    job.findings = [
        Finding(category=TargetType.WEB, source_tool="nuclei", severity=Severity.CRITICAL,
                title="Exposed .env file", description="A .env file leaking secrets was found.",
                affected="https://example.com/.env", remediation="Remove the file from the web root."),
        Finding(category=TargetType.WEB, source_tool="nikto", severity=Severity.MEDIUM,
                title="Missing X-Frame-Options header", description="Clickjacking protection missing.",
                affected="https://example.com", remediation="Add the header."),
        Finding(category=TargetType.WEB, source_tool="testssl.sh", severity=Severity.INFO,
                title="TLS: cert expiry", description="Certificate expires in 60 days.",
                affected="example.com"),
    ]
    job.tool_runs = [
        ToolRunResult(tool="nuclei", command="nuclei -u https://example.com", exit_code=0,
                      started_at=job.started_at, finished_at=job.finished_at, ok=True),
        ToolRunResult(tool="nmap", command="nmap ...", exit_code=None,
                      started_at=job.started_at, finished_at=job.finished_at, ok=False,
                      error="'nmap' is not installed on this host"),
    ]
    return job


def test_severity_counts_and_sort_order():
    job = _sample_job()
    counts = job.severity_counts()
    assert counts["critical"] == 1
    assert counts["medium"] == 1
    assert counts["info"] == 1
    ordered = job.sorted_findings()
    assert [f.severity for f in ordered] == [Severity.CRITICAL, Severity.MEDIUM, Severity.INFO]


def test_html_report_renders_findings(tmp_path: Path):
    job = _sample_job()
    html = report_generate.render_html(job)
    assert "Exposed .env file" in html
    assert "critical" in html
    assert job.id in html

    out = report_generate.write_html(job, tmp_path / "report.html")
    assert out.exists()
    assert "Missing X-Frame-Options" in out.read_text()


def test_pdf_report_generates(tmp_path: Path):
    job = _sample_job()
    out = report_generate.write_pdf(job, tmp_path / "report.pdf")
    assert out is not None
    assert out.exists()
    assert out.stat().st_size > 1000  # sanity: not an empty/broken PDF
