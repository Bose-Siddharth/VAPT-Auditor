"""Renders a ScanJob into an HTML report, and optionally a PDF from that HTML."""
from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.models import ScanJob

TEMPLATE_DIR = Path(__file__).parent / "templates"

_env = Environment(
    loader=FileSystemLoader(str(TEMPLATE_DIR)),
    autoescape=select_autoescape(["html"]),
)


def render_html(job: ScanJob) -> str:
    template = _env.get_template("report.html.j2")
    return template.render(
        job=job,
        findings=job.sorted_findings(),
        severity_counts=job.severity_counts(),
    )


def write_html(job: ScanJob, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_html(job))
    return out_path


def write_pdf(job: ScanJob, out_path: Path) -> Path | None:
    """Best-effort PDF export. Returns None if WeasyPrint isn't installed, or
    if rendering fails for any other reason (missing native libs at runtime,
    a font issue, ...) -- the HTML report is always the source of truth and
    stays available regardless."""
    try:
        from weasyprint import HTML
        out_path.parent.mkdir(parents=True, exist_ok=True)
        html_str = render_html(job)
        HTML(string=html_str, base_url=str(TEMPLATE_DIR)).write_pdf(str(out_path))
        return out_path
    except Exception:
        return None
