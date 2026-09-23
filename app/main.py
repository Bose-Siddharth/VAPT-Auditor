from __future__ import annotations

import ipaddress
import os
import re
import uuid
from pathlib import Path

from fastapi import BackgroundTasks, Depends, FastAPI, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from datetime import datetime, timezone

from app import auth, storage
from app.models import ScanJob, Target, TargetType
from app.orchestrator import run_job
from app.report import generate as report_generate

BASE_DIR = Path(__file__).parent
DATA_DIR = Path(os.environ.get("VAPT_DATA_DIR", "data"))
UPLOAD_DIR = Path(os.environ.get("VAPT_UPLOAD_DIR", "uploads"))
REPORTS_DIR = DATA_DIR / "reports"
MAX_APK_BYTES = 500 * 1024 * 1024  # 500MB: generous for an APK, bounds memory/disk use

app = FastAPI(title="VAPT Auditor")
templates = Jinja2Templates(directory=str(BASE_DIR / "web_ui" / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "web_ui" / "static")), name="static")

HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$")


@app.on_event("startup")
def on_startup() -> None:
    auth.seed_default_admin_if_needed()


def _validate_network_target(value: str) -> str:
    value = value.strip()
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        pass
    if HOSTNAME_RE.match(value):
        return value
    raise HTTPException(400, "Target must be a valid IP, CIDR range, or hostname.")


def _save_upload_capped(upload: UploadFile, dest: Path, max_bytes: int) -> None:
    """Stream the upload to disk in chunks instead of reading it all into
    memory, and abort with 413 if it exceeds max_bytes."""
    written = 0
    with open(dest, "wb") as f:
        while chunk := upload.file.read(1024 * 1024):
            written += len(chunk)
            if written > max_bytes:
                f.close()
                dest.unlink(missing_ok=True)
                raise HTTPException(413, f"Upload exceeds the {max_bytes // (1024 * 1024)}MB limit.")
            f.write(chunk)


def _validate_url_target(value: str) -> str:
    value = value.strip()
    if not re.match(r"^https?://[a-zA-Z0-9][a-zA-Z0-9\-\.]*(:\d+)?(/.*)?$", value):
        raise HTTPException(400, "Target must be a valid http:// or https:// URL.")
    return value


@app.get("/", response_class=HTMLResponse)
def index(request: Request, user: str = Depends(auth.verify_credentials)):
    jobs = storage.list_jobs()[:25]
    return templates.TemplateResponse("index.html.j2", {"request": request, "jobs": jobs, "user": user})


@app.post("/scans")
def create_scan(
    background_tasks: BackgroundTasks,
    target_type: str = Form(...),
    target_value: str = Form(""),
    label: str = Form(""),
    authorized: str = Form(""),
    apk_file: UploadFile | None = None,
    user: str = Depends(auth.verify_credentials),
):
    if authorized != "yes":
        raise HTTPException(400, "You must confirm you are authorized to test this target.")

    try:
        ttype = TargetType(target_type)
    except ValueError:
        raise HTTPException(400, "Unknown target type.")

    if ttype == TargetType.NETWORK:
        value = _validate_network_target(target_value)
    elif ttype in (TargetType.WEB, TargetType.WORDPRESS):
        value = _validate_url_target(target_value)
    elif ttype == TargetType.MOBILE_APK:
        if not apk_file or not apk_file.filename.lower().endswith(".apk"):
            raise HTTPException(400, "Upload a .apk file for mobile scans.")
        # Strip any path components from the client-supplied filename so it
        # can't be used to write outside UPLOAD_DIR (e.g. "../../etc/x.apk").
        safe_name = os.path.basename(apk_file.filename) or "upload.apk"
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        dest = UPLOAD_DIR / f"{uuid.uuid4().hex}_{safe_name}"
        _save_upload_capped(apk_file, dest, max_bytes=MAX_APK_BYTES)
        value = str(dest)
    else:  # pragma: no cover
        raise HTTPException(400, "Unsupported target type.")

    job = ScanJob(target=Target(type=ttype, value=value, label=label or None))
    storage.save_job(job)
    background_tasks.add_task(_execute_job, job.id)
    return RedirectResponse(f"/scans/{job.id}", status_code=303)


def _execute_job(job_id: str) -> None:
    job = storage.load_job(job_id)
    if job is None:
        return
    job.status = "running"
    job.started_at = datetime.now(timezone.utc)
    storage.save_job(job)

    try:
        run_job(job)
        job.status = "completed"
    except Exception as exc:
        job.status = "failed"
        job.error = str(exc)
    finally:
        job.finished_at = datetime.now(timezone.utc)
        storage.save_job(job)
        try:
            report_generate.write_html(job, REPORTS_DIR / f"{job.id}.html")
            report_generate.write_pdf(job, REPORTS_DIR / f"{job.id}.pdf")
        except Exception:
            # Job status/findings are already saved above regardless; report
            # rendering is best-effort on top of that, not load-bearing.
            pass


@app.get("/scans/{job_id}", response_class=HTMLResponse)
def scan_status(request: Request, job_id: str, user: str = Depends(auth.verify_credentials)):
    job = storage.load_job(job_id)
    if job is None:
        raise HTTPException(404, "Job not found.")
    pdf_ready = (REPORTS_DIR / f"{job_id}.pdf").exists()
    return templates.TemplateResponse(
        "job.html.j2",
        {"request": request, "job": job, "user": user, "pdf_ready": pdf_ready,
         "severity_counts": job.severity_counts(), "findings": job.sorted_findings()},
    )


@app.get("/scans/{job_id}/report.html", response_class=HTMLResponse)
def scan_report_html(job_id: str, user: str = Depends(auth.verify_credentials)):
    path = REPORTS_DIR / f"{job_id}.html"
    if not path.exists():
        raise HTTPException(404, "Report not ready yet.")
    return HTMLResponse(path.read_text())


@app.get("/scans/{job_id}/report.pdf")
def scan_report_pdf(job_id: str, user: str = Depends(auth.verify_credentials)):
    path = REPORTS_DIR / f"{job_id}.pdf"
    if not path.exists():
        raise HTTPException(404, "PDF report not available (WeasyPrint may be missing, or scan still running).")
    return FileResponse(str(path), media_type="application/pdf", filename=f"vapt-report-{job_id}.pdf")
