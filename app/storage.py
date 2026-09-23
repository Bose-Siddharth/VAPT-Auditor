"""Simple JSON-file-per-job persistence. No database needed at this scale."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from app.models import ScanJob

DATA_DIR = Path(os.environ.get("VAPT_DATA_DIR", "data"))
JOBS_DIR = DATA_DIR / "jobs"


def save_job(job: ScanJob) -> None:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    path = JOBS_DIR / f"{job.id}.json"
    # Write to a temp file and rename atomically so a concurrent reader (e.g.
    # a browser polling /scans/{job_id} while a background task is mid-write)
    # never observes a truncated/partial JSON file.
    fd, tmp_path = tempfile.mkstemp(dir=JOBS_DIR, prefix=f".{job.id}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(job.model_dump_json(indent=2))
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_job(job_id: str) -> ScanJob | None:
    path = JOBS_DIR / f"{job_id}.json"
    if not path.exists():
        return None
    try:
        return ScanJob.model_validate_json(path.read_text())
    except Exception:
        # Most likely a read racing an in-progress atomic write; the caller
        # treats this the same as "not found yet" rather than a hard error.
        return None


def list_jobs() -> list[ScanJob]:
    if not JOBS_DIR.exists():
        return []
    jobs = []
    for path in JOBS_DIR.glob("*.json"):
        try:
            jobs.append(ScanJob.model_validate_json(path.read_text()))
        except Exception:
            continue
    return sorted(jobs, key=lambda j: j.created_at, reverse=True)
