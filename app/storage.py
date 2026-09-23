"""Simple JSON-file-per-job persistence. No database needed at this scale."""
from __future__ import annotations

import os
from pathlib import Path

from app.models import ScanJob

DATA_DIR = Path(os.environ.get("VAPT_DATA_DIR", "data"))
JOBS_DIR = DATA_DIR / "jobs"


def save_job(job: ScanJob) -> None:
    JOBS_DIR.mkdir(parents=True, exist_ok=True)
    path = JOBS_DIR / f"{job.id}.json"
    path.write_text(job.model_dump_json(indent=2))


def load_job(job_id: str) -> ScanJob | None:
    path = JOBS_DIR / f"{job_id}.json"
    if not path.exists():
        return None
    return ScanJob.model_validate_json(path.read_text())


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
