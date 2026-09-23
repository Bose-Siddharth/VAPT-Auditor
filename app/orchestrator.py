"""Routes a ScanJob's target to the right scanner module(s) and aggregates results."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Callable

from app.models import Finding, ScanJob, TargetType, ToolRunResult
from app.scanners import mobile, network, tls, web, wordpress

ScanFn = Callable[[str], tuple[list[Finding], ToolRunResult]]


def run_job(job: ScanJob) -> None:
    """Mutates `job` in place: runs the relevant scanners, fills findings/tool_runs.

    Each scanner is isolated: a bug in one scanner's tool-output parsing (as
    opposed to a subprocess-level failure, which app.scanners.base already
    isolates) must not abort the rest of the job or lose findings other
    scanners already collected.
    """
    target = job.target
    scan_fns: list[ScanFn] = _scanners_for(target.type, target.value)

    for scan_fn in scan_fns:
        findings, run = _run_scanner(scan_fn, target.value)
        job.findings.extend(findings)
        job.tool_runs.append(run)


def _scanners_for(target_type: TargetType, target_value: str) -> list[ScanFn]:
    if target_type == TargetType.NETWORK:
        return [network.scan]

    if target_type == TargetType.WEB:
        fns: list[ScanFn] = [web.scan_nuclei, web.scan_nikto]
        if target_value.startswith("https://"):
            fns.append(tls.scan)
        return fns

    if target_type == TargetType.WORDPRESS:
        fns = [web.scan_nuclei, web.scan_nikto, wordpress.scan]
        if target_value.startswith("https://"):
            fns.append(tls.scan)
        return fns

    if target_type == TargetType.MOBILE_APK:
        return [mobile.scan]

    raise ValueError(f"unsupported target type: {target_type}")  # pragma: no cover - exhaustive enum


def _run_scanner(scan_fn: ScanFn, target_value: str) -> tuple[list[Finding], ToolRunResult]:
    started = datetime.now(timezone.utc)
    try:
        return scan_fn(target_value)
    except Exception as exc:
        finished = datetime.now(timezone.utc)
        return [], ToolRunResult(
            tool=getattr(scan_fn, "__module__", "unknown"),
            command=f"{scan_fn.__qualname__}({target_value!r})",
            started_at=started,
            finished_at=finished,
            ok=False,
            error=f"scanner raised {type(exc).__name__}: {exc}",
        )
