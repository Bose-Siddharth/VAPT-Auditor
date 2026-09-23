"""Routes a ScanJob's target to the right scanner module(s) and aggregates results."""
from __future__ import annotations

from app.models import ScanJob, TargetType
from app.scanners import mobile, network, tls, web, wordpress


def run_job(job: ScanJob) -> None:
    """Mutates `job` in place: runs the relevant scanners, fills findings/tool_runs."""
    target = job.target

    if target.type == TargetType.NETWORK:
        findings, run = network.scan(target.value)
        job.findings.extend(findings)
        job.tool_runs.append(run)

    elif target.type == TargetType.WEB:
        for scan_fn in (web.scan_nuclei, web.scan_nikto):
            findings, run = scan_fn(target.value)
            job.findings.extend(findings)
            job.tool_runs.append(run)
        if target.value.startswith("https://"):
            findings, run = tls.scan(target.value)
            job.findings.extend(findings)
            job.tool_runs.append(run)

    elif target.type == TargetType.WORDPRESS:
        for scan_fn in (web.scan_nuclei, web.scan_nikto, wordpress.scan):
            findings, run = scan_fn(target.value)
            job.findings.extend(findings)
            job.tool_runs.append(run)
        if target.value.startswith("https://"):
            findings, run = tls.scan(target.value)
            job.findings.extend(findings)
            job.tool_runs.append(run)

    elif target.type == TargetType.MOBILE_APK:
        findings, run = mobile.scan(target.value)
        job.findings.extend(findings)
        job.tool_runs.append(run)

    else:  # pragma: no cover - exhaustive enum
        raise ValueError(f"unsupported target type: {target.type}")
