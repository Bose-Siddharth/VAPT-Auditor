"""Shared subprocess helper for every scanner wrapper.

Every real scanning tool is invoked as a subprocess with a hard timeout and
its own error captured rather than raised, so one missing/failing tool never
takes down the whole scan job -- the report simply notes that tool's output
as unavailable.
"""
from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timezone

from app.models import ToolRunResult


def tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_command(
    tool: str,
    args: list[str],
    timeout: int = 600,
) -> tuple[ToolRunResult, str]:
    """Run `args` (argv list, never a shell string) and return (result, stdout).

    stdout is returned separately (not stored on the model) since it can be
    large; callers hand it straight to the matching parser.
    """
    started = datetime.now(timezone.utc)
    command_str = " ".join(args)

    if not tool_available(args[0]):
        finished = datetime.now(timezone.utc)
        return (
            ToolRunResult(
                tool=tool,
                command=command_str,
                exit_code=None,
                started_at=started,
                finished_at=finished,
                ok=False,
                error=f"'{args[0]}' is not installed on this host",
            ),
            "",
        )

    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        finished = datetime.now(timezone.utc)
        ok = proc.returncode == 0
        return (
            ToolRunResult(
                tool=tool,
                command=command_str,
                exit_code=proc.returncode,
                started_at=started,
                finished_at=finished,
                ok=ok,
                error=None if ok else proc.stderr[-2000:],
            ),
            proc.stdout,
        )
    except subprocess.TimeoutExpired as exc:
        finished = datetime.now(timezone.utc)
        return (
            ToolRunResult(
                tool=tool,
                command=command_str,
                exit_code=None,
                started_at=started,
                finished_at=finished,
                ok=False,
                error=f"timed out after {timeout}s",
            ),
            exc.stdout or "" if isinstance(exc.stdout, str) else "",
        )
    except Exception as exc:  # pragma: no cover - defensive
        finished = datetime.now(timezone.utc)
        return (
            ToolRunResult(
                tool=tool,
                command=command_str,
                exit_code=None,
                started_at=started,
                finished_at=finished,
                ok=False,
                error=str(exc),
            ),
            "",
        )
