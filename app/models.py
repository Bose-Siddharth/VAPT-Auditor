"""Core data model shared by every scanner, parser, and the report renderer."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


class TargetType(str, enum.Enum):
    NETWORK = "network"          # IP / hostname / CIDR
    WEB = "web"                  # http(s) URL, generic web app
    WORDPRESS = "wordpress"      # http(s) URL known to be WordPress
    MOBILE_APK = "mobile_apk"    # uploaded .apk file (static analysis)


class Target(BaseModel):
    type: TargetType
    value: str  # host/IP/CIDR, URL, or uploaded file path depending on type
    label: Optional[str] = None


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex[:10])
    category: TargetType
    source_tool: str
    severity: Severity
    title: str
    description: str
    evidence: Optional[str] = None
    affected: Optional[str] = None       # host:port, URL, file path, component
    remediation: Optional[str] = None
    reference: Optional[str] = None      # CVE id / advisory URL
    cvss: Optional[float] = None


class ToolRunResult(BaseModel):
    tool: str
    command: str
    exit_code: Optional[int] = None
    started_at: datetime
    finished_at: datetime
    ok: bool
    error: Optional[str] = None  # e.g. "tool not installed", timeout, etc.


class ScanJob(BaseModel):
    id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    target: Target
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    status: str = "pending"  # pending | running | completed | failed
    findings: list[Finding] = Field(default_factory=list)
    tool_runs: list[ToolRunResult] = Field(default_factory=list)
    error: Optional[str] = None

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: f.severity.rank)
