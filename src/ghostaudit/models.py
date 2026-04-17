"""Data models for GhostAudit findings and reports."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


class Severity(enum.Enum):
    """Finding severity levels aligned with CIS Kubernetes Benchmark."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }[self]

    def __lt__(self, other: Severity) -> bool:
        return self.weight < other.weight


@dataclass
class Finding:
    """A single security finding from an audit check."""

    check_id: str
    title: str
    description: str
    severity: Severity
    resource_kind: str
    resource_name: str
    namespace: str
    remediation: str

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "resource_kind": self.resource_kind,
            "resource_name": self.resource_name,
            "namespace": self.namespace,
            "remediation": self.remediation,
        }


@dataclass
class CheckResult:
    """Result from running a single check category."""

    category: str
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def passed(self) -> bool:
        return len(self.findings) == 0 and self.error is None


@dataclass
class ScanReport:
    """Complete scan report for a cluster."""

    cluster_name: str
    scan_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    findings: list[Finding] = field(default_factory=list)
    namespaces_scanned: list[str] = field(default_factory=list)
    checks_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        counts["TOTAL"] = len(self.findings)
        return counts

    @property
    def score(self) -> int:
        """Compute security score 0-100. Fewer / less severe findings = higher score."""
        if not self.findings:
            return 100
        total_weight = sum(f.severity.weight for f in self.findings)
        # Diminishing penalty: each point of weight costs less as total grows
        penalty = min(100, int(total_weight * 2.5))
        return max(0, 100 - penalty)

    def to_dict(self) -> dict:
        return {
            "cluster_name": self.cluster_name,
            "scan_time": self.scan_time.isoformat(),
            "score": self.score,
            "summary": self.summary,
            "namespaces_scanned": self.namespaces_scanned,
            "checks_run": self.checks_run,
            "errors": self.errors,
            "findings": [f.to_dict() for f in self.findings],
        }
