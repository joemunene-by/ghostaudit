"""Configuration settings for GhostAudit."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

ALL_CHECK_CATEGORIES = ["rbac", "pods", "secrets", "network", "resources", "images"]


@dataclass
class ScanConfig:
    """Configuration for a scan run."""

    kubeconfig: str | None = None
    namespace: str | None = None  # None = all namespaces
    checks: list[str] = field(default_factory=lambda: list(ALL_CHECK_CATEGORIES))
    output: str | None = None  # Output file path
    format: str = "console"  # console, html, json (auto-detected from output extension)
    verbose: bool = False

    def __post_init__(self) -> None:
        # Validate check categories
        for c in self.checks:
            if c not in ALL_CHECK_CATEGORIES:
                raise ValueError(
                    f"Unknown check category: {c!r}. "
                    f"Valid categories: {', '.join(ALL_CHECK_CATEGORIES)}"
                )
        # Auto-detect format from output path
        if self.output:
            ext = Path(self.output).suffix.lower()
            if ext == ".html":
                self.format = "html"
            elif ext == ".json":
                self.format = "json"
            else:
                self.format = "console"
