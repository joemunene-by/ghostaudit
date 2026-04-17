"""JSON report generator."""

from __future__ import annotations

import json
from pathlib import Path

from ghostaudit.models import ScanReport


def generate_json_report(report: ScanReport, output_path: str | None = None) -> str:
    """Generate a JSON report. Returns the JSON string and optionally writes to file."""
    data = report.to_dict()
    json_str = json.dumps(data, indent=2, ensure_ascii=False)

    if output_path:
        Path(output_path).write_text(json_str, encoding="utf-8")

    return json_str
