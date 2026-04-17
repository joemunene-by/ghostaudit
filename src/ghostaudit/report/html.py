"""HTML report generator using Jinja2."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ghostaudit.models import ScanReport

TEMPLATE_DIR = Path(__file__).parent / "templates"


def generate_html_report(report: ScanReport, output_path: str | None = None) -> str:
    """Generate an HTML report. Returns the HTML string and optionally writes to file."""
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=True,
    )
    template = env.get_template("report.html")

    # Group findings by category (check_id prefix)
    categories: dict[str, list] = {}
    for finding in report.findings:
        prefix = finding.check_id.split("-")[0]
        category_map = {
            "RBAC": "RBAC",
            "POD": "Pod Security",
            "SEC": "Secrets & Config",
            "NET": "Network",
            "RES": "Resource Management",
            "IMG": "Image Security",
        }
        cat_name = category_map.get(prefix, prefix)
        categories.setdefault(cat_name, []).append(finding)

    html = template.render(
        report=report,
        categories=categories,
        summary=report.summary,
        score=report.score,
    )

    if output_path:
        Path(output_path).write_text(html, encoding="utf-8")

    return html
