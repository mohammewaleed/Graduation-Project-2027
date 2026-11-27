"""JSON and standalone offline HTML5 developer report generation package."""

from backend.app.reports.generator import (
    build_html_report,
    build_json_report,
)

__all__ = [
    "build_html_report",
    "build_json_report",
]
