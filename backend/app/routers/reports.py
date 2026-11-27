"""REST router for exporting JSON and standalone HTML developer scan reports."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.db_models import Endpoint, Finding, Project, Scan
from backend.app.reports.generator import build_html_report, build_json_report

router = APIRouter(prefix="/api", tags=["reports"])

_SAFE_ID_RE = re.compile(r"[^a-zA-Z0-9_-]")


def _short_scan_id(scan_id: str) -> str:
    """Build a safe short scan identifier for Content-Disposition filenames."""
    cleaned = _SAFE_ID_RE.sub("", scan_id or "")
    return cleaned[:8] if cleaned else "report"


@router.get("/scans/{scan_id}/report")
def export_scan_report(
    scan_id: str,
    format: str = Query("json", pattern="^(json|html)$"),
    download: bool = Query(False),
    db: Session = Depends(get_db),
) -> Response:
    """Export a scan report in structured JSON or standalone autoescaped HTML5."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "SCAN_NOT_FOUND",
                "message": f"Scan '{scan_id}' not found.",
            },
        )

    project = db.get(Project, scan.project_id)
    if project is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "PROJECT_NOT_FOUND",
                "message": f"Project '{scan.project_id}' not found.",
            },
        )

    endpoints = list(
        db.scalars(
            select(Endpoint)
            .where(Endpoint.scan_id == scan.id)
            .order_by(Endpoint.url.asc(), Endpoint.method.asc())
        ).all()
    )
    findings = list(
        db.scalars(select(Finding).where(Finding.scan_id == scan.id)).all()
    )

    short_id = _short_scan_id(scan.id)

    if format == "html":
        html_body = build_html_report(project, scan, endpoints, findings)
        headers = (
            {
                "Content-Disposition": (
                    f'attachment; filename="scan-{short_id}-report.html"'
                )
            }
            if download
            else None
        )
        return HTMLResponse(content=html_body, headers=headers)

    json_payload = build_json_report(project, scan, endpoints, findings)
    headers = (
        {
            "Content-Disposition": (
                f'attachment; filename="scan-{short_id}-report.json"'
            )
        }
        if download
        else None
    )
    return JSONResponse(content=json_payload, headers=headers)
