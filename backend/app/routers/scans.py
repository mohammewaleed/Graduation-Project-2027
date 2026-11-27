"""REST & SSE API routes for scan execution, live progress streaming, endpoints, findings, and diffs."""

from __future__ import annotations

import asyncio
import json
import queue
import time
from collections.abc import AsyncIterator
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, joinedload, sessionmaker

from backend.app.config import settings
from backend.app.database import SessionLocal, create_session_factory, get_db
from backend.app.db_models import Endpoint, Finding, Project, Scan, utcnow
from backend.app.schemas import (
    EndpointOut,
    FindingOut,
    ScanCompareCounts,
    ScanCompareOut,
    ScanCreate,
    ScanOut,
)
from backend.app.worker import (
    TERMINAL_SCAN_STATUSES,
    ScanJobManager,
    scan_job_manager,
)
from backend.scanner.models import Confidence, ScanConfig, ScanStatus, Severity
from backend.scanner.policy import ScopeGuardrail
from backend.scanner.scoring import CONFIDENCE_RANK, SEVERITY_RANK

router = APIRouter(prefix="/api", tags=["scans"])

_SSE_POLL_INTERVAL_S = 0.05
_SSE_DB_CHECK_INTERVAL_S = 0.5
_SSE_HEARTBEAT_INTERVAL_S = 15.0


def _get_job_manager(request: Request) -> ScanJobManager:
    """Resolve the active ``ScanJobManager`` from app state or module singleton."""
    manager = getattr(request.app.state, "scan_job_manager", None)
    return manager if isinstance(manager, ScanJobManager) else scan_job_manager


def _get_session_factory(request: Request, db: Session) -> sessionmaker[Session]:
    """Return a sessionmaker bound to the same database engine as the current request."""
    state_factory = getattr(request.app.state, "session_factory", None)
    state_engine = getattr(request.app.state, "db_engine", None)
    bind = db.get_bind()
    if state_factory is not None and (state_engine is None or bind is state_engine):
        return state_factory
    if isinstance(bind, Engine):
        return create_session_factory(bind)
    return state_factory or SessionLocal


def _serialize_scan(scan: Scan, project: Project | None = None) -> ScanOut:
    """Convert an ORM ``Scan`` (and owning ``Project``) into ``ScanOut``."""
    owner = project if project is not None else scan.project
    return ScanOut(
        id=scan.id,
        project_id=scan.project_id,
        project_name=owner.name if owner is not None else None,
        target_url=owner.base_url if owner is not None else None,
        profile=scan.profile,
        status=scan.status,
        progress_pct=scan.progress_pct,
        current_stage=scan.current_stage,
        pages_crawled=scan.pages_crawled,
        requests_sent=scan.requests_sent,
        risk_score=scan.risk_score,
        summary=scan.summary,
        errors=scan.errors,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        created_at=scan.created_at,
    )


def _severity_sort_key(finding: Finding) -> tuple[int, int, str, str, str]:
    """Deterministic sort key placing highest severity and confidence first."""
    try:
        sev_rank = SEVERITY_RANK[Severity(finding.severity.lower())]
    except ValueError:
        sev_rank = 0
    try:
        conf_rank = CONFIDENCE_RANK[Confidence(finding.confidence.lower())]
    except ValueError:
        conf_rank = 0
    return (
        -sev_rank,
        -conf_rank,
        finding.check_id,
        finding.endpoint_url,
        finding.parameter or "",
    )


def _format_sse(payload: dict[str, Any]) -> str:
    """Format a JSON payload as a standards-compliant SSE data frame."""
    return f"data: {json.dumps(payload)}\n\n"


@router.post(
    "/projects/{project_id}/scans",
    response_model=ScanOut,
    status_code=status.HTTP_201_CREATED,
)
def start_project_scan(
    project_id: str,
    payload: ScanCreate,
    request: Request,
    db: Session = Depends(get_db),
) -> ScanOut:
    """Validate project scope, create a queued scan record, and enqueue background execution."""
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "PROJECT_NOT_FOUND",
                "message": f"Project '{project_id}' was not found.",
            },
        )

    guardrail = ScopeGuardrail(allowlist=settings.allowlist_hosts)
    validated_url = guardrail.validate_url(project.base_url)

    # Persist only redacted configuration metadata (never raw secrets/passwords).
    config_snapshot: dict[str, Any] = {
        "profile": payload.profile.value,
        "target_stack": project.target_stack,
        "auth_type": payload.auth_type,
        "auto_login_dvwa": payload.auto_login_dvwa,
        "max_depth": payload.max_depth,
        "max_pages": payload.max_pages,
        "enabled_checks": payload.enabled_checks,
        "rate_limit_rps": settings.scan_rate_limit_rps,
        "max_requests": settings.scan_max_requests,
    }

    now = utcnow()
    scan = Scan(
        project_id=project.id,
        profile=payload.profile.value,
        status=ScanStatus.QUEUED.value,
        progress_pct=0,
        current_stage=ScanStatus.QUEUED.value,
        config_json=json.dumps(config_snapshot),
        started_at=now,
        created_at=now,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_config = ScanConfig(
        target_url=validated_url,
        profile=payload.profile,
        target_stack=project.target_stack,
        auth_type=payload.auth_type,
        auth_value=payload.auth_value,
        auto_login_dvwa=payload.auto_login_dvwa,
        dvwa_username=payload.dvwa_username,
        dvwa_password=payload.dvwa_password,
        max_depth=payload.max_depth,
        max_pages=payload.max_pages,
        rate_limit_rps=float(settings.scan_rate_limit_rps),
        max_requests=int(settings.scan_max_requests),
        enabled_checks=payload.enabled_checks,
    )

    job_manager = _get_job_manager(request)
    session_factory = _get_session_factory(request, db)
    job_manager.submit_scan(scan.id, scan_config, session_factory)

    return _serialize_scan(scan, project)


@router.get("/projects/{project_id}/scans", response_model=list[ScanOut])
def list_project_scans(
    project_id: str,
    db: Session = Depends(get_db),
) -> list[ScanOut]:
    """List scans belonging to a project ordered newest first."""
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "PROJECT_NOT_FOUND",
                "message": f"Project '{project_id}' was not found.",
            },
        )

    stmt = (
        select(Scan)
        .where(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
    )
    scans = db.scalars(stmt).all()
    return [_serialize_scan(scan, project) for scan in scans]


@router.get("/scans", response_model=list[ScanOut])
def list_recent_scans(db: Session = Depends(get_db)) -> list[ScanOut]:
    """List all recent scans across projects newest first with project metadata."""
    stmt = (
        select(Scan)
        .options(joinedload(Scan.project))
        .order_by(Scan.created_at.desc())
    )
    scans = db.scalars(stmt).all()
    return [_serialize_scan(scan) for scan in scans]


# IMPORTANT: Registered BEFORE /scans/{scan_id} so 'compare' is not matched as a scan_id.
@router.get("/scans/compare", response_model=ScanCompareOut)
def compare_scans(
    base: str = Query(..., description="Baseline scan UUID"),
    head: str = Query(..., description="Head/target scan UUID"),
    db: Session = Depends(get_db),
) -> ScanCompareOut:
    """Compare two scans by finding fingerprint into new, fixed, and unchanged sets."""
    base_scan = db.get(Scan, base)
    if base_scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "SCAN_NOT_FOUND",
                "message": f"Baseline scan '{base}' was not found.",
            },
        )

    head_scan = db.get(Scan, head)
    if head_scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "SCAN_NOT_FOUND",
                "message": f"Head scan '{head}' was not found.",
            },
        )

    base_findings = db.scalars(select(Finding).where(Finding.scan_id == base)).all()
    head_findings = db.scalars(select(Finding).where(Finding.scan_id == head)).all()

    base_by_fp = {finding.fingerprint: finding for finding in base_findings}
    head_by_fp = {finding.fingerprint: finding for finding in head_findings}

    new_models = sorted(
        [finding for fp, finding in head_by_fp.items() if fp not in base_by_fp],
        key=_severity_sort_key,
    )
    fixed_models = sorted(
        [finding for fp, finding in base_by_fp.items() if fp not in head_by_fp],
        key=_severity_sort_key,
    )
    unchanged_models = sorted(
        [finding for fp, finding in head_by_fp.items() if fp in base_by_fp],
        key=_severity_sort_key,
    )

    new_out = [FindingOut.model_validate(item) for item in new_models]
    fixed_out = [FindingOut.model_validate(item) for item in fixed_models]
    unchanged_out = [FindingOut.model_validate(item) for item in unchanged_models]

    return ScanCompareOut(
        base_scan_id=base,
        head_scan_id=head,
        counts=ScanCompareCounts(
            new=len(new_out),
            fixed=len(fixed_out),
            unchanged=len(unchanged_out),
        ),
        new=new_out,
        fixed=fixed_out,
        unchanged=unchanged_out,
    )


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
) -> ScanOut:
    """Return full status, progress telemetry, and rollups for a single scan."""
    stmt = select(Scan).options(joinedload(Scan.project)).where(Scan.id == scan_id)
    scan = db.scalars(stmt).first()
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "SCAN_NOT_FOUND",
                "message": f"Scan '{scan_id}' was not found.",
            },
        )
    return _serialize_scan(scan)


@router.post("/scans/{scan_id}/cancel", response_model=ScanOut)
def cancel_scan(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> ScanOut:
    """Request cooperative cancellation of a queued or in-progress scan."""
    stmt = select(Scan).options(joinedload(Scan.project)).where(Scan.id == scan_id)
    scan = db.scalars(stmt).first()
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "SCAN_NOT_FOUND",
                "message": f"Scan '{scan_id}' was not found.",
            },
        )

    job_manager = _get_job_manager(request)
    job_manager.cancel_scan(scan_id)

    if scan.status == ScanStatus.QUEUED.value:
        scan.status = ScanStatus.CANCELLED.value
        scan.current_stage = ScanStatus.CANCELLED.value
        scan.finished_at = utcnow()
        db.commit()
        db.refresh(scan)
        job_manager.publish_event(
            scan_id,
            {
                "type": "status",
                "scan_id": scan_id,
                "status": ScanStatus.CANCELLED.value,
                "risk_score": scan.risk_score,
                "summary": scan.summary,
                "pages_crawled": scan.pages_crawled,
                "requests_sent": scan.requests_sent,
                "errors": scan.errors,
            },
        )

    return _serialize_scan(scan)


@router.get("/scans/{scan_id}/stream")
async def stream_scan_events(
    scan_id: str,
    request: Request,
    db: Session = Depends(get_db),
) -> StreamingResponse:
    """Stream live SSE progress, finding, and terminal status events for a scan."""
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "SCAN_NOT_FOUND",
                "message": f"Scan '{scan_id}' was not found.",
            },
        )

    job_manager = _get_job_manager(request)
    session_factory = _get_session_factory(request, db)

    # Subscribe BEFORE reading current DB snapshot to eliminate missed terminal events.
    subscriber_queue = job_manager.subscribe(scan_id)

    async def event_stream() -> AsyncIterator[str]:
        try:
            with session_factory() as snapshot_db:
                current = snapshot_db.get(Scan, scan_id)
                if current is None:
                    return
                if current.status in TERMINAL_SCAN_STATUSES:
                    yield _format_sse(
                        {
                            "type": "status",
                            "scan_id": scan_id,
                            "status": current.status,
                            "risk_score": current.risk_score,
                            "summary": current.summary,
                            "pages_crawled": current.pages_crawled,
                            "requests_sent": current.requests_sent,
                            "errors": current.errors,
                        }
                    )
                    return

                yield _format_sse(
                    {
                        "type": "progress",
                        "scan_id": scan_id,
                        "status": current.status,
                        "stage": current.current_stage,
                        "percent": current.progress_pct,
                        "pages_crawled": current.pages_crawled,
                        "requests_sent": current.requests_sent,
                        "current_check": "",
                    }
                )

            last_db_check = time.monotonic()
            last_heartbeat = time.monotonic()

            while True:
                if await request.is_disconnected():
                    break

                emitted_any = False
                while True:
                    try:
                        event = subscriber_queue.get_nowait()
                    except queue.Empty:
                        break
                    emitted_any = True
                    last_heartbeat = time.monotonic()
                    yield _format_sse(event)
                    if (
                        event.get("type") == "status"
                        and event.get("status") in TERMINAL_SCAN_STATUSES
                    ):
                        return

                now = time.monotonic()
                if not emitted_any and (now - last_db_check) >= _SSE_DB_CHECK_INTERVAL_S:
                    last_db_check = now
                    with session_factory() as check_db:
                        latest = check_db.get(Scan, scan_id)
                        if latest is None:
                            return
                        if latest.status in TERMINAL_SCAN_STATUSES:
                            yield _format_sse(
                                {
                                    "type": "status",
                                    "scan_id": scan_id,
                                    "status": latest.status,
                                    "risk_score": latest.risk_score,
                                    "summary": latest.summary,
                                    "pages_crawled": latest.pages_crawled,
                                    "requests_sent": latest.requests_sent,
                                    "errors": latest.errors,
                                }
                            )
                            return

                if (now - last_heartbeat) >= _SSE_HEARTBEAT_INTERVAL_S:
                    last_heartbeat = now
                    yield _format_sse({"type": "heartbeat", "scan_id": scan_id})

                await asyncio.sleep(_SSE_POLL_INTERVAL_S)
        finally:
            job_manager.unsubscribe(scan_id, subscriber_queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/scans/{scan_id}/endpoints", response_model=list[EndpointOut])
def list_scan_endpoints(
    scan_id: str,
    db: Session = Depends(get_db),
) -> list[EndpointOut]:
    """Return all discovered endpoints for a scan."""
    if db.get(Scan, scan_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "SCAN_NOT_FOUND",
                "message": f"Scan '{scan_id}' was not found.",
            },
        )

    stmt = (
        select(Endpoint)
        .where(Endpoint.scan_id == scan_id)
        .order_by(Endpoint.url.asc(), Endpoint.method.asc())
    )
    endpoints = db.scalars(stmt).all()
    return [EndpointOut.model_validate(ep) for ep in endpoints]


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_scan_findings(
    scan_id: str,
    severity: str | None = Query(default=None),
    owasp: str | None = Query(default=None),
    triage_status: str | None = Query(default=None),
    q: str | None = Query(default=None),
    sort: str = Query(default="severity", pattern="^(severity|created_at)$"),
    db: Session = Depends(get_db),
) -> list[FindingOut]:
    """Return findings for a scan with optional severity, OWASP, triage, search, and sort filters."""
    if db.get(Scan, scan_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "SCAN_NOT_FOUND",
                "message": f"Scan '{scan_id}' was not found.",
            },
        )

    stmt = select(Finding).where(Finding.scan_id == scan_id)

    if severity:
        severities = [item.strip().lower() for item in severity.split(",") if item.strip()]
        if severities:
            stmt = stmt.where(Finding.severity.in_(severities))

    if triage_status:
        statuses = [item.strip().lower() for item in triage_status.split(",") if item.strip()]
        if statuses:
            stmt = stmt.where(Finding.triage_status.in_(statuses))

    findings = list(db.scalars(stmt).all())

    if owasp:
        owasp_needle = owasp.strip().lower()
        findings = [
            item
            for item in findings
            if owasp_needle in (item.owasp_category or "").lower()
        ]

    if q:
        needle = q.strip().lower()
        if needle:
            findings = [
                item
                for item in findings
                if needle in (item.title or "").lower()
                or needle in (item.endpoint_url or "").lower()
                or needle in (item.parameter or "").lower()
                or needle in (item.check_id or "").lower()
            ]

    if sort == "created_at":
        findings.sort(key=lambda item: item.created_at, reverse=True)
    else:
        findings.sort(key=_severity_sort_key)

    return [FindingOut.model_validate(item) for item in findings]
