"""REST API routes for managing authorized local target projects."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.db_models import Project, Scan, utcnow
from backend.app.schemas import ProjectCreate, ProjectOut
from backend.scanner.policy import ScopeGuardrail

router = APIRouter(prefix="/api/projects", tags=["projects"])


def _serialize_project(project: Project, scans: list[Scan]) -> ProjectOut:
    """Build ``ProjectOut`` enriched with total scan count and latest risk score."""
    ordered_scans = sorted(scans, key=lambda s: s.created_at, reverse=True)
    latest_risk_score = ordered_scans[0].risk_score if ordered_scans else None
    return ProjectOut(
        id=project.id,
        name=project.name,
        base_url=project.base_url,
        target_stack=project.target_stack,
        authorized_confirmed=project.authorized_confirmed,
        authorized_at=project.authorized_at,
        created_at=project.created_at,
        scan_count=len(ordered_scans),
        latest_risk_score=latest_risk_score,
    )


@router.get("", response_model=list[ProjectOut])
def list_projects(db: Session = Depends(get_db)) -> list[ProjectOut]:
    """List all registered projects newest-first with scan counts and latest risk score."""
    stmt = (
        select(Project)
        .options(selectinload(Project.scans))
        .order_by(Project.created_at.desc())
    )
    projects = db.scalars(stmt).all()
    return [_serialize_project(project, list(project.scans)) for project in projects]


@router.post("", response_model=ProjectOut, status_code=status.HTTP_201_CREATED)
def create_project(
    payload: ProjectCreate,
    db: Session = Depends(get_db),
) -> ProjectOut:
    """Create a new authorized local target project after scope validation."""
    if payload.authorized_confirmed is not True:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "AUTHORIZATION_REQUIRED",
                "message": "You must confirm authorization to scan this target.",
            },
        )

    guardrail = ScopeGuardrail(allowlist=settings.allowlist_hosts)
    validated_url = guardrail.validate_url(payload.base_url)

    now = utcnow()
    project = Project(
        name=payload.name,
        base_url=validated_url,
        target_stack=payload.target_stack,
        authorized_confirmed=True,
        authorized_at=now,
        created_at=now,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return _serialize_project(project, [])


@router.get("/{project_id}", response_model=ProjectOut)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
) -> ProjectOut:
    """Fetch a single project by UUID along with aggregate scan metrics."""
    stmt = (
        select(Project)
        .options(selectinload(Project.scans))
        .where(Project.id == project_id)
    )
    project = db.scalars(stmt).first()
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "PROJECT_NOT_FOUND",
                "message": f"Project '{project_id}' was not found.",
            },
        )
    return _serialize_project(project, list(project.scans))


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(
    project_id: str,
    db: Session = Depends(get_db),
) -> Response:
    """Delete a project and cascade removal of its scans, endpoints, and findings."""
    project = db.get(Project, project_id)
    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "PROJECT_NOT_FOUND",
                "message": f"Project '{project_id}' was not found.",
            },
        )
    db.delete(project)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
