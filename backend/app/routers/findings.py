"""REST API routes for inspecting individual findings and updating developer triage state."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.db_models import Finding, Scan, utcnow
from backend.app.schemas import FindingOut, FindingTriageUpdate
from backend.scanner.scoring import calculate_risk_score, summarize_findings

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(
    finding_id: str,
    db: Session = Depends(get_db),
) -> FindingOut:
    """Return full finding details including evidence, explanation, and stack-ordered fixes."""
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "FINDING_NOT_FOUND",
                "message": f"Finding '{finding_id}' was not found.",
            },
        )
    return FindingOut.model_validate(finding)


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding_triage(
    finding_id: str,
    payload: FindingTriageUpdate,
    db: Session = Depends(get_db),
) -> FindingOut:
    """Update a finding's triage status/note and atomically recalculate parent scan risk score."""
    finding = db.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "code": "FINDING_NOT_FOUND",
                "message": f"Finding '{finding_id}' was not found.",
            },
        )

    finding.triage_status = payload.triage_status.value
    if "triage_note" in payload.model_fields_set:
        finding.triage_note = payload.triage_note
    finding.updated_at = utcnow()
    db.flush()

    parent_scan = db.get(Scan, finding.scan_id)
    if parent_scan is not None:
        scan_findings = list(
            db.scalars(select(Finding).where(Finding.scan_id == finding.scan_id)).all()
        )
        parent_scan.summary_json = json.dumps(summarize_findings(scan_findings))
        parent_scan.risk_score = calculate_risk_score(scan_findings)

    db.commit()
    db.refresh(finding)
    return FindingOut.model_validate(finding)
