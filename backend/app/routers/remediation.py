"""
CloudGuard Remediation Router
Endpoints for previewing and applying auto-remediation fixes.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Finding, RemediationLog
from app.schemas import RemediationPreview, RemediationResponse, RemediationLogResponse
from app.remediation.engine import remediation_engine

router = APIRouter(prefix="/api/remediation", tags=["Remediation"])


@router.get("/{finding_id}/preview")
def preview_remediation(finding_id: int, db: Session = Depends(get_db)):
    """Preview what a remediation action will do before applying it."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not finding.is_remediable:
        raise HTTPException(
            status_code=400,
            detail="This finding does not support auto-remediation."
        )

    preview = remediation_engine.get_preview(finding)
    return preview


@router.post("/{finding_id}/fix")
def apply_remediation(finding_id: int, db: Session = Depends(get_db)):
    """Apply one-click auto-remediation for a finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if not finding.is_remediable:
        raise HTTPException(
            status_code=400,
            detail="This finding does not support auto-remediation."
        )

    if finding.status == "remediated":
        raise HTTPException(
            status_code=400,
            detail="This finding has already been remediated."
        )

    result = remediation_engine.apply_fix(finding, db)

    if not result["success"]:
        raise HTTPException(status_code=500, detail=result["message"])

    return result


@router.get("/{finding_id}/logs", response_model=list[RemediationLogResponse])
def get_remediation_logs(finding_id: int, db: Session = Depends(get_db)):
    """Get remediation history for a specific finding."""
    logs = db.query(RemediationLog).filter(
        RemediationLog.finding_id == finding_id
    ).order_by(RemediationLog.performed_at.desc()).all()

    return [RemediationLogResponse.model_validate(log) for log in logs]
