"""
CloudGuard Scans Router
Endpoints for triggering and managing security scans.
"""

import asyncio
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Scan, ScanStatus
from app.schemas import ScanTriggerRequest, ScanResponse, ScanHistoryResponse
from app.services.scan_scheduler import run_scan

router = APIRouter(prefix="/api/scans", tags=["Scans"])


@router.post("/trigger", response_model=ScanResponse)
async def trigger_scan(
    request: ScanTriggerRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    """Trigger a new security scan."""
    # Check if a scan is already running
    running = db.query(Scan).filter(
        Scan.status == ScanStatus.RUNNING.value
    ).first()

    if running:
        raise HTTPException(
            status_code=409,
            detail="A scan is already in progress. Please wait for it to complete."
        )

    # Create a pending scan
    scan = Scan(status=ScanStatus.PENDING.value, scan_type=request.scan_type)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Run scan in background
    async def _run():
        await run_scan(scan_type=request.scan_type)

    background_tasks.add_task(asyncio.ensure_future, _run())

    return scan


@router.get("/history", response_model=ScanHistoryResponse)
def get_scan_history(
    page: int = 1,
    page_size: int = 20,
    db: Session = Depends(get_db),
):
    """Get scan history with pagination."""
    total = db.query(Scan).count()
    scans = db.query(Scan).order_by(
        Scan.started_at.desc()
    ).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return ScanHistoryResponse(
        scans=[ScanResponse.model_validate(s) for s in scans],
        total=total,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    """Get a specific scan's details."""
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/results")
def get_scan_results(scan_id: int, db: Session = Depends(get_db)):
    """Get all findings for a specific scan."""
    from app.models import Finding

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    return {
        "scan": ScanResponse.model_validate(scan),
        "findings": [
            {
                "id": f.id,
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "service": f.service,
                "title": f.title,
                "severity": f.severity,
                "risk_score": f.risk_score,
                "status": f.status,
                "is_remediable": f.is_remediable,
            }
            for f in findings
        ],
    }
