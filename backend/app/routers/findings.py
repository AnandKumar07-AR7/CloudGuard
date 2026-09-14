"""
CloudGuard Findings Router
Endpoints for viewing and managing security findings.
"""

import json
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from app.database import get_db
from app.models import Finding, FindingStatus
from app.schemas import FindingResponse, FindingsListResponse, AIAnalysisRequest
from app.ai_agent.agent import ai_agent

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.get("", response_model=FindingsListResponse)
def list_findings(
    severity: str = Query(None, description="Filter by severity"),
    service: str = Query(None, description="Filter by AWS service"),
    status: str = Query(None, description="Filter by status"),
    search: str = Query(None, description="Search in title and description"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
):
    """List all findings with filtering, search, and pagination."""
    query = db.query(Finding)

    if severity:
        query = query.filter(Finding.severity == severity)
    if service:
        query = query.filter(Finding.service == service)
    if status:
        query = query.filter(Finding.status == status)
    if search:
        query = query.filter(
            or_(
                Finding.title.ilike(f"%{search}%"),
                Finding.description.ilike(f"%{search}%"),
                Finding.resource_id.ilike(f"%{search}%"),
            )
        )

    total = query.count()

    findings = query.order_by(
        Finding.risk_score.desc()
    ).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return FindingsListResponse(
        findings=[FindingResponse.model_validate(f) for f in findings],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    """Get detailed information about a specific finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding


@router.post("/{finding_id}/analyze")
async def analyze_finding(
    finding_id: int,
    request: AIAnalysisRequest = AIAnalysisRequest(),
    db: Session = Depends(get_db),
):
    """Trigger AI analysis (or deep analysis) on a specific finding."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding_dict = {
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "service": finding.service,
        "resource_id": finding.resource_id,
        "resource_type": finding.resource_type,
        "check_id": finding.check_id,
        "region": finding.region,
        "raw_config": finding.raw_config or {},
    }

    if request.provider == "claude":
        # Deep analysis with Claude
        result = await ai_agent.deep_analyze_finding(finding_dict)
    else:
        # Standard analysis with Gemini
        result = await ai_agent.analyze_finding(finding_dict, provider=request.provider)

    # Update finding with new AI analysis
    finding.risk_score = result.get("risk_score", finding.risk_score)
    finding.ai_analysis = result.get("explanation", finding.ai_analysis)
    finding.ai_impact = result.get("impact", finding.ai_impact)
    finding.ai_remediation = json.dumps(result.get("remediation_steps", []))

    db.commit()

    return result


@router.patch("/{finding_id}/status")
def update_finding_status(
    finding_id: int,
    new_status: str = Query(..., pattern="^(open|ignored)$"),
    db: Session = Depends(get_db),
):
    """Update a finding's status (e.g., mark as ignored)."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = new_status
    db.commit()

    return {"message": f"Finding status updated to '{new_status}'", "finding_id": finding_id}


@router.get("/services/list")
def list_affected_services(db: Session = Depends(get_db)):
    """Get list of all AWS services with findings."""
    services = db.query(Finding.service).distinct().all()
    return [s[0] for s in services]
