"""
CloudGuard Dashboard Router
Endpoints for dashboard summary data.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.models import Finding, Scan, FindingStatus, ScanStatus
from app.schemas import DashboardSummary, SeverityCounts, ServiceBreakdown
from app.ai_agent.risk_scorer import risk_scorer

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Get overall dashboard summary with risk score and severity counts."""

    # Count open findings by severity
    severity_counts = {}
    for severity in ["critical", "high", "medium", "low"]:
        count = db.query(Finding).filter(
            Finding.status == FindingStatus.OPEN.value,
            Finding.severity == severity,
        ).count()
        severity_counts[severity] = count

    total_findings = sum(severity_counts.values())
    remediated = db.query(Finding).filter(
        Finding.status == FindingStatus.REMEDIATED.value
    ).count()

    # Get all open finding risk scores for overall calculation
    open_scores = db.query(Finding.risk_score).filter(
        Finding.status == FindingStatus.OPEN.value
    ).all()
    score_list = [s[0] for s in open_scores if s[0] is not None]
    overall_risk = risk_scorer.calculate_overall_score(score_list)

    # Affected services
    services = db.query(Finding.service).filter(
        Finding.status == FindingStatus.OPEN.value
    ).distinct().all()
    affected_services = [s[0] for s in services]

    # Last scan
    last_scan = db.query(Scan).order_by(Scan.started_at.desc()).first()
    is_scanning = last_scan.status == ScanStatus.RUNNING.value if last_scan else False

    return DashboardSummary(
        overall_risk_score=overall_risk,
        total_findings=total_findings + remediated,
        open_findings=total_findings,
        remediated_findings=remediated,
        severity_counts=SeverityCounts(**severity_counts),
        services_affected=affected_services,
        last_scan_at=last_scan.completed_at if last_scan else None,
        is_scanning=is_scanning,
    )


@router.get("/services", response_model=list[ServiceBreakdown])
def get_service_breakdown(db: Session = Depends(get_db)):
    """Get findings breakdown by AWS service."""
    services = db.query(
        Finding.service,
        Finding.severity,
        func.count(Finding.id),
    ).filter(
        Finding.status == FindingStatus.OPEN.value
    ).group_by(
        Finding.service, Finding.severity
    ).all()

    # Aggregate by service
    service_map = {}
    for service, severity, count in services:
        if service not in service_map:
            service_map[service] = {"service": service, "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        service_map[service][severity] = count
        service_map[service]["total"] += count

    return [ServiceBreakdown(**data) for data in service_map.values()]


@router.get("/trend")
def get_risk_trend(db: Session = Depends(get_db)):
    """Get risk score trend over recent scans."""
    scans = db.query(Scan).filter(
        Scan.status == ScanStatus.COMPLETED.value
    ).order_by(Scan.started_at.desc()).limit(20).all()

    trend = []
    for scan in reversed(scans):
        # Get finding scores for this scan
        scores = db.query(Finding.risk_score).filter(
            Finding.scan_id == scan.id
        ).all()
        score_list = [s[0] for s in scores if s[0] is not None]
        overall = risk_scorer.calculate_overall_score(score_list)

        trend.append({
            "scan_id": scan.id,
            "date": scan.completed_at.isoformat() if scan.completed_at else scan.started_at.isoformat(),
            "risk_score": overall,
            "total_findings": scan.total_findings,
            "critical": scan.critical_count,
            "high": scan.high_count,
        })

    return trend
