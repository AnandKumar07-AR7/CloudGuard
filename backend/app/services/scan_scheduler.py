"""
CloudGuard Scan Scheduler
Background job scheduler for periodic security scanning.
"""

import json
import asyncio
from datetime import datetime, timezone
from typing import List, Optional, Callable
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import Scan, Finding, ScanStatus
from app.services.aws_service import aws_service
from app.scanners.s3_scanner import S3Scanner
from app.scanners.iam_scanner import IAMScanner
from app.scanners.sg_scanner import SGScanner
from app.scanners.rds_scanner import RDSScanner
from app.scanners.cloudtrail_scanner import CloudTrailScanner
from app.scanners.ebs_scanner import EBSScanner
from app.scanners.vpc_scanner import VPCScanner
from app.scanners.base import ScanFinding
from app.ai_agent.agent import ai_agent
from app.ai_agent.risk_scorer import risk_scorer


# WebSocket broadcast callback (set by main.py)
ws_broadcast: Optional[Callable] = None


def set_ws_broadcast(callback: Callable):
    """Set the WebSocket broadcast callback."""
    global ws_broadcast
    ws_broadcast = callback


async def _broadcast(msg_type: str, data: dict):
    """Broadcast a message to all connected WebSocket clients."""
    if ws_broadcast:
        await ws_broadcast(json.dumps({"type": msg_type, "data": data}))


async def run_scan(scan_type: str = "full", db: Session = None) -> dict:
    """
    Execute a security scan across all or specific AWS services.

    Args:
        scan_type: "full" or a specific service name (s3, iam, ec2, etc.)
        db: Database session (creates one if not provided)

    Returns:
        Dict with scan results summary
    """
    own_db = db is None
    if own_db:
        db = SessionLocal()

    try:
        # Create scan record
        scan = Scan(
            status=ScanStatus.RUNNING.value,
            scan_type=scan_type,
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        await _broadcast("scan_started", {
            "scan_id": scan.id,
            "scan_type": scan_type,
            "started_at": scan.started_at.isoformat(),
        })

        all_findings: List[ScanFinding] = []
        scanner_configs = _get_scanners(scan_type)

        for i, (scanner_name, scanner_class, client_name) in enumerate(scanner_configs):
            try:
                await _broadcast("scan_progress", {
                    "scan_id": scan.id,
                    "current_scanner": scanner_name,
                    "progress": int((i / len(scanner_configs)) * 100),
                })

                # Create scanner with appropriate client
                if client_name == "ec2":
                    client = aws_service.get_client("ec2")
                else:
                    client = aws_service.get_client(client_name)

                scanner = scanner_class(client)
                findings = scanner.scan()
                all_findings.extend(findings)

                # Broadcast each finding in real-time
                for finding in findings:
                    await _broadcast("finding_detected", {
                        "scan_id": scan.id,
                        "title": finding.title,
                        "severity": finding.severity,
                        "service": finding.service,
                        "resource_id": finding.resource_id,
                    })

            except Exception as e:
                print(f"[ScanScheduler] Error in {scanner_name}: {str(e)}")
                continue

        # Run batch AI analysis
        findings_dicts = [
            {
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
                "service": f.service,
                "resource_id": f.resource_id,
                "resource_type": f.resource_type,
                "check_id": f.check_id,
                "region": f.region,
                "raw_config": f.raw_config,
            }
            for f in all_findings
        ]

        ai_results = await ai_agent.batch_analyze(findings_dicts)

        # Save findings to database
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        for scan_finding, ai_result in zip(all_findings, ai_results):
            # Check if this finding already exists (from a previous scan)
            existing = db.query(Finding).filter(
                Finding.check_id == scan_finding.check_id,
                Finding.resource_id == scan_finding.resource_id,
                Finding.status != "remediated",
            ).first()

            if existing:
                # Update existing finding
                existing.scan_id = scan.id
                existing.last_seen = datetime.now(timezone.utc)
                existing.risk_score = ai_result.get("risk_score", scan_finding.base_risk_score)
                existing.ai_analysis = ai_result.get("explanation", "")
                existing.ai_impact = ai_result.get("impact", "")
                existing.ai_remediation = json.dumps(ai_result.get("remediation_steps", []))
            else:
                # Create new finding
                db_finding = Finding(
                    scan_id=scan.id,
                    resource_id=scan_finding.resource_id,
                    resource_arn=scan_finding.resource_arn,
                    resource_type=scan_finding.resource_type,
                    service=scan_finding.service,
                    region=scan_finding.region,
                    title=scan_finding.title,
                    description=scan_finding.description,
                    severity=scan_finding.severity,
                    check_id=scan_finding.check_id,
                    risk_score=ai_result.get("risk_score", scan_finding.base_risk_score),
                    ai_analysis=ai_result.get("explanation", ""),
                    ai_impact=ai_result.get("impact", ""),
                    ai_remediation=json.dumps(ai_result.get("remediation_steps", [])),
                    raw_config=scan_finding.raw_config,
                    is_remediable=scan_finding.is_remediable,
                    remediation_type=scan_finding.remediation_type,
                )
                db.add(db_finding)

            severity_counts[scan_finding.severity] = severity_counts.get(scan_finding.severity, 0) + 1

        # Update scan record
        scan.status = ScanStatus.COMPLETED.value
        scan.completed_at = datetime.now(timezone.utc)
        scan.total_findings = len(all_findings)
        scan.critical_count = severity_counts.get("critical", 0)
        scan.high_count = severity_counts.get("high", 0)
        scan.medium_count = severity_counts.get("medium", 0)
        scan.low_count = severity_counts.get("low", 0)

        db.commit()

        result = {
            "scan_id": scan.id,
            "status": "completed",
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "completed_at": scan.completed_at.isoformat(),
        }

        await _broadcast("scan_completed", result)
        return result

    except Exception as e:
        if scan:
            scan.status = ScanStatus.FAILED.value
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()

        await _broadcast("scan_failed", {"scan_id": scan.id if scan else None, "error": str(e)})
        raise

    finally:
        if own_db:
            db.close()


def _get_scanners(scan_type: str) -> list:
    """Get the list of scanners to run based on scan type."""
    all_scanners = [
        ("S3", S3Scanner, "s3"),
        ("IAM", IAMScanner, "iam"),
        ("Security Groups", SGScanner, "ec2"),
        ("RDS", RDSScanner, "rds"),
        ("CloudTrail", CloudTrailScanner, "cloudtrail"),
        ("EBS", EBSScanner, "ec2"),
        ("VPC", VPCScanner, "ec2"),
    ]

    if scan_type == "full":
        return all_scanners

    scanner_map = {
        "s3": [all_scanners[0]],
        "iam": [all_scanners[1]],
        "ec2": [all_scanners[2]],
        "rds": [all_scanners[3]],
        "cloudtrail": [all_scanners[4]],
        "ebs": [all_scanners[5]],
        "vpc": [all_scanners[6]],
    }

    return scanner_map.get(scan_type, all_scanners)
