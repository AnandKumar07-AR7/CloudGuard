"""
CloudGuard Database Models
SQLAlchemy ORM models for scans, findings, and remediation logs.
"""

from sqlalchemy import (
    Column, Integer, String, Text, Float, DateTime, Boolean,
    ForeignKey, Enum as SQLEnum, JSON
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum

from app.database import Base


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    REMEDIATED = "remediated"
    IGNORED = "ignored"


class Scan(Base):
    """Represents a single scan execution."""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, autoincrement=True)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default=ScanStatus.PENDING.value)
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    scan_type = Column(String(20), default="full")  # full, quick, service-specific
    error_message = Column(Text, nullable=True)

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Scan(id={self.id}, status={self.status}, findings={self.total_findings})>"


class Finding(Base):
    """Represents a single security finding/misconfiguration."""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    
    # Resource identification
    resource_id = Column(String(500), nullable=False)
    resource_arn = Column(String(1000), nullable=True)
    resource_type = Column(String(100), nullable=False)  # e.g., "S3 Bucket", "IAM User"
    service = Column(String(50), nullable=False)  # e.g., "s3", "iam", "ec2"
    region = Column(String(50), default="global")
    
    # Finding details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)
    check_id = Column(String(100), nullable=False)  # Unique identifier for the check type
    
    # AI Analysis
    risk_score = Column(Float, default=0.0)  # 0-100
    ai_analysis = Column(Text, nullable=True)  # AI-generated explanation
    ai_impact = Column(Text, nullable=True)  # AI-generated impact analysis
    ai_remediation = Column(Text, nullable=True)  # AI-generated fix steps
    
    # Raw data
    raw_config = Column(JSON, nullable=True)  # Raw AWS config for context
    
    # Status tracking
    status = Column(String(20), default=FindingStatus.OPEN.value)
    first_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    remediated_at = Column(DateTime, nullable=True)
    
    # Auto-remediation
    is_remediable = Column(Boolean, default=False)
    remediation_type = Column(String(100), nullable=True)  # Type of fix available

    # Relationships
    scan = relationship("Scan", back_populates="findings")
    remediation_logs = relationship("RemediationLog", back_populates="finding", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Finding(id={self.id}, title={self.title}, severity={self.severity})>"


class RemediationLog(Base):
    """Logs every remediation action taken."""
    __tablename__ = "remediation_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False)
    
    action = Column(String(200), nullable=False)  # Description of what was done
    action_type = Column(String(100), nullable=False)  # e.g., "s3_block_public_access"
    
    before_state = Column(JSON, nullable=True)  # Config snapshot before fix
    after_state = Column(JSON, nullable=True)  # Config snapshot after fix
    
    success = Column(Boolean, default=False)
    error_message = Column(Text, nullable=True)
    
    performed_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    performed_by = Column(String(100), default="cloudguard_agent")

    # Relationships
    finding = relationship("Finding", back_populates="remediation_logs")

    def __repr__(self):
        return f"<RemediationLog(id={self.id}, action={self.action}, success={self.success})>"
