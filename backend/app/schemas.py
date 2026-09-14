"""
CloudGuard Pydantic Schemas
Request/response models for API validation and serialization.
"""

from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime


# ============================================
# Dashboard Schemas
# ============================================

class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class DashboardSummary(BaseModel):
    overall_risk_score: float = Field(0.0, ge=0, le=100)
    total_findings: int = 0
    open_findings: int = 0
    remediated_findings: int = 0
    severity_counts: SeverityCounts = SeverityCounts()
    services_affected: List[str] = []
    last_scan_at: Optional[datetime] = None
    is_scanning: bool = False


class ServiceBreakdown(BaseModel):
    service: str
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


# ============================================
# Scan Schemas
# ============================================

class ScanTriggerRequest(BaseModel):
    scan_type: str = Field("full", pattern="^(full|quick|s3|iam|ec2|rds|cloudtrail|ebs|vpc)$")


class ScanResponse(BaseModel):
    id: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    scan_type: str = "full"
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class ScanHistoryResponse(BaseModel):
    scans: List[ScanResponse]
    total: int


# ============================================
# Finding Schemas
# ============================================

class FindingResponse(BaseModel):
    id: int
    scan_id: int
    resource_id: str
    resource_arn: Optional[str] = None
    resource_type: str
    service: str
    region: str = "global"
    title: str
    description: str
    severity: str
    check_id: str
    risk_score: float = 0.0
    ai_analysis: Optional[str] = None
    ai_impact: Optional[str] = None
    ai_remediation: Optional[str] = None
    raw_config: Optional[dict] = None
    status: str = "open"
    first_seen: datetime
    last_seen: datetime
    remediated_at: Optional[datetime] = None
    is_remediable: bool = False
    remediation_type: Optional[str] = None

    class Config:
        from_attributes = True


class FindingsListResponse(BaseModel):
    findings: List[FindingResponse]
    total: int
    page: int = 1
    page_size: int = 50


class FindingFilterParams(BaseModel):
    severity: Optional[str] = None
    service: Optional[str] = None
    status: Optional[str] = None
    search: Optional[str] = None
    page: int = 1
    page_size: int = 50


# ============================================
# AI Analysis Schemas
# ============================================

class AIAnalysisRequest(BaseModel):
    provider: str = Field("gemini", pattern="^(gemini|claude)$")


class AIAnalysisResponse(BaseModel):
    risk_score: float = Field(0.0, ge=0, le=100)
    explanation: str
    impact: str
    remediation_steps: List[str]
    severity_justification: str


# ============================================
# Remediation Schemas
# ============================================

class RemediationPreview(BaseModel):
    finding_id: int
    action: str
    description: str
    current_state: Optional[dict] = None
    expected_state: Optional[dict] = None
    risk_level: str = "low"  # Risk of the remediation itself
    reversible: bool = True


class RemediationRequest(BaseModel):
    confirm: bool = True


class RemediationResponse(BaseModel):
    success: bool
    message: str
    action: str
    before_state: Optional[dict] = None
    after_state: Optional[dict] = None
    performed_at: datetime


class RemediationLogResponse(BaseModel):
    id: int
    finding_id: int
    action: str
    action_type: str
    success: bool
    error_message: Optional[str] = None
    performed_at: datetime
    before_state: Optional[dict] = None
    after_state: Optional[dict] = None

    class Config:
        from_attributes = True


# ============================================
# Settings Schemas
# ============================================

class AWSConfigRequest(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_default_region: str = "us-east-1"


class AWSConnectionTest(BaseModel):
    connected: bool
    account_id: Optional[str] = None
    account_alias: Optional[str] = None
    region: str
    message: str


class APIKeyConfigRequest(BaseModel):
    gemini_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None


class SettingsResponse(BaseModel):
    aws_configured: bool
    aws_region: str
    gemini_configured: bool
    claude_configured: bool
    scan_interval_minutes: int


# ============================================
# WebSocket Schemas
# ============================================

class WSMessage(BaseModel):
    type: str  # "scan_started", "scan_progress", "finding_detected", "scan_completed"
    data: dict
