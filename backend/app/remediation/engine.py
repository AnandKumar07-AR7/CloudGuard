"""
CloudGuard Remediation Engine
Orchestrates auto-remediation with safety checks, snapshots, and verification.
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.orm import Session
from app.models import Finding, RemediationLog, FindingStatus
from app.services.aws_service import aws_service
from app.remediation.s3_fixes import S3Fixes
from app.remediation.iam_fixes import IAMFixes
from app.remediation.sg_fixes import SGFixes


class RemediationEngine:
    """Orchestrates remediation actions with safety checks."""

    def __init__(self):
        self._s3_fixes: Optional[S3Fixes] = None
        self._iam_fixes: Optional[IAMFixes] = None
        self._sg_fixes: Optional[SGFixes] = None

    @property
    def s3_fixes(self) -> S3Fixes:
        if self._s3_fixes is None:
            self._s3_fixes = S3Fixes(aws_service.get_client("s3"))
        return self._s3_fixes

    @property
    def iam_fixes(self) -> IAMFixes:
        if self._iam_fixes is None:
            self._iam_fixes = IAMFixes(aws_service.get_client("iam"))
        return self._iam_fixes

    @property
    def sg_fixes(self) -> SGFixes:
        if self._sg_fixes is None:
            self._sg_fixes = SGFixes(aws_service.get_client("ec2"))
        return self._sg_fixes

    def get_preview(self, finding: Finding) -> dict:
        """
        Preview what a remediation action will do.
        
        Returns:
            Dict with action description, risk level, and expected changes
        """
        remediation_map = {
            "s3_enable_public_access_block": {
                "action": "Enable Block Public Access",
                "description": f"Will enable all 4 Block Public Access settings on S3 bucket '{finding.resource_id}'",
                "risk_level": "low",
                "reversible": True,
            },
            "s3_enable_encryption": {
                "action": "Enable Default Encryption (AES-256)",
                "description": f"Will enable AES-256 server-side encryption on S3 bucket '{finding.resource_id}'",
                "risk_level": "low",
                "reversible": True,
            },
            "s3_enable_versioning": {
                "action": "Enable Versioning",
                "description": f"Will enable object versioning on S3 bucket '{finding.resource_id}'",
                "risk_level": "low",
                "reversible": False,  # Versioning can only be suspended, not disabled
            },
            "s3_enable_logging": {
                "action": "Enable Access Logging",
                "description": f"Will enable server access logging on S3 bucket '{finding.resource_id}'",
                "risk_level": "low",
                "reversible": True,
            },
            "iam_deactivate_old_key": {
                "action": "Deactivate Access Key",
                "description": f"Will deactivate the old/unused access key for '{finding.resource_id}'",
                "risk_level": "medium",
                "reversible": True,
            },
            "sg_restrict_port": {
                "action": "Remove Internet Access Rule",
                "description": f"Will remove 0.0.0.0/0 ingress rule from security group '{finding.resource_id}'",
                "risk_level": "medium",
                "reversible": True,
            },
            "sg_remove_open_rule": {
                "action": "Remove All-Traffic Internet Rule",
                "description": f"Will remove the all-traffic 0.0.0.0/0 rule from security group '{finding.resource_id}'",
                "risk_level": "high",
                "reversible": True,
            },
            "sg_delete_unused": {
                "action": "Delete Unused Security Group",
                "description": f"Will delete the unused security group '{finding.resource_id}'",
                "risk_level": "low",
                "reversible": False,
            },
        }

        preview = remediation_map.get(finding.remediation_type, {
            "action": "Unknown Action",
            "description": "No automated remediation available for this finding.",
            "risk_level": "unknown",
            "reversible": False,
        })

        preview["finding_id"] = finding.id
        preview["current_state"] = finding.raw_config
        return preview

    def apply_fix(self, finding: Finding, db: Session) -> dict:
        """
        Apply the remediation fix for a finding.

        Args:
            finding: The Finding ORM object
            db: Database session

        Returns:
            Dict with success status, message, and state changes
        """
        if not finding.is_remediable:
            return {
                "success": False,
                "message": "This finding does not support auto-remediation.",
                "action": "none",
            }

        # Route to the appropriate fix method
        fix_map = {
            "s3_enable_public_access_block": lambda: self.s3_fixes.enable_public_access_block(finding.resource_id),
            "s3_enable_encryption": lambda: self.s3_fixes.enable_encryption(finding.resource_id),
            "s3_enable_versioning": lambda: self.s3_fixes.enable_versioning(finding.resource_id),
            "s3_enable_logging": lambda: self.s3_fixes.enable_logging(finding.resource_id),
            "iam_deactivate_old_key": lambda: self._fix_iam_key(finding),
            "iam_enable_user_mfa": lambda: self.iam_fixes.generate_mfa_instructions(finding.resource_id),
            "iam_enable_root_mfa": lambda: self.iam_fixes.generate_mfa_instructions("root"),
            "sg_restrict_port": lambda: self._fix_sg_port(finding),
            "sg_remove_open_rule": lambda: self.sg_fixes.remove_all_traffic_rule(finding.resource_id),
            "sg_delete_unused": lambda: self.sg_fixes.delete_unused_sg(finding.resource_id),
        }

        fix_func = fix_map.get(finding.remediation_type)
        if fix_func is None:
            return {
                "success": False,
                "message": f"No handler for remediation type: {finding.remediation_type}",
                "action": finding.remediation_type,
            }

        # Execute the fix
        success, message, before_state, after_state = fix_func()

        # Log the remediation
        log = RemediationLog(
            finding_id=finding.id,
            action=message,
            action_type=finding.remediation_type,
            before_state=before_state,
            after_state=after_state,
            success=success,
            error_message=None if success else message,
        )
        db.add(log)

        # Update finding status if successful
        if success:
            finding.status = FindingStatus.REMEDIATED.value
            finding.remediated_at = datetime.now(timezone.utc)

        db.commit()

        return {
            "success": success,
            "message": message,
            "action": finding.remediation_type,
            "before_state": before_state,
            "after_state": after_state,
            "performed_at": datetime.now(timezone.utc),
        }

    def _fix_iam_key(self, finding: Finding):
        """Extract username and key_id from resource_id (format: username/key_id)."""
        parts = finding.resource_id.split("/")
        if len(parts) == 2:
            return self.iam_fixes.deactivate_old_access_key(parts[0], parts[1])
        return False, "Invalid resource_id format for access key", {}, {}

    def _fix_sg_port(self, finding: Finding):
        """Extract port from raw_config and fix."""
        raw = finding.raw_config or {}
        port = raw.get("port", 0)
        if port:
            return self.sg_fixes.restrict_port(finding.resource_id, port)
        return False, "Could not determine port from finding", {}, {}


# Singleton instance
remediation_engine = RemediationEngine()
