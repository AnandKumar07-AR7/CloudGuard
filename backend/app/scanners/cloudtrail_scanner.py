"""
CloudGuard CloudTrail Scanner
Checks CloudTrail configuration for logging and monitoring gaps.
"""

from typing import List
from app.scanners.base import BaseScanner, ScanFinding


class CloudTrailScanner(BaseScanner):
    """Scans CloudTrail for proper logging configuration."""

    @property
    def service_name(self) -> str:
        return "cloudtrail"

    @property
    def display_name(self) -> str:
        return "AWS CloudTrail"

    def scan(self) -> List[ScanFinding]:
        """Scan CloudTrail configuration."""
        self.reset()

        result = self._safe_api_call(
            self.client.describe_trails,
            default=None,
        )

        if result is None:
            return self.findings

        trails = result.get("trailList", [])

        if not trails:
            self._add_finding(
                resource_id="cloudtrail",
                resource_arn="arn:aws:cloudtrail:::trail",
                resource_type="CloudTrail",
                title="No CloudTrail trails are configured",
                description=(
                    "No CloudTrail trails are configured in this account. CloudTrail records "
                    "all API calls made in your AWS account. Without it, you have no audit "
                    "trail of who did what, making security incident investigation impossible."
                ),
                severity="critical",
                check_id="cloudtrail_no_trails",
                raw_config={"trails": []},
                is_remediable=False,
                remediation_type="cloudtrail_create_trail",
                base_risk_score=92.0,
            )
            return self.findings

        for trail in trails:
            trail_name = trail.get("Name", "unnamed")
            trail_arn = trail.get("TrailARN", "")

            self._check_multi_region(trail, trail_name, trail_arn)
            self._check_log_validation(trail, trail_name, trail_arn)
            self._check_logging_status(trail, trail_name, trail_arn)
            self._check_s3_bucket_logging(trail, trail_name, trail_arn)

        return self.findings

    def _check_multi_region(self, trail: dict, trail_name: str, trail_arn: str):
        """Check if trail is multi-region."""
        if not trail.get("IsMultiRegionTrail", False):
            self._add_finding(
                resource_id=trail_name,
                resource_arn=trail_arn,
                resource_type="CloudTrail Trail",
                title=f"CloudTrail '{trail_name}' is not configured for multi-region logging",
                description=(
                    f"The CloudTrail trail '{trail_name}' is only logging API activity in a "
                    "single region. An attacker could operate in a non-monitored region to "
                    "avoid detection. Multi-region logging ensures all activity is captured."
                ),
                severity="high",
                check_id="cloudtrail_not_multi_region",
                raw_config={
                    "trail_name": trail_name,
                    "is_multi_region": False,
                    "home_region": trail.get("HomeRegion", "unknown"),
                },
                is_remediable=True,
                remediation_type="cloudtrail_enable_multi_region",
            )

    def _check_log_validation(self, trail: dict, trail_name: str, trail_arn: str):
        """Check if log file validation is enabled."""
        if not trail.get("LogFileValidationEnabled", False):
            self._add_finding(
                resource_id=trail_name,
                resource_arn=trail_arn,
                resource_type="CloudTrail Trail",
                title=f"CloudTrail '{trail_name}' does not have log file validation enabled",
                description=(
                    f"The CloudTrail trail '{trail_name}' does not have log file validation "
                    "enabled. Without validation, you cannot verify that log files have not "
                    "been tampered with. An attacker could modify or delete logs to cover "
                    "their tracks."
                ),
                severity="medium",
                check_id="cloudtrail_no_log_validation",
                raw_config={
                    "trail_name": trail_name,
                    "log_file_validation": False,
                },
                is_remediable=True,
                remediation_type="cloudtrail_enable_log_validation",
            )

    def _check_logging_status(self, trail: dict, trail_name: str, trail_arn: str):
        """Check if the trail is actively logging."""
        status = self._safe_api_call(
            self.client.get_trail_status,
            Name=trail_name,
            default=None,
        )

        if status and not status.get("IsLogging", False):
            self._add_finding(
                resource_id=trail_name,
                resource_arn=trail_arn,
                resource_type="CloudTrail Trail",
                title=f"CloudTrail '{trail_name}' is not actively logging",
                description=(
                    f"The CloudTrail trail '{trail_name}' exists but is not currently logging. "
                    "This means API activity is NOT being recorded. This could be due to the "
                    "trail being manually stopped or a configuration issue."
                ),
                severity="critical",
                check_id="cloudtrail_logging_stopped",
                raw_config={
                    "trail_name": trail_name,
                    "is_logging": False,
                },
                is_remediable=True,
                remediation_type="cloudtrail_start_logging",
            )

    def _check_s3_bucket_logging(self, trail: dict, trail_name: str, trail_arn: str):
        """Check if the S3 bucket used for log storage has proper configuration."""
        s3_bucket = trail.get("S3BucketName")

        if not s3_bucket:
            self._add_finding(
                resource_id=trail_name,
                resource_arn=trail_arn,
                resource_type="CloudTrail Trail",
                title=f"CloudTrail '{trail_name}' has no S3 bucket configured for log storage",
                description=(
                    f"The CloudTrail trail '{trail_name}' does not have an S3 bucket configured "
                    "for log storage. Without a log destination, CloudTrail events are not being "
                    "persisted and cannot be analyzed later."
                ),
                severity="critical",
                check_id="cloudtrail_no_s3_bucket",
                raw_config={"trail_name": trail_name, "s3_bucket": None},
                is_remediable=False,
                remediation_type="cloudtrail_configure_s3",
            )
