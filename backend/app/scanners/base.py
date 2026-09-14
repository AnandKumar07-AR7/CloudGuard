"""
CloudGuard Base Scanner
Abstract base class that all service-specific scanners inherit from.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Any
from datetime import datetime, timezone


@dataclass
class ScanFinding:
    """
    Represents a single security finding detected by a scanner.
    This is the scanner's output format before it gets saved to the database.
    """
    # Resource identification
    resource_id: str
    resource_arn: str = ""
    resource_type: str = ""
    service: str = ""
    region: str = "global"

    # Finding details
    title: str = ""
    description: str = ""
    severity: str = "medium"  # critical, high, medium, low
    check_id: str = ""

    # Raw AWS configuration data (for AI analysis context)
    raw_config: dict = field(default_factory=dict)

    # Remediation metadata
    is_remediable: bool = False
    remediation_type: str = ""  # e.g., "s3_block_public_access"

    # Base risk score (before AI adjustment)
    base_risk_score: float = 0.0

    def __post_init__(self):
        """Set the base risk score from severity if not explicitly set."""
        if self.base_risk_score == 0.0:
            severity_scores = {
                "critical": 90.0,
                "high": 70.0,
                "medium": 40.0,
                "low": 15.0,
            }
            self.base_risk_score = severity_scores.get(self.severity.lower(), 40.0)


class BaseScanner(ABC):
    """
    Abstract base class for all AWS service scanners.
    
    Each scanner implements the `scan()` method to check for
    misconfigurations in a specific AWS service and returns
    a list of ScanFinding objects.
    """

    def __init__(self, aws_client):
        """
        Args:
            aws_client: Boto3 client for the specific AWS service
        """
        self.client = aws_client
        self.findings: List[ScanFinding] = []

    @property
    @abstractmethod
    def service_name(self) -> str:
        """Return the AWS service name (e.g., 's3', 'iam', 'ec2')."""
        pass

    @property
    @abstractmethod
    def display_name(self) -> str:
        """Return a human-readable service name (e.g., 'Amazon S3', 'IAM')."""
        pass

    @abstractmethod
    def scan(self) -> List[ScanFinding]:
        """
        Execute the scan and return a list of findings.
        
        Returns:
            List of ScanFinding objects representing detected misconfigurations.
        """
        pass

    def _add_finding(self, **kwargs) -> ScanFinding:
        """Helper to create and track a finding."""
        finding = ScanFinding(service=self.service_name, **kwargs)
        self.findings.append(finding)
        return finding

    def _safe_api_call(self, func, *args, default=None, **kwargs) -> Any:
        """
        Safely call a Boto3 API method with error handling.
        
        Returns the result on success, or the default value on error.
        Handles common AWS exceptions like AccessDenied, Throttling, etc.
        """
        from botocore.exceptions import ClientError, BotoCoreError
        try:
            return func(*args, **kwargs)
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code in ("AccessDenied", "UnauthorizedAccess"):
                print(f"[{self.service_name}] Access denied: {e.response['Error']['Message']}")
            elif error_code == "Throttling":
                print(f"[{self.service_name}] API throttled, skipping check")
            else:
                print(f"[{self.service_name}] AWS error: {error_code} - {e.response['Error']['Message']}")
            return default
        except BotoCoreError as e:
            print(f"[{self.service_name}] BotoCore error: {str(e)}")
            return default
        except Exception as e:
            print(f"[{self.service_name}] Unexpected error: {str(e)}")
            return default

    def reset(self):
        """Reset findings for a new scan."""
        self.findings = []
