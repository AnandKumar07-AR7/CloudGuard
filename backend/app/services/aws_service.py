"""
CloudGuard AWS Service
Manages Boto3 sessions and client creation with proper error handling.
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
from typing import Optional
from app.config import settings


class AWSService:
    """Manages AWS Boto3 sessions and provides client factory methods."""

    def __init__(self):
        self._session: Optional[boto3.Session] = None
        self._account_id: Optional[str] = None

    def _create_session(self) -> boto3.Session:
        """Create a new Boto3 session with configured credentials."""
        if settings.aws_access_key_id and settings.aws_secret_access_key:
            return boto3.Session(
                aws_access_key_id=settings.aws_access_key_id,
                aws_secret_access_key=settings.aws_secret_access_key,
                region_name=settings.aws_default_region,
            )
        # Fall back to default credential chain (env vars, ~/.aws/credentials, IAM role)
        return boto3.Session(region_name=settings.aws_default_region)

    @property
    def session(self) -> boto3.Session:
        """Get or create the Boto3 session."""
        if self._session is None:
            self._session = self._create_session()
        return self._session

    def reset_session(self):
        """Reset the session (e.g., after credential changes)."""
        self._session = None
        self._account_id = None

    def get_client(self, service_name: str, region: Optional[str] = None):
        """
        Get a Boto3 client for the specified AWS service.
        
        Args:
            service_name: AWS service name (e.g., 's3', 'iam', 'ec2')
            region: Optional region override
        """
        kwargs = {}
        if region:
            kwargs["region_name"] = region
        return self.session.client(service_name, **kwargs)

    def get_resource(self, service_name: str, region: Optional[str] = None):
        """Get a Boto3 resource for the specified AWS service."""
        kwargs = {}
        if region:
            kwargs["region_name"] = region
        return self.session.resource(service_name, **kwargs)

    def test_connection(self) -> dict:
        """
        Test AWS connectivity and return account information.
        
        Returns:
            dict with connected status, account_id, and message
        """
        try:
            sts = self.get_client("sts")
            identity = sts.get_caller_identity()
            self._account_id = identity["Account"]

            # Try to get account alias
            iam = self.get_client("iam")
            aliases = iam.list_account_aliases().get("AccountAliases", [])
            alias = aliases[0] if aliases else None

            return {
                "connected": True,
                "account_id": self._account_id,
                "account_alias": alias,
                "region": settings.aws_default_region,
                "message": f"Successfully connected to AWS account {self._account_id}",
            }
        except NoCredentialsError:
            return {
                "connected": False,
                "account_id": None,
                "account_alias": None,
                "region": settings.aws_default_region,
                "message": "No AWS credentials configured. Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.",
            }
        except ClientError as e:
            return {
                "connected": False,
                "account_id": None,
                "account_alias": None,
                "region": settings.aws_default_region,
                "message": f"AWS connection failed: {e.response['Error']['Message']}",
            }
        except BotoCoreError as e:
            return {
                "connected": False,
                "account_id": None,
                "account_alias": None,
                "region": settings.aws_default_region,
                "message": f"AWS connection error: {str(e)}",
            }

    @property
    def account_id(self) -> Optional[str]:
        """Get the AWS account ID."""
        if self._account_id is None:
            result = self.test_connection()
            if result["connected"]:
                self._account_id = result["account_id"]
        return self._account_id

    def get_all_regions(self) -> list[str]:
        """Get all available AWS regions."""
        try:
            ec2 = self.get_client("ec2")
            regions = ec2.describe_regions()["Regions"]
            return [r["RegionName"] for r in regions]
        except Exception:
            # Fallback to common regions
            return [
                "us-east-1", "us-east-2", "us-west-1", "us-west-2",
                "eu-west-1", "eu-central-1", "ap-south-1", "ap-southeast-1",
            ]


# Singleton instance
aws_service = AWSService()
