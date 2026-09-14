"""
CloudGuard S3 Fixes
Auto-remediation actions for S3 misconfigurations.
"""

from typing import Tuple


class S3Fixes:
    """S3 remediation actions."""

    def __init__(self, s3_client):
        self.client = s3_client

    def enable_public_access_block(self, bucket_name: str) -> Tuple[bool, str, dict, dict]:
        """
        Enable all Block Public Access settings on a bucket.
        
        Returns:
            (success, message, before_state, after_state)
        """
        try:
            # Capture before state
            try:
                before = self.client.get_public_access_block(Bucket=bucket_name)
                before_state = before.get("PublicAccessBlockConfiguration", {})
            except Exception:
                before_state = {"status": "not_configured"}

            # Apply fix
            self.client.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )

            # Verify
            after = self.client.get_public_access_block(Bucket=bucket_name)
            after_state = after.get("PublicAccessBlockConfiguration", {})

            return True, f"Successfully enabled Block Public Access on '{bucket_name}'", before_state, after_state

        except Exception as e:
            return False, f"Failed to enable Block Public Access: {str(e)}", {}, {}

    def enable_encryption(self, bucket_name: str) -> Tuple[bool, str, dict, dict]:
        """Enable default AES-256 server-side encryption."""
        try:
            before_state = {"encryption": "not_configured"}

            self.client.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            },
                            "BucketKeyEnabled": True,
                        }
                    ]
                },
            )

            after_state = {"encryption": "AES256", "bucket_key_enabled": True}
            return True, f"Successfully enabled AES-256 encryption on '{bucket_name}'", before_state, after_state

        except Exception as e:
            return False, f"Failed to enable encryption: {str(e)}", {}, {}

    def enable_versioning(self, bucket_name: str) -> Tuple[bool, str, dict, dict]:
        """Enable bucket versioning."""
        try:
            before = self.client.get_bucket_versioning(Bucket=bucket_name)
            before_state = {"versioning": before.get("Status", "Disabled")}

            self.client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={"Status": "Enabled"},
            )

            after_state = {"versioning": "Enabled"}
            return True, f"Successfully enabled versioning on '{bucket_name}'", before_state, after_state

        except Exception as e:
            return False, f"Failed to enable versioning: {str(e)}", {}, {}

    def enable_logging(self, bucket_name: str, target_bucket: str = None) -> Tuple[bool, str, dict, dict]:
        """Enable server access logging."""
        try:
            if target_bucket is None:
                target_bucket = bucket_name  # Log to self (not ideal, but works for demo)

            before_state = {"logging": "disabled"}

            self.client.put_bucket_logging(
                Bucket=bucket_name,
                BucketLoggingStatus={
                    "LoggingEnabled": {
                        "TargetBucket": target_bucket,
                        "TargetPrefix": f"access-logs/{bucket_name}/",
                    }
                },
            )

            after_state = {
                "logging": "enabled",
                "target_bucket": target_bucket,
                "target_prefix": f"access-logs/{bucket_name}/",
            }
            return True, f"Successfully enabled logging on '{bucket_name}'", before_state, after_state

        except Exception as e:
            return False, f"Failed to enable logging: {str(e)}", {}, {}
