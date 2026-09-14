"""
CloudGuard S3 Scanner
Checks Amazon S3 buckets for security misconfigurations.
"""

from typing import List
from app.scanners.base import BaseScanner, ScanFinding


class S3Scanner(BaseScanner):
    """Scans S3 buckets for common security misconfigurations."""

    @property
    def service_name(self) -> str:
        return "s3"

    @property
    def display_name(self) -> str:
        return "Amazon S3"

    def scan(self) -> List[ScanFinding]:
        """Scan all S3 buckets for misconfigurations."""
        self.reset()

        # List all buckets
        response = self._safe_api_call(self.client.list_buckets, default={})
        buckets = response.get("Buckets", [])

        for bucket in buckets:
            bucket_name = bucket["Name"]
            self._check_public_access_block(bucket_name)
            self._check_bucket_policy(bucket_name)
            self._check_bucket_acl(bucket_name)
            self._check_encryption(bucket_name)
            self._check_versioning(bucket_name)
            self._check_logging(bucket_name)

        return self.findings

    def _check_public_access_block(self, bucket_name: str):
        """Check if Block Public Access is enabled."""
        result = self._safe_api_call(
            self.client.get_public_access_block,
            Bucket=bucket_name,
            default=None,
        )

        if result is None:
            # No public access block configured at all
            self._add_finding(
                resource_id=bucket_name,
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                resource_type="S3 Bucket",
                title=f"S3 Bucket '{bucket_name}' has no Public Access Block configured",
                description=(
                    f"The S3 bucket '{bucket_name}' does not have Block Public Access settings "
                    "configured. Without these settings, the bucket may be publicly accessible "
                    "through bucket policies or ACLs. This is a critical security risk as it "
                    "could expose sensitive data to the internet."
                ),
                severity="critical",
                check_id="s3_public_access_block_missing",
                raw_config={"bucket": bucket_name, "public_access_block": None},
                is_remediable=True,
                remediation_type="s3_enable_public_access_block",
            )
            return

        config = result.get("PublicAccessBlockConfiguration", {})
        all_blocked = all([
            config.get("BlockPublicAcls", False),
            config.get("IgnorePublicAcls", False),
            config.get("BlockPublicPolicy", False),
            config.get("RestrictPublicBuckets", False),
        ])

        if not all_blocked:
            disabled_settings = [
                key for key in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
                if not config.get(key, False)
            ]
            self._add_finding(
                resource_id=bucket_name,
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                resource_type="S3 Bucket",
                title=f"S3 Bucket '{bucket_name}' has incomplete Public Access Block",
                description=(
                    f"The S3 bucket '{bucket_name}' has Public Access Block configured but "
                    f"the following settings are disabled: {', '.join(disabled_settings)}. "
                    "All four settings should be enabled to fully prevent public access."
                ),
                severity="high",
                check_id="s3_public_access_block_incomplete",
                raw_config={"bucket": bucket_name, "public_access_block": config},
                is_remediable=True,
                remediation_type="s3_enable_public_access_block",
            )

    def _check_bucket_policy(self, bucket_name: str):
        """Check if bucket policy allows public access (Principal: *)."""
        import json

        result = self._safe_api_call(
            self.client.get_bucket_policy,
            Bucket=bucket_name,
            default=None,
        )

        if result is None:
            return  # No bucket policy — not a finding by itself

        try:
            policy = json.loads(result["Policy"])
        except (json.JSONDecodeError, KeyError):
            return

        for statement in policy.get("Statement", []):
            principal = statement.get("Principal", "")
            effect = statement.get("Effect", "")

            is_public = (
                principal == "*" or
                principal == {"AWS": "*"} or
                (isinstance(principal, dict) and "*" in principal.get("AWS", []))
            )

            if is_public and effect == "Allow":
                actions = statement.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]

                self._add_finding(
                    resource_id=bucket_name,
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    resource_type="S3 Bucket",
                    title=f"S3 Bucket '{bucket_name}' has a public bucket policy",
                    description=(
                        f"The S3 bucket '{bucket_name}' has a bucket policy that grants access "
                        f"to 'Principal: *' (everyone). Allowed actions: {', '.join(actions)}. "
                        "This means anyone on the internet can perform these actions on the bucket."
                    ),
                    severity="critical",
                    check_id="s3_public_bucket_policy",
                    raw_config={
                        "bucket": bucket_name,
                        "policy_statement": statement,
                    },
                    is_remediable=False,  # Risky to auto-remove policies
                    remediation_type="s3_restrict_bucket_policy",
                )
                break  # One finding per bucket is enough

    def _check_bucket_acl(self, bucket_name: str):
        """Check if bucket ACLs grant public access."""
        result = self._safe_api_call(
            self.client.get_bucket_acl,
            Bucket=bucket_name,
            default=None,
        )

        if result is None:
            return

        public_uris = [
            "http://acs.amazonaws.com/groups/global/AllUsers",
            "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
        ]

        for grant in result.get("Grants", []):
            grantee = grant.get("Grantee", {})
            grantee_uri = grantee.get("URI", "")

            if grantee_uri in public_uris:
                permission = grant.get("Permission", "UNKNOWN")
                grantee_type = "Everyone" if "AllUsers" in grantee_uri else "All AWS Users"

                self._add_finding(
                    resource_id=bucket_name,
                    resource_arn=f"arn:aws:s3:::{bucket_name}",
                    resource_type="S3 Bucket",
                    title=f"S3 Bucket '{bucket_name}' ACL grants '{permission}' to {grantee_type}",
                    description=(
                        f"The S3 bucket '{bucket_name}' has an ACL (Access Control List) that "
                        f"grants '{permission}' permission to '{grantee_type}'. "
                        "Legacy ACLs are not recommended — use IAM policies instead."
                    ),
                    severity="critical",
                    check_id="s3_public_acl",
                    raw_config={
                        "bucket": bucket_name,
                        "grant": grant,
                    },
                    is_remediable=False,
                    remediation_type="s3_restrict_acl",
                )

    def _check_encryption(self, bucket_name: str):
        """Check if server-side encryption is enabled."""
        result = self._safe_api_call(
            self.client.get_bucket_encryption,
            Bucket=bucket_name,
            default=None,
        )

        if result is None:
            self._add_finding(
                resource_id=bucket_name,
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                resource_type="S3 Bucket",
                title=f"S3 Bucket '{bucket_name}' does not have default encryption enabled",
                description=(
                    f"The S3 bucket '{bucket_name}' does not have server-side encryption "
                    "configured by default. Objects uploaded without explicit encryption "
                    "settings will be stored unencrypted, posing a data-at-rest security risk."
                ),
                severity="medium",
                check_id="s3_encryption_disabled",
                raw_config={"bucket": bucket_name, "encryption": None},
                is_remediable=True,
                remediation_type="s3_enable_encryption",
            )

    def _check_versioning(self, bucket_name: str):
        """Check if versioning is enabled."""
        result = self._safe_api_call(
            self.client.get_bucket_versioning,
            Bucket=bucket_name,
            default={},
        )

        status = result.get("Status", "Disabled")

        if status != "Enabled":
            self._add_finding(
                resource_id=bucket_name,
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                resource_type="S3 Bucket",
                title=f"S3 Bucket '{bucket_name}' does not have versioning enabled",
                description=(
                    f"The S3 bucket '{bucket_name}' does not have object versioning enabled. "
                    "Without versioning, accidentally deleted or overwritten objects cannot "
                    "be recovered."
                ),
                severity="low",
                check_id="s3_versioning_disabled",
                raw_config={"bucket": bucket_name, "versioning_status": status},
                is_remediable=True,
                remediation_type="s3_enable_versioning",
            )

    def _check_logging(self, bucket_name: str):
        """Check if server access logging is enabled."""
        result = self._safe_api_call(
            self.client.get_bucket_logging,
            Bucket=bucket_name,
            default={},
        )

        logging_config = result.get("LoggingEnabled")

        if not logging_config:
            self._add_finding(
                resource_id=bucket_name,
                resource_arn=f"arn:aws:s3:::{bucket_name}",
                resource_type="S3 Bucket",
                title=f"S3 Bucket '{bucket_name}' does not have access logging enabled",
                description=(
                    f"The S3 bucket '{bucket_name}' does not have server access logging "
                    "enabled. Without logging, you cannot track who accessed your data, "
                    "making it difficult to detect unauthorized access or audit data usage."
                ),
                severity="medium",
                check_id="s3_logging_disabled",
                raw_config={"bucket": bucket_name, "logging": None},
                is_remediable=True,
                remediation_type="s3_enable_logging",
            )
