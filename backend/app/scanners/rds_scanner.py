"""
CloudGuard RDS Scanner
Checks RDS instances for security misconfigurations.
"""

from typing import List
from app.scanners.base import BaseScanner, ScanFinding


class RDSScanner(BaseScanner):
    """Scans RDS instances for security issues."""

    @property
    def service_name(self) -> str:
        return "rds"

    @property
    def display_name(self) -> str:
        return "Amazon RDS"

    def scan(self) -> List[ScanFinding]:
        """Scan all RDS instances for misconfigurations."""
        self.reset()

        result = self._safe_api_call(
            self.client.describe_db_instances,
            default=None,
        )

        if result is None:
            return self.findings

        instances = result.get("DBInstances", [])

        for instance in instances:
            db_id = instance["DBInstanceIdentifier"]
            db_arn = instance.get("DBInstanceArn", "")
            engine = instance.get("Engine", "unknown")

            self._check_public_access(instance, db_id, db_arn, engine)
            self._check_encryption(instance, db_id, db_arn, engine)
            self._check_backup_retention(instance, db_id, db_arn, engine)
            self._check_deletion_protection(instance, db_id, db_arn, engine)
            self._check_auto_minor_version_upgrade(instance, db_id, db_arn, engine)

        return self.findings

    def _check_public_access(self, instance: dict, db_id: str, db_arn: str, engine: str):
        """Check if RDS instance is publicly accessible."""
        if instance.get("PubliclyAccessible", False):
            self._add_finding(
                resource_id=db_id,
                resource_arn=db_arn,
                resource_type="RDS Instance",
                title=f"RDS instance '{db_id}' ({engine}) is publicly accessible",
                description=(
                    f"The RDS instance '{db_id}' running {engine} is set to 'Publicly Accessible'. "
                    "This means the database has a public IP and can potentially be reached from the "
                    "internet. Databases should be placed in private subnets and only accessible "
                    "from within the VPC."
                ),
                severity="critical",
                check_id="rds_publicly_accessible",
                raw_config={
                    "db_id": db_id,
                    "engine": engine,
                    "publicly_accessible": True,
                    "endpoint": instance.get("Endpoint", {}).get("Address", ""),
                },
                is_remediable=True,
                remediation_type="rds_disable_public_access",
            )

    def _check_encryption(self, instance: dict, db_id: str, db_arn: str, engine: str):
        """Check if storage encryption is enabled."""
        if not instance.get("StorageEncrypted", False):
            self._add_finding(
                resource_id=db_id,
                resource_arn=db_arn,
                resource_type="RDS Instance",
                title=f"RDS instance '{db_id}' ({engine}) does not have storage encryption enabled",
                description=(
                    f"The RDS instance '{db_id}' running {engine} does not have storage encryption "
                    "enabled. Data at rest in the database is not encrypted, which poses a "
                    "compliance and security risk."
                ),
                severity="high",
                check_id="rds_encryption_disabled",
                raw_config={"db_id": db_id, "engine": engine, "storage_encrypted": False},
                is_remediable=False,  # Cannot encrypt existing RDS without recreation
                remediation_type="rds_enable_encryption",
            )

    def _check_backup_retention(self, instance: dict, db_id: str, db_arn: str, engine: str):
        """Check backup retention period."""
        retention = instance.get("BackupRetentionPeriod", 0)

        if retention < 7:
            self._add_finding(
                resource_id=db_id,
                resource_arn=db_arn,
                resource_type="RDS Instance",
                title=f"RDS instance '{db_id}' has short backup retention ({retention} days)",
                description=(
                    f"The RDS instance '{db_id}' has a backup retention period of {retention} days. "
                    "AWS recommends at least 7 days of backup retention to ensure adequate "
                    "disaster recovery capability."
                ),
                severity="medium",
                check_id="rds_low_backup_retention",
                raw_config={
                    "db_id": db_id,
                    "engine": engine,
                    "backup_retention_period": retention,
                },
                is_remediable=True,
                remediation_type="rds_increase_backup_retention",
            )

    def _check_deletion_protection(self, instance: dict, db_id: str, db_arn: str, engine: str):
        """Check if deletion protection is enabled."""
        if not instance.get("DeletionProtection", False):
            self._add_finding(
                resource_id=db_id,
                resource_arn=db_arn,
                resource_type="RDS Instance",
                title=f"RDS instance '{db_id}' does not have deletion protection enabled",
                description=(
                    f"The RDS instance '{db_id}' does not have deletion protection enabled. "
                    "Without this, the database could be accidentally deleted via the console "
                    "or CLI, resulting in data loss."
                ),
                severity="medium",
                check_id="rds_no_deletion_protection",
                raw_config={"db_id": db_id, "deletion_protection": False},
                is_remediable=True,
                remediation_type="rds_enable_deletion_protection",
            )

    def _check_auto_minor_version_upgrade(self, instance: dict, db_id: str, db_arn: str, engine: str):
        """Check if auto minor version upgrade is enabled."""
        if not instance.get("AutoMinorVersionUpgrade", False):
            self._add_finding(
                resource_id=db_id,
                resource_arn=db_arn,
                resource_type="RDS Instance",
                title=f"RDS instance '{db_id}' does not have auto minor version upgrade enabled",
                description=(
                    f"The RDS instance '{db_id}' does not have automatic minor version upgrades "
                    "enabled. This means the database engine won't automatically receive security "
                    "patches and bug fixes, potentially leaving it vulnerable."
                ),
                severity="low",
                check_id="rds_no_auto_upgrade",
                raw_config={"db_id": db_id, "auto_minor_version_upgrade": False},
                is_remediable=True,
                remediation_type="rds_enable_auto_upgrade",
            )
