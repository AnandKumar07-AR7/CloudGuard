"""
CloudGuard EBS Scanner
Checks EBS volumes for encryption and attachment status.
"""

from typing import List
from app.scanners.base import BaseScanner, ScanFinding


class EBSScanner(BaseScanner):
    """Scans EBS volumes for security issues."""

    @property
    def service_name(self) -> str:
        return "ebs"

    @property
    def display_name(self) -> str:
        return "Amazon EBS"

    def scan(self) -> List[ScanFinding]:
        """Scan all EBS volumes for misconfigurations."""
        self.reset()

        result = self._safe_api_call(
            self.client.describe_volumes,
            default=None,
        )

        if result is None:
            return self.findings

        volumes = result.get("Volumes", [])

        for volume in volumes:
            vol_id = volume["VolumeId"]
            self._check_encryption(volume, vol_id)
            self._check_unattached(volume, vol_id)

        # Check account-level default encryption
        self._check_default_encryption()

        return self.findings

    def _check_encryption(self, volume: dict, vol_id: str):
        """Check if volume is encrypted."""
        if not volume.get("Encrypted", False):
            size = volume.get("Size", 0)
            state = volume.get("State", "unknown")
            az = volume.get("AvailabilityZone", "unknown")

            self._add_finding(
                resource_id=vol_id,
                resource_arn=f"arn:aws:ec2:::volume/{vol_id}",
                resource_type="EBS Volume",
                region=az,
                title=f"EBS volume '{vol_id}' is not encrypted",
                description=(
                    f"The EBS volume '{vol_id}' ({size} GB, {state}) in {az} is not encrypted. "
                    "Data stored on this volume is at risk if the underlying hardware is "
                    "compromised or improperly decommissioned."
                ),
                severity="high",
                check_id="ebs_not_encrypted",
                raw_config={
                    "volume_id": vol_id,
                    "size_gb": size,
                    "state": state,
                    "availability_zone": az,
                    "encrypted": False,
                },
                is_remediable=False,  # Cannot encrypt in-place
                remediation_type="ebs_encrypt_volume",
            )

    def _check_unattached(self, volume: dict, vol_id: str):
        """Check for unattached (available) volumes."""
        if volume.get("State") == "available":
            size = volume.get("Size", 0)
            az = volume.get("AvailabilityZone", "unknown")

            self._add_finding(
                resource_id=vol_id,
                resource_arn=f"arn:aws:ec2:::volume/{vol_id}",
                resource_type="EBS Volume",
                region=az,
                title=f"EBS volume '{vol_id}' is unattached",
                description=(
                    f"The EBS volume '{vol_id}' ({size} GB) in {az} is not attached to any "
                    "instance. Unattached volumes incur storage costs and may contain "
                    "sensitive data that is not being actively managed."
                ),
                severity="low",
                check_id="ebs_unattached",
                raw_config={
                    "volume_id": vol_id,
                    "size_gb": size,
                    "availability_zone": az,
                    "state": "available",
                },
                is_remediable=False,
                remediation_type="ebs_cleanup_unattached",
            )

    def _check_default_encryption(self):
        """Check if EBS default encryption is enabled for the region."""
        result = self._safe_api_call(
            self.client.get_ebs_encryption_by_default,
            default=None,
        )

        if result and not result.get("EbsEncryptionByDefault", False):
            self._add_finding(
                resource_id="ebs-default-encryption",
                resource_arn="arn:aws:ec2:::ebs-default-encryption",
                resource_type="EBS Default Encryption",
                title="EBS default encryption is not enabled for this region",
                description=(
                    "EBS default encryption is not enabled in this region. When enabled, "
                    "all newly created EBS volumes will be automatically encrypted. This "
                    "prevents accidental creation of unencrypted volumes."
                ),
                severity="medium",
                check_id="ebs_default_encryption_disabled",
                raw_config={"ebs_encryption_by_default": False},
                is_remediable=True,
                remediation_type="ebs_enable_default_encryption",
            )
