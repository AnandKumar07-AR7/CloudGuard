"""
CloudGuard VPC Scanner
Checks VPC default security group rules.
"""

from typing import List
from app.scanners.base import BaseScanner, ScanFinding


class VPCScanner(BaseScanner):
    """Scans VPC configurations for security issues."""

    @property
    def service_name(self) -> str:
        return "vpc"

    @property
    def display_name(self) -> str:
        return "Amazon VPC"

    def scan(self) -> List[ScanFinding]:
        """Scan VPC configurations for misconfigurations."""
        self.reset()

        result = self._safe_api_call(
            self.client.describe_vpcs,
            default=None,
        )

        if result is None:
            return self.findings

        vpcs = result.get("Vpcs", [])

        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            is_default = vpc.get("IsDefault", False)

            self._check_default_sg(vpc_id, is_default)
            self._check_flow_logs(vpc_id, is_default)

        return self.findings

    def _check_default_sg(self, vpc_id: str, is_default: bool):
        """Check if the default security group has permissive rules."""
        result = self._safe_api_call(
            self.client.describe_security_groups,
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {"Name": "group-name", "Values": ["default"]},
            ],
            default=None,
        )

        if result is None:
            return

        for sg in result.get("SecurityGroups", []):
            inbound_rules = sg.get("IpPermissions", [])
            has_permissive_rules = False

            for rule in inbound_rules:
                ip_ranges = rule.get("IpRanges", [])
                for ip_range in ip_ranges:
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        has_permissive_rules = True
                        break

                ipv6_ranges = rule.get("Ipv6Ranges", [])
                for ipv6_range in ipv6_ranges:
                    if ipv6_range.get("CidrIpv6") == "::/0":
                        has_permissive_rules = True
                        break

            if has_permissive_rules:
                self._add_finding(
                    resource_id=f"{vpc_id}/default-sg",
                    resource_arn=f"arn:aws:ec2:::vpc/{vpc_id}",
                    resource_type="VPC Default Security Group",
                    title=f"Default security group in VPC '{vpc_id}' has permissive inbound rules",
                    description=(
                        f"The default security group in VPC '{vpc_id}' "
                        f"{'(default VPC) ' if is_default else ''}"
                        "allows inbound traffic from 0.0.0.0/0. The default security group should "
                        "restrict all inbound and outbound traffic. Resources that accidentally use "
                        "the default SG would be exposed."
                    ),
                    severity="high",
                    check_id="vpc_default_sg_permissive",
                    raw_config={
                        "vpc_id": vpc_id,
                        "is_default_vpc": is_default,
                        "sg_id": sg["GroupId"],
                        "inbound_rules_count": len(inbound_rules),
                    },
                    is_remediable=True,
                    remediation_type="vpc_restrict_default_sg",
                )

    def _check_flow_logs(self, vpc_id: str, is_default: bool):
        """Check if VPC flow logs are enabled."""
        result = self._safe_api_call(
            self.client.describe_flow_logs,
            Filters=[{"Name": "resource-id", "Values": [vpc_id]}],
            default=None,
        )

        if result is None:
            return

        flow_logs = result.get("FlowLogs", [])

        if not flow_logs:
            self._add_finding(
                resource_id=vpc_id,
                resource_arn=f"arn:aws:ec2:::vpc/{vpc_id}",
                resource_type="VPC",
                title=f"VPC '{vpc_id}' does not have flow logs enabled",
                description=(
                    f"The VPC '{vpc_id}' "
                    f"{'(default VPC) ' if is_default else ''}"
                    "does not have VPC Flow Logs enabled. Flow logs capture information about "
                    "the IP traffic going to and from network interfaces in the VPC. Without "
                    "flow logs, network traffic analysis for security incidents is impossible."
                ),
                severity="medium",
                check_id="vpc_no_flow_logs",
                raw_config={
                    "vpc_id": vpc_id,
                    "is_default_vpc": is_default,
                    "flow_logs": [],
                },
                is_remediable=False,
                remediation_type="vpc_enable_flow_logs",
            )
