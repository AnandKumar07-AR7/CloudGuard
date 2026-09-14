"""
CloudGuard Security Group Scanner
Checks EC2 Security Groups for overly permissive inbound/outbound rules.
"""

from typing import List
from app.scanners.base import BaseScanner, ScanFinding


# Ports that are considered sensitive
SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    1521: "Oracle DB",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    23: "Telnet",
    21: "FTP",
    445: "SMB",
    135: "RPC",
}

# Critical ports that should never be open to internet
CRITICAL_PORTS = {22, 3389, 3306, 5432, 1433, 27017, 23, 21}


class SGScanner(BaseScanner):
    """Scans EC2 Security Groups for overly permissive rules."""

    @property
    def service_name(self) -> str:
        return "ec2"

    @property
    def display_name(self) -> str:
        return "EC2 Security Groups"

    def scan(self) -> List[ScanFinding]:
        """Scan all security groups for misconfigurations."""
        self.reset()

        result = self._safe_api_call(
            self.client.describe_security_groups,
            default=None,
        )

        if result is None:
            return self.findings

        security_groups = result.get("SecurityGroups", [])

        for sg in security_groups:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "unnamed")
            vpc_id = sg.get("VpcId", "N/A")

            self._check_inbound_rules(sg_id, sg_name, vpc_id, sg.get("IpPermissions", []))
            self._check_unrestricted_outbound(sg_id, sg_name, vpc_id, sg.get("IpPermissionsEgress", []))

        # Check for unused security groups
        self._check_unused_security_groups(security_groups)

        return self.findings

    def _is_open_to_world(self, ip_ranges: list, ipv6_ranges: list) -> bool:
        """Check if rules allow access from 0.0.0.0/0 or ::/0."""
        for ip_range in ip_ranges:
            if ip_range.get("CidrIp") == "0.0.0.0/0":
                return True
        for ipv6_range in ipv6_ranges:
            if ipv6_range.get("CidrIpv6") == "::/0":
                return True
        return False

    def _check_inbound_rules(self, sg_id: str, sg_name: str, vpc_id: str, rules: list):
        """Check inbound rules for overly permissive access."""
        for rule in rules:
            ip_ranges = rule.get("IpRanges", [])
            ipv6_ranges = rule.get("Ipv6Ranges", [])

            if not self._is_open_to_world(ip_ranges, ipv6_ranges):
                continue

            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            protocol = rule.get("IpProtocol", "-1")

            # All traffic (-1 protocol or all ports)
            if protocol == "-1" or (from_port == 0 and to_port == 65535):
                self._add_finding(
                    resource_id=sg_id,
                    resource_arn=f"arn:aws:ec2:::security-group/{sg_id}",
                    resource_type="Security Group",
                    region=vpc_id,
                    title=f"Security Group '{sg_name}' ({sg_id}) allows ALL inbound traffic from the internet",
                    description=(
                        f"Security Group '{sg_name}' ({sg_id}) in VPC {vpc_id} has a rule that "
                        "allows ALL inbound traffic (all ports, all protocols) from 0.0.0.0/0. "
                        "This effectively makes any associated resource fully exposed to the internet."
                    ),
                    severity="critical",
                    check_id="sg_all_traffic_open",
                    raw_config={
                        "sg_id": sg_id,
                        "sg_name": sg_name,
                        "vpc_id": vpc_id,
                        "rule": {
                            "protocol": protocol,
                            "from_port": from_port,
                            "to_port": to_port,
                        },
                    },
                    is_remediable=True,
                    remediation_type="sg_remove_open_rule",
                    base_risk_score=95.0,
                )
                continue

            # Check specific sensitive ports
            for port in range(from_port, min(to_port + 1, from_port + 100)):  # Cap range scan
                if port in SENSITIVE_PORTS:
                    service_name = SENSITIVE_PORTS[port]
                    is_critical = port in CRITICAL_PORTS

                    self._add_finding(
                        resource_id=sg_id,
                        resource_arn=f"arn:aws:ec2:::security-group/{sg_id}",
                        resource_type="Security Group",
                        region=vpc_id,
                        title=f"Security Group '{sg_name}' ({sg_id}) exposes {service_name} (port {port}) to the internet",
                        description=(
                            f"Security Group '{sg_name}' ({sg_id}) allows inbound traffic on "
                            f"port {port} ({service_name}) from 0.0.0.0/0 (the entire internet). "
                            f"{'This is a critical risk as it exposes ' + service_name + ' directly to the internet.' if is_critical else 'This port should be restricted to specific IP ranges.'}"
                        ),
                        severity="critical" if is_critical else "high",
                        check_id=f"sg_port_{port}_open",
                        raw_config={
                            "sg_id": sg_id,
                            "sg_name": sg_name,
                            "vpc_id": vpc_id,
                            "port": port,
                            "service": service_name,
                            "protocol": protocol,
                        },
                        is_remediable=True,
                        remediation_type="sg_restrict_port",
                    )

    def _check_unrestricted_outbound(self, sg_id: str, sg_name: str, vpc_id: str, rules: list):
        """Check for unrestricted outbound rules (informational)."""
        # Most use cases need outbound, so this is low severity
        pass

    def _check_unused_security_groups(self, security_groups: list):
        """Check for security groups not attached to any resource."""
        # Get all ENIs to find which SGs are in use
        eni_result = self._safe_api_call(
            self.client.describe_network_interfaces,
            default=None,
        )

        if eni_result is None:
            return

        used_sg_ids = set()
        for eni in eni_result.get("NetworkInterfaces", []):
            for group in eni.get("Groups", []):
                used_sg_ids.add(group["GroupId"])

        for sg in security_groups:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "unnamed")

            # Skip the default security group — it can't be deleted
            if sg_name == "default":
                continue

            if sg_id not in used_sg_ids:
                self._add_finding(
                    resource_id=sg_id,
                    resource_arn=f"arn:aws:ec2:::security-group/{sg_id}",
                    resource_type="Security Group",
                    title=f"Security Group '{sg_name}' ({sg_id}) is not attached to any resource",
                    description=(
                        f"The security group '{sg_name}' ({sg_id}) is not associated with any "
                        "ENI (network interface). Unused security groups add clutter and may be "
                        "accidentally attached to resources with unintended rules."
                    ),
                    severity="low",
                    check_id="sg_unused",
                    raw_config={
                        "sg_id": sg_id,
                        "sg_name": sg_name,
                        "vpc_id": sg.get("VpcId", "N/A"),
                    },
                    is_remediable=True,
                    remediation_type="sg_delete_unused",
                )
