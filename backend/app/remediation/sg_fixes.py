"""
CloudGuard Security Group Fixes
Auto-remediation actions for EC2 Security Group misconfigurations.
"""

from typing import Tuple


class SGFixes:
    """Security Group remediation actions."""

    def __init__(self, ec2_client):
        self.client = ec2_client

    def restrict_port(self, sg_id: str, port: int, protocol: str = "tcp") -> Tuple[bool, str, dict, dict]:
        """
        Remove 0.0.0.0/0 ingress rule for a specific port.
        
        Returns:
            (success, message, before_state, after_state)
        """
        try:
            before_state = {
                "sg_id": sg_id,
                "port": port,
                "cidr": "0.0.0.0/0",
                "status": "open_to_internet",
            }

            # Revoke the overly permissive rule
            self.client.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "FromPort": port,
                        "ToPort": port,
                        "IpProtocol": protocol,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )

            # Also try to revoke IPv6
            try:
                self.client.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "FromPort": port,
                            "ToPort": port,
                            "IpProtocol": protocol,
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        }
                    ],
                )
            except Exception:
                pass  # IPv6 rule may not exist

            after_state = {
                "sg_id": sg_id,
                "port": port,
                "status": "restricted",
                "note": "0.0.0.0/0 rule removed. Add specific IP ranges as needed.",
            }
            return True, f"Successfully removed internet access on port {port} for SG '{sg_id}'", before_state, after_state

        except Exception as e:
            return False, f"Failed to restrict port: {str(e)}", {}, {}

    def remove_all_traffic_rule(self, sg_id: str) -> Tuple[bool, str, dict, dict]:
        """Remove all-traffic (0.0.0.0/0 on all ports) ingress rule."""
        try:
            before_state = {"sg_id": sg_id, "status": "all_traffic_open"}

            self.client.revoke_security_group_ingress(
                GroupId=sg_id,
                IpPermissions=[
                    {
                        "IpProtocol": "-1",
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    }
                ],
            )

            try:
                self.client.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[
                        {
                            "IpProtocol": "-1",
                            "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                        }
                    ],
                )
            except Exception:
                pass

            after_state = {"sg_id": sg_id, "status": "restricted"}
            return True, f"Successfully removed all-traffic internet rule from SG '{sg_id}'", before_state, after_state

        except Exception as e:
            return False, f"Failed to remove all-traffic rule: {str(e)}", {}, {}

    def delete_unused_sg(self, sg_id: str) -> Tuple[bool, str, dict, dict]:
        """Delete an unused security group."""
        try:
            # Get SG details before deletion
            sg_info = self.client.describe_security_groups(GroupIds=[sg_id])
            before_state = {
                "sg_id": sg_id,
                "sg_name": sg_info["SecurityGroups"][0].get("GroupName", "unknown"),
                "status": "unused",
            }

            self.client.delete_security_group(GroupId=sg_id)

            after_state = {"sg_id": sg_id, "status": "deleted"}
            return True, f"Successfully deleted unused security group '{sg_id}'", before_state, after_state

        except Exception as e:
            return False, f"Failed to delete security group: {str(e)}", {}, {}
