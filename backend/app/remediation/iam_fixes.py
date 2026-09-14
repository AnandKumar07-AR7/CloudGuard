"""
CloudGuard IAM Fixes
Auto-remediation actions for IAM misconfigurations.
"""

from typing import Tuple


class IAMFixes:
    """IAM remediation actions."""

    def __init__(self, iam_client):
        self.client = iam_client

    def deactivate_old_access_key(self, username: str, key_id: str) -> Tuple[bool, str, dict, dict]:
        """
        Deactivate an old or unused access key.
        
        Returns:
            (success, message, before_state, after_state)
        """
        try:
            before_state = {"key_id": key_id, "status": "Active"}

            self.client.update_access_key(
                UserName=username,
                AccessKeyId=key_id,
                Status="Inactive",
            )

            after_state = {"key_id": key_id, "status": "Inactive"}
            return True, f"Successfully deactivated access key '{key_id}' for user '{username}'", before_state, after_state

        except Exception as e:
            return False, f"Failed to deactivate access key: {str(e)}", {}, {}

    def generate_mfa_instructions(self, username: str) -> Tuple[bool, str, dict, dict]:
        """
        Generate MFA setup instructions (cannot auto-enable MFA).
        
        Returns:
            (success, message, before_state, after_state)
        """
        instructions = {
            "steps": [
                "1. Sign in to the AWS Management Console",
                "2. Go to IAM → Users → " + username,
                "3. Click on the 'Security credentials' tab",
                "4. In the 'Multi-factor authentication (MFA)' section, click 'Assign MFA device'",
                "5. Choose 'Authenticator app' and follow the setup wizard",
                "6. Scan the QR code with Google Authenticator or Authy",
                "7. Enter two consecutive MFA codes to complete setup",
            ],
            "note": "MFA cannot be automatically enabled — it requires physical device registration."
        }
        return True, f"MFA setup instructions generated for '{username}'", {"mfa": "disabled"}, instructions
