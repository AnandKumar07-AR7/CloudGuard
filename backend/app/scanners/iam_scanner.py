"""
CloudGuard IAM Scanner
Checks IAM users, policies, and MFA for security misconfigurations.
"""

from typing import List
from datetime import datetime, timezone, timedelta
from app.scanners.base import BaseScanner, ScanFinding


class IAMScanner(BaseScanner):
    """Scans IAM users, policies, and credentials for security issues."""

    @property
    def service_name(self) -> str:
        return "iam"

    @property
    def display_name(self) -> str:
        return "AWS IAM"

    def scan(self) -> List[ScanFinding]:
        """Scan IAM for misconfigurations."""
        self.reset()

        self._check_root_mfa()
        self._check_users()
        self._check_password_policy()

        return self.findings

    def _check_root_mfa(self):
        """Check if root account has MFA enabled."""
        result = self._safe_api_call(
            self.client.get_account_summary,
            default=None,
        )

        if result is None:
            return

        summary = result.get("SummaryMap", {})
        root_mfa = summary.get("AccountMFAEnabled", 0)

        if root_mfa == 0:
            self._add_finding(
                resource_id="root-account",
                resource_arn="arn:aws:iam::root",
                resource_type="Root Account",
                title="Root account does not have MFA enabled",
                description=(
                    "The AWS root account does not have Multi-Factor Authentication (MFA) "
                    "enabled. The root account has unrestricted access to all resources in "
                    "the AWS account. Without MFA, a compromised password gives full access "
                    "to the entire AWS account. This is the single highest security risk."
                ),
                severity="critical",
                check_id="iam_root_mfa_disabled",
                raw_config={"account_mfa_enabled": root_mfa},
                is_remediable=False,  # Cannot programmatically enable MFA for root
                remediation_type="iam_enable_root_mfa",
                base_risk_score=98.0,
            )

    def _check_users(self):
        """Check all IAM users for security issues."""
        result = self._safe_api_call(
            self.client.list_users,
            default=None,
        )

        if result is None:
            return

        users = result.get("Users", [])

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]

            self._check_user_mfa(username, user_arn)
            self._check_access_keys(username, user_arn)
            self._check_user_policies(username, user_arn)
            self._check_user_activity(user)

    def _check_user_mfa(self, username: str, user_arn: str):
        """Check if an IAM user has MFA enabled."""
        result = self._safe_api_call(
            self.client.list_mfa_devices,
            UserName=username,
            default=None,
        )

        if result is None:
            return

        mfa_devices = result.get("MFADevices", [])

        if not mfa_devices:
            self._add_finding(
                resource_id=username,
                resource_arn=user_arn,
                resource_type="IAM User",
                title=f"IAM user '{username}' does not have MFA enabled",
                description=(
                    f"The IAM user '{username}' does not have Multi-Factor Authentication (MFA) "
                    "enabled. Without MFA, the account relies solely on a password for "
                    "authentication, making it vulnerable to phishing and credential stuffing attacks."
                ),
                severity="high",
                check_id="iam_user_mfa_disabled",
                raw_config={"username": username, "mfa_devices": []},
                is_remediable=False,  # Cannot programmatically set up MFA device
                remediation_type="iam_enable_user_mfa",
            )

    def _check_access_keys(self, username: str, user_arn: str):
        """Check for old or unused access keys."""
        result = self._safe_api_call(
            self.client.list_access_keys,
            UserName=username,
            default=None,
        )

        if result is None:
            return

        now = datetime.now(timezone.utc)
        keys = result.get("AccessKeyMetadata", [])

        for key in keys:
            key_id = key["AccessKeyId"]
            status = key["Status"]
            created = key.get("CreateDate")

            if created:
                age_days = (now - created).days

                # Check for old access keys (>90 days)
                if age_days > 90 and status == "Active":
                    self._add_finding(
                        resource_id=f"{username}/{key_id}",
                        resource_arn=user_arn,
                        resource_type="IAM Access Key",
                        title=f"IAM user '{username}' has access key older than 90 days",
                        description=(
                            f"The access key '{key_id}' for IAM user '{username}' was created "
                            f"{age_days} days ago and is still active. AWS recommends rotating "
                            "access keys every 90 days to reduce the risk of compromised credentials."
                        ),
                        severity="medium",
                        check_id="iam_access_key_old",
                        raw_config={
                            "username": username,
                            "key_id": key_id,
                            "created": created.isoformat(),
                            "age_days": age_days,
                            "status": status,
                        },
                        is_remediable=True,
                        remediation_type="iam_deactivate_old_key",
                    )

            # Check for inactive keys that haven't been deleted
            last_used = self._safe_api_call(
                self.client.get_access_key_last_used,
                AccessKeyId=key_id,
                default=None,
            )

            if last_used and status == "Active":
                last_used_info = last_used.get("AccessKeyLastUsed", {})
                last_used_date = last_used_info.get("LastUsedDate")

                if last_used_date:
                    inactive_days = (now - last_used_date).days
                    if inactive_days > 90:
                        self._add_finding(
                            resource_id=f"{username}/{key_id}",
                            resource_arn=user_arn,
                            resource_type="IAM Access Key",
                            title=f"IAM user '{username}' has inactive access key (unused for {inactive_days} days)",
                            description=(
                                f"The access key '{key_id}' for IAM user '{username}' has not "
                                f"been used in {inactive_days} days. Inactive access keys that "
                                "remain active are potential attack vectors."
                            ),
                            severity="medium",
                            check_id="iam_access_key_inactive",
                            raw_config={
                                "username": username,
                                "key_id": key_id,
                                "last_used": last_used_date.isoformat(),
                                "inactive_days": inactive_days,
                            },
                            is_remediable=True,
                            remediation_type="iam_deactivate_old_key",
                        )

    def _check_user_policies(self, username: str, user_arn: str):
        """Check for overly permissive or inline policies."""
        # Check inline policies
        inline_result = self._safe_api_call(
            self.client.list_user_policies,
            UserName=username,
            default=None,
        )

        if inline_result:
            inline_policies = inline_result.get("PolicyNames", [])
            if inline_policies:
                self._add_finding(
                    resource_id=username,
                    resource_arn=user_arn,
                    resource_type="IAM User",
                    title=f"IAM user '{username}' has {len(inline_policies)} inline policy(ies)",
                    description=(
                        f"The IAM user '{username}' has inline policies: {', '.join(inline_policies)}. "
                        "Inline policies are harder to manage and audit than managed policies. "
                        "Best practice is to use AWS managed or customer managed policies instead."
                    ),
                    severity="medium",
                    check_id="iam_user_inline_policy",
                    raw_config={
                        "username": username,
                        "inline_policies": inline_policies,
                    },
                    is_remediable=False,
                    remediation_type="iam_remove_inline_policy",
                )

        # Check attached managed policies for admin access
        attached_result = self._safe_api_call(
            self.client.list_attached_user_policies,
            UserName=username,
            default=None,
        )

        if attached_result:
            attached_policies = attached_result.get("AttachedPolicies", [])
            admin_policies = [
                p for p in attached_policies
                if "AdministratorAccess" in p.get("PolicyName", "")
                or "FullAccess" in p.get("PolicyName", "")
            ]

            if admin_policies:
                policy_names = [p["PolicyName"] for p in admin_policies]
                self._add_finding(
                    resource_id=username,
                    resource_arn=user_arn,
                    resource_type="IAM User",
                    title=f"IAM user '{username}' has overly permissive policies",
                    description=(
                        f"The IAM user '{username}' has the following overly permissive policies "
                        f"attached: {', '.join(policy_names)}. These policies grant broad access "
                        "to AWS resources, violating the Principle of Least Privilege."
                    ),
                    severity="critical",
                    check_id="iam_user_admin_access",
                    raw_config={
                        "username": username,
                        "admin_policies": policy_names,
                    },
                    is_remediable=False,
                    remediation_type="iam_restrict_user_policy",
                )

    def _check_user_activity(self, user: dict):
        """Check for dormant/inactive users."""
        username = user["UserName"]
        user_arn = user["Arn"]
        password_last_used = user.get("PasswordLastUsed")

        now = datetime.now(timezone.utc)

        if password_last_used:
            inactive_days = (now - password_last_used).days

            if inactive_days > 90:
                self._add_finding(
                    resource_id=username,
                    resource_arn=user_arn,
                    resource_type="IAM User",
                    title=f"IAM user '{username}' is inactive (no login for {inactive_days} days)",
                    description=(
                        f"The IAM user '{username}' has not logged in for {inactive_days} days. "
                        "Dormant accounts are potential attack vectors. Consider disabling or "
                        "removing accounts that are no longer in use."
                    ),
                    severity="medium",
                    check_id="iam_user_inactive",
                    raw_config={
                        "username": username,
                        "password_last_used": password_last_used.isoformat(),
                        "inactive_days": inactive_days,
                    },
                    is_remediable=False,
                    remediation_type="iam_disable_inactive_user",
                )

    def _check_password_policy(self):
        """Check the account password policy."""
        result = self._safe_api_call(
            self.client.get_account_password_policy,
            default=None,
        )

        if result is None:
            self._add_finding(
                resource_id="account-password-policy",
                resource_arn="arn:aws:iam::password-policy",
                resource_type="Password Policy",
                title="No custom password policy is configured",
                description=(
                    "The AWS account is using the default password policy. A custom password "
                    "policy should enforce minimum length, complexity requirements, and "
                    "rotation. The default policy has weaker requirements that may not "
                    "meet security best practices."
                ),
                severity="high",
                check_id="iam_no_password_policy",
                raw_config={"password_policy": None},
                is_remediable=False,
                remediation_type="iam_set_password_policy",
            )
            return

        policy = result.get("PasswordPolicy", {})
        issues = []

        if policy.get("MinimumPasswordLength", 0) < 14:
            issues.append(f"Minimum length is {policy.get('MinimumPasswordLength', 'not set')} (should be ≥ 14)")
        if not policy.get("RequireSymbols", False):
            issues.append("Does not require symbols")
        if not policy.get("RequireNumbers", False):
            issues.append("Does not require numbers")
        if not policy.get("RequireUppercaseCharacters", False):
            issues.append("Does not require uppercase characters")
        if not policy.get("RequireLowercaseCharacters", False):
            issues.append("Does not require lowercase characters")
        if policy.get("MaxPasswordAge", 0) == 0:
            issues.append("No password expiration/rotation configured")

        if issues:
            self._add_finding(
                resource_id="account-password-policy",
                resource_arn="arn:aws:iam::password-policy",
                resource_type="Password Policy",
                title="Account password policy does not meet security best practices",
                description=(
                    f"The account password policy has the following issues: "
                    f"{'; '.join(issues)}. A strong password policy helps prevent brute-force "
                    "and credential-based attacks."
                ),
                severity="medium",
                check_id="iam_weak_password_policy",
                raw_config={"password_policy": policy, "issues": issues},
                is_remediable=False,
                remediation_type="iam_update_password_policy",
            )
