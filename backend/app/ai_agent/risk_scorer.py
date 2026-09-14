"""
CloudGuard Risk Scorer
Hybrid risk scoring: deterministic base + AI adjustment.
"""


class RiskScorer:
    """
    Calculates risk scores using a hybrid approach:
    1. Deterministic base score from severity and check type
    2. AI-adjusted score based on contextual analysis
    """

    # Base scores by severity
    SEVERITY_BASE_SCORES = {
        "critical": 90.0,
        "high": 70.0,
        "medium": 40.0,
        "low": 15.0,
    }

    # Additional weight by check type (some checks are more impactful)
    CHECK_WEIGHT_MODIFIERS = {
        # Critical patterns
        "s3_public_bucket_policy": 5.0,
        "s3_public_acl": 5.0,
        "s3_public_access_block_missing": 3.0,
        "iam_root_mfa_disabled": 8.0,
        "iam_user_admin_access": 5.0,
        "sg_all_traffic_open": 5.0,
        "cloudtrail_no_trails": 5.0,
        "cloudtrail_logging_stopped": 5.0,
        "rds_publicly_accessible": 5.0,

        # High patterns
        "sg_port_22_open": 3.0,
        "sg_port_3389_open": 3.0,
        "iam_user_mfa_disabled": 2.0,
        "iam_no_password_policy": 2.0,

        # Medium patterns
        "s3_encryption_disabled": 0.0,
        "s3_logging_disabled": 0.0,
        "iam_access_key_old": 0.0,

        # Low patterns
        "s3_versioning_disabled": 0.0,
        "sg_unused": -5.0,
        "ebs_unattached": -5.0,
    }

    @classmethod
    def calculate_base_score(cls, severity: str, check_id: str) -> float:
        """
        Calculate the deterministic base risk score.

        Args:
            severity: Finding severity (critical/high/medium/low)
            check_id: Unique check identifier

        Returns:
            Risk score between 0 and 100
        """
        base = cls.SEVERITY_BASE_SCORES.get(severity.lower(), 40.0)
        modifier = cls.CHECK_WEIGHT_MODIFIERS.get(check_id, 0.0)
        return max(0.0, min(100.0, base + modifier))

    @classmethod
    def adjust_with_ai(cls, base_score: float, ai_score: float) -> float:
        """
        Combine base score with AI-provided score.
        AI can adjust by ±15 points from the base score.

        Args:
            base_score: Deterministic base score
            ai_score: AI-provided risk score (0-100)

        Returns:
            Final adjusted risk score between 0 and 100
        """
        # AI can influence score by ±15 points
        ai_adjustment = (ai_score - base_score) * 0.3  # 30% weight to AI opinion
        ai_adjustment = max(-15.0, min(15.0, ai_adjustment))

        final_score = base_score + ai_adjustment
        return max(0.0, min(100.0, round(final_score, 1)))

    @classmethod
    def calculate_overall_score(cls, finding_scores: list[float]) -> float:
        """
        Calculate the overall account security score from individual findings.
        
        Uses a weighted approach where critical findings have more impact.
        A perfect score (100) means no findings. More/worse findings lower the score.

        Args:
            finding_scores: List of individual finding risk scores

        Returns:
            Overall security score (0-100, higher is better/more secure)
        """
        if not finding_scores:
            return 100.0  # No findings = perfect score

        # Weight by score magnitude (critical findings matter more)
        total_risk = sum(score ** 1.5 for score in finding_scores)

        # Normalize: more findings = lower score
        # Use a logarithmic scale so the score doesn't drop too fast
        import math
        risk_factor = total_risk / (len(finding_scores) * 100 ** 1.5)
        risk_factor = min(1.0, risk_factor * math.log(len(finding_scores) + 1, 2))

        overall = 100.0 * (1.0 - risk_factor)
        return max(0.0, min(100.0, round(overall, 1)))


risk_scorer = RiskScorer()
