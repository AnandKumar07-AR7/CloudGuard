"""
CloudGuard AI Agent
Main orchestrator for AI-powered security analysis.
Coordinates between Gemini (bulk analysis) and Claude (deep analysis).
"""

import json
from typing import Optional, List
from app.ai_agent.gemini_client import gemini_client
from app.ai_agent.claude_client import claude_client
from app.ai_agent.risk_scorer import risk_scorer
from app.ai_agent.prompts import (
    SECURITY_ANALYSIS_SYSTEM_PROMPT,
    ANALYSIS_USER_PROMPT_TEMPLATE,
    DEEP_ANALYSIS_SYSTEM_PROMPT,
    DEEP_ANALYSIS_USER_PROMPT_TEMPLATE,
    BATCH_ANALYSIS_SYSTEM_PROMPT,
    BATCH_ANALYSIS_USER_PROMPT_TEMPLATE,
)


class AIAgent:
    """
    AI Agent that analyzes security findings using LLMs.
    
    Uses Gemini Flash for fast bulk analysis and Claude for deep-dive analysis.
    Falls back to deterministic scoring if no AI providers are configured.
    """

    async def analyze_finding(self, finding: dict, provider: str = "gemini") -> dict:
        """
        Analyze a single security finding with AI.

        Args:
            finding: Dict containing finding details (title, description, severity, etc.)
            provider: Which AI to use ("gemini" or "claude")

        Returns:
            Analysis result dict with risk_score, explanation, impact, remediation_steps
        """
        # Build the user prompt
        user_prompt = ANALYSIS_USER_PROMPT_TEMPLATE.format(
            title=finding.get("title", ""),
            service=finding.get("service", ""),
            resource_id=finding.get("resource_id", ""),
            resource_type=finding.get("resource_type", ""),
            severity=finding.get("severity", ""),
            description=finding.get("description", ""),
            region=finding.get("region", "global"),
            raw_config=json.dumps(finding.get("raw_config", {}), indent=2, default=str),
        )

        # Try the requested provider
        result = None
        if provider == "gemini" and gemini_client.is_available:
            result = await gemini_client.analyze(
                SECURITY_ANALYSIS_SYSTEM_PROMPT,
                user_prompt,
            )
        elif provider == "claude" and claude_client.is_available:
            result = await claude_client.analyze(
                SECURITY_ANALYSIS_SYSTEM_PROMPT,
                user_prompt,
            )

        # Fallback: try the other provider
        if result is None:
            if provider == "gemini" and claude_client.is_available:
                result = await claude_client.analyze(
                    SECURITY_ANALYSIS_SYSTEM_PROMPT,
                    user_prompt,
                )
            elif provider == "claude" and gemini_client.is_available:
                result = await gemini_client.analyze(
                    SECURITY_ANALYSIS_SYSTEM_PROMPT,
                    user_prompt,
                )

        # If AI failed entirely, return deterministic analysis
        if result is None:
            return self._fallback_analysis(finding)

        # Adjust risk score using hybrid scoring
        base_score = risk_scorer.calculate_base_score(
            finding.get("severity", "medium"),
            finding.get("check_id", ""),
        )
        ai_score = result.get("risk_score", base_score)
        result["risk_score"] = risk_scorer.adjust_with_ai(base_score, ai_score)

        return result

    async def deep_analyze_finding(self, finding: dict) -> dict:
        """
        Perform a deep analysis using Claude (preferred) or Gemini.
        Deep analysis provides attack scenarios, CLI commands, and breach examples.

        Args:
            finding: Dict containing finding details

        Returns:
            Detailed analysis result dict
        """
        user_prompt = DEEP_ANALYSIS_USER_PROMPT_TEMPLATE.format(
            title=finding.get("title", ""),
            service=finding.get("service", ""),
            resource_id=finding.get("resource_id", ""),
            resource_type=finding.get("resource_type", ""),
            severity=finding.get("severity", ""),
            description=finding.get("description", ""),
            region=finding.get("region", "global"),
            raw_config=json.dumps(finding.get("raw_config", {}), indent=2, default=str),
        )

        # Prefer Claude for deep analysis (better at detailed reasoning)
        result = None
        if claude_client.is_available:
            result = await claude_client.analyze(
                DEEP_ANALYSIS_SYSTEM_PROMPT,
                user_prompt,
            )

        if result is None and gemini_client.is_available:
            result = await gemini_client.analyze(
                DEEP_ANALYSIS_SYSTEM_PROMPT,
                user_prompt,
            )

        if result is None:
            return self._fallback_deep_analysis(finding)

        return result

    async def batch_analyze(self, findings: List[dict]) -> List[dict]:
        """
        Analyze multiple findings in a single API call (cost-efficient).
        Uses Gemini Flash for batch processing.

        Args:
            findings: List of finding dicts

        Returns:
            List of analysis results
        """
        if not findings:
            return []

        # Prepare batch payload
        findings_summary = []
        for f in findings:
            findings_summary.append({
                "check_id": f.get("check_id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "service": f.get("service", ""),
                "resource_id": f.get("resource_id", ""),
                "description": f.get("description", "")[:200],  # Truncate for token efficiency
            })

        user_prompt = BATCH_ANALYSIS_USER_PROMPT_TEMPLATE.format(
            count=len(findings),
            findings_json=json.dumps(findings_summary, indent=2),
        )

        result = None
        if gemini_client.is_available:
            result = await gemini_client.analyze(
                BATCH_ANALYSIS_SYSTEM_PROMPT,
                user_prompt,
            )

        if result is None and claude_client.is_available:
            result = await claude_client.analyze(
                BATCH_ANALYSIS_SYSTEM_PROMPT,
                user_prompt,
            )

        if result is None:
            # Fallback: return deterministic analysis for each
            return [self._fallback_analysis(f) for f in findings]

        # Map results back to findings
        analyses = result.get("analyses", [])
        analysis_map = {a.get("check_id"): a for a in analyses}

        results = []
        for f in findings:
            check_id = f.get("check_id", "")
            if check_id in analysis_map:
                ai_result = analysis_map[check_id]
                base_score = risk_scorer.calculate_base_score(
                    f.get("severity", "medium"), check_id
                )
                ai_result["risk_score"] = risk_scorer.adjust_with_ai(
                    base_score, ai_result.get("risk_score", base_score)
                )
                results.append(ai_result)
            else:
                results.append(self._fallback_analysis(f))

        return results

    def _fallback_analysis(self, finding: dict) -> dict:
        """Generate a deterministic analysis when AI is unavailable."""
        severity = finding.get("severity", "medium")
        check_id = finding.get("check_id", "")
        base_score = risk_scorer.calculate_base_score(severity, check_id)

        return {
            "risk_score": base_score,
            "explanation": finding.get("description", "Security misconfiguration detected."),
            "impact": f"This {severity}-severity finding could lead to unauthorized access or data exposure if not addressed.",
            "remediation_steps": [
                "Review the affected resource configuration",
                "Apply the recommended security settings",
                "Verify the fix by re-scanning",
            ],
            "severity_justification": f"Classified as {severity} based on security best practices.",
            "compliance_frameworks": ["CIS AWS Benchmark"],
            "aws_best_practice": "AWS Well-Architected Framework - Security Pillar",
        }

    def _fallback_deep_analysis(self, finding: dict) -> dict:
        """Generate a deterministic deep analysis when AI is unavailable."""
        base = self._fallback_analysis(finding)
        base.update({
            "attack_scenarios": [{
                "name": "Configuration Exploitation",
                "description": "An attacker could exploit this misconfiguration to gain unauthorized access.",
                "likelihood": "medium",
                "impact_level": finding.get("severity", "medium"),
            }],
            "aws_cli_commands": ["Review AWS documentation for specific CLI commands"],
            "similar_breaches": ["Multiple cloud breaches have been attributed to similar misconfigurations"],
            "monitoring_recommendations": [
                "Enable CloudTrail logging",
                "Set up CloudWatch alarms for configuration changes",
                "Use AWS Config rules for continuous compliance monitoring",
            ],
        })
        return base


# Singleton instance
ai_agent = AIAgent()
