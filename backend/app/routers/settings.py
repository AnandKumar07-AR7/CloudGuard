"""
CloudGuard Settings Router
Endpoints for AWS configuration, API key management, and connection testing.
"""

import os
from fastapi import APIRouter, Depends
from app.schemas import AWSConnectionTest, SettingsResponse
from app.services.aws_service import aws_service
from app.config import settings

router = APIRouter(prefix="/api/settings", tags=["Settings"])


@router.get("", response_model=SettingsResponse)
def get_settings():
    """Get current application settings (without exposing secrets)."""
    return SettingsResponse(
        aws_configured=settings.is_aws_configured,
        aws_region=settings.aws_default_region,
        gemini_configured=settings.is_gemini_configured,
        claude_configured=settings.is_claude_configured,
        scan_interval_minutes=settings.scan_interval_minutes,
    )


@router.post("/test-connection", response_model=AWSConnectionTest)
def test_aws_connection():
    """Test AWS connectivity and return account information."""
    result = aws_service.test_connection()
    return AWSConnectionTest(**result)


@router.get("/health")
def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
        "aws_configured": settings.is_aws_configured,
        "gemini_configured": settings.is_gemini_configured,
        "claude_configured": settings.is_claude_configured,
    }
