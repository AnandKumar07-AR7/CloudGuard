"""
CloudGuard Configuration Module
Loads environment variables and provides application settings.
"""

# pyrefly: ignore [missing-import]
from pydantic_settings import BaseSettings
from typing import Optional
import os
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Application
    app_name: str = "CloudGuard"
    app_version: str = "1.0.0"
    app_env: str = "development"  # Set to 'production' on Render
    app_secret_key: str = "change-this-to-a-random-secret-key"
    # Comma-separated origins. On Render, set to your Vercel URL
    cors_origins: str = "http://localhost:5173"

    # AWS
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_default_region: str = "us-east-1"

    # AI API Keys
    gemini_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None

    # Database
    database_url: str = "sqlite:///./cloudguard.db"

    # Scan Settings
    scan_interval_minutes: int = 30

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",")]

    @property
    def is_aws_configured(self) -> bool:
        return bool(self.aws_access_key_id and self.aws_secret_access_key)

    @property
    def is_gemini_configured(self) -> bool:
        return bool(self.gemini_api_key)

    @property
    def is_claude_configured(self) -> bool:
        return bool(self.anthropic_api_key)

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
