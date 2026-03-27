"""Application configuration handling using Pydantic settings."""
from __future__ import annotations

import functools
from pathlib import Path

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_name: str = "llm-security-proxy"
    environment: str = Field("development", description="Environment name for logging")
    upstream_base_url: AnyHttpUrl = Field(
        "http://localhost:11434", description="Base URL for upstream OpenAI-compatible server"
    )
    upstream_path: str = Field(
        "/v1/chat/completions", description="Path for upstream completions endpoint"
    )
    request_timeout: float = Field(120.0, description="Upstream request timeout in seconds")
    policy_path: Path = Field(
        Path("app/policies/default_policy.yaml"),
        description="Path to policy configuration file",
    )
    log_level: str = Field("INFO", description="Log level for application")
    enable_output_detection: bool = Field(
        False, description="Whether to run output detectors on upstream responses"
    )
    allowed_tools: list[str] | None = Field(
        default=None,
        description="Override tool allowlist; if None, use values from policy file",
    )

    @field_validator("upstream_path", mode="before")
    @classmethod
    def ensure_leading_slash(cls, value: str) -> str:
        if not value.startswith("/"):
            return "/" + value
        return value


@functools.lru_cache
def get_settings() -> Settings:
    return Settings()


__all__ = ["Settings", "get_settings"]
