"""Application configuration.

All settings come from environment variables (or a local .env file) with safe
defaults. Nothing here is required to run: the scanner works fully offline with
no LLM and no external services.

Secrets (LLM_API_KEY) are read into memory for the process lifetime but are
NEVER logged: backend/core/logging.py redacts known secret-bearing field names
and the API never echoes settings back to clients.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Where uploaded config files and generated reports are stored.
DATA_DIR = PROJECT_ROOT / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
REPORT_DIR = DATA_DIR / "reports"
DB_DIR = DATA_DIR / "db"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Automated MCP Pentester"
    debug: bool = False

    # --- Storage -----------------------------------------------------------
    database_url: str = f"sqlite+aiosqlite:///{(DB_DIR / 'mcpentest.db').as_posix()}"

    # --- Scan safety defaults (SAFE BY DEFAULT) ----------------------------
    safe_mode: bool = True
    dynamic_testing_enabled: bool = False
    semantic_analysis_enabled: bool = False

    scan_timeout_seconds: int = Field(default=300, ge=10, le=3600)
    per_test_timeout_seconds: float = Field(default=10.0, ge=0.5, le=120.0)
    max_payload_size_bytes: int = Field(default=64 * 1024, ge=256, le=1024 * 1024)
    max_dynamic_requests: int = Field(default=100, ge=1, le=10_000)
    dynamic_rate_limit_per_second: float = Field(default=5.0, ge=0.1, le=100.0)
    max_upload_size_bytes: int = Field(default=1024 * 1024, ge=1024, le=10 * 1024 * 1024)
    max_tools_per_scan: int = Field(default=500, ge=1, le=5000)

    # --- Network egress control (SSRF defenses) -----------------------------
    # Block private/link-local/loopback targets for dynamic scans unless the
    # operator explicitly allows local testing (needed for the bundled fixture
    # servers, which are themselves localhost-only).
    allow_local_targets: bool = False
    # Explicit extra CIDRs/hostnames that are allowed for dynamic testing even
    # though they look private (e.g. a lab subnet). Never broadens public DNS.
    allowed_target_cidrs: list[str] = Field(default_factory=list)

    # --- Optional semantic layer --------------------------------------------
    # provider: disabled | local | external
    llm_provider: str = "disabled"
    llm_endpoint: str = ""
    llm_model: str = ""
    llm_api_key: str = ""
    llm_timeout_seconds: float = Field(default=20.0, ge=1.0, le=300.0)

    # --- ML -----------------------------------------------------------------
    ml_model_dir: str = str(PROJECT_ROOT / "ml" / "artifacts")
    ml_enabled: bool = True

    # --- Server -------------------------------------------------------------
    # API authentication. ON by default; the key comes from API_KEY or data/api_key (auto-generated).
    auth_required: bool = True
    api_key: str = ""
    auth_max_failures_per_minute: int = Field(default=10, ge=1, le=1000)
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])
    rate_limit_per_minute: int = Field(default=60, ge=1, le=10_000)

    @field_validator("llm_provider")
    @classmethod
    def _validate_llm_provider(cls, v: str) -> str:
        allowed = {"disabled", "local", "external"}
        v = v.strip().lower()
        if v not in allowed:
            raise ValueError(f"LLM_PROVIDER must be one of {sorted(allowed)}")
        return v

    @field_validator("database_url")
    @classmethod
    def _ensure_data_dirs(cls, v: str) -> str:
        DB_DIR.mkdir(parents=True, exist_ok=True)
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
