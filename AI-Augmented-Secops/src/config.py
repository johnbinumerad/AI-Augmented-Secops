"""Configuration for secops-triage-guard.

Single source of truth for environment-driven settings, the allowlisted schema
(Requirement 2.14) and the role policy. Errors name only the offending variable
and never print its value (Requirement 11.7).
"""

from __future__ import annotations

import re
import sys
from typing import Optional
from urllib.parse import urlparse

from pydantic import ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ALLOWED_DIALECTS = ("duckdb", "sqlite")
_MODEL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/\-]*$")
_SUFFIX_RE = re.compile(r"^\.?[A-Za-z0-9][A-Za-z0-9.\-]*$")


class ConfigError(Exception):
    """Raised when a configuration variable is empty or malformed.

    The message names only the variable, never its value.
    """

    def __init__(self, variable: str) -> None:
        self.variable = variable
        super().__init__(f"Invalid or empty configuration variable: {variable}")


def _require_non_empty(value: str) -> str:
    if value is None or not str(value).strip():
        raise ValueError("empty")
    return str(value).strip()


class Settings(BaseSettings):
    """Environment-driven settings. Field names equal environment variable names."""

    model_config = SettingsConfigDict(
        case_sensitive=False,
        extra="ignore",
        env_ignore_empty=False,
        frozen=True,
    )

    LLM_MODEL: str = "llama3.2"
    OLLAMA_URL: str = "http://localhost:11434"
    DB_PATH: str = "data/findings.duckdb"
    RUNBOOK_STORE_PATH: str = "data/runbook_store"
    AUDIT_LOG_PATH: str = "audit_logs.jsonl"
    INTERNAL_DOMAIN_SUFFIXES: str = ".corp.example.com,.internal.example.net"
    API_KEY: Optional[str] = None
    SQL_DIALECT: str = "duckdb"

    @field_validator("LLM_MODEL", mode="before")
    @classmethod
    def _check_model(cls, value: str) -> str:
        value = _require_non_empty(value)
        if not _MODEL_NAME_RE.match(value):
            raise ValueError("malformed")
        return value

    @field_validator("OLLAMA_URL", mode="before")
    @classmethod
    def _check_url(cls, value: str) -> str:
        value = _require_non_empty(value)
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc or not parsed.hostname:
            raise ValueError("malformed")
        try:
            parsed.port  # noqa: B018 - raises ValueError for an invalid port
        except ValueError as exc:
            raise ValueError("malformed") from exc
        return value

    @field_validator("DB_PATH", "RUNBOOK_STORE_PATH", "AUDIT_LOG_PATH", mode="before")
    @classmethod
    def _check_path(cls, value: str) -> str:
        value = _require_non_empty(value)
        if "\x00" in value:
            raise ValueError("malformed")
        return value

    @field_validator("INTERNAL_DOMAIN_SUFFIXES", mode="before")
    @classmethod
    def _check_suffixes(cls, value: str) -> str:
        value = _require_non_empty(value)
        parts = [p.strip() for p in value.split(",")]
        if not parts or any(not p or not _SUFFIX_RE.match(p) for p in parts):
            raise ValueError("malformed")
        return ",".join(parts)

    @field_validator("API_KEY", mode="before")
    @classmethod
    def _check_api_key(cls, value: Optional[str]) -> Optional[str]:
        # API_KEY is optional and has no default; an empty value means "not configured".
        if value is None or not str(value).strip():
            return None
        return str(value)

    @field_validator("SQL_DIALECT", mode="before")
    @classmethod
    def _check_dialect(cls, value: str) -> str:
        value = _require_non_empty(value).lower()
        if value not in ALLOWED_DIALECTS:
            raise ValueError("malformed")
        return value

    @property
    def internal_suffixes(self) -> list[str]:
        """Internal domain suffixes as a list, each starting with a dot."""
        return [s if s.startswith(".") else "." + s for s in self.INTERNAL_DOMAIN_SUFFIXES.split(",")]


def load_settings() -> Settings:
    """Load settings from the environment.

    Raises ConfigError naming only the first offending variable, never its value.
    """
    try:
        return Settings()
    except ValidationError as exc:
        errors = exc.errors()
        variable = "UNKNOWN"
        if errors:
            loc = errors[0].get("loc") or ()
            if loc:
                variable = str(loc[0]).upper()
        raise ConfigError(variable) from None


def load_settings_or_exit() -> Settings:
    """Load settings; on failure log the variable name only and exit non-zero."""
    try:
        return load_settings()
    except ConfigError as err:
        sys.stderr.write(f"Configuration error: variable {err.variable} is empty or malformed\n")
        raise SystemExit(1) from None


# Single configuration structure read by the SQL_Validator, the Triage_Agent prompt
# builder and the Test_Suite (Requirement 2.14).
ALLOWLISTED_SCHEMA: dict[str, list[str]] = {
    "findings": [
        "finding_id",
        "cve_id",
        "provider",
        "category",
        "misconfig_category",
        "severity",
        "cvss_score",
        "asset_id",
        "asset_name",
        "asset_criticality",
        "sla_due_date",
        "sla_status",
        "description",
        "evidence",
        "detected_at",
    ],
}

ROLE_POLICY: dict[str, dict[str, bool]] = {
    "admin": {"audit_read": True, "detail_columns": True},
    "analyst": {"audit_read": True, "detail_columns": True},
    "viewer": {"audit_read": False, "detail_columns": False},
}

# Per-asset detail columns excluded for the "viewer" role (Requirement 6.14).
VIEWER_EXCLUDED_COLUMNS: list[str] = ["asset_id", "asset_name", "description", "evidence"]


def viewer_schema(schema: Optional[dict[str, list[str]]] = None) -> dict[str, list[str]]:
    """Return the allowlisted schema with the viewer-excluded columns removed."""
    base = ALLOWLISTED_SCHEMA if schema is None else schema
    excluded = set(VIEWER_EXCLUDED_COLUMNS)
    return {table: [c for c in cols if c not in excluded] for table, cols in base.items()}


def schema_for_role(role: str, schema: Optional[dict[str, list[str]]] = None) -> dict[str, list[str]]:
    """Return the schema a role may query: restricted for roles without detail columns."""
    base = ALLOWLISTED_SCHEMA if schema is None else schema
    policy = ROLE_POLICY.get(str(getattr(role, "value", role)))
    if policy is None or not policy["detail_columns"]:
        return viewer_schema(base)
    return {table: list(cols) for table, cols in base.items()}
