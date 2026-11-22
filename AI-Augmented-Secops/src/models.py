"""Shared Pydantic models for secops-triage-guard."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field


class UserRole(str, Enum):
    analyst = "analyst"
    admin = "admin"
    viewer = "viewer"


class Decision(str, Enum):
    allowed = "allowed"
    blocked = "blocked"


class GuardrailDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    guard: str  # "input_guard" | "sql_validator" | ...
    decision: Decision
    reason_code: Optional[str] = None


class InputGuardResult(BaseModel):
    decision: GuardrailDecision
    normalized_prompt: Optional[str] = None


class SqlValidationResult(BaseModel):
    decision: GuardrailDecision
    sql: Optional[str] = None  # only set when allowed


class ScrubReport(BaseModel):
    text: str
    removed_count: int = Field(ge=0)
    source: Literal["runbook", "db_row"]


class MaskingSummary(BaseModel):
    counts: dict[str, int] = Field(default_factory=dict)
    degraded_mode: bool = False


class TriageRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=4000)
    role: UserRole


class TriageResponse(BaseModel):
    request_id: str
    answer: str
    generated_sql: str
    validated_sql: str
    rows: list[dict[str, Any]] = Field(default_factory=list)
    cited_runbooks: list[str] = Field(default_factory=list)
    guardrail_decisions: list[GuardrailDecision] = Field(default_factory=list)
    masking_summary: MaskingSummary = Field(default_factory=MaskingSummary)


class BlockedResponse(BaseModel):
    request_id: str
    guardrail: str
    reason_code: str


class ErrorResponse(BaseModel):
    request_id: str
    error: str
    reason_code: str
    message: str = ""
    retry_after_seconds: Optional[int] = None


class AuditEntry(BaseModel):
    """Input to AuditLogger.append; the logger adds timestamp and prev_hash."""

    request_id: str
    user_role: str
    prompt: str
    generated_sql: Optional[str] = None
    validated_sql: Optional[str] = None
    guardrail_decisions: list[GuardrailDecision] = Field(default_factory=list)
    outcome: Literal["success", "blocked", "error"]
    reason_code: Optional[str] = None
    error_class: Optional[str] = None  # database error class name only (Req 3.6)
    row_count: int = Field(default=0, ge=0, le=1_000_000)
    latency_ms: int = Field(default=0, ge=0, le=600_000)
    masking_summary: MaskingSummary = Field(default_factory=MaskingSummary)


class AuditRecord(BaseModel):
    """One written line of audit_logs.jsonl."""

    timestamp: str  # UTC ISO 8601 with millisecond precision
    request_id: str
    user_role: str
    prompt: str
    generated_sql: Optional[str] = None
    validated_sql: Optional[str] = None
    guardrail_decisions: list[GuardrailDecision] = Field(default_factory=list)
    outcome: Literal["success", "blocked", "error"]
    reason_code: Optional[str] = None
    error_class: Optional[str] = None  # database error class name only (Req 3.6)
    row_count: int = Field(default=0, ge=0, le=1_000_000)
    latency_ms: int = Field(default=0, ge=0, le=600_000)
    masking_summary: MaskingSummary = Field(default_factory=MaskingSummary)
    prev_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class VerifyResult(BaseModel):
    valid: bool
    first_invalid_line: Optional[int] = None


TriageOutcome = Union[TriageResponse, BlockedResponse, ErrorResponse]
