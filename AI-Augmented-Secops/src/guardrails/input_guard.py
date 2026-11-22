"""Input_Guard: prompt sanitization and prompt-injection detection.

Deterministic, fail-closed guard that runs before any text reaches the LLM.
All patterns are precompiled, case-insensitive and use only bounded
repetition (no nested quantifiers) so evaluation is linear-time.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Literal

from src.models import Decision, GuardrailDecision, InputGuardResult, ScrubReport

GUARD_NAME = "input_guard"
MAX_PROMPT_CHARS = 2000
_MAX_SCRUB_PASSES = 5


class GuardError(Exception):
    """Raised when the guard cannot complete evaluation of retrieved text."""


# --------------------------------------------------------------------------
# Normalization
# --------------------------------------------------------------------------

_WS_RUN = re.compile(r"\s{2,}")


def normalize(text: str) -> str:
    """NFKC-normalize, drop Cc/Cf characters, and collapse whitespace runs.

    Whitespace characters (including newlines and tabs, which are category Cc)
    are converted to a plain space before control characters are removed so
    words are not fused. The result is stripped, which keeps the function
    idempotent.
    """
    s = unicodedata.normalize("NFKC", text)
    s = "".join(" " if ch.isspace() else ch for ch in s)
    s = "".join(ch for ch in s if unicodedata.category(ch) not in ("Cc", "Cf"))
    s = _WS_RUN.sub(" ", s)
    return s.strip()


# --------------------------------------------------------------------------
# Pattern families
# --------------------------------------------------------------------------

_FLAGS = re.IGNORECASE


def _c(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, _FLAGS)


_INJECTION_PATTERNS = [
    _c(
        r"\b(?:ignore|override|disregard|forget)\b(?:\s+(?:all|any|the|your|my|of|everything|these|those)){0,3}"
        r"\s+(?:previous|prior|above|earlier|preceding)\b"
    ),
    _c(
        r"\b(?:ignore|override|disregard)\b(?:\s+(?:all|any|the|your|my|of|these|those)){0,3}"
        r"\s+(?:instructions?|rules|guidelines|directives)\b"
    ),
]

_EXFIL_VERBS = (
    r"(?:reveal|show|print|repeat|display|output|disclose|tell|dump|leak|give|expose|echo|recite|"
    r"share|list|return|send|read|paste)"
)
_EXFIL_PATTERNS = [
    _c(
        r"\b" + _EXFIL_VERBS + r"\b[^.?!]{0,60}?\b(?:system|hidden|initial|secret|internal|original)\s+"
        r"(?:prompts?|instructions?|configuration|config|messages?|rules)\b"
    ),
    _c(
        r"\b" + _EXFIL_VERBS + r"\b[^.?!]{0,40}?\byour\s+(?:prompts?|instructions|configuration|config|rules|"
        r"guidelines)\b"
    ),
    _c(
        r"\bwhat\s+(?:is|are|were)\s+your\s+(?:system\s+prompt|initial\s+prompt|instructions|rules|"
        r"configuration|config|hidden\s+instructions)\b"
    ),
    _c(r"\b(?:system\s+prompt|hidden\s+instructions)\b[^.?!]{0,30}?\b(?:verbatim|word\s+for\s+word)\b"),
]

_WRITE_KW = r"(?:drop|delete|update|insert|alter|truncate|attach|copy)"
_WRITE_PATTERNS = [
    # Imperative at the start of the prompt or of a clause.
    _c(
        r"(?:^|[;.!?,]\s*|\b(?:then|and|also|now)\s+)"
        r"(?:(?:please|kindly)\s+)?" + _WRITE_KW + r"\b"
    ),
    # Polite / modal imperative forms.
    _c(
        r"\b(?:can|could|would|will)\s+you\s+(?:please\s+)?" + _WRITE_KW + r"\b"
    ),
    _c(
        r"\b(?:i\s+(?:want|need)\s+you\s+to|you\s+(?:must|should|need\s+to)|please)\s+" + _WRITE_KW + r"\b"
    ),
    # SQL statement shapes anywhere in the prompt.
    _c(r"\b(?:drop|truncate)\s+(?:table|database|schema|view|index|all|every|the)\b"),
    _c(r"\bdelete\s+(?:from|all|every|the)\b"),
    _c(r"\binsert\s+into\b"),
    _c(r"\bupdate\s+\w+(?:\.\w+)?\s+set\b"),
    _c(r"\balter\s+(?:table|database|schema|view|index)\b"),
    _c(r"\battach\s+(?:database|['\"]|\S+\s+as\b)"),
    _c(r"\bcopy\s+(?:\w+(?:\.\w+)?|\([^)]{0,200}\))\s+(?:to|from)\b"),
]

_JAILBREAK_PATTERNS = [
    _c(
        r"\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are|that\s+you\s+are)|role-?play\s+as|"
        r"behave\s+(?:as|like)|from\s+now\s+on\s+you|assume\s+the\s+role|take\s+on\s+the\s+role|"
        r"adopt\s+(?:a|an|the)\s+(?:\w+\s+){0,2}persona|new\s+persona|switch\s+to\s+\w+\s+mode)\b"
    ),
    _c(
        r"\b(?:disable|bypass|turn\s+off|switch\s+off|deactivate|circumvent|remove|ignore|override|disregard)\b"
        r"(?:\s+\w+){0,3}?\s+(?:safety|guardrails?|restrictions?|filters?|controls?|protections?|"
        r"safeguards?|limitations?)\b"
    ),
    _c(r"\b(?:developer\s+mode|dan\s+mode|do\s+anything\s+now|jailbreak(?:ed)?)\b"),
]

_PROMPT_CHECKS: list[tuple[str, list[re.Pattern[str]]]] = [
    ("prompt_injection", _INJECTION_PATTERNS),
    ("system_prompt_exfiltration", _EXFIL_PATTERNS),
    ("write_intent", _WRITE_PATTERNS),
    ("jailbreak_attempt", _JAILBREAK_PATTERNS),
]

# Patterns applied to retrieved text (criteria 2, 3 and 5 only).
_SCRUB_PATTERNS = _INJECTION_PATTERNS + _EXFIL_PATTERNS + _JAILBREAK_PATTERNS

# Splits text into sentence/line segments covering the whole string.
_SEGMENT = re.compile(r"[^.!?\n]+(?:[.!?]+|\n)?|[.!?\n]+")


# --------------------------------------------------------------------------
# Decisions
# --------------------------------------------------------------------------


def _blocked(reason: str) -> InputGuardResult:
    return InputGuardResult(
        decision=GuardrailDecision(guard=GUARD_NAME, decision=Decision.blocked, reason_code=reason),
        normalized_prompt=None,
    )


def _matches_any(text: str, patterns: list[re.Pattern[str]]) -> bool:
    return any(p.search(text) is not None for p in patterns)


def check_prompt(prompt: str) -> InputGuardResult:
    """Normalize and evaluate a user prompt.

    Fixed precedence: empty_prompt, prompt_too_long, prompt_injection,
    system_prompt_exfiltration, write_intent, jailbreak_attempt. Any internal
    error yields a blocked ``guard_error`` decision.
    """
    try:
        if not isinstance(prompt, str):
            raise TypeError("prompt must be a string")
        normalized = normalize(prompt)
        if not normalized:
            return _blocked("empty_prompt")
        if len(normalized) > MAX_PROMPT_CHARS:
            return _blocked("prompt_too_long")
        for reason, patterns in _PROMPT_CHECKS:
            if _matches_any(normalized, patterns):
                return _blocked(reason)
        return InputGuardResult(
            decision=GuardrailDecision(guard=GUARD_NAME, decision=Decision.allowed, reason_code=None),
            normalized_prompt=normalized,
        )
    except Exception:  # fail closed
        return _blocked("guard_error")


# --------------------------------------------------------------------------
# Retrieved-content scrubbing
# --------------------------------------------------------------------------


def scrub_retrieved(text: str, source: Literal["runbook", "db_row"]) -> ScrubReport:
    """Remove prompt-injection segments from retrieved runbook or DB row text.

    Each sentence/line segment matching an injection, exfiltration or
    jailbreak pattern (evaluated on its normalized form, so obfuscation does
    not help) is deleted. Returns the cleaned text, the number of removed
    segments and the source. Raises ``GuardError`` on internal failure.
    """
    try:
        if not isinstance(text, str):
            raise TypeError("text must be a string")
        removed = 0
        current = text
        for _ in range(_MAX_SCRUB_PASSES):
            kept: list[str] = []
            removed_this_pass = 0
            for match in _SEGMENT.finditer(current):
                segment = match.group(0)
                if _matches_any(normalize(segment), _SCRUB_PATTERNS):
                    removed_this_pass += 1
                else:
                    kept.append(segment)
            if removed_this_pass == 0:
                break
            removed += removed_this_pass
            current = "".join(kept)
        return ScrubReport(text=current, removed_count=removed, source=source)
    except Exception as exc:
        raise GuardError("input guard failed to scrub retrieved text") from exc
