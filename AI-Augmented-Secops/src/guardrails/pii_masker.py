"""PII and sensitive-data masking (Requirement 4).

Combines Microsoft Presidio detections (score >= 0.5) with custom regex rules for
cloud secrets and infrastructure identifiers. Every detected span is replaced with
``[REDACTED:<ENTITY_TYPE>]``.

Design notes:
- Idempotence: existing redaction markers are split out of the text before detection, so
  detectors never see them; the text is also re-masked until it reaches a fixed
  point (bounded number of passes) so a detector that fires on text exposed by a
  previous replacement cannot break ``mask(mask(s)) == mask(s)``.
- Fail closed: if the regex layer raises for a value, the whole value becomes
  ``[REDACTED:MASKING_FAILURE]``. If only Presidio fails, regex rules are used alone
  and ``degraded_mode`` is set.
- The returned MaskingSummary holds entity-type counts and the degraded flag only,
  never any raw value or fragment.
"""

from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

from src.models import MaskingSummary

MAX_DEPTH = 20
MIN_PRESIDIO_SCORE = 0.5
MASKING_FAILURE = "MASKING_FAILURE"
FAILURE_PLACEHOLDER = f"[REDACTED:{MASKING_FAILURE}]"
_MAX_PASSES = 5
_SPACY_MODEL = "en_core_web_sm"

_PLACEHOLDER_RE = re.compile(r"\[REDACTED:[A-Z0-9_]+\]")

# Presidio entity types treated as Sensitive_Values. Network identifiers, dates and
# locations are deliberately excluded (handled by regex rules or not sensitive here).
_PRESIDIO_ENTITIES = (
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "US_SSN",
    "IBAN_CODE",
    "US_PASSPORT",
    "US_DRIVER_LICENSE",
    "US_BANK_NUMBER",
    "MEDICAL_LICENSE",
    "UK_NHS",
    "CRYPTO",
)


@dataclass(frozen=True)
class _Rule:
    entity: str
    pattern: "re.Pattern[str]"
    group: Any = 0
    validator: Optional[Callable[[str], bool]] = None


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    entity: str
    priority: int


class _MaskingFailure(Exception):
    """Internal: the regex layer failed for a value."""


class _Acc:
    """Accumulates per-entity counts and the degraded-mode flag."""

    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.degraded = False

    def add(self, entity: str, n: int = 1) -> None:
        self.counts[entity] = self.counts.get(entity, 0) + n

    def merge(self, other: "_Acc") -> None:
        for k, v in other.counts.items():
            self.add(k, v)
        self.degraded = self.degraded or other.degraded

    def summary(self) -> MaskingSummary:
        return MaskingSummary(counts=dict(self.counts), degraded_mode=self.degraded)


def _is_mixed_secret(value: str) -> bool:
    return (
        any(c.islower() for c in value)
        and any(c.isupper() for c in value)
        and any(c.isdigit() for c in value)
    )


def _is_bearer_value(value: str) -> bool:
    # "Bearer authentication" is prose; real tokens are long or contain a digit.
    token = value.split(None, 1)[1] if len(value.split(None, 1)) > 1 else ""
    return len(token) >= 16 or any(c.isdigit() for c in token)


_H = r"[0-9A-Fa-f]{1,4}"
_IPV6 = (
    r"(?<![\w:])(?:"
    rf"(?:{_H}:){{7}}{_H}"
    rf"|(?:{_H}:){{1,7}}:"
    rf"|(?:{_H}:){{1,6}}:{_H}"
    rf"|(?:{_H}:){{1,5}}(?::{_H}){{1,2}}"
    rf"|(?:{_H}:){{1,4}}(?::{_H}){{1,3}}"
    rf"|(?:{_H}:){{1,3}}(?::{_H}){{1,4}}"
    rf"|(?:{_H}:){{1,2}}(?::{_H}){{1,5}}"
    rf"|{_H}:(?::{_H}){{1,6}}"
    rf"|::(?:{_H}:){{0,6}}{_H}"
    r")(?![\w:])"
)

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
_IPV4 = rf"(?<![\d.])(?:{_OCTET}\.){{3}}{_OCTET}(?!\d)"

_EMAIL_LOCAL_LB = r"(?<![A-Za-z0-9._%+\-])"

_STATIC_RULES: tuple[_Rule, ...] = (
    _Rule(
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
            r"(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)"
        ),
    ),
    _Rule(
        "GCP_SERVICE_ACCOUNT_EMAIL",
        re.compile(
            _EMAIL_LOCAL_LB + r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*"
            r"\.iam\.gserviceaccount\.com"
        ),
    ),
    _Rule("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b")),
    _Rule(
        "AWS_SECRET_ACCESS_KEY",
        re.compile(
            r"(?i)\baws_?secret_?(?:access_?)?key\b[\"']?\s*[:=]\s*[\"']?(?P<v>[A-Za-z0-9/+=]{40})"
        ),
        group="v",
    ),
    _Rule(
        "AWS_SECRET_ACCESS_KEY",
        re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"),
        validator=_is_mixed_secret,
    ),
    _Rule("GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    _Rule("SLACK_TOKEN", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    _Rule(
        "BEARER_TOKEN",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{8,}=*"),
        validator=_is_bearer_value,
    ),
    _Rule(
        "API_TOKEN",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
    ),
    _Rule("API_TOKEN", re.compile(r"\bSYNTH-[A-Za-z0-9_\-]{6,}")),
    _Rule("API_TOKEN", re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}")),
    _Rule("API_TOKEN", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    _Rule(
        "API_TOKEN",
        re.compile(
            r"(?i)\b(?:api[_\-]?key|apikey|api[_\-]?token|access[_\-]?token|auth[_\-]?token|"
            r"client[_\-]?secret|secret|password|passwd|token)\b[\"']?\s*[:=]\s*[\"']?"
            r"(?P<v>[A-Za-z0-9_\-./+=]{8,})"
        ),
        group="v",
    ),
    _Rule("AWS_ACCOUNT_ID", re.compile(r"(?<!\d)\d{12}(?!\d)")),
    _Rule(
        "GCP_PROJECT_ID",
        re.compile(
            r"(?i)\b(?:gcp[_\-]?project(?:[_\-]?id)?|project[_\-]?id|project)\b[\"']?\s*[:=]\s*[\"']?"
            r"(?P<v>[a-z][a-z0-9\-]{4,28}[a-z0-9])"
        ),
        group="v",
    ),
    _Rule("GCP_PROJECT_ID", re.compile(r"(?<![A-Za-z0-9\-])(?<=projects/)[a-z][a-z0-9\-]{4,28}[a-z0-9]")),
    _Rule("GCP_PROJECT_ID", re.compile(r"(?<![A-Za-z0-9\-])[a-z][a-z\-]{2,24}-\d{5,12}(?![A-Za-z0-9\-])")),
    _Rule("IPV4_ADDRESS", re.compile(_IPV4)),
    _Rule("IPV6_ADDRESS", re.compile(_IPV6)),
    _Rule(
        "EMAIL_ADDRESS",
        re.compile(_EMAIL_LOCAL_LB + r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+"),
    ),
)


def _build_hostname_rules(suffixes: Sequence[str]) -> tuple[_Rule, ...]:
    rules: list[_Rule] = []
    for raw in suffixes:
        suffix = str(raw).strip()
        if not suffix:
            continue
        if not suffix.startswith("."):
            suffix = "." + suffix
        pattern = re.compile(
            r"(?<![A-Za-z0-9\-.])[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?"
            r"(?:\.[A-Za-z0-9][A-Za-z0-9\-]*)*" + re.escape(suffix) + r"(?![A-Za-z0-9\-])",
            re.IGNORECASE,
        )
        rules.append(_Rule("INTERNAL_HOSTNAME", pattern))
    return tuple(rules)


def _configure_tldextract_offline() -> None:
    """Make tldextract (used by Presidio's EmailRecognizer) use only its bundled
    public-suffix snapshot: no HTTP fetch and no on-disk cache."""
    try:
        import tldextract  # type: ignore[import-not-found]
        import tldextract.tldextract as _tld_module  # type: ignore[import-not-found]

        _tld_module.TLD_EXTRACTOR = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=())
    except Exception:  # tldextract absent or API changed: nothing to configure
        pass


class PIIMasker:
    """Masks Sensitive_Values in text and in nested structures."""

    def __init__(
        self,
        internal_suffixes: Sequence[str],
        presidio: bool = True,
        analyzer: Any = None,
    ) -> None:
        self._rules: tuple[_Rule, ...] = _STATIC_RULES + _build_hostname_rules(internal_suffixes)
        self._use_presidio = bool(presidio) or analyzer is not None
        self._analyzer: Any = analyzer
        self._analyzer_failed = False
        self._init_lock = threading.Lock()

    # ------------------------------------------------------------------ public API

    def mask_text(self, text: str) -> tuple[str, MaskingSummary]:
        """Mask Sensitive_Values in one string."""
        acc = _Acc()
        out = self._mask_text(text, acc)
        return out, acc.summary()

    def mask_value(self, value: Any) -> tuple[Any, MaskingSummary]:
        """Recursively mask a value (dict, list, tuple, JSON string, scalar)."""
        acc = _Acc()
        out = self._mask_value(value, 1, acc)
        return out, acc.summary()

    def mask_rows(self, rows: list[dict]) -> tuple[list[dict], MaskingSummary]:
        """Mask every cell of every row, merging the summaries."""
        acc = _Acc()
        out = [self._mask_value(row, 1, acc) for row in rows]
        return out, acc.summary()

    # ------------------------------------------------------------ structure walking

    def _mask_value(self, value: Any, depth: int, acc: _Acc) -> Any:
        if isinstance(value, str):
            return self._mask_string(value, depth, acc)
        if isinstance(value, (dict, list, tuple)):
            if depth > MAX_DEPTH:
                acc.add(MASKING_FAILURE)
                return FAILURE_PLACEHOLDER
            if isinstance(value, dict):
                return {k: self._mask_value(v, depth + 1, acc) for k, v in value.items()}
            items = [self._mask_value(v, depth + 1, acc) for v in value]
            return tuple(items) if isinstance(value, tuple) else items
        if isinstance(value, (bytes, bytearray)):
            return self._mask_text(bytes(value).decode("utf-8", errors="replace"), acc)
        return value  # int, float, bool, None, date/time, Decimal, ...

    def _mask_string(self, text: str, depth: int, acc: _Acc) -> str:
        stripped = text.strip()
        if stripped[:1] in ("{", "[") and stripped[-1:] in ("}", "]"):
            try:
                parsed = json.loads(stripped)
            except (ValueError, RecursionError):
                parsed = None
            if isinstance(parsed, (dict, list)):
                sub = _Acc()
                masked = self._mask_value(parsed, depth + 1, sub)
                acc.merge(sub)
                if not sub.counts:
                    return text  # nothing changed: keep original formatting
                return json.dumps(masked, ensure_ascii=False)
        return self._mask_text(text, acc)

    # ------------------------------------------------------------------ text masking

    def _mask_text(self, text: str, acc: _Acc) -> str:
        local = _Acc()
        try:
            current = text
            for _ in range(_MAX_PASSES):
                nxt = self._mask_pass(current, local)
                if nxt == current:
                    break
                current = nxt
        except Exception:  # fail closed: replace the whole value
            acc.add(MASKING_FAILURE)
            acc.degraded = acc.degraded or local.degraded
            return FAILURE_PLACEHOLDER
        acc.merge(local)
        return current

    def _mask_pass(self, text: str, acc: _Acc) -> str:
        parts: list[str] = []
        pos = 0
        for match in _PLACEHOLDER_RE.finditer(text):
            parts.append(self._mask_segment(text[pos : match.start()], acc))
            parts.append(match.group(0))
            pos = match.end()
        parts.append(self._mask_segment(text[pos:], acc))
        return "".join(parts)

    def _mask_segment(self, segment: str, acc: _Acc) -> str:
        if not segment.strip():
            return segment
        try:
            spans = self._regex_spans(segment)
        except Exception as exc:
            raise _MaskingFailure("regex layer failed") from exc
        spans.extend(self._presidio_spans(segment, acc))
        chosen = self._select_spans(spans)
        if not chosen:
            return segment
        out: list[str] = []
        pos = 0
        for span in chosen:
            out.append(segment[pos : span.start])
            out.append(f"[REDACTED:{span.entity}]")
            acc.add(span.entity)
            pos = span.end
        out.append(segment[pos:])
        return "".join(out)

    @staticmethod
    def _select_spans(spans: list[_Span]) -> list[_Span]:
        """Merge overlaps: longest span wins, ties broken by fixed entity priority."""
        ordered = sorted(spans, key=lambda s: (-(s.end - s.start), s.priority, s.start))
        chosen: list[_Span] = []
        for span in ordered:
            if span.end <= span.start:
                continue
            if all(span.end <= c.start or span.start >= c.end for c in chosen):
                chosen.append(span)
        chosen.sort(key=lambda s: s.start)
        return chosen

    # ------------------------------------------------------------------- detectors

    def _regex_spans(self, text: str) -> list[_Span]:
        spans: list[_Span] = []
        for priority, rule in enumerate(self._rules):
            for match in rule.pattern.finditer(text):
                start, end = match.span(rule.group)
                if start < 0 or end <= start:
                    continue
                if rule.validator is not None and not rule.validator(text[start:end]):
                    continue
                spans.append(_Span(start, end, rule.entity, priority))
        return spans

    def _get_analyzer(self) -> Any:
        if self._analyzer is not None or self._analyzer_failed or not self._use_presidio:
            return self._analyzer
        with self._init_lock:
            if self._analyzer is not None or self._analyzer_failed:
                return self._analyzer
            try:
                self._analyzer = self._build_presidio()
            except Exception:
                self._analyzer_failed = True
                self._analyzer = None
        return self._analyzer

    @staticmethod
    def _build_presidio() -> Any:
        import spacy.util  # type: ignore[import-not-found]
        from presidio_analyzer import AnalyzerEngine  # type: ignore[import-not-found]
        from presidio_analyzer.nlp_engine import NlpEngineProvider  # type: ignore[import-not-found]

        _configure_tldextract_offline()
        # Never let Presidio try to download a model at runtime (offline operation).
        if not spacy.util.is_package(_SPACY_MODEL):
            raise RuntimeError("spaCy model not installed")
        provider = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": _SPACY_MODEL}],
            }
        )
        return AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])

    def _presidio_spans(self, text: str, acc: _Acc) -> list[_Span]:
        if not self._use_presidio:
            return []
        analyzer = self._get_analyzer()
        if analyzer is None:
            acc.degraded = True
            return []
        try:
            results = analyzer.analyze(
                text=text,
                language="en",
                entities=list(_PRESIDIO_ENTITIES),
                score_threshold=MIN_PRESIDIO_SCORE,
            )
            base = len(self._rules)
            return [
                _Span(int(r.start), int(r.end), str(r.entity_type).upper(), base)
                for r in results
                if float(r.score) >= MIN_PRESIDIO_SCORE
            ]
        except Exception:
            acc.degraded = True
            return []
