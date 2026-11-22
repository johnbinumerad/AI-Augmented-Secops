"""Tamper-evident, append-only JSONL audit logger.

Each record is one compact JSON line carrying ``prev_hash``: the SHA-256 hex
digest of the previous line (without its trailing newline). The first record
uses ``GENESIS_HASH``. Writes are serialized with a thread lock plus an
``fcntl.flock`` on a sidecar lock file so the chain stays valid across threads
and processes.

A best-effort head anchor (``<log>.head``: head hash and record count) is
rewritten on every append and checked by ``verify`` so that deletion of the
final record(s) (which the chain alone cannot reveal) is detected.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.guardrails.pii_masker import PIIMasker
from src.models import AuditEntry, AuditRecord, MaskingSummary, VerifyResult

GENESIS_HASH = "0" * 64

_CHUNK = 8192


class AuditWriteError(Exception):
    """Raised when an Audit_Record cannot be written (triggers audit_failure)."""


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class AuditLogger:
    """Append-only hash-chained audit log."""

    def __init__(self, path: Path | str, masker: PIIMasker) -> None:
        self._path = Path(path)
        self._head_path = Path(str(self._path) + ".head")
        self._lock_path = Path(str(self._path) + ".lock")
        self._masker = masker
        self._thread_lock = threading.Lock()

    # ------------------------------------------------------------------ helpers

    @property
    def path(self) -> Path:
        return self._path

    def _read_last_line(self) -> Optional[bytes]:
        """Return the last non-empty line (no newline) or None for an empty/new log.

        Raises OSError if the file exists but cannot be read.
        """
        if not self._path.exists():
            return None
        with open(self._path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            pos = fh.tell()
            buf = b""
            while pos > 0:
                step = min(_CHUNK, pos)
                pos -= step
                fh.seek(pos)
                buf = fh.read(step) + buf
                stripped = buf.rstrip(b"\r\n")
                if b"\n" in stripped:
                    return stripped.rsplit(b"\n", 1)[1]
            stripped = buf.rstrip(b"\r\n")
            return stripped if stripped else None

    def _read_anchor(self) -> Optional[dict]:
        try:
            raw = self._head_path.read_text(encoding="utf-8")
            data = json.loads(raw)
            if (
                isinstance(data, dict)
                and isinstance(data.get("count"), int)
                and isinstance(data.get("head_hash"), str)
            ):
                return data
        except (OSError, ValueError):
            return None
        return None

    def _count_lines(self) -> int:
        count = 0
        with open(self._path, "rb") as fh:
            for line in fh:
                if line.strip():
                    count += 1
        return count

    def _write_anchor(self, head_hash: str, count: int) -> None:
        """Best-effort head anchor update; failures are deliberately ignored."""
        try:
            tmp = Path(str(self._head_path) + ".tmp")
            payload = json.dumps(
                {"head_hash": head_hash, "count": count}, separators=(",", ":"), sort_keys=True
            )
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._head_path)
        except OSError:
            pass

    def _mask(self, text: Optional[str], acc: dict[str, int], degraded: list[bool]) -> Optional[str]:
        if text is None:
            return None
        masked, summary = self._masker.mask_text(text)
        for key, value in summary.counts.items():
            acc[key] = acc.get(key, 0) + value
        if summary.degraded_mode:
            degraded[0] = True
        return masked

    def _build_record(self, entry: AuditEntry, prev_hash: str) -> AuditRecord:
        counts: dict[str, int] = dict(entry.masking_summary.counts)
        degraded = [entry.masking_summary.degraded_mode]
        data = entry.model_dump(mode="json")
        data["prompt"] = self._mask(entry.prompt, counts, degraded)
        data["generated_sql"] = self._mask(entry.generated_sql, counts, degraded)
        data["validated_sql"] = self._mask(entry.validated_sql, counts, degraded)
        data["reason_code"] = self._mask(entry.reason_code, counts, degraded)
        for decision in data["guardrail_decisions"]:
            decision["reason_code"] = self._mask(decision.get("reason_code"), counts, degraded)
        data["masking_summary"] = MaskingSummary(
            counts=counts, degraded_mode=degraded[0]
        ).model_dump(mode="json")
        data["timestamp"] = (
            datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        )
        data["prev_hash"] = prev_hash
        return AuditRecord.model_validate(data)

    # ------------------------------------------------------------------ public API

    def append(self, entry: AuditEntry) -> AuditRecord:
        """Append exactly one record; raises AuditWriteError on any failure."""
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._thread_lock:
                with open(self._lock_path, "a") as lock_fh:
                    fcntl.flock(lock_fh.fileno(), fcntl.LOCK_EX)
                    try:
                        last = self._read_last_line()
                        prev_hash = GENESIS_HASH if last is None else _sha256_hex(last)
                        record = self._build_record(entry, prev_hash)
                        line = json.dumps(
                            record.model_dump(mode="json"),
                            separators=(",", ":"),
                            sort_keys=True,
                            ensure_ascii=True,
                        ).encode("ascii")
                        if b"\n" in line or b"\r" in line:
                            raise AuditWriteError("serialized record is not a single line")

                        if last is None:
                            count = 1
                        else:
                            anchor = self._read_anchor()
                            if anchor is not None and anchor["head_hash"] == prev_hash:
                                count = anchor["count"] + 1
                            else:
                                count = self._count_lines() + 1

                        with open(self._path, "ab") as fh:
                            fh.write(line + b"\n")
                            fh.flush()
                            os.fsync(fh.fileno())
                        self._write_anchor(_sha256_hex(line), count)
                    finally:
                        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
            return record
        except AuditWriteError:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed with a generic error
            raise AuditWriteError(f"audit write failed: {type(exc).__name__}") from exc

    def tail(self, limit: int) -> list[AuditRecord]:
        """Return up to ``limit`` most recent records, newest first."""
        if limit <= 0 or not self._path.exists():
            return []
        records: list[tuple[str, int, AuditRecord]] = []
        with open(self._path, "rb") as fh:
            for number, raw in enumerate(fh, start=1):
                text = raw.rstrip(b"\r\n")
                if not text:
                    continue
                try:
                    rec = AuditRecord.model_validate(json.loads(text.decode("utf-8")))
                except (ValueError, UnicodeDecodeError):
                    continue
                records.append((rec.timestamp, number, rec))
        records.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return [item[2] for item in records[:limit]]

    def verify(self) -> VerifyResult:
        """Recompute the chain; report the first bad 1-based line or validity."""
        lines: list[bytes] = []
        if self._path.exists():
            with open(self._path, "rb") as fh:
                for raw in fh:
                    text = raw.rstrip(b"\r\n")
                    if text:
                        lines.append(text)

        expected = GENESIS_HASH
        for number, text in enumerate(lines, start=1):
            try:
                stored = json.loads(text.decode("utf-8")).get("prev_hash")
            except (ValueError, UnicodeDecodeError, AttributeError):
                return VerifyResult(valid=False, first_invalid_line=number)
            if stored != expected:
                return VerifyResult(valid=False, first_invalid_line=number)
            expected = _sha256_hex(text)

        anchor = self._read_anchor()
        if anchor is not None:
            count = len(lines)
            anchor_count = anchor["count"]
            if count < anchor_count:
                # Tail deletion: the chain cannot show it, the anchor does.
                return VerifyResult(valid=False, first_invalid_line=count + 1)
            if count == anchor_count:
                if anchor["head_hash"] != expected:
                    # Last record was modified after the anchor was written.
                    return VerifyResult(valid=False, first_invalid_line=count)
            else:
                # Anchor is stale (a later anchor write failed). The record at
                # the anchored position must still hash to the anchored head.
                if anchor_count > 0 and _sha256_hex(lines[anchor_count - 1]) != anchor["head_hash"]:
                    return VerifyResult(valid=False, first_invalid_line=anchor_count)
        return VerifyResult(valid=True, first_invalid_line=None)
