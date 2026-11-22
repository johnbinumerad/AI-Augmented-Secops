"""Read-only access to the Findings_Database (DuckDB).

Every connection is opened read-only with external access disabled, so even a
validator bypass cannot write data, read files, attach databases or load
extensions. Queries run only when the caller presents an approval token that
matches the exact validated SQL text, and are cancelled after a hard timeout.
Failures surface as generic, typed errors that never carry raw database text.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from pathlib import Path
from typing import Any, Optional, Union

import duckdb

from src.models import Decision, SqlValidationResult

QUERY_TIMEOUT_SECONDS = 10.0
MAX_ROWS = 10_000


class FindingsDBError(Exception):
    """Base class for database errors.

    Carries only a stable class name and a generic message; never raw
    database error text, table or column names, or SQL fragments.
    """

    reason_code = "query_error"
    generic_message = "The query could not be executed."

    def __init__(self, message: Optional[str] = None) -> None:
        self.message = message or self.generic_message
        super().__init__(self.message)

    @property
    def error_class(self) -> str:
        return type(self).__name__


class QueryTimeout(FindingsDBError):
    reason_code = "query_timeout"
    generic_message = "The query exceeded the time limit and was cancelled."


class QueryRejected(FindingsDBError):
    reason_code = "query_rejected"
    generic_message = "The operation is not permitted."


class QueryError(FindingsDBError):
    reason_code = "query_error"
    generic_message = "The query could not be executed."


def approval_token(sql: str) -> str:
    """Return the approval token (SHA-256 hex) for an exact SQL text."""
    return hashlib.sha256(sql.encode("utf-8")).hexdigest()


def approval_from_result(result: SqlValidationResult) -> Optional[str]:
    """Return the approval token for an allowed validation result, else None."""
    if result.decision.decision != Decision.allowed or not result.sql:
        return None
    return approval_token(result.sql)


_REJECT_MARKERS = (
    "read-only",
    "read only",
    "permission",
    "external access",
    "not allowed",
    "disabled",
    "cannot execute statement of type",
    "extension",
)


def _is_rejection(exc: BaseException) -> bool:
    if isinstance(exc, duckdb.PermissionException):
        return True
    text = str(exc).lower()
    return any(marker in text for marker in _REJECT_MARKERS)


class FindingsDB:
    """Read-only DuckDB access with approval tokens and a hard timeout."""

    def __init__(
        self,
        path: Union[str, Path],
        timeout_seconds: float = QUERY_TIMEOUT_SECONDS,
    ) -> None:
        self._path = str(path)
        self._timeout = float(timeout_seconds)

    def connect(self) -> duckdb.DuckDBPyConnection:
        """Open a new read-only connection with external access disabled."""
        return duckdb.connect(
            self._path,
            read_only=True,
            config={"enable_external_access": False},
        )

    def ping(self) -> bool:
        """Return True when the database can be opened and queried."""
        try:
            conn = self.connect()
            try:
                conn.execute("SELECT 1").fetchall()
            finally:
                conn.close()
            return True
        except Exception:
            return False

    def execute_readonly(
        self, sql: str, approval: Optional[str]
    ) -> list[dict[str, Any]]:
        """Execute approved SQL and return rows as dictionaries.

        Raises QueryRejected when the approval token is missing or does not
        match the exact SQL text, QueryTimeout when the time limit is hit
        (no partial rows are returned), and QueryError for any other failure.
        """
        if (
            not isinstance(sql, str)
            or not sql.strip()
            or not isinstance(approval, str)
            or not hmac.compare_digest(approval, approval_token(sql))
        ):
            raise QueryRejected("The query was not approved for execution.")

        timed_out = threading.Event()
        conn: Optional[duckdb.DuckDBPyConnection] = None
        timer: Optional[threading.Timer] = None
        try:
            conn = self.connect()
            active = conn

            def _cancel() -> None:
                timed_out.set()
                try:
                    active.interrupt()
                except Exception:
                    pass

            timer = threading.Timer(self._timeout, _cancel)
            timer.daemon = True
            timer.start()

            cursor = conn.execute(sql)
            description = cursor.description or []
            columns = [d[0] for d in description]
            fetched = cursor.fetchmany(MAX_ROWS)
            if timed_out.is_set():
                raise QueryTimeout()
            return [dict(zip(columns, row)) for row in fetched]
        except FindingsDBError:
            raise
        except BaseException as exc:  # noqa: BLE001 - classified and sanitized
            if timed_out.is_set() or isinstance(exc, duckdb.InterruptException):
                raise QueryTimeout() from None
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            if _is_rejection(exc):
                raise QueryRejected() from None
            raise QueryError() from None
        finally:
            if timer is not None:
                timer.cancel()
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
