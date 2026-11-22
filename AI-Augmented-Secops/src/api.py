"""FastAPI backend for secops-triage-guard.

Endpoints:
  POST /triage        guarded triage pipeline (rate limited, 30 requests / 60 s)
  GET  /audit         newest-first masked audit records (role + optional API key)
  GET  /audit/verify  hash-chain verification (role + optional API key)
  GET  /health        component health with a 5 second budget (503 when degraded)

Cross-cutting controls: 422 bodies carry field names only (never submitted
values), unhandled errors return a generic 500 with a request id and no trace,
the optional ``X-API-Key`` is compared in constant time, and the role for the
audit endpoints is read from the self-asserted ``X-User-Role`` header (a missing
or unknown role is treated as unauthorized, 403).
"""

from __future__ import annotations

import concurrent.futures
import hmac
import math
import re
import threading
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from typing import Any, Callable, Optional

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from src.audit.logger import AuditLogger
from src.config import ROLE_POLICY, Settings, load_settings_or_exit
from src.models import (
    BlockedResponse,
    ErrorResponse,
    TriageRequest,
    TriageResponse,
)

RATE_LIMIT = 30
RATE_WINDOW_SECONDS = 60.0
HEALTH_BUDGET_SECONDS = 5.0
MAX_TRACKED_CLIENTS = 10_000

_FIELD_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_\-]{0,63}$")

_ERROR_STATUS = {
    "invalid_llm_output": 502,
    "llm_unavailable": 503,
    "query_timeout": 504,
    "query_rejected": 400,
    "query_error": 500,
    "audit_failure": 500,
    "internal_error": 500,
}


class _HttpError(Exception):
    """Internal typed HTTP error rendered with a generic body."""

    def __init__(self, status: int, error: str, reason_code: str, message: str) -> None:
        super().__init__(reason_code)
        self.status = status
        self.error = error
        self.reason_code = reason_code
        self.message = message


class SlidingWindowRateLimiter:
    """In-memory rolling-window limiter: at most ``limit`` hits per ``window`` seconds per key."""

    def __init__(
        self,
        limit: int = RATE_LIMIT,
        window: float = RATE_WINDOW_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._limit = int(limit)
        self._window = float(window)
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int]:
        """Record a hit if allowed. Returns (allowed, retry_after_seconds)."""
        with self._lock:
            now = self._clock()
            cutoff = now - self._window
            hits = self._hits.get(key)
            if hits is None:
                if len(self._hits) >= MAX_TRACKED_CLIENTS:
                    self._evict(cutoff)
                hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) < self._limit:
                hits.append(now)
                return True, 0
            retry = math.ceil(hits[0] + self._window - now)
            return False, min(max(1, retry), math.ceil(self._window))

    def _evict(self, cutoff: float) -> None:
        for key in [k for k, h in self._hits.items() if not h or h[-1] <= cutoff]:
            del self._hits[key]


def _error_body(request_id: str, error: str, reason_code: str, message: str = "",
                retry_after: Optional[int] = None) -> dict[str, Any]:
    return ErrorResponse(
        request_id=request_id,
        error=error,
        reason_code=reason_code,
        message=message,
        retry_after_seconds=retry_after,
    ).model_dump()


def _default_llm_health(settings: Settings) -> Callable[[], bool]:
    def check() -> bool:
        import httpx

        url = settings.OLLAMA_URL.rstrip("/") + "/api/tags"
        try:
            return httpx.get(url, timeout=4.0).status_code == 200
        except Exception:
            return False

    return check


class _Components:
    """Holder for the wired components (injected or built at startup)."""

    def __init__(self) -> None:
        self.settings: Optional[Settings] = None
        self.agent: Any = None
        self.audit: Optional[AuditLogger] = None
        self.db: Any = None
        self.runbooks: Any = None
        self.llm_health: Optional[Callable[[], bool]] = None


def _build_real_components(comp: _Components) -> None:
    """Wire the production agent, logger, masker, DB and store from settings."""
    from src.engine.db import FindingsDB
    from src.engine.llm_client import build_llm_client
    from src.engine.runbook_store import RunbookStore
    from src.engine.triage_agent import TriageAgent
    from src.guardrails.pii_masker import PIIMasker

    settings = comp.settings or load_settings_or_exit()
    comp.settings = settings
    masker = PIIMasker(settings.internal_suffixes)
    if comp.audit is None:
        comp.audit = AuditLogger(settings.AUDIT_LOG_PATH, masker)
    if comp.db is None:
        comp.db = FindingsDB(settings.DB_PATH)
    if comp.runbooks is None:
        comp.runbooks = RunbookStore(settings.RUNBOOK_STORE_PATH)
    if comp.agent is None:
        comp.agent = TriageAgent(
            settings, build_llm_client(settings), comp.db, comp.runbooks, masker, comp.audit
        )
    if comp.llm_health is None:
        comp.llm_health = _default_llm_health(settings)


def create_app(
    *,
    settings: Optional[Settings] = None,
    agent: Any = None,
    audit: Optional[AuditLogger] = None,
    db: Any = None,
    runbooks: Any = None,
    llm_health: Optional[Callable[[], bool]] = None,
    rate_limiter: Optional[SlidingWindowRateLimiter] = None,
) -> FastAPI:
    """Create the API. Any component not injected is built from settings at startup."""
    comp = _Components()
    comp.settings, comp.agent, comp.audit = settings, agent, audit
    comp.db, comp.runbooks, comp.llm_health = db, runbooks, llm_health
    limiter = rate_limiter or SlidingWindowRateLimiter()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        if comp.settings is None:
            comp.settings = load_settings_or_exit()
        if any(c is None for c in (comp.agent, comp.audit, comp.db, comp.runbooks, comp.llm_health)):
            _build_real_components(comp)
        yield

    app = FastAPI(title="secops-triage-guard", lifespan=lifespan)
    app.state.components = comp
    app.state.rate_limiter = limiter

    # ------------------------------------------------------------ error handlers

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        fields: list[dict[str, str]] = []
        for err in exc.errors():
            parts = [
                p for p in err.get("loc", ())
                if isinstance(p, str) and p not in ("body", "query", "header")
            ]
            name = ".".join(p if _FIELD_NAME_RE.match(p) else "?" for p in parts) or "request"
            fields.append({"field": name, "type": str(err.get("type", "invalid"))})
        body = _error_body(str(uuid.uuid4()), "validation_error", "validation_error",
                           "The request failed validation.")
        body["fields"] = fields
        return JSONResponse(status_code=422, content=body)

    @app.exception_handler(Exception)
    async def _unhandled_handler(_request: Request, _exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content=_error_body(str(uuid.uuid4()), "internal_error", "internal_error",
                                "An internal error occurred."),
        )

    # ------------------------------------------------------------ dependencies

    def require_audit_access(
        x_api_key: Optional[str] = Header(default=None),
        x_user_role: Optional[str] = Header(default=None),
    ) -> str:
        configured = comp.settings.API_KEY if comp.settings is not None else None
        if configured:
            supplied = (x_api_key or "").encode("utf-8")
            if not hmac.compare_digest(supplied, configured.encode("utf-8")):
                raise _HttpError(401, "unauthorized", "invalid_api_key", "Missing or invalid API key.")
        role = (x_user_role or "").strip().lower()
        policy = ROLE_POLICY.get(role)
        if policy is None or not policy["audit_read"]:
            raise _HttpError(403, "forbidden", "role_not_permitted", "Role not permitted.")
        return role

    @app.exception_handler(_HttpError)
    async def _http_error_handler(_request: Request, exc: _HttpError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status,
            content=_error_body(str(uuid.uuid4()), exc.error, exc.reason_code, exc.message),
        )

    # ------------------------------------------------------------ endpoints

    @app.post("/triage")
    def triage(req: TriageRequest, request: Request) -> JSONResponse:
        client = request.client.host if request.client else "unknown"
        allowed, retry_after = limiter.check(client)
        if not allowed:
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(retry_after)},
                content=_error_body(str(uuid.uuid4()), "rate_limited", "rate_limited",
                                    "Rate limit exceeded.", retry_after),
            )
        outcome = comp.agent.run(req)
        if isinstance(outcome, TriageResponse):
            return JSONResponse(status_code=200, content=outcome.model_dump(mode="json"))
        if isinstance(outcome, BlockedResponse):
            return JSONResponse(status_code=400, content=outcome.model_dump(mode="json"))
        if isinstance(outcome, ErrorResponse):
            status = _ERROR_STATUS.get(outcome.reason_code, 500)
            return JSONResponse(status_code=status, content=outcome.model_dump(mode="json"))
        raise RuntimeError("unexpected agent outcome")

    @app.get("/audit")
    def get_audit(
        limit: int = Query(50, ge=1, le=200),
        _role: str = Depends(require_audit_access),
    ) -> list[dict[str, Any]]:
        records = comp.audit.tail(limit)
        return [r.model_dump(mode="json") for r in records]

    @app.get("/audit/verify")
    def verify_audit(_role: str = Depends(require_audit_access)) -> dict[str, Any]:
        return comp.audit.verify().model_dump(mode="json")

    @app.get("/health")
    def health() -> JSONResponse:
        checks: dict[str, Callable[[], Any]] = {
            "database": lambda: comp.db.ping(),
            "runbook_store": lambda: comp.runbooks.count() > 0,
            "llm": lambda: comp.llm_health(),
        }
        status = {name: "unavailable" for name in checks}
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=len(checks))
        try:
            futures = {name: executor.submit(fn) for name, fn in checks.items()}
            deadline = time.monotonic() + HEALTH_BUDGET_SECONDS
            for name, fut in futures.items():
                try:
                    if fut.result(timeout=max(0.0, deadline - time.monotonic())):
                        status[name] = "ok"
                except Exception:
                    status[name] = "unavailable"
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        code = 200 if all(v == "ok" for v in status.values()) else 503
        return JSONResponse(status_code=code, content=status)

    return app


app = create_app()
