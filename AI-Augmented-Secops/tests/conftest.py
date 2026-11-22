"""Shared pytest harness for the secops-triage-guard test suite.

Provides:
  * ``StubLLM``            - scripted, recording stand-in for the Ollama client
  * network guard          - autouse fixture failing any outbound socket connect
  * ``FakeEmbedding``      - deterministic offline embedding function
  * temp-path fixtures     - audit log, database and runbook store locations
  * ``integration`` marker - for tests needing real models or slow resources
"""

from __future__ import annotations

import hashlib
import math
import re
import socket
import sys
from pathlib import Path
from typing import Any, Callable, Sequence, Union

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers",
        "integration: needs real models, real embeddings or slow resources "
        "(deselect with -m 'not integration')",
    )


# --------------------------------------------------------------------------
# StubLLM
# --------------------------------------------------------------------------

# A scripted item is a string, an exception (raised), or a callable
# taking the prompt/context and returning a string.
ScriptItem = Union[str, BaseException, Callable[[str, str], str]]


class StubLLM:
    """Scripted LLM stub exposing only ``generate_sql`` and ``generate_answer``.

    Responses are consumed in order; once exhausted the last one repeats.
    Every call's inputs are recorded for later assertions.
    """

    def __init__(
        self,
        sql_responses: Sequence[ScriptItem] = ("SELECT severity FROM findings",),
        answer_responses: Sequence[ScriptItem] = ("Stub answer.",),
    ) -> None:
        self._sql_script: list[ScriptItem] = list(sql_responses)
        self._answer_script: list[ScriptItem] = list(answer_responses)
        self.sql_calls: list[dict[str, str]] = []
        self.answer_calls: list[dict[str, str]] = []

    @staticmethod
    def _next(script: list[ScriptItem], index: int, a: str, b: str) -> str:
        if not script:
            return ""
        item = script[min(index, len(script) - 1)]
        if isinstance(item, BaseException):
            raise item
        if callable(item):
            return item(a, b)
        return item

    def generate_sql(self, system: str, prompt: str) -> str:
        index = len(self.sql_calls)
        self.sql_calls.append({"system": system, "prompt": prompt})
        return self._next(self._sql_script, index, system, prompt)

    def generate_answer(self, system: str, context: str) -> str:
        index = len(self.answer_calls)
        self.answer_calls.append({"system": system, "context": context})
        return self._next(self._answer_script, index, system, context)

    @property
    def all_inputs(self) -> list[str]:
        """Every string ever handed to the LLM (for leak assertions)."""
        out: list[str] = []
        for c in self.sql_calls:
            out.extend((c["system"], c["prompt"]))
        for c in self.answer_calls:
            out.extend((c["system"], c["context"]))
        return out


@pytest.fixture
def stub_llm() -> StubLLM:
    return StubLLM()


@pytest.fixture
def make_stub_llm() -> Callable[..., StubLLM]:
    """Factory for scripted StubLLM instances."""
    return StubLLM


# --------------------------------------------------------------------------
# Network guard (autouse): tests must run fully offline.
# --------------------------------------------------------------------------


def _format_address(address: Any) -> str:
    return repr(address)


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def guarded_connect(self: socket.socket, address: Any) -> None:
        # Local unix-domain sockets (str/bytes paths) are not network access.
        if isinstance(address, (str, bytes)):
            return _real_connect(self, address)
        pytest.fail(
            f"Network access attempted: socket.connect to {_format_address(address)}",
            pytrace=False,
        )

    def guarded_connect_ex(self: socket.socket, address: Any) -> int:
        if isinstance(address, (str, bytes)):
            return _real_connect_ex(self, address)
        pytest.fail(
            f"Network access attempted: socket.connect_ex to {_format_address(address)}",
            pytrace=False,
        )

    def guarded_create_connection(address: Any, *args: Any, **kwargs: Any) -> socket.socket:
        pytest.fail(
            f"Network access attempted: socket.create_connection to {_format_address(address)}",
            pytrace=False,
        )

    _real_connect = socket.socket.connect
    _real_connect_ex = socket.socket.connect_ex
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "create_connection", guarded_create_connection)


# --------------------------------------------------------------------------
# Deterministic fake embeddings (no model download)
# --------------------------------------------------------------------------


class FakeEmbedding:
    """Hash-based bag-of-words embedding. Deterministic and offline.

    Compatible with Chroma's embedding-function protocol (callable on a list
    of documents, returning a list of float vectors).
    """

    DIM = 64
    _TOKEN = re.compile(r"[a-z0-9]+")

    def __init__(self, dim: int = DIM) -> None:
        self.dim = dim

    def _embed_one(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        for tok in self._TOKEN.findall(text.lower()):
            digest = hashlib.sha256(tok.encode("utf-8")).digest()
            idx = int.from_bytes(digest[:4], "big") % self.dim
            sign = 1.0 if digest[4] & 1 else -1.0
            vec[idx] += sign
        norm = math.sqrt(sum(v * v for v in vec))
        if norm == 0.0:
            vec[0] = 1.0
            return vec
        return [v / norm for v in vec]

    def __call__(self, input: Sequence[str]) -> list[list[float]]:  # noqa: A002
        if isinstance(input, str):
            input = [input]
        return [self._embed_one(t) for t in input]

    def embed_documents(self, input: Sequence[str]) -> list[list[float]]:  # noqa: A002
        return self(input)

    def embed_query(self, input: Any) -> list[list[float]]:  # noqa: A002
        return self(input if not isinstance(input, str) else [input])

    @staticmethod
    def name() -> str:
        return "fake-hash-embedding"

    def get_config(self) -> dict[str, Any]:
        return {"dim": self.dim}

    @staticmethod
    def build_from_config(config: dict[str, Any]) -> "FakeEmbedding":
        return FakeEmbedding(dim=int(config.get("dim", FakeEmbedding.DIM)))

    @staticmethod
    def default_space() -> str:
        return "cosine"

    def supported_spaces(self) -> list[str]:
        return ["cosine", "l2", "ip"]


@pytest.fixture
def fake_embedding() -> FakeEmbedding:
    """Default embedding function for Runbook retrieval in tests."""
    return FakeEmbedding()


# --------------------------------------------------------------------------
# Temp-path fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def audit_log_path(tmp_path: Path) -> Path:
    return tmp_path / "audit_logs.jsonl"


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "findings.duckdb"


@pytest.fixture
def runbook_store_path(tmp_path: Path) -> Path:
    return tmp_path / "runbook_store"


# --------------------------------------------------------------------------
# Session-scoped seeded data (fixed seed, fake embeddings, seeded once)
# --------------------------------------------------------------------------

SEEDED_DATA_SEED = 1234


@pytest.fixture(scope="session")
def seeded_data(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Seed a fresh Findings_Database and Runbook_Store once per session.

    Uses a fixed seed and the deterministic fake embedding, so no model is
    downloaded. Tests must treat both stores as read-only.
    """
    from data.seed_findings import generate_findings, seed_all

    root = tmp_path_factory.mktemp("seeded")
    db_file = root / "findings.duckdb"
    store_dir = root / "runbook_store"
    runbook_dir = REPO_ROOT / "data" / "runbooks"
    counts = seed_all(
        SEEDED_DATA_SEED,
        db_file,
        store_dir,
        runbook_dir,
        embedding_function=FakeEmbedding(),
    )
    return {
        "seed": SEEDED_DATA_SEED,
        "db_path": db_file,
        "store_path": store_dir,
        "runbook_dir": runbook_dir,
        "counts": counts,
        "findings": generate_findings(SEEDED_DATA_SEED),
    }


@pytest.fixture(scope="session")
def seeded_db_path(seeded_data: dict[str, Any]) -> Path:
    """Path of the session-seeded Findings_Database (treat as read-only)."""
    return seeded_data["db_path"]
