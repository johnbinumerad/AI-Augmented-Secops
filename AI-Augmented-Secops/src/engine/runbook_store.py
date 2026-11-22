"""Runbook vector store backed by a file-backed Chroma ``PersistentClient``.

Interface:
    * ``RunbookStore.query(text, k)`` -> ``list[RunbookPassage]``
    * ``RunbookStore.replace_all(chunks)`` builds a complete new store in a
      sibling temporary directory and atomically swaps it into place, so any
      failure leaves the previously stored data unmodified.
    * ``chunk_runbook`` / ``load_runbook_chunks`` split runbook markdown into
      ~800 character chunks with 100 characters of overlap on paragraph
      boundaries.

The embedding function is injectable. When none is supplied the real
``all-MiniLM-L6-v2`` sentence-transformers model is used.
"""

from __future__ import annotations

import gc
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

COLLECTION_NAME = "runbooks"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
CHUNK_SIZE = 800
CHUNK_OVERLAP = 100

_PARAGRAPH_SPLIT = re.compile(r"\n\s*\n")


class RunbookStoreError(Exception):
    """Raised when the runbook store cannot be read or written."""


@dataclass(frozen=True)
class RunbookChunk:
    """A chunk of a runbook ready to be embedded and stored."""

    runbook: str
    chunk: int
    text: str

    @property
    def chunk_id(self) -> str:
        return f"{self.runbook}#{self.chunk}"


@dataclass(frozen=True)
class RunbookPassage:
    """A retrieved runbook passage."""

    runbook: str
    chunk_id: str
    text: str


# --------------------------------------------------------------------------
# Chunking
# --------------------------------------------------------------------------


def _overlap_tail(text: str, overlap: int) -> str:
    """Return roughly the last ``overlap`` characters, starting at a word edge."""
    if overlap <= 0 or len(text) <= overlap:
        return text if overlap > 0 else ""
    tail = text[-overlap:]
    space = tail.find(" ")
    if 0 <= space < len(tail) - 1:
        tail = tail[space + 1 :]
    return tail.strip()


def _split_long(paragraph: str, size: int, overlap: int) -> list[str]:
    """Hard-split a paragraph longer than ``size`` into overlapping windows."""
    step = max(1, size - overlap)
    pieces: list[str] = []
    start = 0
    while start < len(paragraph):
        piece = paragraph[start : start + size].strip()
        if piece:
            pieces.append(piece)
        if start + size >= len(paragraph):
            break
        start += step
    return pieces


def chunk_text(
    text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP
) -> list[str]:
    """Split ``text`` into chunks of about ``size`` characters.

    Chunks are packed from whole paragraphs; each chunk after the first starts
    with the last ``overlap`` characters of the previous one. Paragraphs longer
    than ``size`` are split into overlapping windows.
    """
    if size <= overlap:
        raise ValueError("size must be greater than overlap")
    paragraphs: list[str] = []
    for raw in _PARAGRAPH_SPLIT.split(text.replace("\r\n", "\n")):
        para = raw.strip()
        if not para:
            continue
        if len(para) > size:
            paragraphs.extend(_split_long(para, size, overlap))
        else:
            paragraphs.append(para)

    chunks: list[str] = []
    current = ""
    for para in paragraphs:
        if not current:
            current = para
            continue
        if len(current) + 2 + len(para) <= size:
            current = f"{current}\n\n{para}"
            continue
        chunks.append(current)
        tail = _overlap_tail(current, overlap)
        candidate = f"{tail}\n\n{para}" if tail else para
        current = candidate if len(candidate) <= size else para
    if current:
        chunks.append(current)
    return chunks


def chunk_runbook(
    name: str, text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP
) -> list[RunbookChunk]:
    """Chunk one runbook's text into ``RunbookChunk`` objects."""
    return [
        RunbookChunk(runbook=name, chunk=i, text=piece)
        for i, piece in enumerate(chunk_text(text, size, overlap))
    ]


def load_runbook_chunks(runbook_dir: Path | str) -> list[RunbookChunk]:
    """Chunk every ``*.md`` file in ``runbook_dir`` (sorted by file name)."""
    directory = Path(runbook_dir)
    chunks: list[RunbookChunk] = []
    for path in sorted(directory.glob("*.md")):
        chunks.extend(chunk_runbook(path.name, path.read_text(encoding="utf-8")))
    return chunks


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------


def _default_embedding() -> Any:
    from chromadb.utils import embedding_functions

    return embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )


def _release_chroma_clients() -> None:
    """Drop Chroma's per-path client cache so a swapped directory is re-opened."""
    try:
        from chromadb.api.shared_system_client import SharedSystemClient

        SharedSystemClient.clear_system_cache()
    except Exception:  # pragma: no cover - cache API differs across versions
        pass
    gc.collect()


class RunbookStore:
    """File-backed runbook vector store with an injectable embedding function."""

    def __init__(self, path: Path | str, embedding_function: Any | None = None) -> None:
        self.path = Path(path)
        self._embedding_function = embedding_function

    # -- helpers -----------------------------------------------------------

    def _embedder(self) -> Any:
        if self._embedding_function is None:
            self._embedding_function = _default_embedding()
        return self._embedding_function

    def _client(self, path: Path) -> Any:
        import chromadb

        return chromadb.PersistentClient(path=str(path))

    def exists(self) -> bool:
        """True when a persisted store directory exists at ``path``."""
        return self.path.is_dir() and any(self.path.iterdir())

    # -- queries -----------------------------------------------------------

    def count(self) -> int:
        """Number of stored chunks (0 if the store is missing)."""
        if not self.path.is_dir():
            return 0
        try:
            client = self._client(self.path)
            collection = client.get_collection(
                COLLECTION_NAME, embedding_function=self._embedder()
            )
            return int(collection.count())
        except Exception:
            return 0

    def query(self, text: str, k: int = 3) -> list[RunbookPassage]:
        """Return the ``k`` most similar passages (all if fewer exist)."""
        if k <= 0 or not text.strip():
            return []
        try:
            client = self._client(self.path)
            collection = client.get_collection(
                COLLECTION_NAME, embedding_function=self._embedder()
            )
            available = int(collection.count())
            if available == 0:
                return []
            result = collection.query(
                query_texts=[text], n_results=min(k, available)
            )
        except Exception as exc:
            raise RunbookStoreError(
                f"runbook store query failed ({type(exc).__name__})"
            ) from None

        ids = (result.get("ids") or [[]])[0]
        docs = (result.get("documents") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        passages: list[RunbookPassage] = []
        for chunk_id, doc, meta in zip(ids, docs, metas):
            runbook = str((meta or {}).get("runbook", str(chunk_id).split("#")[0]))
            passages.append(
                RunbookPassage(runbook=runbook, chunk_id=str(chunk_id), text=doc or "")
            )
        return passages

    # -- replacement -------------------------------------------------------

    def replace_all(self, chunks: Iterable[RunbookChunk]) -> int:
        """Replace the whole store with ``chunks`` atomically.

        The new store is built in a temporary sibling directory. Only after it
        is fully written is it swapped into place; on any failure the old
        store is left untouched (or restored) and ``RunbookStoreError`` is
        raised. Returns the number of chunks stored.
        """
        items: Sequence[RunbookChunk] = list(chunks)
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        tmp_dir = Path(
            tempfile.mkdtemp(prefix=f".{self.path.name}.new-", dir=str(parent))
        )
        backup: Path | None = None
        try:
            client = self._client(tmp_dir)
            collection = client.get_or_create_collection(
                COLLECTION_NAME,
                embedding_function=self._embedder(),
                metadata={"hnsw:space": "cosine"},
            )
            if items:
                collection.add(
                    ids=[c.chunk_id for c in items],
                    documents=[c.text for c in items],
                    metadatas=[{"runbook": c.runbook, "chunk": c.chunk} for c in items],
                )
            stored = int(collection.count())
            if stored != len(items):
                raise RunbookStoreError("runbook store verification failed")
            del collection, client
            _release_chroma_clients()

            if self.path.exists():
                backup = parent / f".{self.path.name}.old-{uuid.uuid4().hex}"
                self.path.rename(backup)
            try:
                tmp_dir.rename(self.path)
            except Exception:
                if backup is not None and not self.path.exists():
                    backup.rename(self.path)
                    backup = None
                raise
            _release_chroma_clients()
            if backup is not None:
                shutil.rmtree(backup, ignore_errors=True)
            return stored
        except RunbookStoreError:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise
        except Exception as exc:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise RunbookStoreError(
                f"runbook store replace failed ({type(exc).__name__})"
            ) from None
