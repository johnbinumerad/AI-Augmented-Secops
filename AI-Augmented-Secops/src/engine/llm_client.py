"""LLM client for secops-triage-guard.

The LLM is an untrusted component that may only generate SQL text and answer
text (Requirement 6.13). ``LLMClient`` therefore exposes exactly two methods and
the Ollama-backed implementation binds no tools. Any connection failure or a
call exceeding 60 seconds raises ``LLMUnavailable`` (Requirement 6.10).
"""

from __future__ import annotations

import concurrent.futures
from typing import Any, Optional, Protocol, runtime_checkable

from src.config import Settings

LLM_TIMEOUT_SECONDS = 60.0


class LLMUnavailable(Exception):
    """The LLM is unreachable, failed, or did not respond within the timeout."""

    def __init__(self, message: str = "LLM unavailable") -> None:
        super().__init__(message)


@runtime_checkable
class LLMClient(Protocol):
    """The only capabilities granted to the LLM: SQL text and answer text."""

    def generate_sql(self, system: str, prompt: str) -> str: ...

    def generate_answer(self, system: str, context: str) -> str: ...


def _content_to_text(content: Any) -> str:
    """Flatten a LangChain message content (str or list of parts) to text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts)
    return str(content)


class OllamaLLMClient:
    """Ollama-backed ``LLMClient`` using ``langchain_ollama.ChatOllama``.

    ``chat_model`` may be injected (any object with ``invoke(messages)``) so the
    transport can be replaced in tests; by default a ``ChatOllama`` with a
    60 second timeout and no tools bound is created.
    """

    def __init__(
        self,
        settings: Settings,
        chat_model: Optional[Any] = None,
        timeout: float = LLM_TIMEOUT_SECONDS,
    ) -> None:
        self._timeout = timeout
        if chat_model is None:
            from langchain_ollama import ChatOllama

            chat_model = ChatOllama(
                model=settings.LLM_MODEL,
                base_url=settings.OLLAMA_URL,
                temperature=0,
                client_kwargs={"timeout": timeout},
            )
        self._chat = chat_model

    def _invoke(self, system: str, user: str) -> str:
        messages = [("system", system), ("human", user)]
        # Enforce a wall-clock deadline in addition to the HTTP timeout.
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        future = executor.submit(self._chat.invoke, messages)
        try:
            result = future.result(timeout=self._timeout)
        except concurrent.futures.TimeoutError:
            future.cancel()
            raise LLMUnavailable("LLM call timed out") from None
        except LLMUnavailable:
            raise
        except Exception as exc:  # connection errors, HTTP errors, model errors
            raise LLMUnavailable(f"LLM call failed: {type(exc).__name__}") from None
        finally:
            executor.shutdown(wait=False)
        return _content_to_text(getattr(result, "content", result))

    def generate_sql(self, system: str, prompt: str) -> str:
        return self._invoke(system, prompt)

    def generate_answer(self, system: str, context: str) -> str:
        return self._invoke(system, context)


def build_llm_client(settings: Settings) -> LLMClient:
    """Create the default Ollama-backed client from settings."""
    return OllamaLLMClient(settings)
