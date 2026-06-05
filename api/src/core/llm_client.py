"""LLM client abstraction.

One adapter for now (Anthropic Claude via the Messages API + tool use
for structured output). Per design §2, every external dependency goes
through a Protocol so a future Azure OpenAI / on-prem (Ollama) /
OpenAI swap is a constructor change, not a code rewrite.

The IR extraction path uses Anthropic tool use because:
  - Structured output: the model is forced through a JSON schema
  - No retry loop chasing "the model added markdown around the JSON"
  - Cost / token accounting is consistent with the public API

Connection is raw httpx (already in our deps). We DON'T pull the
anthropic SDK in to keep the dependency surface minimal — the
Messages API is stable and the JSON shape is well-defined.
"""
from __future__ import annotations

from typing import Any, Protocol

import httpx

from .config import get_settings


_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


class LlmError(RuntimeError):
    """Raised by the client on any failure (network, 4xx, 5xx, malformed).
    Routers translate to 502 — the LLM is an upstream dependency."""


class ToolUseResult:
    """Structured-output envelope returned by `call_tool`."""

    __slots__ = ("input", "model", "input_tokens", "output_tokens", "stop_reason")

    def __init__(
        self,
        *,
        input: dict[str, Any],
        model: str,
        input_tokens: int,
        output_tokens: int,
        stop_reason: str,
    ) -> None:
        self.input = input
        self.model = model
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.stop_reason = stop_reason


class LlmClient(Protocol):
    """Minimal interface every adapter implements."""

    async def call_tool(
        self,
        *,
        system: str,
        user: str,
        tool_name: str,
        tool_description: str,
        tool_input_schema: dict[str, Any],
        max_tokens: int,
        timeout_seconds: int,
    ) -> ToolUseResult:
        ...


class AnthropicLlmClient:
    """Default adapter — Anthropic Messages API + forced tool use.

    The forced tool use trick (tool_choice = `{"type": "tool", "name": ...}`)
    guarantees the response contains exactly one tool_use block matching
    the requested schema. Any other shape is an LlmError.
    """

    def __init__(self, api_key: str, model: str) -> None:
        if not api_key:
            raise LlmError(
                "anthropic_api_key not configured; "
                "IR extraction is disabled until the operator sets it"
            )
        self._api_key = api_key
        self._model = model

    async def call_tool(
        self,
        *,
        system: str,
        user: str,
        tool_name: str,
        tool_description: str,
        tool_input_schema: dict[str, Any],
        max_tokens: int,
        timeout_seconds: int,
    ) -> ToolUseResult:
        payload = {
            "model": self._model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
            "tools": [
                {
                    "name": tool_name,
                    "description": tool_description,
                    "input_schema": tool_input_schema,
                }
            ],
            # Force the model to invoke our one tool — no free-text fallback,
            # no commentary, just the structured payload.
            "tool_choice": {"type": "tool", "name": tool_name},
        }
        headers = {
            "x-api-key": self._api_key,
            "anthropic-version": _ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=timeout_seconds) as client:
                resp = await client.post(_ANTHROPIC_API_URL, headers=headers, json=payload)
        except httpx.HTTPError as exc:
            raise LlmError(f"anthropic request failed: {exc!s}") from exc

        if resp.status_code != 200:
            # Surface the upstream error body verbatim — useful when the
            # operator forgot to add credit or the model name is stale.
            raise LlmError(
                f"anthropic returned {resp.status_code}: {resp.text[:500]}"
            )

        try:
            body = resp.json()
        except ValueError as exc:
            raise LlmError(f"anthropic returned non-JSON body: {resp.text[:200]}") from exc

        # Walk the content blocks for the tool_use we forced.
        tool_use_block = None
        for block in body.get("content", []):
            if block.get("type") == "tool_use" and block.get("name") == tool_name:
                tool_use_block = block
                break
        if tool_use_block is None:
            raise LlmError(
                f"anthropic response missing tool_use block for {tool_name!r}"
            )

        usage = body.get("usage", {})
        return ToolUseResult(
            input=tool_use_block.get("input", {}),
            model=body.get("model", self._model),
            input_tokens=int(usage.get("input_tokens", 0)),
            output_tokens=int(usage.get("output_tokens", 0)),
            stop_reason=body.get("stop_reason", ""),
        )


_singleton: LlmClient | None = None


def get_llm_client() -> LlmClient:
    """Lazy-initialise the configured adapter.

    Today: Anthropic. Tomorrow: a settings flag picks the impl.
    """
    global _singleton
    if _singleton is None:
        s = get_settings()
        _singleton = AnthropicLlmClient(
            api_key=s.anthropic_api_key,
            model=s.anthropic_model,
        )
    return _singleton
