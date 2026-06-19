"""Thin Claude (Anthropic) wrapper used by analysis, summary and chat.

The whole platform degrades gracefully: if ``ANTHROPIC_API_KEY`` is unset (or
the SDK call fails) callers fall back to deterministic templates so the demo
always works. Set ``SENTINEL_ANTHROPIC_API_KEY`` to enable real Claude output.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from typing import Any

from app.core.config import settings

logger = logging.getLogger("sentinel.ai")


@lru_cache
def get_client():  # -> anthropic.Anthropic | None
    if not settings.ai_enabled:
        return None
    try:
        import anthropic

        return anthropic.Anthropic(api_key=settings.anthropic_api_key)
    except Exception as exc:  # noqa: BLE001 - never break the pipeline on AI setup
        logger.warning("Anthropic client unavailable: %s", exc)
        return None


def ai_available() -> bool:
    return get_client() is not None


def complete(system: str, user_prompt: str, *, fast: bool = False, max_tokens: int | None = None) -> str | None:
    """Single-turn completion. Returns None if AI is unavailable/errors."""
    client = get_client()
    if client is None:
        return None
    model = settings.ai_model_fast if fast else settings.ai_model_deep
    try:
        resp = client.messages.create(
            model=model,
            max_tokens=max_tokens or settings.ai_max_tokens,
            system=system,
            messages=[{"role": "user", "content": user_prompt}],
        )
        return "".join(block.text for block in resp.content if getattr(block, "type", None) == "text")
    except Exception as exc:  # noqa: BLE001
        logger.warning("Claude completion failed: %s", exc)
        return None


def complete_with_tools(system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]):
    """Multi-turn tool-using call for the chat assistant. Returns the raw response or None."""
    client = get_client()
    if client is None:
        return None
    try:
        return client.messages.create(
            model=settings.ai_model_fast,
            max_tokens=settings.ai_max_tokens,
            system=system,
            tools=tools,
            messages=messages,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Claude tool call failed: %s", exc)
        return None
