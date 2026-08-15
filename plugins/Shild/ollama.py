"""Async Ollama client.

Replaces ~/shild/plugins/05_ai.tcl's HTTP transport (Tcl's http package,
itself already a fix over exec curl there -- see that file's comments on
Eggdrop's SIGCHLD handler racing exec's waitpid) with aiohttp, and
replaces regex-based JSON extraction (05_ai.tcl:263-298, seven separate
regexes against freeform LLM text) with Ollama's structured-output
support (`format: <json schema>`, confirmed working against this
server's Ollama 0.32.5 during the M0 spike) plus a real json.loads --
never a regex against LLM output.

This module must never raise out of `analyze()` — every failure mode
(timeout, connection error, non-200, malformed JSON, missing fields, an
action outside the vocabulary) becomes `OllamaResult(ok=False, ...)`.
That boundary is what lets shildml.fusion.decide() guarantee fail-open.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import NamedTuple

import aiohttp

from shildml import fusion

from . import prompts


@dataclass
class OllamaConfig:
    url: str = "http://localhost:11434"
    model: str = "llama3.2:1b"
    timeout: float = 15.0
    temperature: float = 0.1
    num_predict: int = 250


class AnalyzeOutcome(NamedTuple):
    result: fusion.OllamaResult
    latency_ms: float


async def analyze(
    session: aiohttp.ClientSession,
    config: OllamaConfig,
    system_prompt: str,
    user_prompt: str,
) -> AnalyzeOutcome:
    payload = {
        "model": config.model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "format": prompts.RESPONSE_SCHEMA,
        "keep_alive": -1,  # keep the model resident -- large latency win, see 05_ai.tcl
        "options": {"temperature": config.temperature, "num_predict": config.num_predict},
    }
    start = time.monotonic()
    try:
        async with session.post(
            f"{config.url}/api/chat",
            json=payload,
            timeout=aiohttp.ClientTimeout(total=config.timeout),
        ) as resp:
            latency_ms = (time.monotonic() - start) * 1000
            if resp.status != 200:
                return AnalyzeOutcome(
                    fusion.OllamaResult(ok=False, degraded_reason=f"http_{resp.status}"),
                    latency_ms,
                )
            body = await resp.json(content_type=None)
    except Exception as e:  # noqa: BLE001 -- this is the fail-open boundary, must not propagate
        latency_ms = (time.monotonic() - start) * 1000
        return AnalyzeOutcome(
            fusion.OllamaResult(ok=False, degraded_reason=type(e).__name__), latency_ms
        )

    try:
        content = body["message"]["content"]
        parsed = json.loads(content)
        action = parsed["action"]
        confidence = float(parsed["confidence"])
        reason = str(parsed.get("reason", ""))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return AnalyzeOutcome(
            fusion.OllamaResult(ok=False, degraded_reason="unparseable_response"), latency_ms
        )

    if action not in fusion.VALID_ACTIONS:
        return AnalyzeOutcome(
            fusion.OllamaResult(ok=False, degraded_reason="invalid_action"), latency_ms
        )

    return AnalyzeOutcome(
        fusion.OllamaResult(ok=True, action=action, confidence=confidence, reason=reason),
        latency_ms,
    )


async def health_check(session: aiohttp.ClientSession, config: OllamaConfig) -> bool:
    try:
        async with session.get(
            f"{config.url}/api/tags", timeout=aiohttp.ClientTimeout(total=4.0)
        ) as resp:
            if resp.status != 200:
                return False
            body = await resp.json(content_type=None)
            models = [m.get("name", "") for m in body.get("models", [])]
            return any(config.model in m for m in models)
    except Exception:
        return False
