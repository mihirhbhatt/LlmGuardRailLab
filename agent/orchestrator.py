"""Agent orchestrator — the local stand-in for the AWS Strands SDK box.

Runs a classic agent loop against Ollama's /api/chat endpoint:
  model reply → (tool calls? execute tools, feed results back) → final answer
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field

import requests

import config
from .tools import REGISTRY, TOOLS


@dataclass
class AgentResult:
    text: str
    latency_ms: float
    tool_trace: list[str] = field(default_factory=list)
    model: str = config.INFERENCE_MODEL
    error: str | None = None


class Orchestrator:
    def __init__(self, model: str = config.INFERENCE_MODEL,
                 system_prompt: str = config.SYSTEM_PROMPT,
                 enable_tools: bool = True):
        self.model = model
        self.system_prompt = (
            f"{system_prompt} The configured inference model is '{model}'. "
            "If asked which model is running, answer with that model name."
        )
        self.enable_tools = enable_tools

    # ── Ollama call ───────────────────────────────────────────────────
    def _chat(self, messages: list[dict], with_tools: bool) -> dict:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.3},
        }
        if with_tools:
            payload["tools"] = TOOLS
        resp = requests.post(f"{config.OLLAMA_URL}/api/chat",
                             json=payload, timeout=config.REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()["message"]

    # ── Agent loop ────────────────────────────────────────────────────
    def run(self, user_prompt: str, history: list[dict] | None = None) -> AgentResult:
        t0 = time.perf_counter()
        messages = [{"role": "system", "content": self.system_prompt}]
        if history:
            messages += history
        messages.append({"role": "user", "content": user_prompt})

        trace: list[str] = []
        with_tools = self.enable_tools

        try:
            for _ in range(config.MAX_TOOL_ITERATIONS):
                msg = self._chat(messages, with_tools)
                tool_calls = msg.get("tool_calls") or []
                if not tool_calls:
                    return AgentResult(
                        text=(msg.get("content") or "").strip(),
                        latency_ms=(time.perf_counter() - t0) * 1000,
                        tool_trace=trace, model=self.model,
                    )

                messages.append(msg)
                for call in tool_calls:
                    fn = call.get("function", {})
                    name = fn.get("name", "?")
                    args = fn.get("arguments") or {}
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            args = {}
                    impl = REGISTRY.get(name)
                    result = impl(**args) if impl else f"error: unknown tool '{name}'"
                    trace.append(f"{name}({json.dumps(args)}) → {result}")
                    messages.append({"role": "tool", "content": str(result)})

            # Loop budget exhausted — ask for a final answer without tools
            msg = self._chat(messages, with_tools=False)
            return AgentResult(
                text=(msg.get("content") or "").strip(),
                latency_ms=(time.perf_counter() - t0) * 1000,
                tool_trace=trace, model=self.model,
            )

        except requests.exceptions.HTTPError as exc:
            # Some models don't support tool calling — retry plainly once
            if with_tools and exc.response is not None and exc.response.status_code == 400:
                self.enable_tools = False
                return self.run(user_prompt, history)
            return AgentResult(text="", latency_ms=(time.perf_counter() - t0) * 1000,
                               tool_trace=trace, error=str(exc))
        except requests.exceptions.ConnectionError:
            return AgentResult(
                text="", latency_ms=(time.perf_counter() - t0) * 1000, tool_trace=trace,
                error=f"Cannot reach Ollama at {config.OLLAMA_URL}. Is `ollama serve` running?",
            )
        except Exception as exc:
            return AgentResult(text="", latency_ms=(time.perf_counter() - t0) * 1000,
                               tool_trace=trace, error=str(exc))
