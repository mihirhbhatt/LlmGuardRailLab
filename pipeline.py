"""End-to-end guarded pipeline — the whole slide, in one class, now with a
self-learning adaptive layer for proactive blocking.

User Prompt → ⓪ Adaptive Guard → ① AI Guard (Input) → ①.5 AI Guard (Context)
            → ② Orchestrator + Ollama → ②.5 AI Guard (Action) → ③ AI Guard (Output) → User
                     ▲                                       │
                     └────────────── LEARN ◀─────────────────┘
   (every block — input, output, or user /flag — feeds the threat memory,
    so future VARIANTS of the attack are blocked proactively at stage ⓪)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from agent import Orchestrator
from audit import AuditLogger
from guards import AdaptiveGuard, ContextGuard, GuardResult, InputGuard, OutputGuard, Verdict

BLOCK_MESSAGE_INPUT = (
    "🚫 Request blocked by AI Guard (Input Guardrails). "
    "Your prompt triggered one or more security policies."
)
BLOCK_MESSAGE_OUTPUT = (
    "🚫 Response blocked by AI Guard (Output Guardrails). "
    "The model's answer violated one or more security policies."
)
BLOCK_MESSAGE_ADAPTIVE = (
    "🚫 Request blocked PROACTIVELY by AI Guard (Adaptive). "
    "This prompt resembles an attack the guard has already learned."
)
BLOCK_MESSAGE_CONTEXT = (
    "🚫 Request blocked by AI Guard (Context Guardrails). "
    "Retrieved context failed trust validation."
)
BLOCK_MESSAGE_ACTION = (
    "🚫 Action blocked by AI Guard (Action Guardrails). "
    "The requested tool action was not policy-compliant."
)
ESCALATE_MESSAGE_ACTION = (
    "⏸️ Action requires human approval. "
    "The model requested a high-risk operation."
)


@dataclass
class PipelineResult:
    prompt: str
    final_text: str
    blocked_at: str | None            # None | "adaptive" | "input" | "context" | "action" | "output"
    input_guard: GuardResult | None = None
    adaptive_guard: GuardResult | None = None
    context_guard: GuardResult | None = None
    action_guard: GuardResult | None = None
    output_guard: GuardResult | None = None
    agent_text: str | None = None     # raw model output (pre-output-guard)
    tool_trace: list[str] = field(default_factory=list)
    inference_ms: float = 0.0
    model: str = ""
    error: str | None = None
    learn_report: dict | None = None  # what the adaptive layer learned this turn
    sanitized: bool = False

    @property
    def total_guard_ms(self) -> float:
        return sum(g.latency_ms for g in
                   (self.adaptive_guard, self.input_guard, self.context_guard, self.action_guard, self.output_guard) if g)


class GuardedPipeline:
    def __init__(self, model: str | None = None, use_ml_guard: bool | None = None,
                 enable_tools: bool = True):
        import config
        if model:
            config.INFERENCE_MODEL = model
        ml = config.USE_ML_GUARD if use_ml_guard is None else use_ml_guard
        self.adaptive_guard = AdaptiveGuard()
        self.input_guard = InputGuard(use_ml=ml)
        self.context_guard = ContextGuard()
        self.output_guard = OutputGuard(use_ml=ml)
        self.orchestrator = Orchestrator(model=model or config.INFERENCE_MODEL,
                         enable_tools=enable_tools)
        self.audit = AuditLogger()
        self.history: list[dict] = []   # conversation memory (allowed turns only)
        self.last_prompt: str | None = None  # for /flag feedback

    # ── human feedback: user flags the previous allowed exchange ─────
    def flag_last(self) -> dict | None:
        if not self.last_prompt:
            return None
        report = self.adaptive_guard.learn(
            self.last_prompt, source="user_flag", categories=["user_reported"])
        self.audit.log_event("user_flag", prompt=self.last_prompt[:400],
                             learned=report)
        # forget the flagged exchange so it can't poison conversation memory
        if len(self.history) >= 2:
            self.history = self.history[:-2]
        return report

    def run(self, prompt: str, contexts: list[dict[str, str]] | None = None) -> PipelineResult:
        """Run the guarded pipeline and audit-log the decision."""
        res = self._run(prompt, contexts=contexts)
        self.audit.log_result(res)
        return res

    def _run(self, prompt: str, contexts: list[dict[str, str]] | None = None) -> PipelineResult:
        # ── Stage 0: Adaptive guard (learned threats — PROACTIVE) ─────
        ad_res = self.adaptive_guard.check(prompt)
        if ad_res.blocked:
            report = self.adaptive_guard.learn(
                prompt, source="adaptive_rehit",
                categories=[f.category for f in ad_res.findings])
            return PipelineResult(
                prompt=prompt, final_text=BLOCK_MESSAGE_ADAPTIVE,
                blocked_at="adaptive", adaptive_guard=ad_res,
                learn_report=report,
            )

        # ── Stage 1: Input guardrails (static rules + ML) ─────────────
        in_res = self.input_guard.check(prompt)
        if in_res.blocked:
            report = self.adaptive_guard.learn(
                prompt, source="input_guard",
                categories=[f.category for f in in_res.findings])
            return PipelineResult(
                prompt=prompt, final_text=BLOCK_MESSAGE_INPUT,
                blocked_at="input", input_guard=in_res,
                adaptive_guard=ad_res, learn_report=report,
            )

        # ── Stage 1.5: Context guardrails (trust + instruction stripping) ──
        ctx_res, cleaned_contexts = self.context_guard.check(contexts)
        if ctx_res.blocked:
            report = self.adaptive_guard.learn(
                prompt, source="input_guard",
                categories=[f.category for f in ctx_res.findings])
            return PipelineResult(
                prompt=prompt, final_text=BLOCK_MESSAGE_CONTEXT,
                blocked_at="context", input_guard=in_res, adaptive_guard=ad_res,
                context_guard=ctx_res, learn_report=report,
            )

        # ── Stage 2: Orchestration + inference (Ollama) ───────────────
        agent_res = self.orchestrator.run(
            prompt,
            history=self.history,
            context_snippets=[c["content"] for c in cleaned_contexts],
        )
        if agent_res.action_guard and agent_res.action_guard.blocked:
            final_text = (
                ESCALATE_MESSAGE_ACTION
                if agent_res.action_guard.verdict == Verdict.ESCALATE
                else BLOCK_MESSAGE_ACTION
            )
            return PipelineResult(
                prompt=prompt, final_text=final_text, blocked_at="action",
                input_guard=in_res, adaptive_guard=ad_res, context_guard=ctx_res,
                action_guard=agent_res.action_guard, tool_trace=agent_res.tool_trace,
                inference_ms=agent_res.latency_ms, model=agent_res.model,
            )
        if agent_res.error:
            return PipelineResult(
                prompt=prompt, final_text=f"⚠️ Inference error: {agent_res.error}",
                blocked_at=None, input_guard=in_res, adaptive_guard=ad_res, context_guard=ctx_res,
                inference_ms=agent_res.latency_ms, model=agent_res.model,
                error=agent_res.error,
            )

        # ── Stage 3: Output guardrails ────────────────────────────────
        out_res = self.output_guard.check(agent_res.text)
        if out_res.blocked:
            # PROACTIVE learning: remember the PROMPT that produced the bad
            # output, so next time the variant is stopped at stage 0 without
            # ever reaching (and paying for) inference.
            report = self.adaptive_guard.learn(
                prompt, source="output_guard",
                categories=[f.category for f in out_res.findings])
            return PipelineResult(
                prompt=prompt, final_text=BLOCK_MESSAGE_OUTPUT,
                blocked_at="output", input_guard=in_res, adaptive_guard=ad_res,
                context_guard=ctx_res, output_guard=out_res, agent_text=agent_res.text,
                tool_trace=agent_res.tool_trace,
                inference_ms=agent_res.latency_ms, model=agent_res.model,
                learn_report=report,
            )

        final_text = out_res.sanitized_text if out_res.verdict == Verdict.SANITIZE else agent_res.text

        # ── Allowed end-to-end ────────────────────────────────────────
        self.adaptive_guard.record_benign_turn()   # risk cools down
        self.last_prompt = prompt                  # /flag can still report it
        self.history += [
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": final_text},
        ]
        self.history = self.history[-12:]  # keep memory bounded

        return PipelineResult(
            prompt=prompt, final_text=final_text, blocked_at=None,
            input_guard=in_res, adaptive_guard=ad_res, context_guard=ctx_res, output_guard=out_res,
            agent_text=agent_res.text, tool_trace=agent_res.tool_trace,
            inference_ms=agent_res.latency_ms, model=agent_res.model,
            sanitized=out_res.verdict == Verdict.SANITIZE,
        )
