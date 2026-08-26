"""JSONL audit log — one JSON line per pipeline decision.

Every prompt that enters the pipeline produces exactly one audit record with:
  • the decision (allowed / blocked / error) and which stage blocked it
  • per-stage verdicts, findings, and latencies (adaptive / input / output)
  • inference latency, model, tool calls
  • what the adaptive layer learned from the event (if anything)

The file is append-only JSONL (config.AUDIT_LOG_PATH, default audit_log.jsonl)
so it can be tailed, shipped to a SIEM, or loaded into pandas:

    import pandas as pd
    df = pd.read_json("audit_log.jsonl", lines=True)
"""

from __future__ import annotations

import datetime
import json
import time
from pathlib import Path

import config


def guard_to_dict(g) -> dict | None:
    """Serialize a GuardResult (or None) for the audit log / web API."""
    if g is None:
        return None
    return {
        "name": g.guard_name,
        "verdict": g.verdict.value,
        "latency_ms": round(g.latency_ms, 2),
        "ml_verdict": g.ml_verdict,
        "sanitized_text": g.sanitized_text[:200] if g.sanitized_text else None,
        "findings": [
            {"category": f.category, "detail": f.detail,
             "severity": f.severity, "evidence": f.evidence}
            for f in g.findings
        ],
    }


def result_to_record(res, event: str = "pipeline") -> dict:
    """Build the audit record for a PipelineResult."""
    if res.error:
        decision = "error"
    elif res.blocked_at:
        decision = "blocked"
    elif getattr(res, "sanitized", False):
        decision = "sanitized"
    else:
        decision = "allowed"
    return {
        "ts": time.time(),
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "event": event,
        "decision": decision,
        "blocked_at": res.blocked_at,
        "prompt": res.prompt[:400],
        "final_text": res.final_text[:400],
        "quarantined_output": (res.agent_text[:400]
                               if res.blocked_at == "output" and res.agent_text
                               else None),
        "stages": {
            "adaptive": guard_to_dict(res.adaptive_guard),
            "input": guard_to_dict(res.input_guard),
            "context": guard_to_dict(getattr(res, "context_guard", None)),
            "action": guard_to_dict(getattr(res, "action_guard", None)),
            "output": guard_to_dict(res.output_guard),
        },
        "guard_ms": round(res.total_guard_ms, 2),
        "inference_ms": round(res.inference_ms, 1),
        "model": res.model or None,
        "tool_trace": res.tool_trace,
        "learned": res.learn_report,
        "error": res.error,
    }


class AuditLogger:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or config.AUDIT_LOG_PATH)

    def log_result(self, res) -> dict:
        rec = result_to_record(res)
        self._append(rec)
        return rec

    def log_event(self, event: str, **fields) -> dict:
        rec = {
            "ts": time.time(),
            "time": datetime.datetime.now().isoformat(timespec="seconds"),
            "event": event,
            **fields,
        }
        self._append(rec)
        return rec

    def _append(self, rec: dict):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def tail(self, n: int = 100) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").strip().splitlines()
        out = []
        for line in lines[-n:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def summary(self) -> dict:
        recs = self.tail(100000)
        pipe = [r for r in recs if r.get("event") == "pipeline"]
        by_decision: dict[str, int] = {}
        by_stage: dict[str, int] = {}
        for r in pipe:
            by_decision[r["decision"]] = by_decision.get(r["decision"], 0) + 1
            if r.get("blocked_at"):
                by_stage[r["blocked_at"]] = by_stage.get(r["blocked_at"], 0) + 1
        return {"total": len(pipe), "by_decision": by_decision,
                "blocked_by_stage": by_stage, "path": str(self.path)}

    def _actual_result(self, record: dict) -> str:
        if record.get("error"):
            return "error"
        if record.get("blocked_at"):
            return "blocked"
        return "allowed"

    def build_run_artifact(self, runs: list[dict] | None = None,
                          path: str | Path | None = None) -> dict:
        """Build a run artifact from pipeline records or explicit run rows.

        Each run row can include: name, prompt, expected, decision, blocked_at, and
        error. If no explicit expected outcome is given, pass/fail is left null.
        """
        if runs is None:
            rows = []
            for rec in self.tail(100000):
                if rec.get("event") == "pipeline":
                    rows.append({
                        "name": rec.get("prompt", "")[:80],
                        "prompt": rec.get("prompt", ""),
                        "blocked_at": rec.get("blocked_at"),
                        "decision": rec.get("decision", self._actual_result(rec)),
                        "error": rec.get("error"),
                    })
        else:
            rows = list(runs)

        artifact_runs = []
        passed = 0
        failed = 0
        for row in rows:
            actual = row.get("decision") or self._actual_result(row)
            expected = row.get("expected")
            if expected is not None:
                outcome = actual == expected
                if outcome:
                    passed += 1
                else:
                    failed += 1
            else:
                outcome = None
            artifact_runs.append({
                "name": row.get("name") or row.get("scenario") or "run",
                "prompt": row.get("prompt"),
                "expected": expected,
                "actual": actual,
                "passed": outcome,
                "blocked_at": row.get("blocked_at"),
                "error": row.get("error"),
            })

        artifact = {
            "generated_at": datetime.datetime.now().isoformat(timespec="seconds"),
            "total_runs": len(artifact_runs),
            "passed": passed,
            "failed": failed,
            "summary": {
                "total": len(artifact_runs),
                "passed": passed,
                "failed": failed,
            },
            "runs": artifact_runs,
        }

        if path is not None:
            target = Path(path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(artifact, ensure_ascii=False, indent=2), encoding="utf-8")
        return artifact

    def write_run_artifact(self, runs: list[dict] | None = None,
                          path: str | Path | None = None) -> dict:
        target = Path(path or self.path.with_name("run_artifact.json"))
        return self.build_run_artifact(runs=runs, path=target)
