#!/usr/bin/env python3
"""Run the OWASP LLM benchmark through the complete guardrail pipeline."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import config
from guards import InputGuard
from payloads.guardrail_validation_cases import expand_validation_cases
from payloads.owasp_llm_benchmark import generate_1000_test_cases
from pipeline import GuardedPipeline


def _configure_isolated_artifacts(output_dir: Path) -> dict[str, Any]:
    """Redirect mutable pipeline state so a benchmark cannot affect normal runs."""
    original = {
        "ARTIFACTS_DIR": config.ARTIFACTS_DIR,
        "THREAT_DB_PATH": config.THREAT_DB_PATH,
        "SIGNATURE_DB_PATH": config.SIGNATURE_DB_PATH,
        "MEMORY_VAULT_PATH": config.MEMORY_VAULT_PATH,
        "BENIGN_PROMPT_PATH": config.BENIGN_PROMPT_PATH,
        "AUDIT_LOG_PATH": config.AUDIT_LOG_PATH,
    }
    config.ARTIFACTS_DIR = str(output_dir)
    config.THREAT_DB_PATH = str(output_dir / "threat_db.json")
    config.SIGNATURE_DB_PATH = str(output_dir / "learned_signatures.json")
    config.MEMORY_VAULT_PATH = str(output_dir / "memory_vault.jsonl")
    config.BENIGN_PROMPT_PATH = str(output_dir / "benign_prompts.jsonl")
    config.AUDIT_LOG_PATH = str(output_dir / "audit_log.jsonl")
    return original


def _restore_config(original: dict[str, Any]) -> None:
    for name, value in original.items():
        setattr(config, name, value)


def build_report(
    runs: list[dict[str, Any]],
    mode: str,
    use_ml_guard: bool,
    execution_stage: str = "full",
    suite: str = "owasp_llm_1000",
    validation_variants: int = 1,
) -> dict[str, Any]:
    """Summarize expected blocks, enforcement stage coverage, and misses."""
    actual_counts = Counter(run["actual"] for run in runs)
    stage_counts = Counter(run["blocked_at"] for run in runs if run["blocked_at"])
    failed_runs = [run for run in runs if not run["passed"]]
    return {
        "benchmark": suite,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "total_cases": len(runs),
        "expected_blocked": sum(run.get("expected", "blocked") == "blocked" for run in runs),
        "expected_allowed": sum(run.get("expected", "blocked") == "allowed" for run in runs),
        "blocked": actual_counts["blocked"],
        "allowed": actual_counts["allowed"],
        "errors": actual_counts["error"],
        "pass_rate": round((sum(run["passed"] for run in runs) / len(runs) * 100) if runs else 0, 2),
        "blocked_by_stage": dict(sorted(stage_counts.items())),
        "misses": failed_runs,
        "mode": mode,
        "ml_guard_enabled": use_ml_guard,
        "execution_stage": execution_stage,
    }


def run_benchmark(
    output_dir: str | Path = "artifacts/benchmarks/owasp_llm_1000",
    use_ml_guard: bool = False,
    mode: str = "independent",
    limit: int | None = None,
    execution_stage: str = "full",
    suite: str = "owasp_llm_1000",
    validation_variants: int = 1,
) -> dict[str, Any]:
    """Execute benchmark prompts and write `report.json` in *output_dir*.

    Independent mode resets adaptive learning before every case, exposing static
    and ML coverage. Sequential mode preserves learning to measure adaptive
    blocking under a sustained attack campaign.
    """
    if mode not in {"independent", "sequential"}:
        raise ValueError("mode must be 'independent' or 'sequential'")
    if execution_stage not in {"full", "input"}:
        raise ValueError("execution_stage must be 'full' or 'input'")
    if execution_stage == "input" and mode != "independent":
        raise ValueError("input execution only supports independent mode")
    if suite not in {"owasp_llm_1000", "validation"}:
        raise ValueError("suite must be 'owasp_llm_1000' or 'validation'")

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    original_config = _configure_isolated_artifacts(output)
    try:
        pipeline = GuardedPipeline(use_ml_guard=use_ml_guard) if execution_stage == "full" else None
        input_guard = InputGuard(use_ml=use_ml_guard) if execution_stage == "input" else None
        cases = generate_1000_test_cases() if suite == "owasp_llm_1000" else expand_validation_cases(validation_variants)
        cases = cases[:limit]
        runs: list[dict[str, Any]] = []
        for case in cases:
            if pipeline and mode == "independent":
                pipeline.adaptive_guard.reset()
            if execution_stage == "input":
                guard_result = input_guard.check(case.user_input)
                actual = "blocked" if guard_result.blocked else "allowed"
                blocked_at = "input" if guard_result.blocked else None
                error = None
                findings = [finding.category for finding in guard_result.findings]
            else:
                result = pipeline.run(case.user_input)
                actual = "error" if result.error else ("blocked" if result.blocked_at else "allowed")
                blocked_at = result.blocked_at
                error = result.error
                findings = [
                    finding.category
                    for guard in (result.adaptive_guard, result.input_guard, result.context_guard,
                                  result.action_guard, result.output_guard)
                    if guard
                    for finding in guard.findings
                ]
            runs.append({
                "prompt_id": case.prompt_id,
                "owasp_category": case.tags[0].removeprefix("owasp:") if suite == "owasp_llm_1000" else None,
                "risk_category": case.risk_category,
                "purpose": getattr(case, "purpose", None),
                "source_case_id": getattr(case, "source_case_id", None),
                "variant_index": getattr(case, "variant_index", 0),
                "attack_type": getattr(case, "attack_type", None),
                "injection_type": getattr(case, "injection_type", None),
                "injection_variant": getattr(case, "injection_variant", None),
                "severity": getattr(case, "severity", None),
                "tags": getattr(case, "tags", []),
                "cvss3_1_vector": getattr(case, "cvss3_1_vector", None),
                "cvss3_1_score": getattr(case, "cvss3_1_score", None),
                "user_input": case.user_input,
                "judge_question": getattr(case, "judge_question", None),
                "expected": getattr(case, "expected", "blocked"),
                "actual": actual,
                "passed": actual == getattr(case, "expected", "blocked"),
                "blocked_at": blocked_at,
                "error": error,
                "findings": findings,
            })
        report = build_report(runs, mode=mode, use_ml_guard=use_ml_guard,
                              execution_stage=execution_stage, suite=suite)
        report["runs"] = runs
        (output / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
    finally:
        _restore_config(original_config)


def main() -> None:
    parser = argparse.ArgumentParser(description="End-to-end OWASP LLM guardrail benchmark")
    parser.add_argument("--output-dir", default="artifacts/benchmarks/owasp_llm_1000")
    parser.add_argument("--mode", choices=("independent", "sequential"), default="independent")
    parser.add_argument("--execution-stage", choices=("full", "input"), default="full",
                        help="Use input for model-free CI; full exercises the whole pipeline")
    parser.add_argument("--suite", choices=("owasp_llm_1000", "validation"), default="owasp_llm_1000")
    parser.add_argument("--validation-variants", type=int, default=1,
                        help="Deterministic context variants per validation seed (1-5)")
    parser.add_argument("--use-ml-guard", action="store_true", help="Enable Llama Guard via Ollama")
    parser.add_argument("--limit", type=int, help="Run only the first N cases for a smoke test")
    args = parser.parse_args()

    report = run_benchmark(args.output_dir, args.use_ml_guard, args.mode, args.limit,
                           args.execution_stage, args.suite, args.validation_variants)
    print(
        f"{report['blocked']}/{report['total_cases']} blocked "
        f"({report['pass_rate']}%); allowed={report['allowed']}; errors={report['errors']}"
    )
    print(f"Blocked by stage: {report['blocked_by_stage']}")
    print(f"Report: {Path(args.output_dir) / 'report.json'}")


if __name__ == "__main__":
    main()