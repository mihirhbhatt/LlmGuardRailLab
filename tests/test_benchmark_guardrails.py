from benchmark_guardrails import build_report


def test_build_report_counts_blocks_and_misses():
    report = build_report([
        {"actual": "blocked", "blocked_at": "input", "passed": True},
        {"actual": "blocked", "blocked_at": "adaptive", "passed": True},
        {"actual": "allowed", "blocked_at": None, "passed": False},
        {"actual": "error", "blocked_at": None, "passed": False},
    ], mode="independent", use_ml_guard=False)

    assert report["total_cases"] == 4
    assert report["blocked"] == 2
    assert report["allowed"] == 1
    assert report["errors"] == 1
    assert report["pass_rate"] == 50.0
    assert report["blocked_by_stage"] == {"adaptive": 1, "input": 1}
    assert len(report["misses"]) == 2
    assert report["benchmark"] == "owasp_llm_1000"
    assert report["execution_stage"] == "full"
    assert report["expected_blocked"] == 4
    assert report["expected_allowed"] == 0