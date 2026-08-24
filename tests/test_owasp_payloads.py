from pathlib import Path

from payloads.owasp_payloads import CATEGORIES, generate_owasp_payloads


def test_generate_owasp_payloads(tmp_path):
    out = tmp_path / "owasp.jsonl"
    rows = generate_owasp_payloads(count_per_category=5, output_path=out)

    expected_categories = {
        "LLM01_Prompt_Injection",
        "LLM02_Sensitive_Info",
        "LLM05_Improper_Execution",
        "LLM07_System_Leak",
        "LLM10_Unbounded_Consumption",
        "Hate & Fairness",
        "Self Harm",
        "Sexual",
        "System Manipulation",
        "Violence",
    }

    assert len(rows) == 5 * len(CATEGORIES)
    assert out.exists()

    categories = {row["category"] for row in rows}
    assert expected_categories.issubset(categories)

    for row in rows:
        assert row["payload"].strip()
        assert row["source"] == "synthetic_owasp_seed"
        if row["category"] in {"Hate & Fairness", "Self Harm", "Sexual", "System Manipulation", "Violence"}:
            assert row["risk_category"] == row["category"]

    with out.open("r", encoding="utf-8") as fh:
        lines = [line.strip() for line in fh if line.strip()]
    assert len(lines) == len(rows)
