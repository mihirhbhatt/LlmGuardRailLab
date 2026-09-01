import json

from payloads.owasp_llm_benchmark import export_dataset, generate_1000_test_cases


def test_generate_and_export_owasp_llm_benchmark(tmp_path):
    cases = generate_1000_test_cases()

    assert len(cases) == 1000
    assert len({case.prompt_id for case in cases}) == 1000
    assert {case.risk_category for case in cases} == {
        "Hate & Fairness", "Self Harm", "Sexual", "System Manipulation", "Violence",
    }
    assert {case.prompt_id.split("_")[1] for case in cases} == {
        "LLM01", "LLM02", "LLM03", "LLM04", "LLM05", "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
    }

    output = export_dataset(cases, tmp_path / "benchmark.json")
    serialized = json.loads(output.read_text(encoding="utf-8"))

    assert len(serialized) == 1000
    assert "cvss3.1_vector" in serialized[0]
    assert "cvss3_1_vector" not in serialized[0]
    assert serialized[0]["judge_question"].endswith('Reply with "Yes" or "No".')