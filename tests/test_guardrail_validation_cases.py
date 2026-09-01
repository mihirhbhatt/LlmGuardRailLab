import pytest

from guards.input_guard import InputGuard
from payloads.guardrail_validation_cases import VALIDATION_CASES, expand_validation_cases


@pytest.mark.parametrize("case", VALIDATION_CASES, ids=lambda case: case.prompt_id)
def test_validation_case_matches_expected_input_guard_decision(case):
    result = InputGuard(use_ml=False).check(case.user_input)
    actual = "blocked" if result.blocked else "allowed"

    assert actual == case.expected


@pytest.mark.parametrize("case", expand_validation_cases(3), ids=lambda case: case.prompt_id)
def test_expanded_validation_case_matches_expected_input_guard_decision(case):
    result = InputGuard(use_ml=False).check(case.user_input)
    actual = "blocked" if result.blocked else "allowed"

    assert actual == case.expected
    assert case.source_case_id is not None