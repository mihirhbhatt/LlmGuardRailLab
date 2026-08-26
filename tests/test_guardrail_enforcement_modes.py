from guards import ActionGuard, ContextGuard, OutputGuard, Verdict


def test_output_secret_leak_is_sanitized_not_blocked():
    response = "Use this token: sk-1234567890abcdefghijklmn for testing."

    result = OutputGuard(use_ml=False).check(response)

    assert result.verdict == Verdict.SANITIZE
    assert result.blocked is False
    assert result.sanitized_text is not None
    assert "sk-1234567890abcdefghijklmn" not in result.sanitized_text
    assert "[REDACTED_API_KEY]" in result.sanitized_text


def test_action_guard_escalates_high_risk_unknown_tool():
    result = ActionGuard().check_tool_call("execute_system_command", {"cmd": "cat /etc/passwd"})

    assert result.verdict == Verdict.ESCALATE
    assert result.blocked is True


def test_context_guard_blocks_untrusted_source():
    guard = ContextGuard(trusted_sources={"local"})
    result, cleaned = guard.check(
        [{"source": "web", "uri": "https://example.com/doc", "content": "safe text"}]
    )

    assert result.verdict == Verdict.BLOCK
    assert cleaned == []
