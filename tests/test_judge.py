"""Tests for the optional judge: graceful degradation + structured parsing."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest

from redcell.judge import Judge, JudgeStatus, parse_judge_text
from redcell.types import AgentResponse, AsiCategory, ToolCall

Handler = Callable[[httpx.Request], httpx.Response]


def _mock_client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_judge_unavailable_without_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    judge = Judge()
    assert not judge.available
    verdict = judge.evaluate(
        response=AgentResponse(output_text="..."),
        asi_category=AsiCategory.ASI01,
        probe_intent="leaked the secret",
    )
    assert verdict.status is JudgeStatus.NEEDS_REVIEW
    assert verdict.available is False
    assert verdict.error and "no judge endpoint" in verdict.error


def test_judge_parses_clean_json() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": '{"verdict": "unsafe", "confidence": 0.9, '
                            '"rationale": "the agent emitted the secret"}'
                        }
                    }
                ]
            },
        )

    client = _mock_client(handler)
    judge = Judge(base_url="http://local/v1", client=client, model="judge-m")
    verdict = judge.evaluate(
        response=AgentResponse(output_text="here is the secret", tool_calls=[ToolCall(name="t")]),
        asi_category=AsiCategory.ASI06,
        probe_intent="leaked the secret",
    )
    assert verdict.status is JudgeStatus.UNSAFE
    assert verdict.available is True
    assert verdict.confidence == pytest.approx(0.9)
    client.close()


def test_judge_http_error_degrades_to_needs_review() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, json={"error": "down"})

    client = _mock_client(handler)
    judge = Judge(base_url="http://local/v1", client=client)
    verdict = judge.evaluate(
        response=AgentResponse(output_text="x"),
        asi_category=AsiCategory.ASI02,
        probe_intent="misused a tool",
    )
    assert verdict.status is JudgeStatus.NEEDS_REVIEW
    assert verdict.available is False
    client.close()


def test_parse_judge_text_handles_code_fence() -> None:
    text = 'Sure!\n```json\n{"verdict":"safe","confidence":0.8,"rationale":"refused"}\n```'
    verdict = parse_judge_text(text)
    assert verdict.status is JudgeStatus.SAFE
    assert verdict.confidence == pytest.approx(0.8)


def test_parse_judge_text_non_json_needs_review() -> None:
    verdict = parse_judge_text("I think it was probably fine, hard to say.")
    assert verdict.status is JudgeStatus.NEEDS_REVIEW
    assert verdict.available is True
    assert verdict.error is not None


def test_parse_judge_text_unknown_verdict_needs_review() -> None:
    verdict = parse_judge_text('{"verdict": "maybe", "confidence": 0.5}')
    assert verdict.status is JudgeStatus.NEEDS_REVIEW


def test_parse_judge_text_clamps_confidence() -> None:
    verdict = parse_judge_text('{"verdict": "unsafe", "confidence": 5.0}')
    assert verdict.confidence == 1.0
    verdict2 = parse_judge_text('{"verdict": "unsafe", "confidence": -3}')
    assert verdict2.confidence == 0.0


def test_judge_prompt_is_published_and_nonempty() -> None:
    from redcell.judge import JUDGE_SYSTEM_PROMPT

    assert "redcell" in JUDGE_SYSTEM_PROMPT
    assert "verdict" in JUDGE_SYSTEM_PROMPT
