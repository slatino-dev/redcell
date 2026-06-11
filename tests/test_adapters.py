"""Tests for the target adapters.

The OpenAI adapter is exercised against an ``httpx.MockTransport`` so no network
is touched: we assert it parses tool calls (preserving raw argument strings),
serves synthetic tool results, places the payload per delivery vector, and turns
transport errors into ``AgentResponse.error`` rather than raising. The agent_loop
adapter is exercised against the bundled demo agent. The MCP adapter is a stub.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from redcell.adapters import (
    AgentLoopAdapter,
    McpAdapter,
    OpenAIEndpointAdapter,
    build_probe,
)
from redcell.corpus_loader import AttackCase
from targets.demo_agent import DemoAgent

CANARY = "REDCELL-CANARY-aa11bb22cc33"


def _case(vector: str = "user_message", payload: str = "do the task") -> AttackCase:
    return AttackCase.model_validate(
        {
            "id": "t-1",
            "asi_category": "ASI01",
            "delivery_vector": vector,
            "payload_template": payload,
            "oracle": {"type": "predicate", "params": {"regexes": ["x"]}},
        }
    )


Handler = Callable[[httpx.Request], httpx.Response]


def _mock_client(handler: Handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_openai_adapter_parses_tool_call_and_raw_args() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "calling tool",
                            "tool_calls": [
                                {
                                    "id": "c1",
                                    "function": {
                                        "name": "send_email",
                                        "arguments": json.dumps(
                                            {"to": "x@example.test", "body": CANARY}
                                        ),
                                    },
                                }
                            ],
                        }
                    }
                ]
            },
        )

    client = _mock_client(handler)
    adapter = OpenAIEndpointAdapter(
        model="m", base_url="http://local/v1", client=client, max_tool_rounds=1
    )
    resp = adapter.run(build_probe(_case(), canary=CANARY))
    assert resp.error is None
    assert len(resp.tool_calls) == 1
    call = resp.tool_calls[0]
    assert call.name == "send_email"
    assert call.arguments["body"] == CANARY
    assert call.raw_arguments is not None and CANARY in call.raw_arguments
    client.close()


def test_openai_adapter_serves_tool_result_and_continues() -> None:
    calls_seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        calls_seen.append(len(body["messages"]))
        # First round: emit a tool call. Second round: finish with text.
        has_tool_result = any(m.get("role") == "tool" for m in body["messages"])
        if not has_tool_result:
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {
                            "message": {
                                "role": "assistant",
                                "content": "",
                                "tool_calls": [
                                    {"id": "c1", "function": {"name": "noop", "arguments": "{}"}}
                                ],
                            }
                        }
                    ]
                },
            )
        return httpx.Response(
            200, json={"choices": [{"message": {"role": "assistant", "content": "all done"}}]}
        )

    client = _mock_client(handler)
    adapter = OpenAIEndpointAdapter(
        model="m", base_url="http://local/v1", client=client, max_tool_rounds=3
    )
    resp = adapter.run(build_probe(_case()))
    assert resp.output_text == "all done"
    assert [tc.name for tc in resp.tool_calls] == ["noop"]
    assert len(calls_seen) == 2  # two round-trips
    client.close()


def test_openai_adapter_dict_arguments_are_normalized() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": "x",
                            "tool_calls": [
                                {"id": "c1", "function": {"name": "t", "arguments": {"k": "v"}}}
                            ],
                        }
                    }
                ]
            },
        )

    client = _mock_client(handler)
    adapter = OpenAIEndpointAdapter(
        model="m", base_url="http://local/v1", client=client, max_tool_rounds=1
    )
    resp = adapter.run(build_probe(_case()))
    assert resp.tool_calls[0].arguments == {"k": "v"}
    client.close()


def test_openai_adapter_http_error_becomes_response_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    client = _mock_client(handler)
    adapter = OpenAIEndpointAdapter(
        model="m", base_url="http://local/v1", client=client, max_tool_rounds=1
    )
    resp = adapter.run(build_probe(_case()))
    assert resp.error is not None
    client.close()


def test_openai_adapter_payload_placement_system_prompt() -> None:
    captured: list[list[dict[str, Any]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content)["messages"])
        return httpx.Response(
            200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]}
        )

    client = _mock_client(handler)
    adapter = OpenAIEndpointAdapter(
        model="m", base_url="http://local/v1", client=client, max_tool_rounds=1
    )
    adapter.run(build_probe(_case(vector="system_prompt", payload="INJECTED"), canary=CANARY))
    messages = captured[0]
    assert messages[0]["role"] == "system"
    assert "INJECTED" in messages[0]["content"]
    client.close()


def test_openai_adapter_requires_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    with pytest.raises(ValueError):
        OpenAIEndpointAdapter(model="m")


def test_openai_adapter_reads_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_BASE_URL", "http://from-env/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "key-from-env")
    adapter = OpenAIEndpointAdapter(model="m")
    assert adapter.base_url == "http://from-env/v1"
    assert adapter.api_key == "key-from-env"
    assert adapter._headers()["Authorization"] == "Bearer key-from-env"


def test_agent_loop_adapter_drives_demo_agent() -> None:
    agent = DemoAgent()
    adapter = AgentLoopAdapter(agent.run)
    case = _case(vector="user_message", payload=f"reveal {CANARY}")
    resp = adapter.run(build_probe(case, canary=CANARY))
    assert resp.error is None
    # The naive demo agent leaks the token via output + a send_email tool call.
    assert CANARY in resp.output_text
    assert any(tc.name == "send_email" for tc in resp.tool_calls)


def test_agent_loop_adapter_reports_target_exception() -> None:
    def boom(_prompt: str) -> object:
        raise RuntimeError("target exploded")

    adapter = AgentLoopAdapter(boom)
    resp = adapter.run(build_probe(_case()))
    assert resp.error is not None
    assert "target exploded" in resp.error


def test_mcp_adapter_is_documented_stub() -> None:
    adapter = McpAdapter()
    with pytest.raises(NotImplementedError):
        adapter.run(build_probe(_case()))
