"""Tests for shared types: severity ordering, ASI titles, surface flattening."""

from __future__ import annotations

from redcell.types import (
    ASI_TITLES,
    MVP_CATEGORIES,
    AgentResponse,
    AsiCategory,
    Severity,
    ToolCall,
)


def test_severity_ordering() -> None:
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL > Severity.LOW
    assert Severity.HIGH >= Severity.HIGH
    assert max([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]) is Severity.CRITICAL


def test_all_asi_titles_present() -> None:
    for category in AsiCategory:
        assert ASI_TITLES[category]
        assert category.display_title == ASI_TITLES[category]


def test_mvp_categories_are_the_five_targeted() -> None:
    assert MVP_CATEGORIES == frozenset(
        {
            AsiCategory.ASI01,
            AsiCategory.ASI02,
            AsiCategory.ASI03,
            AsiCategory.ASI05,
            AsiCategory.ASI06,
        }
    )


def test_all_text_surfaces_includes_output_and_tool_args() -> None:
    resp = AgentResponse(
        output_text="final answer",
        tool_calls=[
            ToolCall(
                name="send_email",
                arguments={"to": "x@y.test", "body": "leaked"},
                raw_arguments='{"to":"x@y.test","body":"leaked"}',
            )
        ],
    )
    surfaces = resp.all_text_surfaces()
    joined = "\n".join(surfaces)
    assert "final answer" in joined
    assert "send_email" in joined
    assert "leaked" in joined
    # raw_arguments and stringified values both present
    assert any("body" in s for s in surfaces)


def test_all_text_surfaces_stringifies_nested_values() -> None:
    resp = AgentResponse(
        tool_calls=[ToolCall(name="t", arguments={"opts": {"nested": [1, 2, "deep"]}})]
    )
    joined = "\n".join(resp.all_text_surfaces())
    assert "deep" in joined
