"""Permission boundary tests for the trusted Flying Bird Islands chat route."""

import sys
import types
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from gateway.config import Platform
from gateway.run import (
    _resolve_enabled_toolsets_for_source,
    _toolset_platform_config_key_for_source,
)
from hermes_cli.tools_config import _get_platform_tools
from toolsets import resolve_toolset


def _source(**overrides):
    values = {
        "platform": Platform.WEBHOOK,
        "route": "",
        "user_name": "",
        "user_id": "",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def _resolved_tools(platform_key: str) -> set[str]:
    enabled_toolsets = _get_platform_tools({}, platform_key)
    tools: set[str] = set()
    for toolset in enabled_toolsets:
        tools.update(resolve_toolset(toolset))
    return tools


def _resolved_source_tools(source) -> set[str]:
    tools: set[str] = set()
    for toolset in _resolve_enabled_toolsets_for_source({}, source):
        tools.update(resolve_toolset(toolset))
    return tools


def test_isles_story_route_uses_its_trusted_permission_identity():
    source = _source(route="isles-story", user_id="webhook:isles-story")

    assert _toolset_platform_config_key_for_source(source) == "isles_story"


def test_generic_webhook_routes_remain_sandboxed():
    source = _source(route="isles-comment", user_id="webhook:isles-comment")

    assert _toolset_platform_config_key_for_source(source) == "webhook"
    assert _resolved_tools("webhook") == {
        "web_search",
        "web_extract",
        "vision_analyze",
        "clarify",
    }


def test_payload_style_user_name_cannot_elevate_another_webhook_route():
    source = _source(
        route="isles-comment",
        user_id="webhook:isles-comment",
        user_name="isles-story",
    )

    assert _toolset_platform_config_key_for_source(source) == "webhook"


def test_isles_story_default_contains_full_memory_and_expression_tools():
    tools = _resolved_source_tools(
        _source(route="isles-story", user_id="webhook:isles-story")
    )

    assert {
        "terminal",
        "process",
        "read_file",
        "write_file",
        "search_files",
        "skills_list",
        "skill_view",
        "text_to_speech",
        "memory",
        "session_search",
        "execute_code",
        "delegate_task",
    } <= tools


def test_isles_story_can_be_explicitly_scoped_without_changing_webhook():
    config = {
        "platform_toolsets": {
            "isles_story": ["file", "tts", "memory"],
            "webhook": ["web"],
        }
    }

    isles_toolsets = _get_platform_tools(config, "isles_story")
    webhook_toolsets = _get_platform_tools(config, "webhook")

    assert {"file", "tts", "memory"} <= isles_toolsets
    assert "tts" not in webhook_toolsets
    assert "memory" not in webhook_toolsets


@pytest.mark.asyncio
async def test_isles_story_complete_agent_path_keeps_transport_platform_key(
    monkeypatch, tmp_path
):
    """Run the real gateway path far enough to catch dangling platform locals."""
    from gateway.session import SessionSource
    from tests.gateway.test_run_cleanup_progress import (
        CleanupCaptureAdapter,
        ProgressAgent,
        _install_fakes,
        _make_runner,
    )

    captured = {}

    class IslesAgent(ProgressAgent):
        def __init__(self, **kwargs):
            captured.update(kwargs)
            super().__init__(**kwargs)

    adapter = CleanupCaptureAdapter(platform=Platform.WEBHOOK)
    runner = _make_runner(adapter)
    gateway_run = _install_fakes(monkeypatch, IslesAgent, cleanup_on=False)
    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)

    source = SessionSource(
        platform=Platform.WEBHOOK,
        chat_id="webhook:isles-story:main",
        chat_name="webhook/isles-story",
        chat_type="webhook",
        user_id="webhook:isles-story",
        user_name="isles-story",
    )

    result = await runner._run_agent(
        message="hello",
        context_prompt="",
        history=[],
        source=source,
        session_id="sess-isles",
        session_key="agent:main:webhook:webhook:isles-story:main",
    )

    assert result["final_response"] == "done"
    assert captured["platform"] == "webhook"
    assert {"file", "memory", "tts"} <= set(captured["enabled_toolsets"])


@pytest.mark.asyncio
async def test_isles_story_complete_background_path_keeps_transport_platform_key(
    monkeypatch,
):
    """Exercise the background closure so dangling platform locals fail the test."""
    from gateway import run as gateway_run
    from gateway.session import SessionSource
    from tests.gateway.test_background_command import _make_runner

    captured = {}

    class BackgroundAgent:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def run_conversation(self, **kwargs):
            return {"final_response": "done", "messages": []}

    fake_run_agent = types.ModuleType("run_agent")
    fake_run_agent.AIAgent = BackgroundAgent
    monkeypatch.setitem(sys.modules, "run_agent", fake_run_agent)
    monkeypatch.setattr(gateway_run, "_load_gateway_config", lambda: {})

    runner = _make_runner()
    adapter = AsyncMock()
    adapter.send = AsyncMock()
    adapter.extract_media = MagicMock(return_value=([], "done"))
    adapter.extract_images = MagicMock(return_value=([], "done"))
    runner.adapters[Platform.WEBHOOK] = adapter
    runner._resolve_session_agent_runtime = MagicMock(
        return_value=("test-model", {"api_key": "test-key"})
    )
    runner._resolve_session_reasoning_config = MagicMock(return_value=None)
    runner._resolve_session_service_tier = MagicMock(return_value=None)
    runner._resolve_turn_agent_config = MagicMock(
        return_value={
            "model": "test-model",
            "runtime": {"api_key": "test-key"},
            "request_overrides": None,
        }
    )
    runner._refresh_fallback_model = MagicMock(return_value=None)
    runner._cleanup_agent_resources = MagicMock()

    async def run_inline(callback):
        return callback()

    runner._run_in_executor_with_context = run_inline

    source = SessionSource(
        platform=Platform.WEBHOOK,
        chat_id="webhook:isles-story:main",
        chat_name="webhook/isles-story",
        chat_type="webhook",
        user_id="webhook:isles-story",
        user_name="isles-story",
    )

    await runner._run_background_task("hello", source, "bg-isles")

    assert captured["platform"] == "webhook"
    assert {"file", "memory", "tts"} <= set(captured["enabled_toolsets"])
    adapter.send.assert_awaited_once()
