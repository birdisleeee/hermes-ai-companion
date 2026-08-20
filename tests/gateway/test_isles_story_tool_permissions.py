"""Permission boundary tests for the trusted Flying Bird Islands chat route."""

from types import SimpleNamespace

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
