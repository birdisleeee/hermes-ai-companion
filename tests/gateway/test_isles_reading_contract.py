from __future__ import annotations

import io
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from gateway.config import Platform
from gateway.isles_reading import (
    build_reading_prompt,
    canonical_json,
    reading_session_id,
    validate_reading_reply,
    validate_reading_turn,
)
from gateway.run import _resolve_enabled_toolsets_for_source, _toolset_platform_config_key_for_source
from toolsets import resolve_toolset
from tools.isles_reading_tool import isles_reading_turn_scope, read_isles_reading_source


@pytest.mark.asyncio
async def test_processing_status_uses_bound_reading_session_not_transcript_id():
    from gateway.run import GatewayRunner
    from gateway.session import SessionSource
    adapter = SimpleNamespace(update_isles_turn_status=AsyncMock())
    runner = object.__new__(GatewayRunner)
    runner.adapters = {Platform.WEBHOOK: adapter}
    source = SessionSource(platform=Platform.WEBHOOK,
        chat_id="webhook:isles-reading:thread_one", chat_name="webhook/isles-reading",
        user_id="webhook:isles-reading")
    await runner._emit_isles_processing_status(
        SimpleNamespace(source=source, message_id="turn_one"),
        session_entry=SimpleNamespace(session_id="internal-transcript-uuid"),
        session_is_new=True,
    )
    adapter.update_isles_turn_status.assert_awaited_once_with(
        "turn_one", "processing", session_id=source.chat_id,
        session_is_new=True, route_name="isles-reading",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("state", ["delivering", "delivery_failed"])
@pytest.mark.parametrize("outcome", ["SUCCESS", "FAILURE", "CANCELLED"])
async def test_agent_completion_preserves_reading_outbox(state, outcome):
    from gateway.platforms.base import ProcessingOutcome
    from gateway.platforms.webhook import WebhookAdapter
    adapter = object.__new__(WebhookAdapter)
    adapter._routes = {"isles-reading": {"deliver": "http_callback"}}
    adapter._isles_turn_store = SimpleNamespace(get=lambda _: {"state": state})
    adapter.update_isles_turn_status = AsyncMock()
    await adapter.on_processing_complete(
        SimpleNamespace(source=SimpleNamespace(chat_name="webhook/isles-reading"), message_id="turn_one"),
        getattr(ProcessingOutcome, outcome),
    )
    adapter.update_isles_turn_status.assert_not_awaited()


def turn(**overrides):
    value = {
        "protocol": "isles-reading-turn-v1",
        "thread_id": "thread_one",
        "turn_id": "turn_one",
        "delivery_id": "delivery_one",
        "book": {"title": "沿着海岸慢慢走", "author": "林屿舟"},
        "discussion": {"topic": "为什么停下来？", "status": "open"},
        "source": {"document_id": "doc_one", "document_version": 1, "exact": "停下来，听一听风。", "insight": "先别急着下结论。"},
        "source_link": f"isles-reading://source/thread_one/doc_one?version=1&sha={'a' * 64}",
        "user_message": {"message_id": "message_one", "text": "你怎么看？"},
    }
    value.update(overrides)
    return value


def test_turn_is_bound_to_its_own_session_and_prompt_keeps_link_only():
    checked = validate_reading_turn(turn())
    assert checked["session_id"] == "webhook:isles-reading:thread_one"
    prompt = build_reading_prompt(turn())
    assert "停下来，听一听风。" in prompt
    assert "isles-reading://source/thread_one/doc_one" in prompt
    assert "前文" not in prompt
    assert reading_session_id("thread_two") != checked["session_id"]


def test_reading_speaks_as_the_same_person_without_an_owner_role():
    prompt = build_reading_prompt(turn())
    assert "岛主" not in prompt
    assert "延续你们既有的身份、关系和称呼" in prompt
    assert "我对摘录的想法：先别急着下结论。" in prompt
    assert prompt.endswith("我说：\n你怎么看？")
    # Quoted or user-authored words remain verbatim, even when they name a role.
    text = "书里的‘岛主’是什么意思？\n**你怎么看**"
    assert build_reading_prompt(turn(user_message={"message_id": "message_two", "text": text})).endswith(text)
    assert reading_session_id("thread_one") != reading_session_id("thread_two")


def test_whole_book_turn_has_no_fabricated_source():
    checked = validate_reading_turn(turn(source=None, source_link=None))
    assert checked["source"] is None
    assert "没有附带摘录" in build_reading_prompt(turn(source=None, source_link=None))


def test_whole_book_turn_may_offer_a_frozen_source_link():
    value = turn(source=None)
    checked = validate_reading_turn(value)
    assert checked["source"] is None
    assert checked["source_link"] in build_reading_prompt(value)


def test_turn_rejects_closed_or_cross_protocol_input():
    with pytest.raises(ValueError):
        validate_reading_turn(turn(discussion={"topic": "x", "status": "closed"}))
    with pytest.raises(ValueError):
        validate_reading_turn(turn(protocol="isles-story-v1"))


def test_reply_must_match_turn_and_is_natural_text_actions():
    current = validate_reading_turn(turn())
    reply = {"protocol": "isles-reading-reply-v1", "thread_id": "thread_one", "turn_id": "turn_one", "delivery_id": "delivery_one", "actions": [{"kind": "text", "index": 0, "count": 1, "text": "我也愿意先停在这里想一想。"}], "terminal": {"status": "completed", "retryable": False}}
    assert validate_reading_reply(reply, current)["actions"][0]["text"].startswith("我也")
    with pytest.raises(ValueError):
        validate_reading_reply({**reply, "thread_id": "other"}, current)


def test_failed_reply_cannot_contain_text():
    current = validate_reading_turn(turn())
    reply = {"protocol": "isles-reading-reply-v1", "thread_id": "thread_one", "turn_id": "turn_one", "delivery_id": "delivery_one", "actions": [{"kind": "text", "index": 0, "count": 1, "text": "不应该出现"}], "terminal": {"status": "failed", "retryable": True}}
    with pytest.raises(ValueError):
        validate_reading_reply(reply, current)


def test_canonical_json_is_stable_and_utf8():
    assert canonical_json({"b": "海", "a": 1}) == '{"a":1,"b":"海"}'.encode("utf-8")


def test_reading_route_has_only_the_bound_source_reader():
    source = SimpleNamespace(
        platform=Platform.WEBHOOK,
        route="isles-reading",
        user_id="webhook:isles-reading",
        user_name="isles-reading",
    )
    assert _toolset_platform_config_key_for_source(source) == "isles_reading"
    tools = {
        name
        for toolset in _resolve_enabled_toolsets_for_source({}, source)
        for name in resolve_toolset(toolset)
    }
    assert tools == {"read_isles_reading_source"}


def test_source_reader_accepts_only_the_current_turn_link():
    sha = "a" * 64
    link = f"isles-reading://source/thread_one/doc_one?version=1&sha={sha}"

    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    captured = {}

    def fake_open(request, timeout):
        captured["url"] = request.full_url
        captured["auth"] = request.headers["Authorization"]
        captured["body"] = json.loads(request.data.decode("utf-8"))
        assert timeout == 8
        return Response(json.dumps({
            "start": 10,
            "end": 14,
            "next_start": 14,
            "total": 100,
            "text": "海风吹过",
        }, ensure_ascii=False).encode("utf-8"))

    with isles_reading_turn_scope(
        turn_id="turn_one",
        source_link=link,
        source_url="https://isles-story.site/api/reading/gateway/source",
        token="secret-token",
    ):
        with patch("tools.isles_reading_tool.urlopen", fake_open):
            result = json.loads(read_isles_reading_source({
                "source_link": link,
                "start": 10,
                "limit": 20,
            }))
        rejected = json.loads(read_isles_reading_source({
            "source_link": link.replace("thread_one", "thread_two"),
        }))

    assert result["ok"] is True
    assert result["text"] == "海风吹过"
    assert captured == {
        "url": "https://isles-story.site/api/reading/gateway/source",
        "auth": "Bearer secret-token",
        "body": {
            "thread_id": "thread_one",
            "document_id": "doc_one",
            "version": 1,
            "sha": sha,
            "start": 10,
            "limit": 20,
        },
    }
    assert "只能读取当前讨论绑定的原文链接" in rejected["error"]


@pytest.mark.asyncio
async def test_complete_agent_path_binds_the_source_tool_to_this_turn(
    monkeypatch, tmp_path
):
    from gateway.session import SessionSource
    from tests.gateway.test_run_cleanup_progress import (
        CleanupCaptureAdapter,
        ProgressAgent,
        _install_fakes,
        _make_runner,
    )

    sha = "b" * 64
    link = f"isles-reading://source/thread_one/doc_one?version=2&sha={sha}"
    captured = {}

    class SourceResponse(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class ReadingAgent(ProgressAgent):
        def __init__(self, **kwargs):
            captured.update(kwargs)
            super().__init__(**kwargs)

        def run_conversation(self, message, conversation_history=None, task_id=None):
            result = json.loads(read_isles_reading_source({
                "source_link": link,
                "start": 0,
                "limit": 80,
            }))
            assert result["text"] == "冻结原文的一小段"
            return {"final_response": "**我读到了。**", "messages": [], "api_calls": 1}

    adapter = CleanupCaptureAdapter(platform=Platform.WEBHOOK)
    adapter._delivery_info = {
        "turn:turn_reading": {
            "deliver_extra": {
                "url": "https://isles-story.site/api/reading/gateway/reply",
            },
            "callback_secret": "reading-secret",
            "payload": {"source_link": link},
        }
    }
    runner = _make_runner(adapter)
    gateway_run = _install_fakes(monkeypatch, ReadingAgent, cleanup_on=False)
    monkeypatch.setattr(gateway_run, "_hermes_home", tmp_path)
    monkeypatch.setattr(
        "tools.isles_reading_tool.urlopen",
        lambda *_args, **_kwargs: SourceResponse(
            json.dumps({"start": 0, "end": 9, "text": "冻结原文的一小段"}, ensure_ascii=False).encode()
        ),
    )
    source = SessionSource(
        platform=Platform.WEBHOOK,
        chat_id="webhook:isles-reading:thread_one",
        chat_name="webhook/isles-reading",
        chat_type="webhook",
        user_id="webhook:isles-reading",
        user_name="isles-reading",
    )

    result = await runner._run_agent(
        message="围绕这段聊聊",
        context_prompt="",
        history=[],
        source=source,
        session_id="sess-reading",
        session_key="agent:main:webhook:webhook:isles-reading:thread_one",
        event_message_id="turn_reading",
    )

    assert result["final_response"] == "**我读到了。**"
    assert captured["platform"] == "webhook"
    assert {
        tool
        for toolset in captured["enabled_toolsets"]
        for tool in resolve_toolset(toolset)
    } == {"read_isles_reading_source"}
