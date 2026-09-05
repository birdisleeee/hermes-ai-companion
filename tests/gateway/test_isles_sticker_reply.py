from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from gateway.config import PlatformConfig
from gateway.platforms.base import SendResult
from gateway.platforms.webhook import WebhookAdapter
from gateway.reply_delivery import (
    ReplyDeliveryConfig,
    build_structured_reply_units,
)
from tools.isles_sticker_tool import (
    COMPOSE_ISLES_REPLY_SCHEMA,
    compose_isles_reply,
    get_isles_reply_plan,
    isles_sticker_turn_scope,
    search_isles_stickers,
)


TURN_ID = "msg_sticker_turn_001"
TOKEN = "callback-token"
CATALOG = "test-2026-08-31.1"
CANDIDATE_TOKEN = "ab" * 16


class _FakeHTTPResponse:
    def __init__(self, value: dict):
        self.value = value

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self) -> bytes:
        return json.dumps(self.value, ensure_ascii=False).encode()


def _candidate_response() -> dict:
    return {
        "ok": True,
        "candidate_token": CANDIDATE_TOKEN,
        "catalog_version": CATALOG,
        "candidates": [
            {
                "sticker_id": "giz_comfort_wipe_tears_01",
                "label": "安慰宝宝",
                "meaning": "温柔安慰难过的对方",
                "emotions": ["心疼", "关心"],
                "tones": ["温柔", "陪伴"],
                "scenarios": ["安慰对方"],
                "keywords": ["抱抱", "陪伴"],
                "avoid": ["正式通知", "严肃说明"],
                "intensity": 2,
                "fallback_text": "抱抱你，我在呢。",
            },
            {
                "sticker_id": "giz_comfort_headpat_01",
                "label": "摸摸宝宝头",
                "meaning": "摸摸头安抚",
                "emotions": ["心疼"],
                "tones": ["轻柔"],
                "scenarios": ["安抚对方"],
                "intensity": 2,
                "fallback_text": "摸摸你。",
            },
        ],
    }


def test_compose_schema_keeps_plain_replies_outside_sticker_tool() -> None:
    description = COMPOSE_ISLES_REPLY_SCHEMA["description"]
    assert "不使用表情包时不要调用，照常直接回复" in description
    assert "把本轮要发送的全部文字和唯一一张表情包" in description
    assert "表情包不影响本轮正常回复的内容和长度" in description


def test_compose_rejects_plain_text_only_plan() -> None:
    with isles_sticker_turn_scope(
        turn_id=TURN_ID,
        candidates_url="https://isles.example/api/chat/stickers/candidates",
        token=TOKEN,
    ):
        result = compose_isles_reply({"actions": [
            {"type": "text", "content": "这是一条普通文字回复。"},
        ]})
    assert "照常直接回复" in result


def test_tool_search_then_compose_ordered_text_and_one_sticker() -> None:
    with isles_sticker_turn_scope(
        turn_id=TURN_ID,
        candidates_url="https://isles.example/api/chat/stickers/candidates",
        token=TOKEN,
    ) as state, patch(
        "tools.isles_sticker_tool.urlopen",
        return_value=_FakeHTTPResponse(_candidate_response()),
    ):
        search = json.loads(search_isles_stickers({
            "intent": "对方难过，我想陪着他",
            "emotion": "心疼",
            "tone": "轻柔",
            "contexts": ["安慰对方"],
        }))
        assert [item["sticker_id"] for item in search["candidates"]] == [
            "giz_comfort_wipe_tears_01", "giz_comfort_headpat_01"
        ]
        assert search["candidates"][0]["keywords"] == ["抱抱", "陪伴"]
        assert set(search["candidates"][0]) == {
            "sticker_id", "label", "meaning", "emotions", "tones", "scenarios", "keywords"
        }
        composed = json.loads(compose_isles_reply({"actions": [
            {"type": "text", "content": "来，靠过来一点。"},
            {"type": "sticker", "sticker_id": "giz_comfort_wipe_tears_01"},
        ]}))
        assert composed["ok"] is True
        plan = get_isles_reply_plan(state)

    assert [action["type"] for action in plan] == ["text", "sticker"]
    assert plan[1]["candidate_token"] == CANDIDATE_TOKEN
    assert plan[1]["catalog_version"] == CATALOG
    assert "fallback_text" not in plan[1]
    assert "url" not in plan[1] and "path" not in plan[1]


def test_tool_rejects_sticker_not_returned_for_this_turn() -> None:
    with isles_sticker_turn_scope(
        turn_id=TURN_ID,
        candidates_url="https://isles.example/api/chat/stickers/candidates",
        token=TOKEN,
    ), patch(
        "tools.isles_sticker_tool.urlopen",
        return_value=_FakeHTTPResponse(_candidate_response()),
    ):
        search_isles_stickers({"intent": "安慰", "emotion": "心疼", "tone": "温柔"})
        result = compose_isles_reply({"actions": [
            {"type": "sticker", "sticker_id": "giz_laugh_tears_01"},
        ]})
    assert "可信候选" in result


def test_tool_rejects_two_stickers_in_one_reply() -> None:
    with isles_sticker_turn_scope(
        turn_id=TURN_ID,
        candidates_url="https://isles.example/api/chat/stickers/candidates",
        token=TOKEN,
    ), patch(
        "tools.isles_sticker_tool.urlopen",
        return_value=_FakeHTTPResponse(_candidate_response()),
    ):
        search_isles_stickers({"intent": "安慰", "emotion": "心疼", "tone": "温柔"})
        result = compose_isles_reply({"actions": [
            {"type": "sticker", "sticker_id": "giz_comfort_wipe_tears_01"},
            {"type": "sticker", "sticker_id": "giz_comfort_headpat_01"},
        ]})
    assert "最多只能发送一张" in result


def test_structured_units_keep_order_keys_and_final_context() -> None:
    plan = [
        {"type": "text", "content": "先说一句"},
        {
            "type": "sticker",
            "sticker_id": "giz_comfort_wipe_tears_01",
            "candidate_token": CANDIDATE_TOKEN,
            "catalog_version": CATALOG,
            "fallback_text": "抱抱你。",
        },
    ]
    units = build_structured_reply_units(
        plan, turn_id=TURN_ID, context_window={"used_tokens": 10}
    )
    assert [unit.type for unit in units] == ["text", "sticker"]
    assert units[0].meta["reply_group"]["segment_key"] == f"{TURN_ID}:0"
    assert units[1].meta["reply_group"]["segment_key"] == f"{TURN_ID}:1"
    assert units[1].meta["reply_group"]["is_final"] is True
    assert units[1].meta["context_window"] == {"used_tokens": 10}
    assert units[1].fallback_text == ""


def test_structured_text_reuses_gateway_segmentation_around_sticker() -> None:
    plan = [
        {
            "type": "text",
            "content": "先说第一段。[[SPLIT]]再说第二段。",
        },
        {
            "type": "sticker",
            "sticker_id": "giz_comfort_wipe_tears_01",
            "candidate_token": CANDIDATE_TOKEN,
            "catalog_version": CATALOG,
            "fallback_text": "抱抱你。",
        },
        {
            "type": "text",
            "content": "图片之后也能继续说。[[SPLIT]]最后再单独说一句。",
        },
    ]
    units = build_structured_reply_units(
        plan,
        turn_id=TURN_ID,
        context_window={"used_tokens": 12},
        config=ReplyDeliveryConfig(
            segmented=True,
            hard_split_marker="[[SPLIT]]",
        ),
    )

    assert [unit.type for unit in units] == [
        "text",
        "text",
        "sticker",
        "text",
        "text",
    ]
    assert [unit.content for unit in units] == [
        "先说第一段。",
        "再说第二段。",
        "",
        "图片之后也能继续说。",
        "最后再单独说一句。",
    ]
    assert [unit.meta["reply_group"]["index"] for unit in units] == list(range(5))
    assert all(unit.meta["reply_group"]["count"] == 5 for unit in units)
    assert units[-1].meta["context_window"] == {"used_tokens": 12}


def test_structured_long_text_keeps_automatic_semantic_segmentation() -> None:
    long_text = (
        "今天发生了很多事情，我想慢慢讲给你听。"
        "先把第一件事说完，再说第二件。"
        "然后我们歇一会儿，不用着急。"
        "最后我再抱抱你，陪你把今天收好。"
    )
    units = build_structured_reply_units(
        [
            {"type": "text", "content": long_text},
            {
                "type": "sticker",
                "sticker_id": "giz_comfort_wipe_tears_01",
                "candidate_token": CANDIDATE_TOKEN,
                "catalog_version": CATALOG,
                "fallback_text": "抱抱你。",
            },
        ],
        turn_id=TURN_ID,
        config=ReplyDeliveryConfig(
            segmented=True,
            short_reply_max=20,
            target_segment=40,
        ),
    )

    text_units = [unit for unit in units if unit.type == "text"]
    assert len(text_units) >= 2
    assert "".join(unit.content for unit in text_units) == long_text
    assert units[-1].type == "sticker"


def _adapter() -> WebhookAdapter:
    return WebhookAdapter(PlatformConfig(enabled=True, extra={
        "host": "127.0.0.1",
        "port": 0,
        "routes": {
            "isles-story": {
                "secret": "test-secret-that-is-long-enough",
                "deliver": "http_callback",
                "deliver_extra": {
                    "url": "https://isles.example/api/chat/callback",
                    "token": TOKEN,
                },
                "reply_delivery": {"segmented": True, "min_delay_ms": 0, "max_delay_ms": 0},
            },
        },
    }))


@pytest.mark.asyncio
async def test_webhook_send_uses_structured_units_instead_of_final_text() -> None:
    adapter = _adapter()
    adapter._emit_isles_turn_status = AsyncMock(return_value=True)
    adapter._deliver_grouped_http_callbacks = AsyncMock(return_value=SendResult(success=True))
    adapter.mark_pending_reply_turn(
        TURN_ID,
        {"used_tokens": 1},
        reply_plan=[
            {"type": "text", "content": "文字"},
            {
                "type": "sticker",
                "sticker_id": "giz_comfort_wipe_tears_01",
                "candidate_token": CANDIDATE_TOKEN,
                "catalog_version": CATALOG,
                "fallback_text": "抱抱你。",
            },
        ],
    )
    result = await adapter.send(
        "webhook:isles-story:main",
        "模型结束语不会被解析成动作",
        reply_to=TURN_ID,
    )
    assert result.success is True
    units = adapter._deliver_grouped_http_callbacks.await_args.args[0]
    assert [unit.type for unit in units] == ["text", "sticker"]
    assert units[0].content == "文字"
    assert units[1].sticker["sticker_id"] == "giz_comfort_wipe_tears_01"


@pytest.mark.asyncio
async def test_single_sticker_failure_is_not_replaced_with_text() -> None:
    adapter = _adapter()
    unit = build_structured_reply_units([{
        "type": "sticker",
        "sticker_id": "giz_comfort_wipe_tears_01",
        "candidate_token": CANDIDATE_TOKEN,
        "catalog_version": CATALOG,
        "fallback_text": "抱抱你，我在呢。",
    }], turn_id=TURN_ID)[0]
    adapter._deliver_http_callback = AsyncMock(side_effect=[
        SendResult(success=False),
        SendResult(success=False),
        SendResult(success=False),
    ])
    with patch("gateway.platforms.webhook.asyncio.sleep", new=AsyncMock()):
        result = await adapter._deliver_grouped_http_callbacks(
            [unit], adapter._static_isles_delivery(), TURN_ID, ReplyDeliveryConfig()
        )
    assert result.success is False
    assert adapter._deliver_http_callback.await_count == 3
    assert all(
        call.kwargs.get("reply_type") == "sticker"
        for call in adapter._deliver_http_callback.await_args_list
    )
