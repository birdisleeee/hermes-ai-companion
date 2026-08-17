"""Tests for the opt-in grouped callback reply contract."""

from datetime import datetime, timezone
from types import SimpleNamespace
import re

import pytest

from gateway.reply_delivery import (
    ReplyDeliveryConfig,
    build_context_window,
    build_fallback_reply_unit,
    build_reply_group,
    build_reply_units,
    extract_context_window,
    make_segment_key,
    reply_delay_seconds,
    segment_reply,
)


def _config(**overrides) -> ReplyDeliveryConfig:
    values = {
        "segmented": True,
        "short_reply_max": 90,
        "target_segment": 110,
        "max_segments": 8,
    }
    values.update(overrides)
    return ReplyDeliveryConfig(**values)


def _non_whitespace(text: str) -> str:
    return re.sub(r"\s+", "", text)


class TestReplyDeliveryConfig:
    def test_default_is_disabled(self):
        assert ReplyDeliveryConfig.from_route({}).segmented is False

    def test_only_literal_true_enables_segmentation(self):
        route = {"reply_delivery": {"segmented": "true"}}
        assert ReplyDeliveryConfig.from_route(route).segmented is False
        route["reply_delivery"]["segmented"] = True
        assert ReplyDeliveryConfig.from_route(route).segmented is True

    def test_values_are_bounded_and_delays_are_ordered(self):
        route = {
            "reply_delivery": {
                "segmented": True,
                "short_reply_max": 1,
                "target_segment": 99999,
                "max_segments": 99,
                "min_delay_ms": 5000,
                "max_delay_ms": 100,
            }
        }
        config = ReplyDeliveryConfig.from_route(route)
        assert config.short_reply_max == 20
        assert config.target_segment == 1000
        assert config.max_segments == 8
        assert config.min_delay_ms == config.max_delay_ms == 5000


class TestSegmentReply:
    def test_short_reply_stays_single(self):
        assert segment_reply("嗯，在呢。", _config()) == ["嗯，在呢。"]

    def test_three_natural_paragraphs_become_three_messages(self):
        text = (
            "我看到你刚才说的事了，也知道你现在心里有点乱。"
            "先不用急着马上得出答案。\n\n"
            "如果你愿意，可以先告诉我最让你难受的是哪一部分。"
            "我们从那里慢慢说。\n\n"
            "今晚先照顾好自己，剩下的事情我会陪你一起理清楚。"
        )
        segments = segment_reply(text, _config(short_reply_max=20, target_segment=120))
        assert len(segments) == 3
        assert _non_whitespace("".join(segments)) == _non_whitespace(text)

    def test_roughly_six_hundred_chars_without_newlines_is_five_to_six_messages(self):
        sentence = "这件事不用一下子想明白，我们可以先把最重要的部分找出来，再慢慢处理剩下的细节。"
        text = sentence * 15
        segments = segment_reply(text, _config(target_segment=110))
        assert 5 <= len(segments) <= 6
        assert "".join(segments) == text

    def test_english_sentence_spacing_is_preserved_inside_segments(self):
        sentence = "This sentence has enough words to exercise semantic packing. "
        text = (sentence * 10).strip()
        segments = segment_reply(text, _config(short_reply_max=20, target_segment=180))
        assert len(segments) > 1
        assert " ".join(segments) == text

    def test_expressive_lead_can_stand_alone_but_tiny_fragment_is_merged(self):
        body = "这次确实是按错了位置，不过没关系，我们重新来一遍就好。" * 4
        expressive = segment_reply(f"哈哈哈哈笑死。\n\n{body}", _config(target_segment=90))
        assert expressive[0] == "哈哈哈哈笑死。"

        ordinary = segment_reply(f"对。\n\n{body}", _config(target_segment=90))
        assert ordinary[0] != "对。"

    def test_code_url_and_markdown_link_are_never_split(self):
        code = "```python\ndef hello():\n    return 'world'\n```"
        url = "https://example.com/a/very/long/path?x=1&y=2"
        link = "[说明文档](https://example.com/docs/start-here)"
        text = f"先看这段说明。{code} 然后打开 {url}，最后阅读{link}。" * 3
        segments = segment_reply(text, _config(target_segment=70))
        assert len(segments) <= 8
        assert sum(segment.count(code) for segment in segments) == 3
        assert sum(segment.count(url) for segment in segments) == 3
        assert sum(segment.count(link) for segment in segments) == 3

    def test_max_segments_is_enforced_without_losing_text(self):
        text = "第一件事慢慢说清楚。第二件事也不用着急。第三件事我们一起处理。" * 30
        segments = segment_reply(text, _config(target_segment=45, max_segments=4))
        assert len(segments) == 4
        assert _non_whitespace("".join(segments)) == _non_whitespace(text)


class TestReplyMetadata:
    def test_segment_key_is_stable(self):
        assert make_segment_key("msg_abc123", 2) == "msg_abc123:2"
        assert make_segment_key("msg_abc123", 2) == make_segment_key("msg_abc123", 2)
        assert make_segment_key("msg_abc123", 2, fallback=True) == "msg_abc123:fallback"

    def test_reply_group_contract(self):
        group = build_reply_group("msg_abc123", 1, 2)
        assert group == {
            "origin": "user_turn",
            "turn_id": "msg_abc123",
            "segment_key": "msg_abc123:1",
            "index": 1,
            "count": 2,
            "is_final": True,
        }

    @pytest.mark.parametrize("turn_id", ["", "has space", "x" * 201])
    def test_invalid_turn_ids_are_rejected(self, turn_id):
        with pytest.raises(ValueError):
            make_segment_key(turn_id, 0)

    def test_only_final_unit_carries_context_and_final_meta(self):
        text = "第一段要说得稍微完整一些，让它自然形成一条消息。" * 5
        context = {"used_percent": 37, "limit_tokens": 258000}
        units = build_reply_units(
            text,
            turn_id="msg_turn_1",
            config=_config(target_segment=70),
            context_window=context,
            final_meta={"visible_inner_note": {"text": "心里话"}},
        )
        assert len(units) > 1
        assert all("reply_group" in unit.meta for unit in units)
        assert all("context_window" not in unit.meta for unit in units[:-1])
        assert units[-1].meta["context_window"] == context
        assert "visible_inner_note" in units[-1].meta

    def test_cron_origin_fails_closed_to_one_ordinary_message(self):
        text = "自动整理通知。" * 50
        units = build_reply_units(
            text,
            turn_id="cron_123",
            config=_config(),
            origin="cron",
        )
        assert len(units) == 1
        assert "reply_group" not in units[0].meta

    def test_disabling_origin_requirement_disables_grouping_instead_of_weakening_it(self):
        config = _config(require_user_turn_origin=False)
        units = build_reply_units(
            "正常用户回复。" * 50,
            turn_id="msg_turn_unsafe_config",
            config=config,
            origin="user_turn",
        )
        assert len(units) == 1
        assert "reply_group" not in units[0].meta

    def test_disabled_route_stays_single_and_ungrouped(self):
        units = build_reply_units(
            "很长的回复。" * 100,
            turn_id="msg_turn_2",
            config=ReplyDeliveryConfig(),
        )
        assert len(units) == 1
        assert units[0].meta == {}

    def test_fallback_merges_failed_tail_and_preserves_final_meta(self):
        units = build_reply_units(
            "第一句话需要足够长一些。" * 20,
            turn_id="msg_turn_fallback",
            config=_config(short_reply_max=20, target_segment=55),
            context_window={"used_percent": 37},
        )
        assert len(units) > 2
        fallback = build_fallback_reply_unit(
            units,
            turn_id="msg_turn_fallback",
            failed_index=1,
        )
        group = fallback.meta["reply_group"]
        assert group["segment_key"] == "msg_turn_fallback:fallback:1"
        assert group["fallback_from_index"] == 1
        assert group["is_final"] is True
        assert fallback.meta["context_window"] == {"used_percent": 37}
        assert fallback.content == "\n\n".join(unit.content for unit in units[1:])

    def test_reply_delay_is_deterministic_and_bounded(self):
        config = _config(min_delay_ms=1200, max_delay_ms=3200)
        first = reply_delay_seconds("msg_turn_delay", 1, "下一条回复。" * 8, config)
        second = reply_delay_seconds("msg_turn_delay", 1, "下一条回复。" * 8, config)
        assert first == second
        assert 1.2 <= first <= 3.2


class TestContextWindow:
    def test_builds_from_explicit_usage_values(self):
        measured_at = datetime(2026, 8, 17, 10, 0, 10, tzinfo=timezone.utc)
        result = build_context_window(95_000, 258_000, measured_at=measured_at)
        assert result is not None
        assert result["used_percent"] == 37
        assert result["remaining_percent"] == 63

    def test_extracts_real_usage_with_deterministic_timestamp(self):
        compressor = SimpleNamespace(last_prompt_tokens=95_000, context_length=258_000)
        agent = SimpleNamespace(context_compressor=compressor)
        measured_at = datetime(2026, 8, 17, 10, 0, 10, tzinfo=timezone.utc)
        result = extract_context_window(agent, measured_at=measured_at)
        assert result == {
            "used_tokens": 95_000,
            "limit_tokens": 258_000,
            "remaining_tokens": 163_000,
            "used_percent": 37,
            "remaining_percent": 63,
            "measured_at": "2026-08-17T10:00:10.000Z",
            "source": "provider_usage",
        }

    @pytest.mark.parametrize(
        ("used", "limit"),
        [(0, 258_000), (None, 258_000), (95_000, 0), ("bad", 258_000)],
    )
    def test_missing_or_untrusted_usage_returns_none(self, used, limit):
        compressor = SimpleNamespace(last_prompt_tokens=used, context_length=limit)
        assert extract_context_window(compressor) is None

    def test_percentage_and_remaining_are_clamped(self):
        compressor = SimpleNamespace(last_prompt_tokens=300_000, context_length=258_000)
        result = extract_context_window(compressor)
        assert result is not None
        assert result["used_percent"] == 100
        assert result["remaining_percent"] == 0
        assert result["remaining_tokens"] == 0
