from __future__ import annotations

import pytest

from gateway.isles_reading import (
    build_reading_prompt,
    canonical_json,
    reading_session_id,
    validate_reading_reply,
    validate_reading_turn,
)


def turn(**overrides):
    value = {
        "protocol": "isles-reading-turn-v1",
        "thread_id": "thread_one",
        "turn_id": "turn_one",
        "delivery_id": "delivery_one",
        "book": {"title": "沿着海岸慢慢走", "author": "林屿舟"},
        "discussion": {"topic": "为什么停下来？", "status": "open"},
        "source": {"document_id": "doc_one", "document_version": 1, "exact": "停下来，听一听风。", "insight": "先别急着下结论。"},
        "source_link": "isles-reading://source/thread_one/doc_one?version=1&sha=abc",
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


def test_whole_book_turn_has_no_fabricated_source():
    checked = validate_reading_turn(turn(source=None, source_link=None))
    assert checked["source"] is None
    assert "没有附带摘录" in build_reading_prompt(turn(source=None, source_link=None))


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
