from __future__ import annotations

import pytest

from gateway.platforms.base import _looks_like_image
from gateway.platforms.webhook import (
    WebhookAdapter,
    _download_isles_media_items,
    _validate_isles_media_items,
)
from gateway.reply_delivery import ReplyDeliveryConfig, build_reply_units, segment_reply


def test_isles_media_contract_requires_https_images() -> None:
    payload = {
        "message": {
            "media": [
                {
                    "kind": "image",
                    "url": "https://isles.example/api/media/hermes?sig=abc",
                    "mime": "image/png",
                    "name": "home.png",
                }
            ]
        }
    }
    assert _validate_isles_media_items(payload) == [
        ("https://isles.example/api/media/hermes?sig=abc", "image/png", ".png")
    ]
    with pytest.raises(ValueError):
        _validate_isles_media_items({"message": {"media": [{"kind": "image", "url": "http://unsafe/image.png", "mime": "image/png"}]}})
    with pytest.raises(ValueError):
        _validate_isles_media_items({"message": {"media": [{"kind": "file", "url": "https://isles.example/a", "mime": "text/plain"}]}})


@pytest.mark.asyncio
async def test_isles_media_is_downloaded_before_event_creation() -> None:
    calls: list[tuple[str, str]] = []

    async def downloader(url: str, *, ext: str) -> str:
        calls.append((url, ext))
        return "/cache/isles-image" + ext

    paths, media_types = await _download_isles_media_items(
        {"message": {"media": [{"kind": "image", "url": "https://isles.example/image", "mime": "image/webp"}]}},
        downloader=downloader,
    )
    assert calls == [("https://isles.example/image", ".webp")]
    assert paths == ["/cache/isles-image.webp"]
    assert media_types == ["image/webp"]


def test_heic_magic_is_accepted_as_an_image() -> None:
    assert _looks_like_image(b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00")


def test_segmented_reply_has_no_artificial_message_count_cap() -> None:
    paragraphs = [f"第 {index} 条是一句完整的话。" for index in range(1, 13)]
    content = "\n\n".join(paragraphs)
    config = ReplyDeliveryConfig(
        segmented=True,
        short_reply_max=20,
        target_segment=40,
        min_delay_ms=0,
        max_delay_ms=0,
    )
    segments = segment_reply(content, config)
    assert len(segments) > 8
    assert "\n\n".join(segments) == content
    units = build_reply_units(content, turn_id="turn_1", config=config)
    assert len(units) == len(segments)
    assert units[-1].meta["reply_group"]["is_final"] is True


def test_route_config_ignores_legacy_max_segments_cap() -> None:
    config = ReplyDeliveryConfig.from_route(
        {"reply_delivery": {"segmented": True, "target_segment": 40, "max_segments": 2}}
    )
    content = "\n\n".join(f"自然段 {index}，这是一句完整的话。" for index in range(12))
    assert len(segment_reply(content, config)) > 2


def test_accepted_turn_keeps_enabled_segment_delivery_policy() -> None:
    adapter = object.__new__(WebhookAdapter)
    adapter._routes = {
        "isles-story": {
            "deliver": "http_callback",
            "deliver_extra": {"url": "https://isles.example/api/chat/callback"},
            "reply_delivery": {"segmented": True, "target_segment": 180},
        }
    }
    delivery = adapter._delivery_config_for_route("isles-story", {})
    assert delivery["reply_delivery"].segmented is True
    assert delivery["reply_delivery"].target_segment == 180


def test_hard_split_marker_splits_reply_on_own_line() -> None:
    config = ReplyDeliveryConfig(segmented=True, hard_split_marker="[[SPLIT]]")
    content = "今天天气不错\n\n[[SPLIT]]\n\n你那边怎么样？"
    assert segment_reply(content, config) == ["今天天气不错", "你那边怎么样？"]


def test_hard_split_marker_ignored_inside_code_block() -> None:
    config = ReplyDeliveryConfig(segmented=True, hard_split_marker="[[SPLIT]]")
    content = "看这段：\n```\n[[SPLIT]]\n```\n\n上面是代码。"
    assert segment_reply(content, config) == [content]


def test_hard_split_marker_disabled_by_default() -> None:
    config = ReplyDeliveryConfig(segmented=True)
    content = "今天天气不错\n\n[[SPLIT]]\n\n你那边怎么样？"
    assert "[[SPLIT]]" in "\n\n".join(segment_reply(content, config))


def test_hard_split_marker_respected_for_short_reply() -> None:
    config = ReplyDeliveryConfig(segmented=True, short_reply_max=90, hard_split_marker="[[SPLIT]]")
    content = "你好\n\n[[SPLIT]]\n\n我也想你"
    assert segment_reply(content, config) == ["你好", "我也想你"]


def test_route_config_reads_hard_split_marker() -> None:
    config = ReplyDeliveryConfig.from_route(
        {"reply_delivery": {"segmented": True, "hard_split_marker": "[[SPLIT]]"}}
    )
    assert config.hard_split_marker == "[[SPLIT]]"


def test_route_config_rejects_multiline_marker() -> None:
    config = ReplyDeliveryConfig.from_route(
        {"reply_delivery": {"segmented": True, "hard_split_marker": "a\nb"}}
    )
    assert config.hard_split_marker == ""
