"""Pure contract helpers for the future 共读岛 Gateway route.

This module deliberately has no network, model, filesystem, or session side
effects.  The route adapter can use it after authenticating a Worker payload;
keeping the checks here makes it possible to gate the integration before it is
connected to the production webhook listener.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping


_IDENTITY = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
_PROTOCOL = "isles-reading-turn-v1"
_REPLY_PROTOCOL = "isles-reading-reply-v1"
_SESSION_PREFIX = "webhook:isles-reading:"


def _identity(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _IDENTITY.fullmatch(value):
        raise ValueError(f"invalid {name}")
    return value


def reading_session_id(thread_id: str) -> str:
    return _SESSION_PREFIX + _identity(thread_id, "thread_id")


def validate_reading_turn(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and copy the minimum Worker → Gateway turn envelope."""

    if payload.get("protocol") != _PROTOCOL:
        raise ValueError("invalid reading protocol")
    thread_id = _identity(payload.get("thread_id"), "thread_id")
    turn_id = _identity(payload.get("turn_id"), "turn_id")
    delivery_id = _identity(payload.get("delivery_id"), "delivery_id")
    book = payload.get("book")
    discussion = payload.get("discussion")
    message = payload.get("user_message")
    if not isinstance(book, Mapping) or not isinstance(discussion, Mapping) or not isinstance(message, Mapping):
        raise ValueError("incomplete reading context")
    title = book.get("title")
    author = book.get("author", "")
    topic = discussion.get("topic", "")
    text = message.get("text")
    if not isinstance(title, str) or not title.strip() or len(title) > 300:
        raise ValueError("invalid book title")
    if not isinstance(author, str) or len(author) > 200:
        raise ValueError("invalid book author")
    if discussion.get("status") != "open" or not isinstance(topic, str) or len(topic) > 500:
        raise ValueError("invalid discussion")
    message_id = _identity(message.get("message_id"), "message_id")
    if not isinstance(text, str) or not text.strip() or len(text) > 16_000:
        raise ValueError("invalid user message")
    source = payload.get("source")
    source_link = payload.get("source_link")
    if source is not None:
        if not isinstance(source, Mapping) or not isinstance(source.get("exact"), str) or len(source["exact"]) > 4_000:
            raise ValueError("invalid source")
        if not isinstance(source_link, str) or not source_link.startswith("isles-reading://source/"):
            raise ValueError("source link required")
    elif source_link is not None:
        raise ValueError("source link without source")
    return {
        "protocol": _PROTOCOL,
        "thread_id": thread_id,
        "turn_id": turn_id,
        "delivery_id": delivery_id,
        "session_id": reading_session_id(thread_id),
        "book": {"title": title, "author": author},
        "discussion": {"topic": topic, "status": "open"},
        "source": dict(source) if source is not None else None,
        "source_link": source_link,
        "user_message": {"message_id": message_id, "text": text},
    }


def build_reading_prompt(turn: Mapping[str, Any]) -> str:
    """Build a model-facing prompt without expanding the source document."""

    checked = validate_reading_turn(turn)
    lines = [
        "你正在参加一个独立的共读讨论。请围绕当前议题自然回应，使用正常的 Markdown 排版。",
        "不要声称读过没有提供的章节或整本书；需要更多原文时，使用 source_link 通过已授权工具按范围读取。",
        f"书名：{checked['book']['title']}",
        f"作者：{checked['book']['author'] or '未知'}",
        f"议题：{checked['discussion']['topic']}",
    ]
    source = checked.get("source")
    if source:
        lines.extend([f"已核验摘录：\n> {source['exact'].replace(chr(10), chr(10) + '> ')}", f"原文引用链接：{checked['source_link']}"])
        if source.get("insight"):
            lines.append(f"岛主对摘录的想法：{source['insight']}")
    else:
        lines.append("这是围绕整本书的议题，没有附带摘录。")
    lines.append(f"岛主本轮发言：\n{checked['user_message']['text']}")
    return "\n\n".join(lines)


def validate_reading_reply(reply: Mapping[str, Any], turn: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the Gateway → Worker natural Markdown reply envelope."""

    if reply.get("protocol") != _REPLY_PROTOCOL:
        raise ValueError("invalid reading reply protocol")
    for key in ("thread_id", "turn_id", "delivery_id"):
        if reply.get(key) != turn.get(key):
            raise ValueError("reading reply identity mismatch")
    terminal = reply.get("terminal")
    actions = reply.get("actions")
    if not isinstance(terminal, Mapping) or terminal.get("status") not in {"completed", "failed", "cancelled"} or not isinstance(terminal.get("retryable"), bool):
        raise ValueError("invalid reading terminal state")
    if not isinstance(actions, list) or len(actions) > 12:
        raise ValueError("invalid reading actions")
    if terminal["status"] == "completed" and not actions:
        raise ValueError("completed reading reply is empty")
    if terminal["status"] != "completed" and actions:
        raise ValueError("noncompleted reading reply has actions")
    checked_actions = []
    for index, action in enumerate(actions):
        if not isinstance(action, Mapping) or action.get("kind") != "text" or action.get("index") != index or action.get("count") != len(actions):
            raise ValueError("invalid reading text action")
        text = action.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > 12_000:
            raise ValueError("invalid reading text")
        checked_actions.append({"kind": "text", "index": index, "count": len(actions), "text": text})
    return {"protocol": _REPLY_PROTOCOL, "thread_id": turn["thread_id"], "turn_id": turn["turn_id"], "delivery_id": turn["delivery_id"], "actions": checked_actions, "terminal": {"status": terminal["status"], "retryable": terminal["retryable"]}}


def canonical_json(value: Mapping[str, Any]) -> bytes:
    """Stable bytes for the existing Gateway/Worker HMAC envelope."""

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
