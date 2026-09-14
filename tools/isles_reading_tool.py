"""Turn-scoped source reader for one authenticated 共读岛 discussion."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import json
import re
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

from tools.registry import registry, tool_error


_ID = re.compile(r"^[A-Za-z0-9_-]{1,100}$")
_SHA = re.compile(r"^[a-f0-9]{64}$")
_ACTIVE: ContextVar[dict[str, Any] | None] = ContextVar("isles_reading_active_turn", default=None)


def _safe_source_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except Exception:
        return False
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return False
    if parsed.path != "/api/reading/gateway/source":
        return False
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}


def _parse_link(value: str) -> dict[str, Any] | None:
    try:
        parsed = urlparse(value)
        parts = [part for part in parsed.path.split("/") if part]
        query = parse_qs(parsed.query, strict_parsing=True)
    except Exception:
        return None
    if parsed.scheme != "isles-reading" or parsed.netloc != "source" or len(parts) != 2:
        return None
    thread_id, document_id = parts
    version = (query.get("version") or [""])[0]
    sha = (query.get("sha") or [""])[0]
    if not _ID.fullmatch(thread_id) or not _ID.fullmatch(document_id) or not version.isdigit() or not _SHA.fullmatch(sha):
        return None
    return {"thread_id": thread_id, "document_id": document_id, "version": int(version), "sha": sha}


@contextmanager
def isles_reading_turn_scope(*, turn_id: str, source_link: str, source_url: str, token: str) -> Iterator[dict[str, Any]]:
    link = str(source_link or "").strip()
    state = {
        "enabled": bool(_ID.fullmatch(str(turn_id or "")) and _parse_link(link) and _safe_source_url(str(source_url or "")) and str(token or "")),
        "turn_id": str(turn_id or ""),
        "source_link": link,
        "source_url": str(source_url or ""),
        "token": str(token or ""),
    }
    reset = _ACTIVE.set(state)
    try:
        yield state
    finally:
        _ACTIVE.reset(reset)


def read_isles_reading_source(args: dict[str, Any], **_: Any) -> str:
    state = _ACTIVE.get()
    if not state or not state.get("enabled"):
        return tool_error("当前讨论没有可读取的原文链接")
    requested = str(args.get("source_link") or "").strip()
    if requested != state["source_link"]:
        return tool_error("只能读取当前讨论绑定的原文链接")
    link = _parse_link(requested)
    if not link:
        return tool_error("原文链接无效")
    start = args.get("start", 0)
    limit = args.get("limit", 2000)
    if not isinstance(start, int) or isinstance(start, bool) or start < 0:
        return tool_error("start 必须是非负整数")
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 4000:
        return tool_error("limit 必须是 1-4000")
    body = json.dumps({**link, "start": start, "limit": limit}, ensure_ascii=False).encode("utf-8")
    request = Request(
        state["source_url"],
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {state['token']}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "hermes-isles-reading/1.0",
        },
    )
    try:
        with urlopen(request, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))
    except Exception:
        return tool_error("原文暂时无法读取，请只根据已经提供的摘录继续讨论")
    text = result.get("text") if isinstance(result, dict) else None
    if not isinstance(text, str):
        return tool_error("原文服务没有返回有效文字")
    return json.dumps({
        "ok": True,
        "source_link": requested,
        "start": result.get("start", start),
        "end": result.get("end", start + len(text)),
        "next_start": result.get("next_start"),
        "total": result.get("total"),
        "text": text,
    }, ensure_ascii=False)


READ_ISLES_READING_SOURCE_SCHEMA = {
    "name": "read_isles_reading_source",
    "description": (
        "按需读取当前共读议题绑定的冻结原文。只能使用提示中给出的 source_link，"
        "每次最多读取 4000 个文字单位；不要一次加载整本书。"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "source_link": {"type": "string", "description": "当前讨论提示中原样给出的原文引用链接"},
            "start": {"type": "integer", "minimum": 0},
            "limit": {"type": "integer", "minimum": 1, "maximum": 4000},
        },
        "required": ["source_link"],
    },
}


registry.register(
    name="read_isles_reading_source",
    toolset="isles_reading",
    schema=READ_ISLES_READING_SOURCE_SCHEMA,
    handler=read_isles_reading_source,
    emoji="📖",
)

