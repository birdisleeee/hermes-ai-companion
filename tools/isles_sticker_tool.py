"""Turn-scoped sticker selection tools for the trusted isles-story route.

The model never receives local paths, R2 keys, arbitrary URLs, or the full
catalog. It searches a Worker-owned trusted catalog, sees a small candidate
set, then records an ordered typed reply plan. The gateway consumes that plan
directly; no ordinary assistant text is parsed for magic markers.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import json
import re
from typing import Any, Iterator
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from tools.registry import registry, tool_error


_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_TURN_RE = re.compile(r"^[^\s]{1,200}$")
_ACTIVE_TURN: ContextVar[dict[str, Any] | None] = ContextVar(
    "isles_sticker_active_turn", default=None
)


def _safe_candidates_url(value: str) -> bool:
    try:
        parsed = urlparse(value)
    except Exception:
        return False
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        return False
    if parsed.path != "/api/chat/stickers/candidates":
        return False
    if parsed.scheme == "https" and parsed.hostname:
        return True
    return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost", "::1"}


@contextmanager
def isles_sticker_turn_scope(
    *, turn_id: str, candidates_url: str, token: str
) -> Iterator[dict[str, Any]]:
    """Bind one isles-story user turn to the two model-facing tools."""
    normalized_turn = str(turn_id or "").strip()
    normalized_url = str(candidates_url or "").strip()
    normalized_token = str(token or "").strip()
    enabled = bool(
        _TURN_RE.fullmatch(normalized_turn)
        and _safe_candidates_url(normalized_url)
        and normalized_token
    )
    state: dict[str, Any] = {
        "enabled": enabled,
        "turn_id": normalized_turn,
        "candidates_url": normalized_url,
        "token": normalized_token,
        "searches": [],
        "plan": None,
    }
    reset_token = _ACTIVE_TURN.set(state)
    try:
        yield state
    finally:
        _ACTIVE_TURN.reset(reset_token)


def get_isles_reply_plan(state: dict[str, Any] | None) -> list[dict[str, Any]] | None:
    plan = state.get("plan") if isinstance(state, dict) else None
    if not isinstance(plan, list) or not plan:
        return None
    return json.loads(json.dumps(plan, ensure_ascii=False))


def _require_turn() -> dict[str, Any]:
    state = _ACTIVE_TURN.get()
    if not state or not state.get("enabled"):
        raise RuntimeError("表情包功能只在桔小鸟的飞鸟群岛主聊天回合中可用")
    return state


def _clean_text(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    return text[:limit]


def _clean_string_list(value: Any, limit: int = 8) -> list[str]:
    if not isinstance(value, list):
        return []
    result: list[str] = []
    for item in value:
        text = _clean_text(item, 48)
        if text and text not in result:
            result.append(text)
        if len(result) >= limit:
            break
    return result


def search_isles_stickers(args: dict[str, Any], **_: Any) -> str:
    """Retrieve a small intent-ranked candidate set from the Worker."""
    try:
        state = _require_turn()
    except RuntimeError as error:
        return tool_error(str(error))
    query = {
        "intent": _clean_text(args.get("intent"), 240),
        "emotion": _clean_text(args.get("emotion"), 48),
        "tone": _clean_text(args.get("tone"), 48),
        "contexts": _clean_string_list(args.get("contexts")),
        "keywords": _clean_string_list(args.get("keywords")),
    }
    if not query["intent"] or not query["emotion"] or not query["tone"]:
        return tool_error("intent、emotion 和 tone 都必须填写；检索失败时直接正常文字回复，不要改用 emoji")
    payload = json.dumps(
        {"turn_id": state["turn_id"], "query": query, "limit": 6},
        ensure_ascii=False,
    ).encode("utf-8")
    request = Request(
        state["candidates_url"],
        data=payload,
        method="POST",
        headers={
            "Authorization": f"Bearer {state['token']}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "hermes-isles-sticker/1.0",
        },
    )
    try:
        with urlopen(request, timeout=8) as response:
            result = json.loads(response.read().decode("utf-8"))
    except Exception:
        return tool_error("表情包候选检索暂时失败。请继续正常文字回复，不要用 emoji 代替，也不要猜 sticker_id")
    candidates = result.get("candidates") if isinstance(result, dict) else None
    candidate_token = str(result.get("candidate_token") or "") if isinstance(result, dict) else ""
    catalog_version = str(result.get("catalog_version") or "") if isinstance(result, dict) else ""
    if not isinstance(candidates, list) or not candidates:
        return json.dumps(
            {"ok": True, "candidates": [], "instruction": "没有合适候选，请正常文字回复，不要用 emoji 代替"},
            ensure_ascii=False,
        )
    safe_candidates: list[dict[str, Any]] = []
    for raw in candidates[:6]:
        sticker_id = str(raw.get("sticker_id") or "") if isinstance(raw, dict) else ""
        if not _ID_RE.fullmatch(sticker_id):
            continue
        safe_candidates.append({
            "sticker_id": sticker_id,
            "label": _clean_text(raw.get("label"), 24),
            "meaning": _clean_text(raw.get("meaning"), 160),
            "emotions": _clean_string_list(raw.get("emotions")),
            "tones": _clean_string_list(raw.get("tones")),
            "scenarios": _clean_string_list(raw.get("scenarios")),
            "keywords": _clean_string_list(raw.get("keywords")),
        })
    if not safe_candidates or not re.fullmatch(r"[a-f0-9]{32}", candidate_token):
        return tool_error("Worker 没有返回可验证候选。请正常文字回复，不要用 emoji 代替")
    state["searches"].append({
        "candidate_token": candidate_token,
        "catalog_version": catalog_version,
        "candidates": {item["sticker_id"]: item for item in safe_candidates},
    })
    return json.dumps({
        "ok": True,
        "catalog_version": catalog_version,
        "candidates": safe_candidates,
        "instruction": "只有确实贴合当前表达意图时才选择；也可以不用表情包",
    }, ensure_ascii=False)


def _find_candidate(state: dict[str, Any], sticker_id: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    for search in reversed(state.get("searches") or []):
        candidate = (search.get("candidates") or {}).get(sticker_id)
        if candidate:
            return search, candidate
    return None


def compose_isles_reply(args: dict[str, Any], **_: Any) -> str:
    """Record an ordered text/sticker reply plan for gateway delivery."""
    try:
        state = _require_turn()
    except RuntimeError as error:
        return tool_error(str(error))
    raw_actions = args.get("actions")
    if not isinstance(raw_actions, list) or not 1 <= len(raw_actions) <= 6:
        return tool_error("actions 必须包含 1-6 个按发送顺序排列的动作")
    plan: list[dict[str, Any]] = []
    sticker_count = 0
    for index, raw in enumerate(raw_actions):
        if not isinstance(raw, dict):
            return tool_error(f"第 {index + 1} 个动作格式无效")
        action_type = str(raw.get("type") or "").strip()
        if action_type == "text":
            content = _clean_text(raw.get("content"), 4000)
            if not content:
                return tool_error(f"第 {index + 1} 个文字动作为空")
            plan.append({"type": "text", "content": content})
            continue
        if action_type == "sticker":
            sticker_count += 1
            if sticker_count > 1:
                return tool_error("一轮回应最多只能发送一张表情包；请保留最贴合表达意图的那一张")
            sticker_id = str(raw.get("sticker_id") or "").strip()
            found = _find_candidate(state, sticker_id)
            if not _ID_RE.fullmatch(sticker_id) or found is None:
                return tool_error(f"第 {index + 1} 个表情包不在本轮可信候选中")
            search, candidate = found
            plan.append({
                "type": "sticker",
                "sticker_id": sticker_id,
                "candidate_token": search["candidate_token"],
                "catalog_version": search["catalog_version"],
            })
            continue
        return tool_error(f"第 {index + 1} 个动作 type 只能是 text 或 sticker")
    if sticker_count != 1:
        return tool_error("没有选择表情包时不要调用本工具；请照常直接回复")
    state["plan"] = plan
    return json.dumps({
        "ok": True,
        "accepted": len(plan),
        "instruction": "本轮完整回复已接收，发送由系统接管；直接结束当前回答即可",
    }, ensure_ascii=False)


SEARCH_ISLES_STICKERS_SCHEMA = {
    "name": "search_isles_stickers",
    "description": (
        "当且仅当你认为图片表情包可能比纯文字更自然地表达当前情绪时，从桔小鸟的受信任库中按意图检索少量候选。"
        "这不是 emoji 工具。不要每轮都调用；严肃解释、信息密集或没有合适候选时直接用文字。检索失败时用正常文字，绝不改用 emoji。"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "intent": {"type": "string", "description": "这次真正想传达的意思，而不是复述用户原话"},
            "emotion": {"type": "string", "description": "主要情绪，如心疼、开心、委屈、疑惑"},
            "tone": {"type": "string", "description": "表达语气，如轻柔、调皮、认真、夸张"},
            "contexts": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
            "keywords": {"type": "array", "items": {"type": "string"}, "maxItems": 8},
        },
        "required": ["intent", "emotion", "tone"],
    },
}


COMPOSE_ISLES_REPLY_SCHEMA = {
    "name": "compose_isles_reply",
    "description": (
        "仅当这一轮确定要使用表情包时调用；不使用表情包时不要调用，照常直接回复。"
        "调用时，把本轮要发送的全部文字和唯一一张表情包按实际发送顺序放进 actions，发送随后由系统接管。"
        "表情包不影响本轮正常回复的内容和长度；长文字会按原有规则自动分成多个文字气泡。"
        "可仅发表情包，也可把表情包放在文字之前、中间或之后；同一轮最多一张图。"
        "sticker_id 必须来自本轮 search_isles_stickers 的候选；系统会自己补齐验证凭据。"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "actions": {
                "type": "array",
                "minItems": 1,
                "maxItems": 6,
                "items": {
                    "type": "object",
                    "properties": {
                        "type": {"type": "string", "enum": ["text", "sticker"]},
                        "content": {
                            "type": "string",
                            "description": "type=text 时填写本轮要发送的文字；可写长文，系统会按需自动分段",
                        },
                        "sticker_id": {"type": "string", "description": "type=sticker 时填写本轮候选 ID"},
                    },
                    "required": ["type"],
                },
            },
        },
        "required": ["actions"],
    },
}


registry.register(
    name="search_isles_stickers",
    toolset="isles_stickers",
    schema=SEARCH_ISLES_STICKERS_SCHEMA,
    handler=search_isles_stickers,
    emoji="🖼️",
)
registry.register(
    name="compose_isles_reply",
    toolset="isles_stickers",
    schema=COMPOSE_ISLES_REPLY_SCHEMA,
    handler=compose_isles_reply,
    emoji="🖼️",
)
