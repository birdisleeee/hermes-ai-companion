"""Pure helpers for grouped HTTP callback reply delivery.

The gateway's existing send path remains the compatibility baseline.  This
module only describes how an opted-in webhook route can turn one completed
agent response into stable callback units.  It deliberately has no network,
session, prompt, or persistence side effects.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Mapping, Sequence


_PROTECTED_SPAN_RE = re.compile(
    r"```[\s\S]*?```"  # fenced code blocks
    r"|`[^`\n]+`"  # inline code
    r"|\[[^\]\n]+\]\([^\)\n]+\)"  # Markdown links
    r"|https?://[^\s<>\[\]()`\"'，。！？；、]+",  # bare URLs
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(r"\ue000(\d+)\ue001")
_PARAGRAPH_BREAK_RE = re.compile(r"\n{2,}")
_CLOSING_PUNCTUATION = frozenset("\"'”’」』）》】")
_CJK_SENTENCE_END = frozenset("。！？")


@dataclass(frozen=True)
class ReplyDeliveryConfig:
    """Validated route-level settings for grouped reply callbacks.

    ``segmented`` defaults to false, so importing this module or adding a
    ``reply_delivery`` block without explicitly enabling it cannot alter
    production delivery behaviour.
    """

    segmented: bool = False
    require_user_turn_origin: bool = True
    short_reply_max: int = 90
    target_segment: int = 110
    hard_split_marker: str = ""
    min_delay_ms: int = 1200
    max_delay_ms: int = 3200

    @classmethod
    def from_route(cls, route_config: Mapping[str, Any] | None) -> "ReplyDeliveryConfig":
        route_config = route_config if isinstance(route_config, Mapping) else {}
        raw = route_config.get("reply_delivery", {})
        raw = raw if isinstance(raw, Mapping) else {}

        min_delay = _bounded_int(raw.get("min_delay_ms"), 1200, 0, 30_000)
        max_delay = _bounded_int(raw.get("max_delay_ms"), 3200, 0, 30_000)
        if max_delay < min_delay:
            max_delay = min_delay

        return cls(
            # Strict boolean check prevents strings such as "false" from
            # accidentally enabling production segmentation.
            segmented=raw.get("segmented") is True,
            require_user_turn_origin=raw.get("require_user_turn_origin") is not False,
            short_reply_max=_bounded_int(raw.get("short_reply_max"), 90, 20, 500),
            target_segment=_bounded_int(raw.get("target_segment"), 110, 40, 1000),
            hard_split_marker=_clean_marker(raw.get("hard_split_marker")),
            min_delay_ms=min_delay,
            max_delay_ms=max_delay,
        )


@dataclass(frozen=True)
class ReplyUnit:
    """One independently deliverable callback body."""

    content: str
    meta: Mapping[str, Any]


def segment_reply(
    content: str,
    config: ReplyDeliveryConfig | None = None,
) -> list[str]:
    """Split a completed reply at semantic boundaries.

    Fenced code, inline code, Markdown links, and bare URLs are protected as
    indivisible spans.  The function works on the completed visible response;
    it never exposes model-stream fragments.
    """

    cfg = config or ReplyDeliveryConfig(segmented=True)
    text = content.strip() if isinstance(content, str) else ""
    if not text:
        return []

    masked, protected = _mask_protected_spans(text)
    if cfg.hard_split_marker and cfg.hard_split_marker in masked:
        parts = _split_on_hard_marker(masked, cfg.hard_split_marker)
        parts = [_restore_protected(part, protected).strip() for part in parts]
        parts = [part for part in parts if part]
        if parts:
            return parts

    if len(text) <= cfg.short_reply_max:
        return [text]

    paragraphs = [part.strip() for part in _PARAGRAPH_BREAK_RE.split(masked) if part.strip()]
    chunks: list[str] = []
    for paragraph in paragraphs:
        units = _sentence_units(paragraph)
        chunks.extend(_pack_units(units, cfg.target_segment, protected))

    chunks = [_restore_protected(part, protected).strip() for part in chunks]
    chunks = [part for part in chunks if part]
    chunks = _merge_tiny_chunks(chunks, cfg.target_segment)
    return chunks or [text]


def make_segment_key(turn_id: str, index: int, *, fallback: bool = False) -> str:
    """Return the stable Worker idempotency key for a callback segment."""

    normalized_turn_id = _valid_turn_id(turn_id)
    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise ValueError("segment index must be a non-negative integer")
    suffix = "fallback" if fallback else str(index)
    return f"{normalized_turn_id}:{suffix}"


def build_reply_group(turn_id: str, index: int, count: int) -> dict[str, Any]:
    """Build validated metadata shared by every segment in one user turn."""

    normalized_turn_id = _valid_turn_id(turn_id)
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("segment count must be a positive integer")
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < count:
        raise ValueError("segment index must be within segment count")
    return {
        "origin": "user_turn",
        "turn_id": normalized_turn_id,
        "segment_key": make_segment_key(normalized_turn_id, index),
        "index": index,
        "count": count,
        "is_final": index == count - 1,
    }


def build_reply_units(
    content: str,
    *,
    turn_id: str | None,
    config: ReplyDeliveryConfig,
    origin: str = "user_turn",
    context_window: Mapping[str, Any] | None = None,
    final_meta: Mapping[str, Any] | None = None,
) -> list[ReplyUnit]:
    """Create callback units without performing delivery.

    Automatic jobs and other unsolicited callbacks fail closed to one ordinary
    message.  Group metadata is emitted only for an explicitly enabled route
    and a valid inbound user turn.
    """

    base_final_meta = dict(final_meta or {})
    if context_window:
        base_final_meta["context_window"] = dict(context_window)

    eligible = (
        config.segmented
        and config.require_user_turn_origin
        and bool(turn_id)
        and origin == "user_turn"
    )
    if not eligible:
        return [ReplyUnit(content=content, meta=base_final_meta)] if content else []

    normalized_turn_id = _valid_turn_id(turn_id or "")
    segments = segment_reply(content, config)
    count = len(segments)
    units: list[ReplyUnit] = []
    for index, segment in enumerate(segments):
        meta: dict[str, Any] = {
            "reply_group": build_reply_group(normalized_turn_id, index, count),
        }
        if index == count - 1:
            meta.update(base_final_meta)
        units.append(ReplyUnit(content=segment, meta=meta))
    return units


def build_fallback_reply_unit(
    units: Sequence[ReplyUnit],
    *,
    turn_id: str,
    failed_index: int,
) -> ReplyUnit:
    """Merge a failed segment and its tail into one stable final callback."""

    normalized_turn_id = _valid_turn_id(turn_id)
    if (
        isinstance(failed_index, bool)
        or not isinstance(failed_index, int)
        or failed_index < 0
        or failed_index >= len(units)
    ):
        raise ValueError("failed_index must reference an existing reply unit")
    content = "\n\n".join(unit.content for unit in units[failed_index:] if unit.content)
    final_meta = dict(units[-1].meta)
    final_meta["reply_group"] = {
        "origin": "user_turn",
        "turn_id": normalized_turn_id,
        "segment_key": f"{normalized_turn_id}:fallback:{failed_index}",
        "index": failed_index,
        "count": len(units),
        "is_final": True,
        "fallback_from_index": failed_index,
    }
    return ReplyUnit(content=content, meta=final_meta)


def reply_delay_seconds(
    turn_id: str,
    next_index: int,
    next_content: str,
    config: ReplyDeliveryConfig,
) -> float:
    """Return deterministic human-like pacing without global randomness."""

    normalized_turn_id = _valid_turn_id(turn_id)
    if isinstance(next_index, bool) or not isinstance(next_index, int) or next_index < 1:
        raise ValueError("next_index must be a positive integer")
    minimum = config.min_delay_ms
    maximum = max(minimum, config.max_delay_ms)
    if maximum == minimum:
        return minimum / 1000
    length_ratio = min(1.0, max(0.0, len(next_content) / max(1, config.target_segment * 2)))
    digest = hashlib.sha256(f"{normalized_turn_id}:{next_index}".encode()).digest()
    jitter_ratio = int.from_bytes(digest[:2], "big") / 65535
    ratio = min(1.0, (length_ratio * 0.75) + (jitter_ratio * 0.25))
    return (minimum + ((maximum - minimum) * ratio)) / 1000


def build_context_window(
    used_tokens: Any,
    limit_tokens: Any,
    *,
    session_id: Any = None,
    measured_at: datetime | None = None,
    source: str = "provider_usage",
) -> dict[str, Any] | None:
    """Normalize one actual prompt-window measurement.

    ``session_id`` binds the measurement to the information window that
    produced it.  Callers that do not have a session id keep the legacy shape;
    Isles callbacks always provide one so the Worker cannot carry a stale
    reading across a session rotation.
    """

    used = _positive_int(used_tokens)
    limit = _positive_int(limit_tokens)
    if used is None or limit is None:
        return None

    timestamp = measured_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    timestamp = timestamp.astimezone(timezone.utc)

    used_percent = max(0, min(100, round((used / limit) * 100)))
    context_window = {
        "used_tokens": used,
        "limit_tokens": limit,
        "remaining_tokens": max(0, limit - used),
        "used_percent": used_percent,
        "remaining_percent": 100 - used_percent,
        "measured_at": timestamp.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "source": source,
    }
    normalized_session_id = session_id.strip() if isinstance(session_id, str) else ""
    if normalized_session_id:
        context_window["session_id"] = normalized_session_id
    return context_window


def extract_context_window(
    agent_or_compressor: Any,
    *,
    session_id: Any = None,
    measured_at: datetime | None = None,
    source: str = "provider_usage",
) -> dict[str, Any] | None:
    """Extract the latest trustworthy prompt-window measurement.

    Returns ``None`` when either actual prompt usage or the model context limit
    is missing.  The caller should then keep its previous trustworthy reading
    instead of estimating from visible messages.
    """

    compressor = getattr(agent_or_compressor, "context_compressor", agent_or_compressor)
    return build_context_window(
        getattr(compressor, "last_prompt_tokens", None),
        getattr(compressor, "context_length", None),
        session_id=session_id,
        measured_at=measured_at,
        source=source,
    )


def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _clean_marker(value: Any) -> str:
    """Normalize an explicit hard-split marker from route config.

    The marker must be a short single-line token.  Empty, multi-line, or
    oversized values disable the feature so an accidental config cannot split
    every reply.
    """

    if not isinstance(value, str):
        return ""
    marker = value.strip()
    if not marker or len(marker) > 64 or "\n" in marker or "\r" in marker:
        return ""
    return marker


def _positive_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _valid_turn_id(turn_id: str) -> str:
    if not isinstance(turn_id, str):
        raise ValueError("turn_id must be a string")
    normalized = turn_id.strip()
    if not normalized or len(normalized) > 200 or any(ch.isspace() for ch in normalized):
        raise ValueError("turn_id must be non-empty, whitespace-free, and at most 200 characters")
    return normalized


def _split_on_hard_marker(masked: str, marker: str) -> list[str]:
    """Split on lines consisting solely of the configured marker token."""
    pieces: list[str] = []
    current: list[str] = []
    for line in masked.split("\n"):
        if line.strip() == marker:
            pieces.append("\n".join(current))
            current = []
        else:
            current.append(line)
    pieces.append("\n".join(current))
    return pieces


def _mask_protected_spans(text: str) -> tuple[str, Sequence[str]]:
    protected: list[str] = []

    def replace(match: re.Match[str]) -> str:
        protected.append(match.group(0))
        return f"\ue000{len(protected) - 1}\ue001"

    return _PROTECTED_SPAN_RE.sub(replace, text), protected


def _restore_protected(text: str, protected: Sequence[str]) -> str:
    def replace(match: re.Match[str]) -> str:
        index = int(match.group(1))
        return protected[index] if index < len(protected) else match.group(0)

    return _PLACEHOLDER_RE.sub(replace, text)


def _visible_len(text: str, protected: Sequence[str]) -> int:
    return len(_restore_protected(text, protected))


def _sentence_units(text: str) -> list[str]:
    units: list[str] = []
    start = 0
    index = 0
    while index < len(text):
        char = text[index]
        boundary = char in _CJK_SENTENCE_END or char == "\n"
        if char in ".!?":
            next_char = text[index + 1] if index + 1 < len(text) else ""
            boundary = not next_char or next_char.isspace() or next_char in _CLOSING_PUNCTUATION

        if boundary:
            end = index + 1
            while end < len(text) and text[end] in _CLOSING_PUNCTUATION:
                end += 1
            unit = text[start:end]
            if unit.strip():
                # Keep inter-sentence whitespace while packing.  Whitespace at
                # an actual message boundary is trimmed later, but spaces
                # between English sentences must not silently disappear.
                units.append(unit)
            start = end
            index = end
            continue
        index += 1

    tail = text[start:]
    if tail.strip():
        units.append(tail)
    return units or [text]


def _pack_units(units: Sequence[str], target: int, protected: Sequence[str]) -> list[str]:
    chunks: list[str] = []
    current = ""
    for unit in units:
        if _visible_len(unit, protected) > target * 2:
            oversized = _split_oversized(unit, target, protected)
        else:
            oversized = [unit]
        for part in oversized:
            separator = "\n" if current and (current.endswith("\n") or part.startswith(('-', '*', '+'))) else ""
            candidate = f"{current}{separator}{part}" if current else part
            # A modest overshoot avoids mechanical two-sentence chunks when
            # three complete short sentences are still close to the target.
            if current and _visible_len(candidate, protected) > int(target * 1.25):
                chunks.append(current)
                current = part
            else:
                current = candidate
    if current:
        chunks.append(current)
    return chunks


def _split_oversized(text: str, target: int, protected: Sequence[str]) -> list[str]:
    pieces: list[str] = []
    remaining = text.strip()
    while _visible_len(remaining, protected) > target * 2:
        cut = min(target, len(remaining))

        # Never cut through a protected placeholder.
        open_at = remaining.rfind("\ue000", 0, cut)
        close_at = remaining.rfind("\ue001", 0, cut)
        if open_at > close_at:
            placeholder_end = remaining.find("\ue001", cut)
            if placeholder_end >= 0:
                cut = placeholder_end + 1

        search_start = max(1, int(cut * 0.65))
        preferred = max(
            remaining.rfind(" ", search_start, cut),
            remaining.rfind("，", search_start, cut),
            remaining.rfind("；", search_start, cut),
            remaining.rfind("、", search_start, cut),
        )
        if preferred > 0:
            cut = preferred + 1
        pieces.append(remaining[:cut].strip())
        remaining = remaining[cut:].strip()
    if remaining:
        pieces.append(remaining)
    return pieces


def _merge_tiny_chunks(chunks: list[str], target: int) -> list[str]:
    if len(chunks) < 2:
        return chunks
    # Merge true fragments ("对。", orphan list markers), while preserving
    # short but complete conversational paragraphs as their own messages.
    minimum = max(8, target // 6)
    merged: list[str] = []
    index = 0
    while index < len(chunks):
        chunk = chunks[index]
        is_expressive_lead = (
            index == 0
            and len(chunk) <= 30
            and re.match(r"^(?:哈{3,}|哈哈哈哈|笑死|天哪|救命)", chunk) is not None
        )
        if len(chunk) < minimum and not is_expressive_lead:
            if index + 1 < len(chunks):
                chunks[index + 1] = f"{chunk}\n\n{chunks[index + 1]}"
            elif merged:
                merged[-1] = f"{merged[-1]}\n\n{chunk}"
            else:
                merged.append(chunk)
        else:
            merged.append(chunk)
        index += 1
    return merged
