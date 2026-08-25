"""Generic webhook platform adapter.

Runs an aiohttp HTTP server that receives webhook POSTs from external
services (GitHub, GitLab, JIRA, Stripe, etc.), validates HMAC signatures,
transforms payloads into agent prompts, and routes responses back to the
source or to another configured platform.

Configuration lives in config.yaml under platforms.webhook.extra.routes.
Each route defines:
  - events: which event types to accept (header-based filtering)
  - secret: HMAC secret for signature validation (REQUIRED)
  - prompt: template string formatted with the webhook payload
  - skills: optional list of skills to load for the agent
  - deliver: where to send the response (github_comment, telegram, etc.)
  - deliver_extra: additional delivery config (repo, pr_number, chat_id)
  - deliver_only: if true, skip the agent — the rendered prompt IS the
    message that gets delivered.  Use for external push notifications
    (Supabase, monitoring alerts, inter-agent pings) where zero LLM cost
    and sub-second delivery matter more than agent reasoning.

Security:
  - HMAC secret is required per route (validated at startup)
  - Rate limiting per route (fixed-window, configurable)
  - Idempotency cache prevents duplicate agent runs on webhook retries
  - Body size limits checked before reading payload
  - Generic HMAC supports a V2 signature (X-Webhook-Signature-V2) that
    binds a timestamp into the signed data for replay protection; the
    legacy body-only V1 (X-Webhook-Signature) is deprecated but still
    accepted with a warning, since it has no replay protection
  - Set secret to "INSECURE_NO_AUTH" to skip validation (testing only)
"""

import asyncio
import base64
import binascii
import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import sys
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

try:
    from aiohttp import web

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None  # type: ignore[assignment]

from gateway.config import Platform, PlatformConfig
from gateway.isles_turn_store import IslesTurnStore
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    ProcessingOutcome,
    SendResult,
    cache_image_from_url,
)
from gateway.platforms.webhook_filters import (
    DEFAULT_SCRIPT_TIMEOUT_SECONDS,
    WebhookRouteProcessor,
)
from gateway.reply_delivery import (
    ReplyDeliveryConfig,
    ReplyUnit,
    build_context_window,
    build_fallback_reply_unit,
    build_reply_units,
    reply_delay_seconds,
)

logger = logging.getLogger(__name__)

# Sentinel returned by _resolve_request_profile when a /p/<profile>/ prefix
# names a profile this gateway does not serve (→ 404). Distinct from None
# (no prefix / multiplexing off → handle as the default profile).
_PROFILE_REJECTED = object()

_BUILTIN_DELIVER_PLATFORMS = {
    "telegram", "discord", "slack", "signal", "sms", "whatsapp",
    "matrix", "mattermost", "homeassistant", "email", "dingtalk",
    "feishu", "wecom", "wecom_callback", "weixin", "bluebubbles",
    "qqbot", "yuanbao",
}

# Default bind host. ``None`` tells aiohttp/asyncio's ``create_server`` to bind
# BOTH address families (IPv4 + IPv6) — the portable dual-stack default.
#
# Why not "0.0.0.0" (the old default) or "::"?
#   - "0.0.0.0" binds IPv4 ONLY. On IPv6-only private networks — notably Fly.io
#     6PN, where an agent's ``<app>.internal`` name resolves to an ``fdaa:…``
#     IPv6 address — an IPv4-only listener is unreachable. That is exactly why
#     hosted-agent webhook routes were publicly unreachable: the edge router
#     reverse-proxies to ``<app>.internal:8644`` over 6PN (IPv6) but the adapter
#     was listening on 0.0.0.0 (v4 only) → connection refused.
#   - "::" is NOT a safe fix: on hosts where the kernel sets IPV6_V6ONLY=1
#     (verified on Fly machines), binding "::" yields an IPv6-ONLY socket, which
#     then breaks the IPv4 loopback health check (``curl 127.0.0.1:8644/health``)
#     and the AF_INET port-conflict probe in connect().
#   - ``None`` asks the event loop to create a listening socket per resolved
#     family, so both 127.0.0.1 (v4) and the 6PN fdaa (v6) are served regardless
#     of the bindv6only sysctl. Users can still pin a specific host via
#     ``platforms.webhook.extra.host``.
DEFAULT_HOST = None
DEFAULT_PORT = 8644
_INSECURE_NO_AUTH = "INSECURE_NO_AUTH"
_DYNAMIC_ROUTES_FILENAME = "webhook_subscriptions.json"
_RATE_WINDOW_SECONDS = 60.0
_ISLES_IMAGE_EXTENSIONS = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/gif": ".gif",
    "image/webp": ".webp",
    "image/heic": ".heic",
    "image/heif": ".heif",
}


def _validate_isles_media_items(payload: Any) -> list[tuple[str, str, str]]:
    """Return trusted-shape image descriptors from an authenticated Isles turn."""
    if not isinstance(payload, dict):
        raise ValueError("invalid payload")
    message_payload = payload.get("message", {})
    if not isinstance(message_payload, dict):
        raise ValueError("invalid message payload")
    media_items = message_payload.get("media", [])
    if media_items is None:
        media_items = []
    if not isinstance(media_items, list) or len(media_items) > 12:
        raise ValueError("invalid media payload")
    validated: list[tuple[str, str, str]] = []
    for item in media_items:
        if not isinstance(item, dict) or item.get("kind") != "image":
            raise ValueError("invalid media item")
        media_url = str(item.get("url") or "").strip()
        media_mime = str(item.get("mime") or "image/jpeg").lower().strip()
        extension = _ISLES_IMAGE_EXTENSIONS.get(media_mime)
        if not media_url.startswith("https://") or extension is None:
            raise ValueError("unsupported media item")
        validated.append((media_url, media_mime, extension))
    return validated


async def _download_isles_media_items(
    payload: Any,
    downloader: Any = None,
) -> tuple[list[str], list[str]]:
    """Download authenticated Isles images before acknowledging the user turn."""
    download = downloader or cache_image_from_url
    paths: list[str] = []
    media_types: list[str] = []
    for media_url, media_mime, extension in _validate_isles_media_items(payload):
        paths.append(await download(media_url, ext=extension))
        media_types.append(media_mime)
    return paths, media_types
# Hostnames/IP literals that only serve connections originating on the same
# machine. Anything else is treated as a public bind for safety-rail purposes.
_LOOPBACK_HOSTS = frozenset({
    "127.0.0.1",
    "localhost",
    "::1",
    "ip6-localhost",
    "ip6-loopback",
})


def _is_loopback_host(host: Optional[str]) -> bool:
    """True when `host` binds only to the local machine.

    Covers IPv4 loopback, the standard `localhost` alias, IPv6 loopback in
    both bracketed and bare form, and the common Debian-style aliases. Any
    falsy value (empty string, None) is conservatively treated as non-loopback
    because an unset host usually means the platform-default public bind.
    """
    if not host:
        return False
    return host.strip().lower() in _LOOPBACK_HOSTS


def _hmac_str_equal(provided: str, expected: str) -> bool:
    """Timing-safe equality for two ``str`` values, tolerant of non-ASCII input.

    ``hmac.compare_digest`` raises ``TypeError`` when given a ``str`` that
    contains non-ASCII characters. The ``provided`` value here is an
    attacker-controlled signature/token header on a public, unauthenticated
    webhook endpoint, so a single non-ASCII byte would otherwise raise out of
    the request handler and return a 500 instead of rejecting the request.
    Comparing as UTF-8 bytes keeps the constant-time guarantee while making a
    hostile header fail closed with a clean rejection.
    """
    return hmac.compare_digest(provided.encode(), expected.encode())


def check_webhook_requirements() -> bool:
    """Check if webhook adapter dependencies are available."""
    return AIOHTTP_AVAILABLE


class WebhookAdapter(BasePlatformAdapter):
    """Generic webhook receiver that triggers agent runs from HTTP POSTs."""

    # No human is present to answer a "session restored — what next?" prompt:
    # webhook runs are event-triggered.  The startup auto-resume turn must
    # instruct the model to FINISH the interrupted work instead of emitting an
    # interactive acknowledgement that abandons the task (#57056).
    interactive_resume: bool = False

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.WEBHOOK)
        # ``host`` may be None (dual-stack default) or a user-pinned string.
        # A config value of empty string / null is normalised to None so it
        # also means "bind all families" rather than an invalid "" host.
        _cfg_host = config.extra.get("host", DEFAULT_HOST)
        self._host: Optional[str] = _cfg_host or None
        self._port: int = int(config.extra.get("port", DEFAULT_PORT))
        self._global_secret: str = config.extra.get("secret", "")
        self._static_routes: Dict[str, dict] = config.extra.get("routes", {})
        self._dynamic_routes: Dict[str, dict] = {}
        self._dynamic_routes_mtime: float = 0.0
        self._routes: Dict[str, dict] = dict(self._static_routes)
        self._runner = None
        # Routes already warned about legacy V1 body-only signatures
        # (once-per-route so a busy sender doesn't spam the log).
        self._v1_signature_warned: set[str] = set()

        # Delivery info keyed by session chat_id.
        #
        # Read by every send() invocation for the chat_id (status messages
        # AND the final response).  Cleaned up via TTL on each POST so the
        # dict stays bounded — see _prune_delivery_info().  Do NOT pop on
        # send(), or interim status messages (e.g. fallback notifications,
        # context-pressure warnings) will consume the entry before the
        # final response arrives, causing the response to silently fall
        # back to the "log" deliver type.
        self._delivery_info: Dict[str, dict] = {}
        self._delivery_info_created: Dict[str, float] = {}
        self._delivery_info_order: Deque[tuple[float, str]] = deque()

        # ── v4.2.19: isles-story voice bridge + turn delivery state ──
        # Ported from giz v0.10.0 webhook.py for the isles-story (飞鸟群岛)
        # http_callback delivery chain (scheme B).
        self._pending_voice_meta: Optional[dict] = None
        self._pending_reply_turns: Dict[str, dict] = {}
        self._isles_turn_store = IslesTurnStore()
        self._process_token = f"{os.getpid()}:{uuid.uuid4().hex}"
        self._isles_retry_tasks: Dict[str, asyncio.Task] = {}
        self._vr_meta_cache: Dict[str, dict] = {}
        self._vr_meta_cache_ts: Dict[str, float] = {}
        self._inner_note_cache: Dict[str, dict] = {}
        self._inner_note_cache_ts: Dict[str, float] = {}
        # Interactive approvals for the private isles-story route.  The map
        # binds an opaque approval ID to the exact gateway session so a button
        # can never release a different concurrent approval by FIFO accident.
        self._isles_approval_states: Dict[str, dict] = {}

        # Reference to gateway runner for cross-platform delivery (set externally)
        self.gateway_runner = None

        # Idempotency: TTL cache of recently processed delivery IDs.
        # Prevents duplicate agent runs when webhook providers retry.
        self._seen_deliveries: Dict[str, float] = {}
        self._idempotency_ttl: int = 3600  # 1 hour
        self._seen_deliveries_next_prune_at: float = 0.0

        # Rate limiting: per-route timestamps in a fixed window.
        self._rate_counts: Dict[str, Deque[float]] = {}
        self._rate_limit: int = int(config.extra.get("rate_limit", 30))  # per minute

        # Body size limit (auth-before-body pattern)
        self._max_body_bytes: int = int(
            config.extra.get("max_body_bytes", 1_048_576)
        )  # 1MB
        self._script_timeout_seconds: int = int(
            config.extra.get(
                "script_timeout_seconds",
                DEFAULT_SCRIPT_TIMEOUT_SECONDS,
            )
        )
        self._route_processor = WebhookRouteProcessor(
            script_timeout_seconds=self._script_timeout_seconds
        )

    # ── v4.2.19: isles-story voice bridge + turn delivery (ported from giz) ──

    def set_pending_voice_meta(self, voice_meta: Optional[dict]) -> None:
        """Set voice metadata for the upcoming callback.

        Called by run.py _isles_voice_bridge_sync() before return response.
        voice_meta is {voice: {audio_key, mime, duration_ms, size},
                        transcript: {text, status, provider}} or None.
        None triggers text-only fallback.
        """
        self._pending_voice_meta = voice_meta

    def consume_pending_voice_meta(self) -> Optional[dict]:
        """Atomically read and clear pending voice metadata.

        Called by send() during callback assembly.
        Returns the voice_meta dict or None.
        """
        meta = self._pending_voice_meta
        self._pending_voice_meta = None
        return meta

    def mark_pending_reply_turn(
        self,
        turn_id: str,
        context_window: Optional[dict],
    ) -> None:
        """Mark one completed Isles user turn as eligible for final delivery."""
        if not isinstance(turn_id, str) or not turn_id or any(ch.isspace() for ch in turn_id):
            return
        self._pending_reply_turns[turn_id] = {
            "context_window": dict(context_window) if context_window else None,
            "completed_at": time.time(),
        }
        while len(self._pending_reply_turns) > 200:
            self._pending_reply_turns.pop(next(iter(self._pending_reply_turns)), None)
        self._isles_turn_store.transition(
            turn_id,
            "reply_ready",
            retryable=True,
            process_token=self._process_token,
        )

    async def update_isles_turn_status(
        self,
        turn_id: str,
        status: str,
        *,
        retryable: bool = False,
        detail_code: str | None = None,
        session_id: str | None = None,
        session_is_new: bool | None = None,
    ) -> None:
        """Persist and forward a real Agent lifecycle event to the Worker."""
        if not isinstance(turn_id, str) or not turn_id:
            return
        state = status if status != "failed" else "processing_failed"
        self._isles_turn_store.transition(
            turn_id,
            state,
            retryable=retryable,
            detail_code=detail_code,
            process_token=self._process_token,
        )
        await self._emit_isles_turn_status(
            turn_id,
            status,
            retryable=retryable,
            detail_code=detail_code,
            session_id=session_id,
            session_is_new=session_is_new,
        )

    def _static_isles_delivery(self, route_name: str = "isles-story") -> dict:
        return self._delivery_config_for_route(route_name, {})

    def _delivery_config_for_route(self, route_name: str, payload: dict) -> dict:
        route = self._routes.get(route_name, {})
        return {
            "deliver": route.get("deliver", "log"),
            "deliver_extra": self._render_delivery_extra(
                route.get("deliver_extra", {}), payload
            ),
            "reply_delivery": ReplyDeliveryConfig.from_route(route),
        }

    async def _emit_isles_turn_status(
        self,
        turn_id: str,
        status: str,
        *,
        retryable: bool = False,
        detail_code: str | None = None,
        session_id: str | None = None,
        session_is_new: bool | None = None,
        route_name: str = "isles-story",
    ) -> bool:
        """Send metadata-only state; never create a visible chat message."""
        import aiohttp

        delivery = self._static_isles_delivery(route_name)
        extra = delivery.get("deliver_extra", {})
        callback_url = str(extra.get("url") or "")
        token = str(extra.get("token") or "")
        if not callback_url or not token:
            return False
        if "/api/chat/callback" in callback_url:
            status_url = callback_url.rsplit("/api/chat/callback", 1)[0] + "/api/chat/turn/status"
        else:
            status_url = callback_url.rstrip("/") + "/turn/status"
        payload = {
            "turn_id": turn_id,
            "status": status,
            "retryable": bool(retryable),
            "updated_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        }
        if detail_code:
            payload["detail_code"] = detail_code
        normalized_session_id = session_id.strip() if isinstance(session_id, str) else ""
        if normalized_session_id:
            payload["session_id"] = normalized_session_id
        if session_is_new is not None:
            payload["session_is_new"] = bool(session_is_new)
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    status_url,
                    json=payload,
                    headers={"Authorization": f"Bearer {token}"},
                ) as response:
                    delivered = 200 <= response.status < 300
                    if not delivered:
                        logger.warning(
                            "[webhook] turn status rejected status=%s http=%s turn=%s",
                            status,
                            response.status,
                            hashlib.sha256(turn_id.encode()).hexdigest()[:8],
                        )
                    return delivered
        except Exception as error:
            logger.warning(
                "[webhook] turn status delivery failed status=%s type=%s turn=%s",
                status,
                type(error).__name__,
                hashlib.sha256(turn_id.encode()).hexdigest()[:8],
            )
            return False

    def _schedule_isles_outbox_retry(self, turn_id: str) -> None:
        existing = self._isles_retry_tasks.get(turn_id)
        if existing and not existing.done():
            return
        task = asyncio.create_task(self._retry_isles_outbox(turn_id))
        self._isles_retry_tasks[turn_id] = task
        task.add_done_callback(lambda _: self._isles_retry_tasks.pop(turn_id, None))

    async def _retry_isles_outbox(self, turn_id: str) -> None:
        delay = 5.0
        while self.is_connected:
            record = self._isles_turn_store.get(turn_id)
            if not record or not record.get("outbox"):
                return
            if record.get("state") not in {"delivery_failed", "delivering"}:
                return
            if await self._resume_isles_outbox(record):
                return
            await asyncio.sleep(delay)
            delay = min(60.0, delay * 2)

    async def _resume_isles_outbox(self, record: dict) -> bool:
        turn_id = str(record.get("turn_id") or "")
        route_name = str(record.get("route") or "isles-story")
        units = [
            ReplyUnit(content=str(item.get("content") or ""), meta=dict(item.get("meta") or {}))
            for item in record.get("outbox", [])
            if isinstance(item, dict) and item.get("content") is not None
        ]
        if not turn_id or not units:
            return False
        delivery = self._static_isles_delivery(route_name)
        config = delivery.get("reply_delivery")
        if not isinstance(config, ReplyDeliveryConfig):
            config = ReplyDeliveryConfig()
        self._isles_turn_store.transition(
            turn_id,
            "delivering",
            retryable=True,
            process_token=self._process_token,
        )
        await self._emit_isles_turn_status(turn_id, "delivering", route_name=route_name)
        if len(units) > 1:
            result = await self._deliver_grouped_http_callbacks(units, delivery, turn_id, config)
        else:
            result = await self._deliver_http_callback(
                units[0].content,
                delivery,
                meta=dict(units[0].meta),
            )
        if not result.success:
            self._isles_turn_store.transition(
                turn_id,
                "delivery_failed",
                retryable=True,
                detail_code="callback_failed",
                process_token=self._process_token,
            )
            return False
        self._pending_reply_turns.pop(turn_id, None)
        self._isles_turn_store.transition(
            turn_id,
            "completed",
            retryable=False,
            process_token=self._process_token,
        )
        await self._emit_isles_turn_status(turn_id, "completed", route_name=route_name)
        return True

    async def _deliver_grouped_http_callbacks(
        self,
        units: List[ReplyUnit],
        delivery: dict,
        turn_id: str,
        config: ReplyDeliveryConfig,
    ) -> "SendResult":
        """Deliver stable message units in order with bounded transport retries."""
        last_result = SendResult(success=False, error="No reply units")
        for index, unit in enumerate(units):
            for attempt in range(3):
                last_result = await self._deliver_http_callback(
                    unit.content,
                    delivery,
                    meta=dict(unit.meta),
                )
                if last_result.success:
                    break
                if attempt < 2:
                    await asyncio.sleep(0.5 * (2 ** attempt))
            if not last_result.success:
                fallback = build_fallback_reply_unit(
                    units,
                    turn_id=turn_id,
                    failed_index=index,
                )
                logger.warning(
                    "[webhook] grouped callback segment %d/%d failed; sending fallback tail",
                    index + 1,
                    len(units),
                )
                return await self._deliver_http_callback(
                    fallback.content,
                    delivery,
                    meta=dict(fallback.meta),
                )
            if index + 1 < len(units):
                await asyncio.sleep(
                    reply_delay_seconds(
                        turn_id,
                        index + 1,
                        units[index + 1].content,
                        config,
                    )
                )
        return last_result

    async def _deliver_http_callback(
        self, content: str, delivery: dict, meta: Optional[dict] = None
    ) -> "SendResult":
        """POST agent response to a callback URL."""
        import aiohttp

        url = delivery.get("deliver_extra", {}).get("url", "")
        token = delivery.get("deliver_extra", {}).get("token", "")
        if not url:
            logger.warning("[webhook] http_callback missing url")
            return SendResult(success=False, error="Missing callback URL")

        # Build payload (frontend contract: msg.meta.visible_reasoning)
        if delivery.get("deliver_extra", {}).get("forward_raw_body"):
            payload = delivery.get("payload", {"content": content, "author": "bird"})
        elif meta and isinstance(meta, dict) and 'voice' in meta:
            payload = {
                "content": "",
                "author": "bird",
                "type": "voice",
                "meta": meta,
            }
            logger.info(
                "[webhook] voice callback audio_key=%s duration_ms=%s",
                meta.get("voice", {}).get("audio_key", "?"),
                meta.get("voice", {}).get("duration_ms", "?"),
            )
        else:
            payload = {"content": content, "author": "bird"}

        if meta is not None and isinstance(meta, dict):
            _payload_meta = payload.get("meta")
            if not isinstance(_payload_meta, dict):
                _payload_meta = {}
            for _key in (
                "reply_group",
                "delivery_key",
                "reply_turn_id",
                "context_window",
                "voice",
                "transcript",
                "spoken_text",
            ):
                if _key in meta:
                    _payload_meta[_key] = meta[_key]
            if _payload_meta:
                payload["meta"] = _payload_meta

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "hermes-webhook/1.0",
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        _msg_id = None
                        try:
                            _body = await resp.json()
                            _raw_id = (_body.get("message") or {}).get("id")
                            if isinstance(_raw_id, str) and _raw_id.startswith("msg_"):
                                _msg_id = _raw_id
                        except Exception:
                            pass  # fail-open: body parse failure -> msg_id stays None
                        logger.info("[webhook] http_callback OK")
                        # TODO(fp7): VIN rewriter async delivery omitted for now
                        return SendResult(success=True, message_id=_msg_id)
                    body = await resp.text()
                    logger.warning(
                        "[webhook] http_callback %d: %s", resp.status, body[:200]
                    )
                    return SendResult(success=False, error=f"HTTP {resp.status}")
        except Exception as e:
            logger.error("[webhook] http_callback failed: %s", e)
            return SendResult(success=False, error=str(e))

    @staticmethod
    def _isles_system_event_url(delivery: dict) -> str:
        callback_url = str(delivery.get("deliver_extra", {}).get("url") or "")
        if "/api/chat/callback" not in callback_url:
            return ""
        return callback_url.rsplit("/api/chat/callback", 1)[0] + "/api/chat/system-event"

    def _prune_isles_approval_states(self, now: float) -> None:
        stale = []
        for approval_id, state in self._isles_approval_states.items():
            expires_at = float(state.get("expires_at") or 0)
            terminal_at = float(state.get("terminal_at") or 0)
            if terminal_at and now - terminal_at > 3600:
                stale.append(approval_id)
            elif not terminal_at and expires_at and now - expires_at > 3600:
                stale.append(approval_id)
        for approval_id in stale:
            self._isles_approval_states.pop(approval_id, None)

    async def _deliver_isles_system_event(
        self, payload: dict, delivery: dict
    ) -> SendResult:
        """Deliver one out-of-band event without forging a final turn reply."""
        import aiohttp

        url = self._isles_system_event_url(delivery)
        token = str(delivery.get("deliver_extra", {}).get("token") or "")
        if not url or not token:
            return SendResult(success=False, error="Missing Isles system-event callback")
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers={
                        "Authorization": f"Bearer {token}",
                        "Content-Type": "application/json",
                        "User-Agent": "hermes-webhook/1.0",
                    },
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    if 200 <= response.status < 300:
                        return SendResult(success=True)
                    logger.warning(
                        "[webhook] isles system event rejected http=%s kind=%s",
                        response.status,
                        str(payload.get("kind") or "unknown")[:32],
                    )
                    return SendResult(
                        success=False,
                        error=f"HTTP {response.status}",
                        retryable=response.status >= 500,
                    )
        except Exception as error:
            logger.warning(
                "[webhook] isles system event delivery failed type=%s",
                type(error).__name__,
            )
            return SendResult(success=False, error=str(error), retryable=True)

    async def send_exec_approval(
        self,
        chat_id: str,
        command: str,
        session_key: str,
        description: str = "dangerous command",
        metadata: Optional[Dict[str, Any]] = None,
        allow_permanent: bool = True,
        smart_denied: bool = False,
    ) -> SendResult:
        """Render an Isles approval as a structured, exact-ID system event."""
        if chat_id != "webhook:isles-story:main":
            return SendResult(success=False, error="Unsupported webhook approval surface")
        metadata = metadata if isinstance(metadata, dict) else {}
        approval_id = str(metadata.get("_isles_approval_id") or "")
        if not re.fullmatch(r"[a-f0-9]{32}", approval_id):
            return SendResult(success=False, error="Missing approval ID")
        timeout_seconds = max(int(metadata.get("_isles_approval_timeout_seconds") or 0), 0)
        expires_at = float(metadata.get("_isles_approval_expires_at") or 0)
        if expires_at <= time.time():
            expires_at = time.time() + timeout_seconds
        choices = ["once"]
        if allow_permanent:
            choices.append("always")
        choices.append("deny")
        self._prune_isles_approval_states(time.time())
        self._isles_approval_states[approval_id] = {
            "session_key": session_key,
            "expires_at": expires_at,
            "choices": tuple(choices),
            "status": "pending",
        }
        delivery = self._delivery_info.get(chat_id) or self._static_isles_delivery()
        payload = {
            "protocol": "isles-system-event-v1",
            "event_id": approval_id,
            "kind": "approval",
            "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "approval": {
                "approval_id": approval_id,
                "title": "命令执行审批",
                "command": command,
                "description": description,
                "timeout_seconds": timeout_seconds,
                "expires_at": expires_at,
                "choices": choices,
                "status": "pending",
                "smart_denied": bool(smart_denied),
            },
        }
        return await self._deliver_isles_system_event(payload, delivery)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self, *, is_reconnect: bool = False) -> bool:
        # Load agent-created subscriptions before validating
        self._reload_dynamic_routes()

        # Validate routes at startup — secret is required per route
        for name, route in self._routes.items():
            secret = route.get("secret", self._global_secret)
            if not secret:
                raise ValueError(
                    f"[webhook] Route '{name}' has no HMAC secret. "
                    f"Set 'secret' on the route or globally. "
                    f"For testing without auth, set secret to '{_INSECURE_NO_AUTH}'."
                )

            # Safety rail: refuse to start if INSECURE_NO_AUTH is combined with a
            # non-loopback bind. The escape hatch is for local testing only;
            # serving an unauthenticated route on a public interface is a
            # deployment-grade footgun we'd rather crash early than ship.
            if secret == _INSECURE_NO_AUTH and not _is_loopback_host(self._host):
                raise ValueError(
                    f"[webhook] Route '{name}' uses INSECURE_NO_AUTH secret "
                    f"but is bound to non-loopback host '{self._host}'. "
                    f"INSECURE_NO_AUTH is for local testing only. "
                    f"Refusing to start to prevent accidental exposure."
                )
            # deliver_only routes bypass the agent — the POST body becomes a
            # direct push notification via the configured delivery target.
            # Validate up-front so misconfiguration surfaces at startup rather
            # than on the first webhook POST.
            if route.get("deliver_only"):
                deliver = route.get("deliver", "log")
                if not deliver or deliver == "log":
                    raise ValueError(
                        f"[webhook] Route '{name}' has deliver_only=true but "
                        f"deliver is '{deliver}'. Direct delivery requires a "
                        f"real target (telegram, discord, slack, github_comment, etc.)."
                    )

        # client_max_size makes aiohttp enforce the cap on every read path,
        # including Transfer-Encoding: chunked bodies that carry no
        # Content-Length and would otherwise bypass the header check below.
        app = web.Application(client_max_size=self._max_body_bytes)
        app.router.add_get("/health", self._handle_health)
        app.router.add_post(
            "/webhooks/isles-story/approval",
            self._handle_isles_approval_action,
        )
        app.router.add_post("/webhooks/{route_name}", self._handle_webhook)
        # Multi-profile multiplexing: a /p/<profile>/webhooks/<route> prefix
        # routes the inbound event to that profile. Same handler; the profile is
        # captured from the path and stamped onto the SessionSource so the agent
        # turn resolves that profile's config/skills/credentials. Only honored
        # when gateway.multiplex_profiles is on (the handler validates).
        app.router.add_post(
            "/p/{profile}/webhooks/{route_name}", self._handle_webhook
        )

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        # Do not probe only one address family before binding. With the
        # dual-stack default, an IPv6-only listener can already own this port
        # while 127.0.0.1 still looks free.
        #
        # SO_REUSEADDR is platform-dependent:
        #   - macOS (BSD semantics): two wildcard/specific sockets with
        #     SO_REUSEADDR can silently split traffic while both servers
        #     report success — so disable it there.
        #   - Linux: SO_REUSEADDR only permits rebinding past TIME_WAIT
        #     (a second live listener needs SO_REUSEPORT, which we never
        #     set). Disabling it would make a quick gateway restart fail
        #     to bind for up to ~60s — so keep the default (enabled).
        site = web.TCPSite(
            self._runner,
            self._host,
            self._port,
            reuse_address=False if sys.platform == "darwin" else None,
        )
        try:
            await site.start()
        except OSError as exc:
            await self._runner.cleanup()
            self._runner = None
            logger.error(
                "[webhook] Could not bind %s:%d: %s. "
                "Set a different host or port in config.yaml under "
                "platforms.webhook.extra.",
                self._host or "all IPv4+IPv6 interfaces",
                self._port,
                exc,
            )
            return False
        self._mark_connected()

        route_names = ", ".join(self._routes.keys()) or "(none configured)"
        logger.info(
            "[webhook] Listening on %s:%d — routes: %s",
            self._host or "* (all interfaces, IPv4+IPv6)",
            self._port,
            route_names,
        )
        return True

    async def disconnect(self) -> None:
        if self._runner:
            await self._runner.cleanup()
            self._runner = None
        self._mark_disconnected()
        logger.info("[webhook] Disconnected")

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """Deliver the agent's response to the configured destination.

        chat_id is ``webhook:{route}:{delivery_id}``.  The delivery info
        stored during webhook receipt is read with ``.get()`` (not popped)
        so that interim status messages emitted before the final response
        — fallback-model notifications, context-pressure warnings, etc. —
        do not consume the entry and silently downgrade the final response
        to the ``log`` deliver type.  TTL cleanup happens on POST.
        """
        delivery = self._delivery_info.get(chat_id, {})
        if chat_id == "webhook:isles-story:main" and not delivery:
            delivery = self._static_isles_delivery()
        deliver_type = delivery.get("deliver", "log")

        if deliver_type == "log":
            logger.info("[webhook] Response for %s: %s", chat_id, content[:200])
            return SendResult(success=True)

        if deliver_type == "github_comment":
            return await self._deliver_github_comment(content, delivery)

        if deliver_type == "http_callback":
            _turn_marker = (
                self._pending_reply_turns.get(reply_to)
                if isinstance(reply_to, str) and reply_to
                else None
            )
            if chat_id == "webhook:isles-story:main" and _turn_marker is None:
                event_metadata = metadata if isinstance(metadata, dict) else {}
                event_id = str(event_metadata.get("_isles_system_event_id") or "")
                if not re.fullmatch(r"[a-f0-9]{32}", event_id):
                    event_id = uuid.uuid4().hex
                    event_metadata["_isles_system_event_id"] = event_id
                return await self._deliver_isles_system_event(
                    {
                        "protocol": "isles-system-event-v1",
                        "event_id": event_id,
                        "kind": "notice",
                        "title": "系统提示",
                        "body": content,
                        "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                    },
                    delivery,
                )
            # ── v4.2.19: isles-story delivery (ported from giz) ──
            # _combined_meta: voice injection only for now (VR/inner_note → fp7)
            _combined_meta: Dict[str, Any] = {}
            _voice_meta = self.consume_pending_voice_meta()
            if _voice_meta is not None:
                _combined_meta.update(_voice_meta)

            if _turn_marker is not None:
                _reply_config = delivery.get("reply_delivery")
                if not isinstance(_reply_config, ReplyDeliveryConfig):
                    _reply_config = ReplyDeliveryConfig()
                _can_segment = (
                    _reply_config.segmented
                    and _voice_meta is None
                    and "MEDIA:" not in content
                )
                _units = build_reply_units(
                    content,
                    turn_id=reply_to,
                    config=_reply_config if _can_segment else ReplyDeliveryConfig(),
                    origin="user_turn",
                    context_window=_turn_marker.get("context_window"),
                    final_meta=_combined_meta,
                )
                if not _units:
                    _units = [ReplyUnit(content=content, meta=_combined_meta)]
                if len(_units) == 1 and "reply_group" not in _units[0].meta:
                    _single_meta = dict(_units[0].meta)
                    _single_meta.update({
                        "delivery_key": f"{reply_to}:final",
                        "reply_turn_id": reply_to,
                    })
                    _units = [ReplyUnit(content=_units[0].content, meta=_single_meta)]

                self._isles_turn_store.transition(
                    reply_to,
                    "delivering",
                    retryable=True,
                    process_token=self._process_token,
                    outbox=[{"content": unit.content, "meta": dict(unit.meta)} for unit in _units],
                )
                await self._emit_isles_turn_status(reply_to, "delivering")
                if len(_units) > 1:
                    _result = await self._deliver_grouped_http_callbacks(
                        _units, delivery, reply_to, _reply_config
                    )
                else:
                    _result = await self._deliver_http_callback(
                        _units[0].content,
                        delivery,
                        meta=dict(_units[0].meta) if _units[0].meta else None,
                    )
                if _result.success:
                    self._pending_reply_turns.pop(reply_to, None)
                    self._isles_turn_store.transition(
                        reply_to,
                        "completed",
                        retryable=False,
                        process_token=self._process_token,
                    )
                    await self._emit_isles_turn_status(reply_to, "completed")
                else:
                    self._isles_turn_store.transition(
                        reply_to,
                        "delivery_failed",
                        retryable=True,
                        detail_code="callback_failed",
                        process_token=self._process_token,
                    )
                    await self._emit_isles_turn_status(
                        reply_to,
                        "failed",
                        retryable=True,
                        detail_code="callback_failed",
                    )
                    self._schedule_isles_outbox_retry(reply_to)
                return _result

            return await self._deliver_http_callback(
                content, delivery, meta=_combined_meta if _combined_meta else None
            )

        # Cross-platform delivery — any platform with a gateway adapter.
        # Check both built-in names and plugin-registered platforms.
        _is_known_platform = deliver_type in _BUILTIN_DELIVER_PLATFORMS
        if not _is_known_platform:
            try:
                from gateway.platform_registry import platform_registry
                _is_known_platform = platform_registry.is_registered(deliver_type)
            except Exception:
                pass
        if self.gateway_runner and _is_known_platform:
            return await self._deliver_cross_platform(
                deliver_type, content, delivery
            )

        logger.warning("[webhook] Unknown deliver type: %s", deliver_type)
        return SendResult(
            success=False, error=f"Unknown deliver type: {deliver_type}"
        )

    def _prune_delivery_info(self, now: float) -> None:
        """Drop delivery_info entries older than the idempotency TTL.

        Mirrors the cleanup pattern used for ``_seen_deliveries``.  Called
        on each POST so the dict size is bounded by ``rate_limit * TTL``
        even if many webhooks fire and never receive a final response.
        """
        if len(self._delivery_info_order) < len(self._delivery_info_created):
            self._delivery_info_order = deque(
                (created_at, key)
                for key, created_at in sorted(
                    self._delivery_info_created.items(), key=lambda item: item[1]
                )
            )
        cutoff = now - self._idempotency_ttl
        while self._delivery_info_order and self._delivery_info_order[0][0] < cutoff:
            created_at, key = self._delivery_info_order.popleft()
            if self._delivery_info_created.get(key) != created_at:
                continue
            self._delivery_info.pop(key, None)
            self._delivery_info_created.pop(key, None)

    def _prune_seen_deliveries(self, now: float) -> None:
        """Occasionally prune expired delivery IDs without scanning every POST."""
        if now < self._seen_deliveries_next_prune_at:
            return
        cutoff = now - self._idempotency_ttl
        stale = [k for k, t in self._seen_deliveries.items() if t < cutoff]
        for k in stale:
            self._seen_deliveries.pop(k, None)
        self._seen_deliveries_next_prune_at = now + min(60.0, max(1.0, self._idempotency_ttl / 10))

    def _record_rate_limit_hit(self, route_name: str, now: float) -> bool:
        """Return True if route is still within limit after recording this hit."""
        window = self._rate_counts.get(route_name)
        if not isinstance(window, deque):
            new_window: Deque[float] = deque(window or ())
            self._rate_counts[route_name] = new_window
            window = new_window
        cutoff = now - _RATE_WINDOW_SECONDS
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= self._rate_limit:
            return False
        window.append(now)
        return True

    def _record_delivery_id(self, delivery_id: str, now: float) -> bool:
        """Return True when this delivery should be processed."""
        seen_at = self._seen_deliveries.get(delivery_id)
        if seen_at is not None and now - seen_at < self._idempotency_ttl:
            return False
        if seen_at is not None:
            self._seen_deliveries.pop(delivery_id, None)
        self._seen_deliveries[delivery_id] = now
        if len(self._seen_deliveries) > max(self._rate_limit * 2, 128):
            self._prune_seen_deliveries(now)
        return True

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"name": chat_id, "type": "webhook"}

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------

    async def _handle_isles_approval_action(
        self, request: "web.Request"
    ) -> "web.Response":
        """Resolve one exact Isles approval via replay-protected Worker HMAC."""
        route = self._routes.get("isles-story", {})
        secret = str(route.get("secret", self._global_secret) or "")
        if not secret or secret == _INSECURE_NO_AUTH:
            return web.json_response({"error": "Approval route unavailable"}, status=503)
        content_length = request.content_length or 0
        if content_length > 16 * 1024:
            return web.json_response({"error": "Payload too large"}, status=413)
        try:
            raw_body = await request.read()
        except Exception:
            return web.json_response({"error": "Bad request"}, status=400)
        if len(raw_body) > 16 * 1024:
            return web.json_response({"error": "Payload too large"}, status=413)
        # State-changing approval actions require timestamp-bound V2 only.
        if not request.headers.get("X-Webhook-Signature-V2", ""):
            return web.json_response({"error": "V2 signature required"}, status=401)
        if not self._validate_signature(request, raw_body, secret):
            return web.json_response({"error": "Invalid signature"}, status=401)
        try:
            payload = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return web.json_response({"error": "Invalid JSON"}, status=400)
        if not isinstance(payload, dict) or payload.get("protocol") != "isles-approval-action-v1":
            return web.json_response({"error": "Invalid protocol"}, status=400)
        approval_id = str(payload.get("approval_id") or "")
        choice = str(payload.get("choice") or "")
        if not re.fullmatch(r"[a-f0-9]{32}", approval_id) or choice not in {"once", "always", "deny"}:
            return web.json_response({"error": "Invalid approval action"}, status=400)

        now = time.time()
        self._prune_isles_approval_states(now)
        state = self._isles_approval_states.get(approval_id)
        if not state:
            return web.json_response({"error": "Approval not active"}, status=404)
        if state.get("status") != "pending":
            return web.json_response({
                "ok": True,
                "approval_id": approval_id,
                "status": state.get("status"),
                "duplicate": True,
            })
        if now >= float(state.get("expires_at") or 0):
            state.update(status="expired", terminal_at=now)
            return web.json_response({
                "ok": False,
                "approval_id": approval_id,
                "status": "expired",
            }, status=410)
        if choice not in set(state.get("choices") or ()):
            return web.json_response({"error": "Choice not allowed"}, status=403)

        from tools.approval import resolve_gateway_approval

        resolved = resolve_gateway_approval(
            str(state.get("session_key") or ""),
            choice,
            approval_id=approval_id,
        )
        if resolved != 1:
            state.update(status="expired", terminal_at=now)
            return web.json_response({
                "ok": False,
                "approval_id": approval_id,
                "status": "expired",
            }, status=409)
        terminal_status = {
            "once": "approved_once",
            "always": "approved_always",
            "deny": "denied",
        }[choice]
        state.update(status=terminal_status, terminal_at=now)
        return web.json_response({
            "ok": True,
            "approval_id": approval_id,
            "status": terminal_status,
            "duplicate": False,
        })

    async def _handle_health(self, request: "web.Request") -> "web.Response":
        """GET /health — simple health check."""
        return web.json_response({"status": "ok", "platform": "webhook"})

    def _reload_dynamic_routes(self) -> None:
        """Reload agent-created subscriptions from disk if the file changed."""
        from hermes_constants import get_hermes_home
        hermes_home = get_hermes_home()
        subs_path = hermes_home / _DYNAMIC_ROUTES_FILENAME
        if not subs_path.exists():
            if self._dynamic_routes:
                self._dynamic_routes = {}
                self._routes = dict(self._static_routes)
                logger.debug("[webhook] Dynamic subscriptions file removed, cleared dynamic routes")
            return
        try:
            mtime = subs_path.stat().st_mtime
            if mtime <= self._dynamic_routes_mtime:
                return  # No change
            data = json.loads(subs_path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return
            # Merge: static routes take precedence over dynamic ones.
            # Reject any dynamic route whose effective secret is empty —
            # an empty secret would cause _handle_webhook to skip HMAC
            # validation entirely, letting unauthenticated callers in.
            new_dynamic: Dict[str, dict] = {}
            for k, v in data.items():
                if k in self._static_routes:
                    continue
                effective_secret = v.get("secret", self._global_secret)
                if not effective_secret:
                    logger.warning(
                        "[webhook] Dynamic route '%s' skipped: 'secret' is "
                        "missing or empty. Set a valid HMAC secret, or use "
                        "'%s' to explicitly disable auth (testing only).",
                        k,
                        _INSECURE_NO_AUTH,
                    )
                    continue
                if (
                    effective_secret == _INSECURE_NO_AUTH
                    and not _is_loopback_host(self._host)
                ):
                    logger.warning(
                        "[webhook] Dynamic route '%s' skipped: INSECURE_NO_AUTH "
                        "is only allowed on loopback hosts. Current host: '%s'.",
                        k,
                        self._host,
                    )
                    continue
                new_dynamic[k] = v
            self._dynamic_routes = new_dynamic
            self._routes = {**self._dynamic_routes, **self._static_routes}
            self._dynamic_routes_mtime = mtime
            logger.info(
                "[webhook] Reloaded %d dynamic route(s): %s",
                len(self._dynamic_routes),
                ", ".join(self._dynamic_routes.keys()) or "(none)",
            )
        except Exception as e:
            logger.error("[webhook] Failed to reload dynamic routes: %s", e)

    def _resolve_request_profile(self, request: "web.Request"):
        """Resolve + validate the /p/<profile>/ URL prefix on a webhook request.

        Returns:
          - ``None`` when no profile prefix is present, or multiplexing is off
            (the prefix is ignored, request handled as the default profile).
          - the profile name (str) when present, multiplexing is on, and the
            profile is one this gateway serves.
          - ``_PROFILE_REJECTED`` when a prefix is present but the profile is
            unknown/unconfigured (handler returns 404).
        """
        profile = (request.match_info.get("profile") or "").strip()
        if not profile:
            return None
        runner = self.gateway_runner
        cfg = getattr(runner, "config", None)
        if not getattr(cfg, "multiplex_profiles", False):
            # Prefix supplied but multiplexing is off — ignore it, behave as
            # the single-profile gateway (don't 404 a would-be valid route).
            return None
        try:
            from hermes_cli.profiles import profiles_to_serve
            served = {name for name, _ in profiles_to_serve(multiplex=True)}
        except Exception:
            return _PROFILE_REJECTED
        if profile not in served:
            return _PROFILE_REJECTED
        return profile

    async def _handle_webhook(self, request: "web.Request") -> "web.Response":
        """POST /webhooks/{route_name} — receive and process a webhook event."""
        # Hot-reload dynamic subscriptions on each request (mtime-gated, cheap)
        self._reload_dynamic_routes()

        route_name = request.match_info.get("route_name", "")
        route_config = self._routes.get(route_name)

        # Multi-profile: resolve + validate the /p/<profile>/ prefix if present.
        profile = self._resolve_request_profile(request)
        if profile is _PROFILE_REJECTED:
            return web.json_response(
                {"error": "Unknown or unconfigured profile"}, status=404
            )

        if not route_config:
            return web.json_response(
                {"error": f"Unknown route: {route_name}"}, status=404
            )

        # Disabled routes are kept in the subscriptions file (so the dashboard
        # can re-enable them) but reject incoming events.  Default-enabled:
        # only an explicit ``enabled: false`` turns a route off, matching the
        # mcp_servers ``enabled`` semantics.
        if route_config.get("enabled", True) is False:
            return web.json_response(
                {"error": f"Route disabled: {route_name}"}, status=403
            )

        # ── Auth-before-body ─────────────────────────────────────
        # Check Content-Length before reading the full payload.
        content_length = request.content_length or 0
        if content_length > self._max_body_bytes:
            return web.json_response(
                {"error": "Payload too large"}, status=413
            )

        # Read body (must be done before any validation)
        try:
            raw_body = await request.read()
        except web.HTTPRequestEntityTooLarge:
            # aiohttp's client_max_size tripped — chunked or lying
            # Content-Length. Same 413 as the header check above.
            return web.json_response(
                {"error": "Payload too large"}, status=413
            )
        except Exception as e:
            logger.error("[webhook] Failed to read body: %s", e)
            return web.json_response({"error": "Bad request"}, status=400)
        if len(raw_body) > self._max_body_bytes:
            # Defense in depth: enforce the cap on the actual bytes read even
            # if the server-level limit was bypassed or misconfigured.
            return web.json_response(
                {"error": "Payload too large"}, status=413
            )

        # Validate HMAC signature FIRST (skip only for the explicit local-test
        # INSECURE_NO_AUTH mode). Missing/empty secrets must fail closed here,
        # not only during connect(), so direct handler reuse cannot turn a
        # network webhook route into an unauthenticated agent-dispatch surface.
        secret = route_config.get("secret", self._global_secret)
        if not secret:
            logger.error(
                "[webhook] Route %s has no HMAC secret; refusing request",
                route_name,
            )
            return web.json_response(
                {"error": "Webhook route is missing an HMAC secret"},
                status=403,
            )
        if secret != _INSECURE_NO_AUTH:
            if not self._validate_signature(request, raw_body, secret):
                logger.warning(
                    "[webhook] Invalid signature for route %s", route_name
                )
                return web.json_response(
                    {"error": "Invalid signature"}, status=401
                )

        # ── Rate limiting (after auth) ───────────────────────────
        now = time.time()
        if not self._record_rate_limit_hit(route_name, now):
            return web.json_response(
                {"error": "Rate limit exceeded"}, status=429
            )

        # Parse payload
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            # Try form-encoded as fallback
            try:
                import urllib.parse

                payload = dict(
                    urllib.parse.parse_qsl(raw_body.decode("utf-8"))
                )
            except Exception:
                return web.json_response(
                    {"error": "Cannot parse body"}, status=400
                )

        # Check event type filter
        event_type = (
            request.headers.get("X-GitHub-Event", "")
            or request.headers.get("X-GitLab-Event", "")
            or payload.get("event_type", "")
            or payload.get("type", "")
            or "unknown"
        )
        allowed_events = route_config.get("events", [])
        if allowed_events and event_type not in allowed_events:
            logger.debug(
                "[webhook] Ignoring event %s for route %s (allowed: %s)",
                event_type,
                route_name,
                allowed_events,
            )
            return web.json_response(
                {"status": "ignored", "event": event_type}
            )

        if not self._route_processor.route_filters_match(
            route_config, payload, event_type, request.headers
        ):
            logger.info(
                "[webhook] filtered event=%s route=%s",
                event_type,
                route_name,
            )
            return web.json_response(
                {
                    "status": "ignored",
                    "reason": "filter",
                    "route": route_name,
                }
            )

        if route_config.get("script"):
            # run_route_script shells out (subprocess.run, up to its timeout);
            # run it in a worker thread so it can't block the gateway event loop.
            keep, transformed_payload = await asyncio.to_thread(
                self._route_processor.run_route_script,
                route_config.get("script"),
                payload,
            )
            if not keep:
                logger.info(
                    "[webhook] script ignored event=%s route=%s",
                    event_type,
                    route_name,
                )
                return web.json_response(
                    {
                        "status": "ignored",
                        "reason": "script",
                        "route": route_name,
                    }
                )
            payload = transformed_payload or payload

        # Format prompt from template
        prompt_template = route_config.get("prompt", "")
        prompt = self._render_prompt(
            prompt_template, payload, event_type, route_name
        )

        # Inject skill content if configured.
        # We call build_skill_invocation_message() directly rather than
        # using /skill-name slash commands — the gateway's command parser
        # would intercept those and break the flow.
        skills = route_config.get("skills", [])
        if skills:
            try:
                from agent.skill_commands import (
                    build_skill_invocation_message,
                    get_skill_commands,
                )

                skill_cmds = get_skill_commands()
                for skill_name in skills:
                    cmd_key = f"/{skill_name}"
                    if cmd_key in skill_cmds:
                        skill_content = build_skill_invocation_message(
                            cmd_key, user_instruction=prompt
                        )
                        if skill_content:
                            prompt = skill_content
                            break  # Load the first matching skill
                    else:
                        logger.warning(
                            "[webhook] Skill '%s' not found", skill_name
                        )
            except Exception as e:
                logger.warning("[webhook] Skill loading failed: %s", e)

        # Build a unique delivery ID
        delivery_id = request.headers.get(
            "X-GitHub-Delivery",
            request.headers.get(
                "svix-id",
                request.headers.get("X-Request-ID", str(int(time.time() * 1000))),
            ),
        )

        # ── Idempotency ─────────────────────────────────────────
        # Generic routes keep the in-memory TTL. Isles story additionally
        # keeps a durable receipt so a process restart cannot turn an already
        # accepted user message into an unsafe second Agent run.
        now = time.time()
        is_durable_isles = (
            route_name == "isles-story"
            and route_config.get("deliver") == "http_callback"
        )
        durable_record = self._isles_turn_store.get(delivery_id) if is_durable_isles else None
        payload_sha256 = self._isles_turn_store.payload_fingerprint(raw_body)
        if durable_record and durable_record.get("payload_sha256") != payload_sha256:
            return web.json_response(
                {"status": "conflict", "delivery_id": delivery_id},
                status=409,
            )
        retry_durable_turn = bool(
            durable_record
            and durable_record.get("retryable")
            and durable_record.get("state") in {"interrupted", "processing_failed"}
        )
        if durable_record and durable_record.get("state") == "delivery_failed" and durable_record.get("outbox"):
            self._schedule_isles_outbox_retry(delivery_id)
            return web.json_response(
                {
                    "status": "accepted",
                    "route": route_name,
                    "event": event_type,
                    "delivery_id": delivery_id,
                    "turn_status": "delivering",
                    "duplicate": True,
                },
                status=202,
            )
        if durable_record and not retry_durable_turn:
            durable_state = str(durable_record.get("state") or "accepted")
            response_status = (
                "accepted"
                if durable_state not in {"interrupted", "processing_failed"}
                else "failed"
            )
            return web.json_response(
                {
                    "status": response_status,
                    "route": route_name,
                    "event": event_type,
                    "delivery_id": delivery_id,
                    "turn_status": durable_state,
                    "retryable": bool(durable_record.get("retryable")),
                    "duplicate": True,
                },
                status=202 if response_status == "accepted" else 409,
            )
        if not self._record_delivery_id(delivery_id, now) and not retry_durable_turn:
            logger.info(
                "[webhook] Skipping duplicate delivery %s", delivery_id
            )
            return web.json_response(
                {"status": "duplicate", "delivery_id": delivery_id},
                status=200,
            )
        if is_durable_isles:
            if durable_record:
                self._isles_turn_store.transition(
                    delivery_id,
                    "accepted",
                    retryable=False,
                    process_token=self._process_token,
                )
            else:
                self._isles_turn_store.receive(
                    delivery_id,
                    payload_sha256=payload_sha256,
                    route=route_name,
                    process_token=self._process_token,
                )

        # ── Direct delivery mode (deliver_only) ─────────────────
        # Skip the agent entirely — the rendered prompt IS the message we
        # deliver.  Use case: external services (Supabase, monitoring,
        # cron jobs, other agents) that need to push a plain notification
        # to a user's chat with zero LLM cost.  Reuses the same HMAC auth,
        # rate limiting, idempotency, and template rendering as agent mode.
        if route_config.get("deliver_only"):
            delivery = {
                "deliver": route_config.get("deliver", "log"),
                "deliver_extra": self._render_delivery_extra(
                    route_config.get("deliver_extra", {}), payload
                ),
                "payload": payload,
            }
            logger.info(
                "[webhook] direct-deliver event=%s route=%s target=%s msg_len=%d delivery=%s",
                event_type,
                route_name,
                delivery["deliver"],
                len(prompt),
                delivery_id,
            )
            try:
                result = await self._direct_deliver(prompt, delivery)
            except Exception:
                logger.exception(
                    "[webhook] direct-deliver failed route=%s delivery=%s",
                    route_name,
                    delivery_id,
                )
                return web.json_response(
                    {"status": "error", "error": "Delivery failed", "delivery_id": delivery_id},
                    status=502,
                )

            if result.success:
                return web.json_response(
                    {
                        "status": "delivered",
                        "route": route_name,
                        "target": delivery["deliver"],
                        "delivery_id": delivery_id,
                    },
                    status=200,
                )
            # Delivery attempted but target rejected it — surface as 502
            # with a generic error (don't leak adapter-level detail).
            logger.warning(
                "[webhook] direct-deliver target rejected route=%s target=%s error=%s",
                route_name,
                delivery["deliver"],
                result.error,
            )
            return web.json_response(
                {"status": "error", "error": "Delivery failed", "delivery_id": delivery_id},
                status=502,
            )

        # Conversational HTTP callbacks (including isles-story) deliberately
        # keep one stable session per route so chat context survives ordinary
        # messages. Non-conversational webhooks retain the official per-delivery
        # isolation used for CI/events and other one-shot work.
        if route_config.get("deliver") == "http_callback":
            session_chat_id = f"webhook:{route_name}:main"
        else:
            session_chat_id = f"webhook:{route_name}:{delivery_id}"

        # Store delivery info for send().  Read by every send() invocation
        # for this chat_id (interim status messages and the final response),
        # so we do NOT pop on send.  TTL-based cleanup keeps the dict bounded.
        # Keep the route's validated reply policy with this accepted turn.
        # Without it send() silently falls back to non-segmented delivery.
        deliver_config = self._delivery_config_for_route(route_name, payload)
        self._delivery_info[session_chat_id] = deliver_config
        self._delivery_info_created[session_chat_id] = now
        self._delivery_info_order.append((now, session_chat_id))
        self._prune_delivery_info(now)

        # Build source and event
        source = self.build_source(
            chat_id=session_chat_id,
            chat_name=f"webhook/{route_name}",
            chat_type="webhook",
            user_id=f"webhook:{route_name}",
            user_name=route_name,
        )
        if profile and isinstance(profile, str):
            source.profile = profile
        media_urls: list[str] = []
        media_types: list[str] = []
        if route_name == "isles-story":
            try:
                media_urls, media_types = await _download_isles_media_items(payload)
            except ValueError as exc:
                if is_durable_isles:
                    self._isles_turn_store.transition(
                        delivery_id,
                        "processing_failed",
                        retryable=True,
                        detail_code="invalid_media",
                        process_token=self._process_token,
                    )
                return web.json_response({"error": str(exc)}, status=400)
            except Exception as exc:
                logger.warning(
                    "[webhook] Isles media download failed route=%s delivery=%s: %s",
                    route_name,
                    delivery_id,
                    exc,
                )
                if is_durable_isles:
                    self._isles_turn_store.transition(
                        delivery_id,
                        "processing_failed",
                        retryable=True,
                        detail_code="media_download_failed",
                        process_token=self._process_token,
                    )
                return web.json_response(
                    {"error": "Media download failed", "delivery_id": delivery_id},
                    status=422,
                )

        event = MessageEvent(
            text=prompt,
            message_type=MessageType.PHOTO if media_urls else MessageType.TEXT,
            source=source,
            raw_message=payload,
            message_id=delivery_id,
            media_urls=media_urls,
            media_types=media_types,
        )

        logger.info(
            "[webhook] %s event=%s route=%s prompt_len=%d delivery=%s",
            request.method,
            event_type,
            route_name,
            len(prompt),
            delivery_id,
        )

        # Non-blocking — return 202 Accepted immediately. One-shot webhook
        # sessions are closed by ``on_processing_complete`` once their Agent
        # run finishes. Conversational http_callback sessions remain open for
        # the next message (``handle_message`` itself is fire-and-forget: it
        # spawns ``_process_message_background`` and returns before the run).
        task = asyncio.create_task(self.handle_message(event))
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

        return web.json_response(
            {
                "status": "accepted",
                "route": route_name,
                "event": event_type,
                "delivery_id": delivery_id,
            },
            status=202,
        )

    async def on_processing_complete(
        self, event: "MessageEvent", outcome: Any
    ) -> None:
        """Close only a one-shot webhook session once its run finishes.

        Non-http-callback routes bake ``delivery_id`` into the session key and
        will never receive a second turn. Mirror the cron completion path
        (``cron/scheduler.py`` → ``end_session(..., "cron_complete")``) by
        marking those sessions ended when the run completes. Conversational
        http_callback routes use a stable ``:main`` key and must stay open so
        the next user message sees the same Agent information window.

        Without closing the one-shot rows, webhook sessions keep ``ended_at``
        NULL forever; ``SessionDB.prune_sessions`` only reaps rows with
        ``ended_at`` set, so they accumulate and drive state.db bloat (the
        ghost-session leak).

        This hook is the one seam that runs at the TRUE end of the run:
        ``BasePlatformAdapter._process_message_background`` fires it after the
        message handler returns, on the success, failure, and cancellation
        paths alike — so error runs are reaped too.  (``handle_message`` is
        fire-and-forget; wrapping IT closes before the run even starts.)
        ``end_session()`` is first-reason-wins and no-ops on an already-ended
        row, so this never clobbers a ``compression``/``agent_close`` reason.
        """
        # Use route configuration rather than the chat-id suffix: a one-shot
        # delivery is allowed to have the literal delivery id ``main`` and
        # must still be closed.
        chat_name = str(getattr(event.source, "chat_name", "") or "")
        route_name = chat_name.removeprefix("webhook/")
        route_config = self._routes.get(route_name, {})
        if route_config.get("deliver") == "http_callback" and route_name == "isles-story":
            turn_id = str(getattr(event, "message_id", "") or "")
            if not turn_id:
                return
            record = self._isles_turn_store.get(turn_id) or {}
            state = str(record.get("state") or "")
            if outcome == ProcessingOutcome.SUCCESS and state != "completed":
                # Intentional-silence turns have no visible callback, but they
                # are still terminal. Do not leave the Worker/UI in processing.
                self._pending_reply_turns.pop(turn_id, None)
                await self.update_isles_turn_status(turn_id, "completed")
            elif outcome == ProcessingOutcome.CANCELLED and state != "completed":
                self._pending_reply_turns.pop(turn_id, None)
                await self.update_isles_turn_status(
                    turn_id,
                    "interrupted",
                    retryable=True,
                    detail_code="processing_cancelled",
                )
            elif outcome == ProcessingOutcome.FAILURE and state not in {
                "completed", "delivery_failed", "processing_failed"
            }:
                self._pending_reply_turns.pop(turn_id, None)
                await self.update_isles_turn_status(
                    turn_id,
                    "failed",
                    retryable=True,
                    detail_code="processing_failed",
                )
            return
        if route_config.get("deliver") != "http_callback":
            await self._end_webhook_session(event, event.source.chat_id)

    async def _end_webhook_session(
        self, event: "MessageEvent", session_chat_id: str
    ) -> None:
        """Mark the per-delivery webhook session ended in state.db.

        Resolves the persisted ``session_id`` from the gateway session store
        using the SAME source the run was keyed on (so profile multiplexing
        and key construction match exactly), then closes it via the existing
        ``SessionDB.end_session`` API — never a hand-written UPDATE.
        """
        runner = self.gateway_runner
        if runner is None:
            return
        session_db = getattr(runner, "_session_db", None)
        store = getattr(runner, "session_store", None)
        if session_db is None or store is None:
            return
        try:
            key_fn = getattr(runner, "_session_key_for_source", None)
            if key_fn is None:
                return
            session_key = key_fn(event.source)
            # Resolve the persisted session_id via the store's public,
            # lock-held accessor (peek_session_id) rather than reaching into
            # the private _entries dict without the store lock. Fall back to
            # the private path only for older stores / test doubles that
            # predate the accessor.
            peek = getattr(store, "peek_session_id", None)
            if callable(peek):
                session_id = peek(session_key)
            else:
                if hasattr(store, "_ensure_loaded"):
                    try:
                        store._ensure_loaded()
                    except Exception:
                        pass
                entries = getattr(store, "_entries", {}) or {}
                entry = entries.get(session_key)
                session_id = getattr(entry, "session_id", None) if entry else None
            if not session_id:
                logger.debug(
                    "[webhook] No session_id to close for %s (key=%s)",
                    session_chat_id,
                    session_key,
                )
                return
            # AsyncSessionDB forwards end_session via asyncio.to_thread; a
            # plain SessionDB exposes it synchronously.  Handle both.
            _end = session_db.end_session
            result = _end(session_id, "webhook_complete")
            if asyncio.iscoroutine(result):
                await result
            logger.debug(
                "[webhook] Closed session %s for delivery %s",
                session_id,
                session_chat_id,
            )
        except Exception as e:
            logger.debug(
                "[webhook] Failed to close session for %s: %s",
                session_chat_id,
                e,
            )

    # ------------------------------------------------------------------
    # Signature validation
    # ------------------------------------------------------------------

    def _validate_signature(
        self, request: "web.Request", body: bytes, secret: str
    ) -> bool:
        """Validate webhook signature (GitHub, GitLab, Svix, generic HMAC-SHA256)."""
        def _header(name: str) -> str:
            return (
                request.headers.get(name, "")
                or request.headers.get(name.lower(), "")
                or request.headers.get(name.upper(), "")
            )

        # Svix / AgentMail:
        #   svix-id: msg_...
        #   svix-timestamp: unix seconds
        #   svix-signature: v1,<base64-hmac> [v1,<base64-hmac> ...]
        # Signed content is: "{id}.{timestamp}.{raw_body}".  Svix secrets
        # usually start with "whsec_" and the remainder is base64-encoded.
        svix_id = _header("svix-id")
        svix_timestamp = _header("svix-timestamp")
        svix_signature = _header("svix-signature")
        if svix_id or svix_timestamp or svix_signature:
            return self._validate_svix_signature(
                body=body,
                secret=secret,
                msg_id=svix_id,
                timestamp=svix_timestamp,
                signature_header=svix_signature,
            )

        # GitHub: X-Hub-Signature-256 = sha256=<hex>
        gh_sig = request.headers.get("X-Hub-Signature-256", "")
        if gh_sig:
            expected = "sha256=" + hmac.new(
                secret.encode(), body, hashlib.sha256
            ).hexdigest()
            return _hmac_str_equal(gh_sig, expected)

        # GitLab: X-Gitlab-Token = <plain secret>
        gl_token = request.headers.get("X-Gitlab-Token", "")
        if gl_token:
            return _hmac_str_equal(gl_token, secret)

        # Generic V2: X-Webhook-Signature-V2 = <hex HMAC-SHA256 of "<timestamp>.<body>">
        #             X-Webhook-Timestamp = <unix seconds> (required for V2)
        # Checked independently of (and before) legacy V1 below — a sender
        # that only ever sends V2 headers must still validate here; nesting
        # this inside `if generic_sig:` would silently skip V2-only senders.
        #
        # The presence of X-Webhook-Signature-V2 alone selects V2 mode and
        # commits to it — it must NOT fall through to the V1 branch just
        # because the timestamp is missing/malformed/expired. A sender
        # migrating to V2 typically sends both V1 and V2 headers together
        # for compatibility; if incomplete V2 fell through to V1, an
        # attacker who captured one such mixed request could strip the
        # X-Webhook-Timestamp header from a replay and have it validate
        # against the still-present, still-unprotected V1 signature instead
        # — silently downgrading a V2-protected request back to the replay
        # hole V2 exists to close.
        v2_sig = request.headers.get("X-Webhook-Signature-V2", "")
        if v2_sig:
            v2_timestamp = request.headers.get("X-Webhook-Timestamp", "")
            if not v2_timestamp:
                logger.warning(
                    "[webhook] Route '%s' sent X-Webhook-Signature-V2 with "
                    "no X-Webhook-Timestamp — rejecting rather than "
                    "falling back to legacy V1",
                    request.match_info.get("route_name", ""),
                )
                return False
            try:
                ts = int(v2_timestamp)
            except (TypeError, ValueError):
                return False
            if abs(int(time.time()) - ts) > 300:
                logger.warning(
                    "[webhook] Route '%s' generic HMAC V2 timestamp outside replay window",
                    request.match_info.get("route_name", ""),
                )
                return False
            signed_content = v2_timestamp.encode() + b"." + body
            expected_v2 = hmac.new(
                secret.encode(), signed_content, hashlib.sha256
            ).hexdigest()
            return _hmac_str_equal(v2_sig, expected_v2)

        # Generic V1 (legacy): X-Webhook-Signature = <hex HMAC-SHA256 of body>
        # (deprecated — no replay protection, since the signature only
        # covers the body: a captured (body, signature) pair replays
        # indefinitely with no timestamp binding it to a specific delivery.)
        # Only reachable when X-Webhook-Signature-V2 was not sent at all —
        # see the guard above.
        generic_sig = request.headers.get("X-Webhook-Signature", "")
        if generic_sig:
            expected = hmac.new(
                secret.encode(), body, hashlib.sha256
            ).hexdigest()
            route_name = request.match_info.get("route_name", "")
            if route_name not in self._v1_signature_warned:
                self._v1_signature_warned.add(route_name)
                logger.warning(
                    "[webhook] Route '%s' uses legacy body-only HMAC (no "
                    "timestamp), which is vulnerable to replay attacks. Add "
                    "an 'X-Webhook-Timestamp' header and switch to "
                    "'X-Webhook-Signature-V2' (HMAC-SHA256 of "
                    "'<timestamp>.<body>').",
                    route_name,
                )
            return _hmac_str_equal(generic_sig, expected)

        # No recognised signature header but secret is configured → reject
        logger.debug(
            "[webhook] Secret configured but no signature header found"
        )
        return False

    def _validate_svix_signature(
        self,
        body: bytes,
        secret: str,
        msg_id: str,
        timestamp: str,
        signature_header: str,
        tolerance_seconds: int = 300,
    ) -> bool:
        """Validate Svix-compatible signatures used by AgentMail webhooks."""
        if not (msg_id and timestamp and signature_header and secret):
            return False

        try:
            ts = int(timestamp)
        except (TypeError, ValueError):
            return False
        if abs(int(time.time()) - ts) > tolerance_seconds:
            logger.warning("[webhook] Svix signature timestamp outside replay window")
            return False

        if secret.startswith("whsec_"):
            encoded_secret = secret.removeprefix("whsec_")
            try:
                key = base64.b64decode(encoded_secret, validate=True)
            except (binascii.Error, ValueError):
                logger.debug("[webhook] Invalid whsec_ Svix signing secret")
                return False
        else:
            # Be permissive for providers that document Svix-style headers but
            # hand out raw shared secrets rather than whsec_ base64 secrets.
            logger.debug("[webhook] Validating Svix-style signature with raw secret")
            key = secret.encode()

        signed_content = msg_id.encode() + b"." + timestamp.encode() + b"." + body
        expected = base64.b64encode(
            hmac.new(key, signed_content, hashlib.sha256).digest()
        ).decode()

        # Svix can send multiple signatures separated by spaces during secret
        # rotation. Each entry is formatted as "vN,<base64>".
        for part in signature_header.split():
            try:
                version, signature = part.split(",", 1)
            except ValueError:
                continue
            if version == "v1" and _hmac_str_equal(signature, expected):
                return True
        return False

    # ------------------------------------------------------------------
    # Prompt rendering
    # ------------------------------------------------------------------

    def _render_prompt(
        self,
        template: str,
        payload: dict,
        event_type: str,
        route_name: str,
    ) -> str:
        """Render a prompt template with the webhook payload.

        Supports dot-notation access into nested dicts:
        ``{pull_request.title}`` → ``payload["pull_request"]["title"]``

        Special token ``{__raw__}`` dumps the entire payload as indented
        JSON (truncated to 4000 chars).  Useful for monitoring alerts or
        any webhook where the agent needs to see the full payload.
        """
        if not template:
            truncated = json.dumps(payload, indent=2)[:4000]
            return (
                f"Webhook event '{event_type}' on route "
                f"'{route_name}':\n\n```json\n{truncated}\n```"
            )

        def _resolve(match: re.Match) -> str:
            key = match.group(1)
            # Special token: dump the entire payload as JSON
            if key == "__raw__":
                return json.dumps(payload, indent=2)[:4000]
            if key == "event_type":
                return event_type
            value: Any = payload
            for part in key.split("."):
                if isinstance(value, dict):
                    value = value.get(part, f"{{{key}}}")
                else:
                    return f"{{{key}}}"
            if isinstance(value, (dict, list)):
                return json.dumps(value, indent=2)[:2000]
            return str(value)

        return re.sub(r"\{([a-zA-Z0-9_.]+)\}", _resolve, template)

    def _render_delivery_extra(
        self, extra: dict, payload: dict
    ) -> dict:
        """Render delivery_extra template values with payload data."""
        rendered: Dict[str, Any] = {}
        for key, value in extra.items():
            if isinstance(value, str):
                rendered[key] = self._render_prompt(value, payload, "", "")
            else:
                rendered[key] = value
        return rendered

    # ------------------------------------------------------------------
    # Response delivery
    # ------------------------------------------------------------------

    async def _direct_deliver(
        self, content: str, delivery: dict
    ) -> SendResult:
        """Deliver *content* directly without invoking the agent.

        Used by ``deliver_only`` routes: the rendered template becomes the
        literal message body, and we dispatch to the same delivery helpers
        that the agent-mode ``send()`` flow uses.  All target types that
        work in agent mode work here — Telegram, Discord, Slack, GitHub
        PR comments, etc.
        """
        deliver_type = delivery.get("deliver", "log")

        if deliver_type == "log":
            # Shouldn't reach here — startup validation rejects deliver_only
            # with deliver=log — but guard defensively.
            logger.info("[webhook] direct-deliver log-only: %s", content[:200])
            return SendResult(success=True)

        if deliver_type == "github_comment":
            return await self._deliver_github_comment(content, delivery)

        # Fall through to the cross-platform dispatcher, which validates the
        # target name and routes via the gateway runner.
        return await self._deliver_cross_platform(
            deliver_type, content, delivery
        )

    async def _deliver_github_comment(
        self, content: str, delivery: dict
    ) -> SendResult:
        """Post agent response as a GitHub PR/issue comment via ``gh`` CLI."""
        extra = delivery.get("deliver_extra", {})
        repo = extra.get("repo", "")
        pr_number = extra.get("pr_number", "")

        if not repo or not pr_number:
            logger.error(
                "[webhook] github_comment delivery missing repo or pr_number"
            )
            return SendResult(
                success=False, error="Missing repo or pr_number"
            )

        # --- Input validation (prevent CLI argument injection) ---
        # pr_number must be a positive integer.
        try:
            pr_int = int(pr_number)
            if pr_int <= 0:
                raise ValueError("non-positive")
        except (ValueError, TypeError):
            logger.error(
                "[webhook] invalid pr_number: %r", pr_number
            )
            return SendResult(
                success=False, error="Invalid pr_number"
            )

        # repo must match owner/name (alphanumeric, hyphens, underscores, dots).
        if not re.fullmatch(r"[A-Za-z0-9._-]+/[A-Za-z0-9._-]+", repo):
            logger.error("[webhook] invalid repo format: %r", repo)
            return SendResult(
                success=False, error="Invalid repo format"
            )

        try:
            result = subprocess.run(
                [
                    "gh",
                    "pr",
                    "comment",
                    str(pr_int),
                    "--repo",
                    repo,
                    "--body",
                    content,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info(
                    "[webhook] Posted comment on %s#%s", repo, pr_number
                )
                return SendResult(success=True)
            else:
                logger.error(
                    "[webhook] gh pr comment failed: %s", result.stderr
                )
                return SendResult(success=False, error=result.stderr)
        except FileNotFoundError:
            logger.error(
                "[webhook] 'gh' CLI not found — install GitHub CLI for "
                "github_comment delivery"
            )
            return SendResult(
                success=False, error="gh CLI not installed"
            )
        except Exception as e:
            logger.error("[webhook] github_comment delivery error: %s", e)
            return SendResult(success=False, error=str(e))

    async def _deliver_cross_platform(
        self, platform_name: str, content: str, delivery: dict
    ) -> SendResult:
        """Route response to another platform (telegram, discord, etc.)."""
        if not self.gateway_runner:
            return SendResult(
                success=False,
                error="No gateway runner for cross-platform delivery",
            )

        try:
            target_platform = Platform(platform_name)
        except ValueError:
            return SendResult(
                success=False, error=f"Unknown platform: {platform_name}"
            )

        # Default adapters first; multiplex may park Slack/etc. only on a
        # secondary profile (self._profile_adapters). Fall back so webhook
        # deliver:slack still works when default has slack disabled.
        adapter = self.gateway_runner.adapters.get(target_platform)
        if not adapter:
            for _prof, amap in (getattr(self.gateway_runner, "_profile_adapters", None) or {}).items():
                if not isinstance(amap, dict):
                    continue
                cand = amap.get(target_platform)
                if cand is not None:
                    adapter = cand
                    break
        if not adapter:
            return SendResult(
                success=False,
                error=f"Platform {platform_name} not connected",
            )

        # Use home channel if no specific chat_id in deliver_extra
        extra = delivery.get("deliver_extra", {})
        chat_id = extra.get("chat_id", "")
        if not chat_id:
            home = self.gateway_runner.config.get_home_channel(target_platform)
            if home:
                chat_id = home.chat_id
            else:
                return SendResult(
                    success=False,
                    error=f"No chat_id or home channel for {platform_name}",
                )

        # Pass thread_id from deliver_extra so Telegram forum topics work
        metadata = None
        thread_id = extra.get("message_thread_id") or extra.get("thread_id")
        if thread_id:
            metadata = {"thread_id": thread_id}

        return await adapter.send(chat_id, content, metadata=metadata)
