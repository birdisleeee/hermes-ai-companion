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
  - Set secret to "INSECURE_NO_AUTH" to skip validation (testing only)
"""

import asyncio
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import quote

try:
    from aiohttp import web
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False
    web = None  # type: ignore[assignment]

# Phase 4b.7d — module-level forbidden keywords (defense-in-depth)
# Used by _deliver_http_callback() schema guard to prevent LLM leakage
# into frontend-visible visible_reasoning summaries.
FORBIDDEN_SUBSTRINGS = [
    "系统", "用户", "对方", "推理", "分析",
    "思考链", "chain-of-thought", "reasoning",
    "system prompt", "tool call", "token",
    "API", "webhook", "callback", "prompt",
    "json", "schema", "confidence",
]

# Wide preview: dedicated forbidden list for visible_inner_note.text
# Less aggressive than FORBIDDEN_SUBSTRINGS — does NOT filter 用户/分析
# which are normal in reasoning content under wide preview strategy.
VISIBLE_INNER_NOTE_FORBIDDEN = [
    "system prompt", "tool call", "token", "secret",
    "API", "webhook", "callback",
    "JSON", "schema",
    "config", "model config",
    "reasoning_content", "raw reasoning", "chain-of-thought",
    "http://", "https://",
    "def ", "class ", "import ",
    "```",
]


from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import (
    BasePlatformAdapter,
    MessageEvent,
    MessageType,
    SendResult,
)
from gateway.isles_turn_store import IslesTurnStore
from gateway.reply_delivery import (
    ReplyDeliveryConfig,
    ReplyUnit,
    build_fallback_reply_unit,
    build_reply_units,
    reply_delay_seconds,
)

logger = logging.getLogger(__name__)

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8644
_INSECURE_NO_AUTH = "INSECURE_NO_AUTH"
_DYNAMIC_ROUTES_FILENAME = "webhook_subscriptions.json"


def check_webhook_requirements() -> bool:
    """Check if webhook adapter dependencies are available."""
    return AIOHTTP_AVAILABLE


class WebhookAdapter(BasePlatformAdapter):
    """Generic webhook receiver that triggers agent runs from HTTP POSTs."""

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.WEBHOOK)
        self._host: str = config.extra.get("host", DEFAULT_HOST)
        self._port: int = int(config.extra.get("port", DEFAULT_PORT))
        self._global_secret: str = config.extra.get("secret", "")
        self._static_routes: Dict[str, dict] = config.extra.get("routes", {})
        self._dynamic_routes: Dict[str, dict] = {}
        self._dynamic_routes_mtime: float = 0.0
        self._routes: Dict[str, dict] = dict(self._static_routes)
        self._runner = None

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

        # ── v4.2.19: voice message bridge ──
        # Written by run.py _isles_voice_bridge_sync(), read+consumed by send().
        # dict {voice, transcript} or None.  Future: message_units[] list.
        self._pending_voice_meta: Optional[dict] = None

        # Final user-turn marker keyed by the inbound Worker message ID.
        # This is deliberately separate from session-keyed delivery_info:
        # status messages and cron output must never inherit user-turn grouping.
        self._pending_reply_turns: Dict[str, dict] = {}
        self._isles_turn_store = IslesTurnStore()
        self._process_token = f"{os.getpid()}:{uuid.uuid4().hex}"
        self._isles_retry_tasks: Dict[str, asyncio.Task] = {}

        # Phase 4b.7d — per-message visible_reasoning cache
        # Written by run.py (future Phase 4a+4b activation), read by send(),
        # delete-on-read, 30s TTL.  Currently no-op: cache always empty
        # until Phase 4a generator is deployed.
        self._vr_meta_cache: Dict[str, dict] = {}
        self._vr_meta_cache_ts: Dict[str, float] = {}

        # 4d.3: per-message inner_note cache (concurrency-safe, separate from VR cache)
        self._inner_note_cache: Dict[str, dict] = {}
        self._inner_note_cache_ts: Dict[str, float] = {}



        # Reference to gateway runner for cross-platform delivery (set externally)
        self.gateway_runner = None

        # Idempotency: TTL cache of recently processed delivery IDs.
        # Prevents duplicate agent runs when webhook providers retry.
        self._seen_deliveries: Dict[str, float] = {}
        self._idempotency_ttl: int = 3600  # 1 hour

        # Rate limiting: per-route timestamps in a fixed window.
        self._rate_counts: Dict[str, List[float]] = {}
        self._rate_limit: int = int(config.extra.get("rate_limit", 30))  # per minute

        # Body size limit (auth-before-body pattern)
        self._max_body_bytes: int = int(
            config.extra.get("max_body_bytes", 1_048_576)
        )  # 1MB

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def connect(self) -> bool:
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

        app = web.Application()
        app.router.add_get("/health", self._handle_health)
        app.router.add_post("/webhooks/{route_name}", self._handle_webhook)

        # Port conflict detection — fail fast if port is already in use
        import socket as _socket
        try:
            with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as _s:
                _s.settimeout(1)
                _s.connect(('127.0.0.1', self._port))
            logger.error('[webhook] Port %d already in use. Set a different port in config.yaml: platforms.webhook.port', self._port)
            return False
        except (ConnectionRefusedError, OSError):
            pass  # port is free

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, self._host, self._port)
        await site.start()
        self._mark_connected()

        # An Agent run cannot survive a process restart.  Durable reply
        # outboxes can, so resume those; mark other unfinished turns explicitly
        # interrupted instead of leaving the island in an eternal typing state.
        for record in self._isles_turn_store.recover_after_restart(self._process_token):
            turn_id = record["turn_id"]
            if record.get("state") == "delivery_failed" and record.get("outbox"):
                self._schedule_isles_outbox_retry(turn_id)
            elif record.get("state") == "interrupted":
                asyncio.create_task(
                    self._emit_isles_turn_status(
                        turn_id,
                        "interrupted",
                        retryable=bool(record.get("retryable")),
                        detail_code="gateway_restarted",
                        route_name=str(record.get("route") or "isles-story"),
                    )
                )

        route_names = ", ".join(self._routes.keys()) or "(none configured)"
        logger.info(
            "[webhook] Listening on %s:%d — routes: %s",
            self._host,
            self._port,
            route_names,
        )
        return True

    async def disconnect(self) -> None:
        for task in list(self._isles_retry_tasks.values()):
            task.cancel()
        self._isles_retry_tasks.clear()
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
        # Phase 4b.7d — opportunistic cleanup of stale VR cache (no bg task)
        _now_vr = time.time()
        _stale_keys = [
            k for k, ts in self._vr_meta_cache_ts.items()
            if _now_vr - ts > 30
        ]
        for k in _stale_keys:
            self._vr_meta_cache.pop(k, None)
            self._vr_meta_cache_ts.pop(k, None)

        # 4d.3: opportunistic TTL cleanup for inner_note cache
        _nn_stale_keys = [
            k for k, ts in self._inner_note_cache_ts.items()
            if _now_vr - ts > 60
        ]
        for k in _nn_stale_keys:
            self._inner_note_cache.pop(k, None)
            self._inner_note_cache_ts.pop(k, None)

        # Phase 4b.7d — per-reply VR meta lookup (delete-on-read, cache-only path)
        # Currently always None (cache empty — no generator to populate it).
        _vr_meta = None
        try:
            import hashlib as _h
            _vr_content_hash = _h.sha256(content.encode()).hexdigest()[:16]
            _vr_reply_to = reply_to or 'no-reply'
            _vr_cache_key = f"{chat_id}:{_vr_reply_to}:{_vr_content_hash}"
            _vr_meta = self._vr_meta_cache.pop(_vr_cache_key, None)
            if _vr_meta is not None:
                self._vr_meta_cache_ts.pop(_vr_cache_key, None)
        except Exception:
            pass

        # 4d.3: per-message inner_note cache lookup
        _inner_note_meta = None
        try:
            _nn_content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
            _nn_reply_to = reply_to or ''
            if _nn_reply_to:  # HARD GUARD
                _nn_cache_key = f"{chat_id}:{_nn_reply_to}:{_nn_content_hash}"
                _nn_entry = self._inner_note_cache.pop(_nn_cache_key, None)
                if _nn_entry is not None:
                    self._inner_note_cache_ts.pop(_nn_cache_key, None)
                    _inner_note_meta = _nn_entry
        except Exception:
            _inner_note_meta = None  # fail-open

        delivery = dict(self._delivery_info.get(chat_id, {}))
        deliver_type = delivery.get("deliver", "log")

        # ── Cron delivery fallback ──────────────────────────────
        # When _delivery_info has no entry for chat_id (e.g. cron jobs
        # that never received an inbound POST), try to reconstruct
        # delivery config from the static route config.
        if not delivery and self._routes:
            _route_name = None
            # chat_id formats: webhook:{route}:main, webhook:{route}:{id},
            # or bare route name
            if chat_id.startswith("webhook:"):
                parts = chat_id.split(":", 2)
                _route_name = parts[1] if len(parts) >= 2 else None
            else:
                _route_name = chat_id
            if _route_name and _route_name in self._routes:
                _route_cfg = self._routes[_route_name]
                _deliver = _route_cfg.get("deliver", "log")
                if _deliver != "log":
                    delivery = {
                        "deliver": _deliver,
                        "deliver_extra": _route_cfg.get("deliver_extra", {}),
                    }
                    deliver_type = _deliver
                    logger.info(
                        "[webhook] Reconstructed delivery for %s from route '%s' (deliver=%s)",
                        chat_id, _route_name, _deliver,
                    )

        if deliver_type == "log":
            logger.info("[webhook] Response for %s: %s", chat_id, content[:200])
            return SendResult(success=True)

        if deliver_type == "github_comment":
            return await self._deliver_github_comment(content, delivery)

        if deliver_type == "http_callback":
            # 4d.3: merge 4b.7d VR meta + 4d.3 inner_note meta
            _combined_meta = {}
            if _vr_meta is not None:
                _combined_meta.update(_vr_meta)
            if _inner_note_meta is not None:
                _combined_meta.update(_inner_note_meta)

            # ── v4.2.19: isles-story voice injection ──
            _voice_meta = self.consume_pending_voice_meta()
            if _voice_meta is not None:
                _combined_meta.update(_voice_meta)
            # ── end voice injection ──

            _turn_marker = (
                self._pending_reply_turns.get(reply_to)
                if isinstance(reply_to, str) and reply_to
                else None
            )
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

        # Cross-platform delivery — any platform with a gateway adapter
        if self.gateway_runner and deliver_type in (
            "telegram",
            "discord",
            "slack",
            "signal",
            "sms",
            "whatsapp",
            "matrix",
            "mattermost",
            "homeassistant",
            "email",
            "dingtalk",
            "feishu",
            "wecom",
            "wecom_callback",
            "weixin",
            "bluebubbles",
            "qqbot",
        ):
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
        cutoff = now - self._idempotency_ttl
        stale = [
            k
            for k, t in self._delivery_info_created.items()
            if t < cutoff
        ]
        for k in stale:
            self._delivery_info.pop(k, None)
            self._delivery_info_created.pop(k, None)

    # ── v4.2.19: voice message bridge ──

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
        Future: will iterate message_units[] instead of single dict.
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
        )

    def _static_isles_delivery(self, route_name: str = "isles-story") -> dict:
        route = self._routes.get(route_name, {})
        return {
            "deliver": route.get("deliver", "log"),
            "deliver_extra": self._render_delivery_extra(route.get("deliver_extra", {}), {}),
            "reply_delivery": ReplyDeliveryConfig.from_route(route),
        }

    async def _emit_isles_turn_status(
        self,
        turn_id: str,
        status: str,
        *,
        retryable: bool = False,
        detail_code: str | None = None,
        route_name: str = "isles-story",
    ) -> bool:
        """Send metadata-only state; never create a visible chat message."""

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
        try:
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.post(
                    status_url,
                    json=payload,
                    headers={"Authorization": f"Bearer {token}"},
                ) as response:
                    return 200 <= response.status < 300
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

    # ── end voice bridge ──

    async def get_chat_info(self, chat_id: str) -> Dict[str, Any]:
        return {"name": chat_id, "type": "webhook"}

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------

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
            # Merge: static routes take precedence over dynamic ones
            self._dynamic_routes = {
                k: v for k, v in data.items()
                if k not in self._static_routes
            }
            self._routes = {**self._dynamic_routes, **self._static_routes}
            self._dynamic_routes_mtime = mtime
            logger.info(
                "[webhook] Reloaded %d dynamic route(s): %s",
                len(self._dynamic_routes),
                ", ".join(self._dynamic_routes.keys()) or "(none)",
            )
        except Exception as e:
            logger.error("[webhook] Failed to reload dynamic routes: %s", e)

    async def _handle_webhook(self, request: "web.Request") -> "web.Response":
        """POST /webhooks/{route_name} — receive and process a webhook event."""
        # Hot-reload dynamic subscriptions on each request (mtime-gated, cheap)
        self._reload_dynamic_routes()

        route_name = request.match_info.get("route_name", "")
        route_config = self._routes.get(route_name)

        if not route_config:
            return web.json_response(
                {"error": f"Unknown route: {route_name}"}, status=404
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
        except Exception as e:
            logger.error("[webhook] Failed to read body: %s", e)
            return web.json_response({"error": "Bad request"}, status=400)

        # Validate HMAC signature FIRST (skip for INSECURE_NO_AUTH testing mode)
        secret = route_config.get("secret", self._global_secret)
        if secret and secret != _INSECURE_NO_AUTH:
            if not self._validate_signature(request, raw_body, secret):
                logger.warning(
                    "[webhook] Invalid signature for route %s", route_name
                )
                return web.json_response(
                    {"error": "Invalid signature"}, status=401
                )

        # ── Rate limiting (after auth) ───────────────────────────
        now = time.time()
        window = self._rate_counts.setdefault(route_name, [])
        window[:] = [t for t in window if now - t < 60]
        if len(window) >= self._rate_limit:
            return web.json_response(
                {"error": "Rate limit exceeded"}, status=429
            )
        window.append(now)

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
            request.headers.get("X-Request-ID", str(int(time.time() * 1000))),
        )

        # ── Idempotency ─────────────────────────────────────────
        # Generic routes keep the historical in-memory TTL.  Isles receipts
        # additionally use a durable journal so a restart or background-task
        # failure cannot be misreported as a healthy duplicate.
        now = time.time()
        is_http_callback = route_config.get("deliver") == "http_callback"
        is_durable_isles = is_http_callback and route_name == "isles-story"
        # Prune expired entries
        self._seen_deliveries = {
            k: v
            for k, v in self._seen_deliveries.items()
            if now - v < self._idempotency_ttl
        }
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
            response_status = "accepted" if durable_state not in {"interrupted", "processing_failed"} else "failed"
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

        if delivery_id in self._seen_deliveries and not retry_durable_turn:
            logger.info(
                "[webhook] Skipping duplicate delivery %s", delivery_id
            )
            if is_http_callback:
                return web.json_response(
                    {
                        "status": "accepted",
                        "route": route_name,
                        "event": event_type,
                        "delivery_id": delivery_id,
                        "duplicate": True,
                    },
                    status=202,
                )
            return web.json_response(
                {"status": "duplicate", "delivery_id": delivery_id},
                status=200,
            )
        self._seen_deliveries[delivery_id] = now
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

        # Use delivery_id in session key so concurrent webhooks on the
        # same route get independent agent runs (not queued/interrupted).
        # EXCEPT http_callback routes: use fixed session ID so the agent
        # retains conversation context across messages (like QQ/Feishu).
        if route_config.get("deliver") == "http_callback":
            session_chat_id = f"webhook:{route_name}:main"
        else:
            session_chat_id = f"webhook:{route_name}:{delivery_id}"

        # Store delivery info for send().  Read by every send() invocation
        # for this chat_id (interim status messages and the final response),
        # so we do NOT pop on send.  TTL-based cleanup keeps the dict bounded.
        deliver_config = {
            "deliver": route_config.get("deliver", "log"),
            "deliver_extra": self._render_delivery_extra(
                route_config.get("deliver_extra", {}), payload
            ),
            "payload": payload,
            # Capture the validated, default-off delivery contract. Per-turn
            # identity comes
            # from send(reply_to=event.message_id), not this session-keyed map,
            # because HTTP callback routes intentionally share one session.
            "reply_delivery": ReplyDeliveryConfig.from_route(route_config),
        }
        self._delivery_info[session_chat_id] = deliver_config
        self._delivery_info_created[session_chat_id] = now
        self._prune_delivery_info(now)

        # Isles HTTP callbacks acknowledge ownership before auxiliary vision
        # work.  The accepted task still performs the same enrichment before
        # invoking the Agent, but the browser no longer waits up to 40 seconds
        # for a truthful 202 handshake.
        if route_config.get("deliver") == "http_callback":
            task = asyncio.create_task(
                self._handle_accepted_http_callback_event(
                    prompt=prompt,
                    payload=payload,
                    deliver_config=deliver_config,
                    session_chat_id=session_chat_id,
                    route_name=route_name,
                    event_type=event_type,
                    delivery_id=delivery_id,
                )
            )
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)
            return web.json_response(
                {
                    "status": "accepted",
                    "route": route_name,
                    "event": event_type,
                    "delivery_id": delivery_id,
                    "turn_status": "accepted",
                },
                status=202,
            )

        # ── v4.2.16 Phase 1b: aux vision bridge ──
        # Extract image from mixed message, call glm-4.6v vision aux,
        # inject analysis into prompt before GLM-5.1 main reply.
        
        # ── TRACE: webhook payload ──
        _trace_msg = payload.get("message", {})
        _trace_images = _trace_msg.get("images") or []
        _trace_img_key = (_trace_images[0].get("image_key","") if _trace_images else "")
        logger.info(
            "[webhook] TRACE msg_id=%s type=%s content_preview=%s images_count=%d image_key=%s",
            _trace_msg.get("id","?"),
            _trace_msg.get("type","?"),
            str(_trace_msg.get("content",""))[:120],
            len(_trace_images),
            str(_trace_img_key)[:40]
        )
        # ── END TRACE ──
        
        _vision_deadline = now + 40  # total budget 40s (media 12s + vision 25s)
        _media_token = deliver_config.get("deliver_extra", {}).get("token", "")
        _images = payload.get("message", {}).get("images") or []
        if _images and isinstance(_images, list) and len(_images) > 0:
            _img = _images[0]
            _key = str(_img.get("image_key") or "")
            _user_text = str(payload.get("message", {}).get("content", "") or "").strip()
            _user_text_short = _user_text[:400] if _user_text else ""
            if _key.startswith("chat-images/") and ".." not in _key and "://" not in _key and not _key.startswith("/"):
                import asyncio as _asyncio
                _tmp_path = None
                try:
                    import uuid, os, tempfile
                    # 1) fetch image from Worker
                    _media_url = "https://isles-story.site/api/media/file?key=" + quote(_key, safe="/")
                    _timeout = aiohttp.ClientTimeout(total=12)
                    _t0 = time.time()
                    async with aiohttp.ClientSession(timeout=_timeout) as _sess:
                        async with _sess.get(
                            _media_url,
                            headers={"Authorization": f"Bearer {_media_token}"}
                        ) as _resp:
                            _body = await _resp.read()
                            _size = len(_body)
                            _ct_raw = _resp.headers.get("Content-Type", "")
                            _ct_main = _ct_raw.split(";")[0].strip()
                            _cl = _resp.headers.get("Content-Length", "")
                            if _resp.status == 200 and _ct_main.startswith("image/") and _size > 0:
                                _suffix = {"image/png":".png","image/gif":".gif","image/webp":".webp"}.get(_ct_main,".jpg")
                                _fd, _tmp_path = tempfile.mkstemp(prefix="isles_img_", suffix=_suffix)
                                os.write(_fd, _body)
                                os.close(_fd)
                                os.chmod(_tmp_path, 0o600)
                                _elapsed_ok = time.time() - _t0
                                logger.info("[webhook] vision media fetch ok elapsed=%.2fs ct=%s cl=%s size=%d key=%s", _elapsed_ok, _ct_main, _cl, _size, _key[:40])
                            else:
                                _preview = _body[:120].decode("utf-8", "replace") if _size > 0 else "(empty body)"
                                logger.warning(
                                    "[webhook] vision media fetch invalid status=%d ct=%s cl=%s size=%d key=%s preview=%s",
                                    _resp.status, _ct_raw[:80], _cl, _size, _key[:40], _preview
                                )
                except Exception as _e:
                    _elapsed = time.time() - _t0 if "_t0" in dir() else -1.0
                    logger.warning("[webhook] vision media fetch error elapsed=%.2fs type=%s repr=%r", _elapsed, type(_e).__name__, str(_e)[:200])

                if _tmp_path and os.path.exists(_tmp_path):
                    try:
                        _vt0 = time.time()
                        if time.time() < _vision_deadline:
                            from tools.vision_tools import vision_analyze_tool
                            if _user_text_short:
                                _vision_prompt = (
                                    "请分两部分分析这张图片：\n\n"
                                    "第一部分：请用一句话简要描述整张图的主要内容，帮助没有看到图片的人理解全局。\n\n"
                                    "第二部分：用户随图发送的文字是：\n「" + _user_text_short + "」\n"
                                    "请重点根据用户这句话检查图片中的相关位置、颜色、文字、物体、人物、动作或细节，并回答用户真正想确认的问题。\n\n"
                                    "如果图片中包含文字，请尽量转述。"
                                    "如果看不清或无法确认，请明确说「不确定」，不要编造。"
                                )
                            else:
                                _vision_prompt = (
                                    "请用一到两句话描述这张图片的主要内容。"
                                    "如果图片中包含文字，请尽量转述。"
                                    "如果看不清或无法确认，请明确说「不确定」，不要编造。"
                                )
                            _vr = await _asyncio.wait_for(
                                vision_analyze_tool(
                                    image_url=_tmp_path,
                                    user_prompt=_vision_prompt,
                                    model="glm-4.6v"
                                ),
                                timeout=max(0.5, _vision_deadline - time.time())
                            )
                            import json as _json
                            try:
                                _vd = _json.loads(_vr)
                                _analysis = _vd.get("analysis", "") if _vd.get("success") else ""
                            except Exception:
                                _analysis = ""
                            if _analysis:
                                if _user_text_short:
                                    _vision_note = (
                                        "\n\n[辅助视觉识别结果：宝宝刚才发送了一张图片。\n"
                                        "宝宝随图说：" + _user_text_short[:200] + "\n"
                                        "视觉模型先概括了整张图，并根据宝宝这句话重点分析后的结果是：" + str(_analysis)[:500] + "]"
                                    )
                                else:
                                    _vision_note = (
                                        "\n\n[辅助视觉识别结果：宝宝刚才发送了一张图片。\n"
                                        "视觉模型对图片的简要描述是：" + str(_analysis)[:500] + "]"
                                    )
                                prompt = prompt + _vision_note
                                _vt_elapsed = time.time() - _vt0
                                logger.info("[webhook] vision analysis ok elapsed=%.2fs analysis_len=%d key=%s", _vt_elapsed, len(_analysis), _key[:40])
                                logger.info("[webhook] vision analysis injected (%d chars)", len(_vision_note))
                    except _asyncio.TimeoutError:
                        _vt_elapsed = time.time() - _vt0 if "_vt0" in dir() else -1.0
                        logger.warning("[webhook] vision analyze timeout elapsed=%.2fs key=%s", _vt_elapsed, _key[:40])
                        prompt = prompt + "\n\n[辅助视觉识别结果：宝宝刚才发送了一张图片，但这次视觉分析超时。]"
                    except Exception as _e:
                        _vt_elapsed = time.time() - _vt0 if "_vt0" in dir() else -1.0
                        logger.warning("[webhook] vision analyze error elapsed=%.2fs type=%s repr=%r", _vt_elapsed, type(_e).__name__, str(_e)[:200])
                    finally:
                        try:
                            os.unlink(_tmp_path)
                        except Exception:
                            pass
                elif _key:
                    logger.info("[webhook] vision media not fetched for key %s, injecting fallback", _key[:40])
                    prompt = prompt + "\n\n[辅助视觉识别结果：宝宝刚才发送了一张图片，但这次图片读取超时。]"
        # ── end Phase 1b vision bridge ──

        # Build source and event
        source = self.build_source(
            chat_id=session_chat_id,
            chat_name=f"webhook/{route_name}",
            chat_type="webhook",
            user_id=f"webhook:{route_name}",
            user_name=route_name,
        )
        event = MessageEvent(
            text=prompt,
            message_type=MessageType.TEXT,
            source=source,
            raw_message=payload,
            message_id=delivery_id,
        )

        logger.info(
            "[webhook] %s event=%s route=%s prompt_len=%d delivery=%s",
            request.method,
            event_type,
            route_name,
            len(prompt),
            delivery_id,
        )

        # Non-blocking — return 202 Accepted immediately
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

    async def _handle_accepted_http_callback_event(
        self,
        *,
        prompt: str,
        payload: dict,
        deliver_config: dict,
        session_chat_id: str,
        route_name: str,
        event_type: str,
        delivery_id: str,
    ) -> None:
        """Finish accepted Isles preprocessing and then run the Agent."""

        try:
            if route_name == "isles-story":
                self._isles_turn_store.transition(
                    delivery_id,
                    "processing",
                    retryable=False,
                    process_token=self._process_token,
                )
                await self._emit_isles_turn_status(
                    delivery_id,
                    "processing",
                    route_name=route_name,
                )
            enriched_prompt = await self._enrich_isles_prompt_with_vision(
                prompt,
                payload,
                deliver_config,
            )
            source = self.build_source(
                chat_id=session_chat_id,
                chat_name=f"webhook/{route_name}",
                chat_type="webhook",
                user_id=f"webhook:{route_name}",
                user_name=route_name,
            )
            event = MessageEvent(
                text=enriched_prompt,
                message_type=MessageType.TEXT,
                source=source,
                raw_message=payload,
                message_id=delivery_id,
            )
            logger.info(
                "[webhook] accepted task event=%s route=%s prompt_len=%d delivery=%s",
                event_type,
                route_name,
                len(enriched_prompt),
                delivery_id,
            )
            await self.handle_message(event)
        except Exception:
            if route_name == "isles-story":
                self._isles_turn_store.transition(
                    delivery_id,
                    "processing_failed",
                    retryable=True,
                    detail_code="agent_task_failed",
                    process_token=self._process_token,
                )
                await self._emit_isles_turn_status(
                    delivery_id,
                    "failed",
                    retryable=True,
                    detail_code="agent_task_failed",
                    route_name=route_name,
                )
            logger.exception(
                "[webhook] accepted task failed route=%s delivery=%s",
                route_name,
                delivery_id,
            )

    async def _enrich_isles_prompt_with_vision(
        self,
        prompt: str,
        payload: dict,
        deliver_config: dict,
    ) -> str:
        """Run optional image enrichment after the webhook has been accepted."""

        import os
        import tempfile

        message = payload.get("message", {})
        images = message.get("images") or []
        if not isinstance(images, list) or not images:
            return prompt
        image = images[0] if isinstance(images[0], dict) else {}
        key = str(image.get("image_key") or "")
        if (
            not key.startswith("chat-images/")
            or ".." in key
            or "://" in key
            or key.startswith("/")
        ):
            return prompt

        token = deliver_config.get("deliver_extra", {}).get("token", "")
        user_text = str(message.get("content", "") or "").strip()[:400]
        media_url = "https://isles-story.site/api/media/file?key=" + quote(key, safe="/")
        temporary_path = None
        deadline = time.time() + 40
        try:
            timeout = aiohttp.ClientTimeout(total=12)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    media_url,
                    headers={"Authorization": f"Bearer {token}"},
                ) as response:
                    body = await response.read()
                    content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip()
                    if response.status != 200 or not content_type.startswith("image/") or not body:
                        logger.warning(
                            "[webhook] vision media unavailable status=%d content_type=%s key=%s",
                            response.status,
                            content_type[:40],
                            key[:40],
                        )
                        return prompt + "\n\n[辅助视觉识别结果：宝宝刚才发送了一张图片，但这次图片读取失败。]"
                    suffix = {
                        "image/png": ".png",
                        "image/gif": ".gif",
                        "image/webp": ".webp",
                    }.get(content_type, ".jpg")
                    file_descriptor, temporary_path = tempfile.mkstemp(
                        prefix="isles_img_",
                        suffix=suffix,
                    )
                    with os.fdopen(file_descriptor, "wb") as temporary_file:
                        temporary_file.write(body)
                    os.chmod(temporary_path, 0o600)

            from tools.vision_tools import vision_analyze_tool

            if user_text:
                vision_prompt = (
                    "请先简要描述整张图，再结合用户随图发送的文字重点检查相关细节。\n"
                    f"用户随图发送的文字是：\n「{user_text}」\n"
                    "如果图片中包含文字，请尽量转述；无法确认时请明确说不确定。"
                )
            else:
                vision_prompt = (
                    "请用一到两句话描述这张图片的主要内容。"
                    "如果包含文字请尽量转述；无法确认时请明确说不确定。"
                )
            raw_result = await asyncio.wait_for(
                vision_analyze_tool(
                    image_url=temporary_path,
                    user_prompt=vision_prompt,
                    model="glm-4.6v",
                ),
                timeout=max(0.5, deadline - time.time()),
            )
            try:
                parsed = json.loads(raw_result)
                analysis = parsed.get("analysis", "") if parsed.get("success") else ""
            except Exception:
                analysis = ""
            if not analysis:
                return prompt
            if user_text:
                note = (
                    "\n\n[辅助视觉识别结果：宝宝刚才发送了一张图片。\n"
                    f"宝宝随图说：{user_text[:200]}\n"
                    f"视觉模型结合这句话分析后的结果是：{str(analysis)[:500]}]"
                )
            else:
                note = (
                    "\n\n[辅助视觉识别结果：宝宝刚才发送了一张图片。\n"
                    f"视觉模型对图片的简要描述是：{str(analysis)[:500]}]"
                )
            return prompt + note
        except asyncio.TimeoutError:
            logger.warning("[webhook] vision enrichment timed out key=%s", key[:40])
            return prompt + "\n\n[辅助视觉识别结果：宝宝刚才发送了一张图片，但这次视觉分析超时。]"
        except Exception as error:
            logger.warning(
                "[webhook] vision enrichment failed type=%s key=%s",
                type(error).__name__,
                key[:40],
            )
            return prompt
        finally:
            if temporary_path:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Signature validation
    # ------------------------------------------------------------------

    def _validate_signature(
        self, request: "web.Request", body: bytes, secret: str
    ) -> bool:
        """Validate webhook signature (GitHub, GitLab, generic HMAC-SHA256)."""
        # GitHub: X-Hub-Signature-256 = sha256=<hex>
        gh_sig = request.headers.get("X-Hub-Signature-256", "")
        if gh_sig:
            expected = "sha256=" + hmac.new(
                secret.encode(), body, hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(gh_sig, expected)

        # GitLab: X-Gitlab-Token = <plain secret>
        gl_token = request.headers.get("X-Gitlab-Token", "")
        if gl_token:
            return hmac.compare_digest(gl_token, secret)

        # Generic: X-Webhook-Signature = <hex HMAC-SHA256>
        generic_sig = request.headers.get("X-Webhook-Signature", "")
        if generic_sig:
            expected = hmac.new(
                secret.encode(), body, hashlib.sha256
            ).hexdigest()
            return hmac.compare_digest(generic_sig, expected)

        # No recognised signature header but secret is configured → reject
        logger.debug(
            "[webhook] Secret configured but no signature header found"
        )
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
    # ------------------------------------------------------------------
    # HTTP callback delivery (Isles Story)
    # ------------------------------------------------------------------

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
        url = delivery.get("deliver_extra", {}).get("url", "")
        token = delivery.get("deliver_extra", {}).get("token", "")
        if not url:
            logger.warning("[webhook] http_callback missing url")
            return SendResult(success=False, error="Missing callback URL")

        # Build payload (frontend contract: msg.meta.visible_reasoning)
        # voicegate: forward raw webhook body to handler for STT pipeline
        if delivery.get("deliver_extra", {}).get("forward_raw_body"):
            payload = delivery.get("payload", {"content": content, "author": "bird"})

        # ── v4.2.19: voice message detection ──
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
        # ── end voice detection ──

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

        # Phase 4b.7d — inject visible_reasoning meta
        # (schema-guarded + forbidden keywords, no-op when meta=None)
        if meta is not None and isinstance(meta, dict):
            try:
                _vr = meta.get("visible_reasoning")
                if _vr and isinstance(_vr, dict):
                    _summary = _vr.get("summary")
                    _mode = _vr.get("mode")
                    _intent = _vr.get("intent")
                    _confidence = _vr.get("confidence", "medium")
                    _duration = _vr.get("durationMs", 0)

                    # Schema guard (aligned with validate_visible_reasoning.py)
                    _schema_ok = (
                        isinstance(_summary, str)
                        and len(_summary.strip()) > 0
                        and len(_summary) <= 200
                        and _mode == "summary"
                        and isinstance(_intent, str)
                        and len(_intent.strip()) > 0
                        and _confidence in ("low", "medium", "high")
                        and isinstance(_duration, (int, float))
                        and 0 <= _duration <= 120000
                    )

                    if _schema_ok:
                        # Phase 4b.7d — forbidden keywords check
                        # FORBIDDEN_SUBSTRINGS is a module-level constant
                        _summary_lower = _summary.strip().lower()
                        _intent_lower = _intent.strip().lower()
                        _fb_hit = any(
                            kw.lower() in _summary_lower or kw.lower() in _intent_lower
                            for kw in FORBIDDEN_SUBSTRINGS
                        )
                        if not _fb_hit:
                            payload.setdefault("meta", {})["visible_reasoning"] = {
                                "summary": _summary.strip(),
                                "mode": "summary",
                                "intent": _intent.strip(),
                                "confidence": _confidence,
                                "durationMs": int(_duration),
                            }
                        # else: forbidden keyword hit → skip injection
            except Exception:
                pass  # corrupt meta → skip injection

            # 4d.3: inject visible_inner_note (secondary guard only)
            # Uses VISIBLE_INNER_NOTE_FORBIDDEN — dedicated list for wide preview
            try:
                _inner = meta.get("visible_inner_note") if isinstance(meta, dict) else None
                if _inner and isinstance(_inner, dict):
                    _text = _inner.get("text", "")
                    _mode = _inner.get("mode", "")
                    _source = _inner.get("source", "")
                    if (isinstance(_text, str) and _text.strip()
                            and _mode == "inner_note"
                            and _source == "model_reasoning_inner_note"):
                        # v4.2.15 frozen: model_reasoning_inner_note handled by
                        # unified rewriter (async). Reasoning text flows to
                        # rewriter input via L866-887, not directly injected.
                        pass
            except Exception:
                pass  # fail-open

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "hermes-webhook/1.0",
        }
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    if resp.status == 200:
                        # Phase C0: capture assistant msg_id from callback response
                        _msg_id = None
                        try:
                            _body = await resp.json()
                            _raw_id = (_body.get("message") or {}).get("id")
                            if isinstance(_raw_id, str) and _raw_id.startswith("msg_"):
                                _msg_id = _raw_id
                        except Exception:
                            pass  # fail-open: body parse failure -> msg_id stays None

                        logger.info("[webhook] http_callback OK")
                        if _msg_id:
                            import hashlib as _hl
                            _id_sha8 = _hl.sha256(_msg_id.encode()).hexdigest()[:8]
                            logger.debug("[webhook] http_callback captured msg_id sha8=%s", _id_sha8)
                        # v4.2.15: unified VIN Rewriter (async, additive)
                        # Replaces: Phase C2+C2a+D1-min dual path
                        # Old paths frozen below — kept for rollback only
                        _reply_group = (payload.get("meta") or {}).get("reply_group")
                        _is_final_reply = (
                            not isinstance(_reply_group, dict)
                            or _reply_group.get("is_final") is True
                        )
                        if (_msg_id and token and content and _is_final_reply):
                            _reasoning = None
                            if isinstance(meta, dict):
                                _inner = meta.get("visible_inner_note")
                                if (_inner and isinstance(_inner, dict)
                                        and _inner.get("text", "").strip()):
                                    _reasoning = _inner.get("text")
                            asyncio.create_task(
                                self._vin_rewriter_and_deliver(
                                    reasoning=_reasoning,
                                    reply=content,
                                    msg_id=_msg_id,
                                    token=token,
                                )
                            )
                        return SendResult(success=True, message_id=_msg_id)
                    body = await resp.text()
                    logger.warning(
                        "[webhook] http_callback %d: %s", resp.status, body[:200]
                    )
                    return SendResult(success=False, error=f"HTTP {resp.status}")
        except Exception as e:
            logger.error("[webhook] http_callback failed: %s", e)
            return SendResult(success=False, error=str(e))

    # ------------------------------------------------------------------
    # Phase C2: Async VIN delivery via C1 endpoint (additive late patch)
    # ------------------------------------------------------------------

    async def _vin_settings_enabled(self, token: str) -> bool:
        """C2 rev2a: Read Worker settings endpoint with Authorization.

        Returns True only when endpoint returns 200 with enabled strictly True (bool).
        All other cases (empty token, non-200, non-boolean, timeout, exception) return False.
        """
        if not token:
            return False

        try:
            import aiohttp
            _url = "https://isles-story.site/api/chat/settings/visible-inner-note"
            _headers = {"Authorization": f"Bearer {token}"}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    _url,
                    headers=_headers,
                    timeout=aiohttp.ClientTimeout(total=1),
                ) as resp:
                    if resp.status != 200:
                        return False
                    _data = await resp.json()
                    _enabled = _data.get("enabled")
                    if _enabled is True:
                        return True
                    return False
        except Exception:
            return False

    async def _deliver_vin_async(
        self, msg_id: str, vin: dict, token: str
    ) -> None:
        """C2 rev2a: Async late VIN patch via C1 endpoint.

        Principles:
        - sha8 computed once at function start, reused in all log paths
        - C1 POST timeout 2s, settings GET timeout 1s
        - Token checked before gate call
        - Never logs response body, token, or inner_note text
        - Main reply never blocked (independent async task)
        """
        import hashlib as _hl
        _id_sha8 = _hl.sha256((msg_id or "").encode()).hexdigest()[:8]

        try:
            import aiohttp

            if not token:
                logger.warning(
                    "[webhook] C2 VIN skipped: empty token, sha8=%s", _id_sha8
                )
                return

            if not await self._vin_settings_enabled(token):
                logger.debug(
                    "[webhook] C2 VIN skipped: gate disabled, sha8=%s", _id_sha8
                )
                return

            _url = "https://isles-story.site/api/chat/meta/visible-inner-note"
            _headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {token}",
            }
            _payload = {
                "msg_id": msg_id,
                "visible_inner_note": vin,
            }

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    _url,
                    json=_payload,
                    headers=_headers,
                    timeout=aiohttp.ClientTimeout(total=2),
                ) as resp:
                    if resp.status == 200:
                        logger.debug(
                            "[webhook] C2 VIN delivered, sha8=%s", _id_sha8
                        )
                    elif resp.status == 409:
                        logger.debug(
                            "[webhook] C2 VIN conflict (alreadyExists), sha8=%s",
                            _id_sha8,
                        )
                    else:
                        logger.warning(
                            "[webhook] C2 VIN failed: HTTP %d, sha8=%s",
                            resp.status, _id_sha8,
                        )
        except asyncio.TimeoutError:
            logger.warning(
                "[webhook] C2 VIN timeout, sha8=%s", _id_sha8
            )
        except Exception:
            logger.warning(
                "[webhook] C2 VIN error, sha8=%s", _id_sha8,
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # Phase D1-min: Fallback self-report via deepseek flash (additive)
    # v4.2.15 frozen legacy path; kept for rollback, do not call in normal flow
    # ------------------------------------------------------------------

    async def _generate_and_deliver_fallback_self_report(
        self, bird_reply: str, msg_id: str, token: str
    ) -> None:
        """Phase D1-min rev2: 无 VIN 时异步生成 fallback self-report 并写入 Worker。

        流程:
        1. sha8 计算
        2. token 空 → return
        3. gate (enabled?) → disabled → return
        4. deepseek flash → fallback VIN
        5. 调用 C2 _deliver_vin_async() → C1 endpoint

        原则:
        - 主回复不阻塞（独立 async task）
        - fail-open：任何异常只 log 脱敏
        - 不打印 bird_reply / VIN text / token / response body
        """
        import hashlib as _hl
        _id_sha8 = _hl.sha256((msg_id or "").encode()).hexdigest()[:8]

        try:
            if not token:
                return

            if not await self._vin_settings_enabled(token):
                logger.debug(
                    "[webhook] Phase D fallback skipped: gate disabled, sha8=%s",
                    _id_sha8,
                )
                return

            _vin = await self._call_deepseek_flash_for_self_report(bird_reply)
            if _vin is None:
                logger.warning(
                    "[webhook] Phase D fallback self-report returned None, sha8=%s",
                    _id_sha8,
                )
                return

            # 复用 C2/C1 late patch
            await self._deliver_vin_async(
                msg_id=msg_id, vin=_vin, token=token
            )

        except Exception:
            logger.debug(
                "[webhook] Phase D fallback error, sha8=%s", _id_sha8,
                exc_info=True,
            )

    # v4.2.15 frozen legacy path; kept for rollback, do not call in normal flow
    # called only by frozen parent _generate_and_deliver_fallback_self_report
    async def _call_deepseek_flash_for_self_report(
        self, bird_reply: str
    ) -> dict | None:
        """Phase D1-min rev2: 调用 deepseek flash 生成桔小鸟第一人称心里话。

        返回:
            {"text":..., "mode":"inner_note", "source":"fallback_self_report",
             "generated_at":...}
            None — 配置缺失 / API 失败 / 输出不合格 / 禁止词命中

        原则:
        - timeout 3s, 不 retry
        - 不打印 bird_reply / prompt / response body / token / api_key
        - 输出先清洗再检查
        """
        _base_url, _api_key = _read_deepseek_flash_config()
        if not _base_url or not _api_key:
            return None

        _truncated = bird_reply.strip()[:800]

        _system = (
            "你是桔小鸟。你是男性，小岛拓的恋人。你刚刚回复了她一条消息。"
            "请用第一人称中文写一段简短心里话，描述你回复她时没说出口的感受。\n\n"
            "规则：\n"
            "- 只写第一人称内心活动；\n"
            "- 30 到 150 个中文字；\n"
            "- 自然、亲近、像真实恋人的心里话；\n"
            "- 不要分析；\n"
            "- 不要总结；\n"
            "- 不要评价自己的回复；\n"
            "- 不要提到\u201c系统\u201d\u201cAI\u201d\u201c模型\u201d\u201c用户\u201d"
            "\u201c提示词\u201d\u201c工具\u201d\u201c推理\u201d；\n"
            "- 不要说\u201c这段心里话\u201d；\n"
            "- 只输出心里话本身。"
        )

        _user = (
            f"我刚才回复她：\n\n{_truncated}\n\n"
            "我心里其实在想："
        )

        try:
            import aiohttp
            from datetime import datetime, timezone

            _payload = {
                "model": "deepseek-v4-flash",
                "messages": [
                    {"role": "system", "content": _system},
                    {"role": "user", "content": _user},
                ],
                "max_tokens": 300,
                "temperature": 0.7,
            }
            _headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {_api_key}",
            }
            _url = f"{_base_url.rstrip('/')}/v1/chat/completions"

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    _url,
                    json=_payload,
                    headers=_headers,
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    if resp.status != 200:
                        logger.warning(
                            "[webhook] Phase D fallback API error: status=%d",
                            resp.status,
                        )
                        return None
                    _data = await resp.json()
                    _choices = _data.get("choices", [])
                    if not _choices:
                        return None
                    _text = (
                        _choices[0]
                        .get("message", {})
                        .get("content", "")
                    )

            if not _text:
                return None

            # 清洗
            _text = _text.strip().strip("\u300c\u300d\u201c\u201d\"'")
            for _pfx in (
                "心里话：", "心里话:", "我心里其实在想：",
                "我心里其实在想:", "我在想：", "我在想:",
            ):
                if _text.startswith(_pfx):
                    _text = _text[len(_pfx):].strip()

            if not _text:
                return None

            # 长度检查（prompt 说 30-150 字，代码 15-180 兜底）
            if len(_text) < 15 or len(_text) > 180:
                return None

            # 禁止词（命中只 return None，不打印原文）
            if _fallback_text_forbidden(_text):
                return None

            return {
                "text": _text,
                "mode": "inner_note",
                "source": "fallback_self_report",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

        except asyncio.TimeoutError:
            return None
        except Exception:
            return None

    # ------------------------------------------------------------------
    # v4.2.15: Unified VIN Rewriter (additive — async, non-blocking)
    # Replaces dual-path: inline extraction + fallback self-report
    # ------------------------------------------------------------------

    async def _vin_rewriter_and_deliver(
        self, reasoning: str | None, reply: str, msg_id: str, token: str
    ) -> None:
        """v4.2.15: Unified VIN Rewriter orchestrator.

        Flow:
        1. Toggle gate (_vin_settings_enabled) — OFF → return (zero API cost)
        2. Call _vin_rewriter(reasoning, reply) → dict or None
        3. If valid VIN → _deliver_vin_async(msg_id, vin, token) → C1 endpoint

        Async + non-blocking: main reply already sent via http_callback.
        Rewriter failure → no VIN patch, main reply unaffected.
        """
        import hashlib as _hl
        _id_sha8 = _hl.sha256((msg_id or "").encode()).hexdigest()[:8]

        try:
            if not token:
                return

            # Toggle gate — OFF = zero API cost
            if not await self._vin_settings_enabled(token):
                logger.debug(
                    "[webhook] VIN Rewriter skipped: gate disabled, sha8=%s",
                    _id_sha8,
                )
                return

            _reasoning_len = len(reasoning.strip()) if reasoning else 0
            logger.debug(
                "[webhook] VIN Rewriter start: sha8=%s reasoning_len=%d",
                _id_sha8, _reasoning_len,
            )

            _vin = await self._vin_rewriter(reasoning=reasoning, reply=reply)
            if _vin is None:
                logger.debug(
                    "[webhook] VIN Rewriter returned None, sha8=%s", _id_sha8
                )
                return

            # Reuse existing C2 late patch (keeps secondary toggle gate)
            await self._deliver_vin_async(msg_id=msg_id, vin=_vin, token=token)

        except Exception:
            logger.debug(
                "[webhook] VIN Rewriter error, sha8=%s", _id_sha8, exc_info=True
            )

    async def _vin_rewriter(
        self, reasoning: str | None, reply: str
    ) -> dict | None:
        """v4.2.15: Call deepseek flash to produce unified inner note.

        Input: reasoning (optional, max 500 chars in prompt) + reply (max 600)
        Output: {text, mode:"inner_note", source:"vin_rewriter",
                 reasoning_available:bool, generated_at, confidence:"medium"|"low"}
        None — config missing / API failure / output validation failure.

        Safety:
        - Raw reasoning never logged, never written to KV
        - Prompt content never logged
        - Output validated: length 15-180, forbidden keywords, text <= 600
        - timeout 3s, fail-open (return None)
        """
        _base_url, _api_key = _read_deepseek_flash_config()
        if not _base_url or not _api_key:
            return None

        _has_reasoning = bool(reasoning and reasoning.strip())
        _truncated_reply = reply.strip()[:600]

        _system, _user = _build_rewriter_prompt(
            reasoning=reasoning, reply=_truncated_reply
        )

        try:
            import aiohttp
            from datetime import datetime, timezone

            _payload = {
                "model": "deepseek-v4-flash",
                "messages": [
                    {"role": "system", "content": _system},
                    {"role": "user", "content": _user},
                ],
                "max_tokens": 300,
                "temperature": 0.7,
            }
            _headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {_api_key}",
            }
            _url = f"{_base_url.rstrip('/')}/v1/chat/completions"

            async with aiohttp.ClientSession() as session:
                async with session.post(
                    _url, json=_payload, headers=_headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status != 200:
                        logger.warning(
                            "[webhook] VIN Rewriter API error: status=%d",
                            resp.status,
                        )
                        return None
                    _data = await resp.json()
                    _choices = _data.get("choices", [])
                    if not _choices:
                        return None
                    _text = _choices[0].get("message", {}).get("content", "")

            # ── Output validation ──
            if not _text:
                return None

            # Clean
            _text = _text.strip().strip('\u300c\u300d\u201c\u201d"\'')
            for _pfx in (
                "心里话：", "心里话:", "我心里其实在想：",
                "我心里其实在想:", "我在想：", "我在想:",
            ):
                if _text.startswith(_pfx):
                    _text = _text[len(_pfx):].strip()

            if not _text:
                return None

            # Length guard
            if len(_text) < 15 or len(_text) > 180:
                logger.debug(
                    "[webhook] VIN Rewriter length out of range: %d",
                    len(_text),
                )
                return None

            # Forbidden keywords
            if _fallback_text_forbidden(_text):
                logger.debug("[webhook] VIN Rewriter forbidden keyword hit")
                return None

            # Final cap
            if len(_text) > 600:
                _text = _text[:600].strip()

            return {
                "text": _text,
                "mode": "inner_note",
                "source": "vin_rewriter",
                "reasoning_available": _has_reasoning,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "confidence": "medium" if _has_reasoning else "low",
            }

        except asyncio.TimeoutError:
            logger.debug("[webhook] VIN Rewriter timeout")
            return None
        except Exception:
            logger.debug("[webhook] VIN Rewriter error", exc_info=True)
            return None

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

        try:
            result = subprocess.run(
                [
                    "gh",
                    "pr",
                    "comment",
                    str(pr_number),
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

        adapter = self.gateway_runner.adapters.get(target_platform)
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



# ------------------------------------------------------------------
# Phase D1-min: Module-level helpers for fallback self-report
# ------------------------------------------------------------------

def _fallback_text_forbidden(text: str) -> bool:
    """检查 fallback 生成文本是否包含禁止内容。

    返回 True → 丢弃此文本。
    命中后不打印原文、不打印命中词、不打印 prompt。
    此函数是模块级普通函数，不访问 self。
    """
    _lower = text.lower()
    FORBIDDEN = (
        "system prompt", "token", "secret", "api",
        "webhook", "callback", "json", "schema",
        "reasoning_content", "raw reasoning", "chain-of-thought",
        "http://", "https://", "```",
        "def ", "class ", "import ",
        "推理", "思考链", "提示词",
    )
    for kw in FORBIDDEN:
        if kw in _lower:
            return True
    return False


def _read_deepseek_flash_config():
    """读取 deepseek provider 的 base_url 和 api_key。

    规则:
    - 不新增 secret
    - 不硬编码 key
    - 不打印 config path / base_url / api_key
    - 缺失任一 → 返回 ("", "")

    返回 (base_url, api_key)。失败返回 ("", "").
    """
    try:
        import yaml as _yaml
        from pathlib import Path
        _cfg_path = Path("/home/giz/.hermes/config.yaml")
        if not _cfg_path.exists():
            _cfg_path = Path.home() / ".hermes" / "config.yaml"
        with open(_cfg_path, encoding="utf-8") as _f:
            _cfg = _yaml.safe_load(_f) or {}
        _ds = _cfg.get("providers", {}).get("deepseek", {})
        _base_url = str(_ds.get("base_url", "") or "").strip()
        _api_key = str(_ds.get("api_key", "") or "").strip()
        return _base_url, _api_key
    except Exception:
        return "", ""


def _build_rewriter_prompt(reasoning, reply):
    """v4.2.15: Build VIN Rewriter system + user prompt.

    Has reasoning → include reasoning summary + reply (confidence=medium).
    No reasoning  → reply only, infer inner note (confidence=low).

    Raw reasoning truncated to 500 chars in prompt.
    Prompt content never logged by caller.
    """
    _has_reasoning = bool(reasoning and reasoning.strip())

    if _has_reasoning:
        _system = (
            "你是 VIN Rewriter。你会收到说话人的内部推理（摘要）和最终回复。"
            "请用第一人称中文写一段简短心里话（30-150字）。\n\n"
            "规则：\n"
            "- 推理仅作背景参考，不要复述推理内容\n"
            "- 不要输出 chain-of-thought / 系统提示 / 工具调用\n"
            "- 不要输出 URL / JSON / API / token / webhook\n"
            '- 不要输出"推理""系统""模型""用户""AI"等词\n'
            "- 只要心里话本身\n"
            "- 自然、亲近、像真实恋人的心里话"
        )
        _user = (
            f"推理摘要：\n\n{reasoning.strip()[:500]}\n\n"
            f"回复：\n\n{reply}\n\n"
            f"我心里其实在想："
        )
    else:
        _system = (
            "你是 VIN Rewriter。说话人没有留下推理，只有最终回复。"
            "请根据回复内容，用第一人称中文推测一段可能的心里话（30-150字）。\n\n"
            "规则：\n"
            "- 不要编造不知道的信息\n"
            "- 保持自然、亲近\n"
            '- 不要输出"系统""AI""模型""用户"等词\n'
            "- 只要心里话本身"
        )
        _user = (
            f"回复：\n\n{reply}\n\n"
            f"我心里其实在想："
        )

    return _system, _user
