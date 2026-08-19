"""Isles-story (飞鸟群岛) platform adapter.

Delivers agent responses back to the isles-story custom frontend via HTTP
callback. The isles-story frontend is not a standard messaging platform; it
exchanges messages with the agent over HTTP. This adapter implements the
``BasePlatformAdapter.send()`` contract by POSTing the response to the
frontend's callback URL (carried through ``metadata``).

Ported from giz v0.10.0 ``webhook.py::_deliver_http_callback`` (v4.2.19
voice bridge + turn_segments contract) as part of the v0.19.0 shadow upgrade.
"""

import logging
from typing import Any, Dict, Optional

from gateway.config import Platform, PlatformConfig
from gateway.platforms.base import BasePlatformAdapter, SendResult

logger = logging.getLogger(__name__)

# Meta fields the isles-story frontend understands (payload.meta contract).
# Kept in sync with the original _deliver_http_callback whitelist.
_ISLES_META_KEYS = (
    "reply_group",
    "delivery_key",
    "reply_turn_id",
    "context_window",
    "voice",
    "transcript",
    "spoken_text",
)


class IslesStoryAdapter(BasePlatformAdapter):
    """Deliver agent responses to the isles-story (飞鸟群岛) frontend."""

    def __init__(self, config: PlatformConfig):
        super().__init__(config, Platform.WEBHOOK)
        # v4.2.19: voice message bridge state — written by run.py
        # _isles_voice_bridge_sync() before the callback, read+consumed by
        # send() during callback assembly. {voice, transcript, spoken_text}
        self._pending_voice_meta: Optional[dict] = None

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

    async def send(
        self,
        chat_id: str,
        content: str,
        reply_to: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SendResult:
        """POST the agent response to the isles-story callback URL.

        ``metadata`` carries the delivery contract::

            {
                "url":   "https://isles-story.site/api/chat/callback",
                "token": "hrm_...",
                "meta":  { ... voice / turn / spoken_text / vin ... },
            }
        """
        metadata = metadata or {}
        url = metadata.get("url", "")
        token = metadata.get("token", "")
        if not url:
            logger.warning("[isles-story] send missing callback url")
            return SendResult(success=False, error="Missing callback URL")

        meta = metadata.get("meta")

        # ── Build payload (frontend contract) ──
        # v4.2.19: voice message → type=voice payload with empty content.
        if meta and isinstance(meta, dict) and "voice" in meta:
            payload: Dict[str, Any] = {
                "content": "",
                "author": "bird",
                "type": "voice",
                "meta": meta,
            }
            logger.info(
                "[isles-story] voice callback audio_key=%s duration_ms=%s",
                meta.get("voice", {}).get("audio_key", "?"),
                meta.get("voice", {}).get("duration_ms", "?"),
            )
        else:
            payload = {"content": content, "author": "bird"}

        # ── Inject whitelisted meta fields into payload.meta ──
        if meta is not None and isinstance(meta, dict):
            _payload_meta = payload.get("meta")
            if not isinstance(_payload_meta, dict):
                _payload_meta = {}
            for _key in _ISLES_META_KEYS:
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
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        logger.info("[isles-story] callback OK")
                        return SendResult(success=True)
                    logger.warning(
                        "[isles-story] callback HTTP %s", resp.status
                    )
                    return SendResult(
                        success=False, error=f"HTTP {resp.status}"
                    )
        except Exception as exc:
            logger.error(
                "[isles-story] callback failed: %s", type(exc).__name__
            )
            return SendResult(
                success=False, error=str(exc), retryable=True
            )
