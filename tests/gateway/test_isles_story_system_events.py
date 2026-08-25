import hashlib
import hmac
import json
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from gateway.config import PlatformConfig
from gateway.platforms.base import SendResult
from gateway.platforms.webhook import WebhookAdapter


SECRET = "isles-test-secret-at-least-32-bytes"


def _adapter() -> WebhookAdapter:
    return WebhookAdapter(PlatformConfig(enabled=True, extra={
        "host": "127.0.0.1",
        "port": 0,
        "routes": {
            "isles-story": {
                "secret": SECRET,
                "deliver": "http_callback",
                "deliver_extra": {
                    "url": "https://isles-story.site/api/chat/callback",
                    "token": "callback-token",
                },
            },
        },
    }))


def _signed_request(payload: dict):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    timestamp = str(int(time.time()))
    signature = hmac.new(
        SECRET.encode(), timestamp.encode() + b"." + raw, hashlib.sha256
    ).hexdigest()
    request = MagicMock()
    request.headers = {
        "X-Webhook-Timestamp": timestamp,
        "X-Webhook-Signature-V2": signature,
    }
    request.content_length = len(raw)
    request.match_info = {"route_name": "isles-story"}

    async def read():
        return raw

    request.read = read
    return request


def _clear_approval_queues():
    from tools import approval

    approval._gateway_queues.clear()
    approval._gateway_notify_cbs.clear()


def test_exact_approval_id_does_not_release_fifo_neighbor():
    from tools.approval import _ApprovalEntry, _gateway_queues, resolve_gateway_approval

    _clear_approval_queues()
    first = _ApprovalEntry({"approval_id": "11" * 16})
    second = _ApprovalEntry({"approval_id": "22" * 16})
    _gateway_queues["webhook:isles-story:main"] = [first, second]

    resolved = resolve_gateway_approval(
        "webhook:isles-story:main", "once", approval_id="22" * 16
    )

    assert resolved == 1
    assert first.event.is_set() is False
    assert second.event.is_set() is True
    assert second.result == "once"
    assert _gateway_queues["webhook:isles-story:main"] == [first]
    _clear_approval_queues()


@pytest.mark.asyncio
async def test_unbound_isles_send_uses_system_event_not_final_callback():
    adapter = _adapter()
    adapter._deliver_isles_system_event = AsyncMock(return_value=SendResult(success=True))
    adapter._deliver_http_callback = AsyncMock(return_value=SendResult(success=True))
    metadata = {}

    result = await adapter.send(
        "webhook:isles-story:main", "memory updated", metadata=metadata
    )

    assert result.success is True
    adapter._deliver_isles_system_event.assert_awaited_once()
    adapter._deliver_http_callback.assert_not_awaited()
    payload = adapter._deliver_isles_system_event.await_args.args[0]
    assert payload["kind"] == "notice"
    assert payload["body"] == "memory updated"
    assert len(payload["event_id"]) == 32
    assert metadata["_isles_system_event_id"] == payload["event_id"]


@pytest.mark.asyncio
async def test_structured_approval_registers_exact_session_and_choices():
    adapter = _adapter()
    adapter._deliver_isles_system_event = AsyncMock(return_value=SendResult(success=True))
    approval_id = "33" * 16

    result = await adapter.send_exec_approval(
        chat_id="webhook:isles-story:main",
        command="rm -rf /tmp/approval-test",
        session_key="webhook:isles-story:main",
        description="delete test directory",
        metadata={
            "_isles_approval_id": approval_id,
            "_isles_approval_timeout_seconds": 300,
            "_isles_approval_expires_at": time.time() + 300,
        },
        allow_permanent=True,
    )

    assert result.success is True
    state = adapter._isles_approval_states[approval_id]
    assert state["session_key"] == "webhook:isles-story:main"
    assert state["choices"] == ("once", "always", "deny")
    payload = adapter._deliver_isles_system_event.await_args.args[0]
    assert payload["kind"] == "approval"
    assert payload["approval"]["approval_id"] == approval_id
    assert payload["approval"]["status"] == "pending"


@pytest.mark.asyncio
async def test_approval_action_requires_v2_and_is_idempotent_after_resolution():
    adapter = _adapter()
    approval_id = "44" * 16
    adapter._isles_approval_states[approval_id] = {
        "session_key": "webhook:isles-story:main",
        "expires_at": time.time() + 300,
        "choices": ("once", "always", "deny"),
        "status": "pending",
    }
    payload = {
        "protocol": "isles-approval-action-v1",
        "approval_id": approval_id,
        "choice": "always",
    }

    with patch("tools.approval.resolve_gateway_approval", return_value=1) as resolve:
        response = await adapter._handle_isles_approval_action(_signed_request(payload))
    assert response.status == 200
    body = json.loads(response.text)
    assert body["status"] == "approved_always"
    resolve.assert_called_once_with(
        "webhook:isles-story:main", "always", approval_id=approval_id
    )

    with patch("tools.approval.resolve_gateway_approval", return_value=0) as replay_resolve:
        replay = await adapter._handle_isles_approval_action(_signed_request(payload))
    assert replay.status == 200
    assert json.loads(replay.text)["duplicate"] is True
    replay_resolve.assert_not_called()

    unsigned = _signed_request(payload)
    unsigned.headers = {}
    rejected = await adapter._handle_isles_approval_action(unsigned)
    assert rejected.status == 401


@pytest.mark.asyncio
async def test_expired_approval_never_calls_resolver():
    adapter = _adapter()
    approval_id = "55" * 16
    adapter._isles_approval_states[approval_id] = {
        "session_key": "webhook:isles-story:main",
        "expires_at": time.time() - 1,
        "choices": ("once", "deny"),
        "status": "pending",
    }
    payload = {
        "protocol": "isles-approval-action-v1",
        "approval_id": approval_id,
        "choice": "once",
    }
    with patch("tools.approval.resolve_gateway_approval") as resolve:
        response = await adapter._handle_isles_approval_action(_signed_request(payload))
    assert response.status == 410
    assert json.loads(response.text)["status"] == "expired"
    resolve.assert_not_called()
