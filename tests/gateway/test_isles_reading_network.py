"""Real loopback HTTP through the reading adapter; no model or production access."""
import asyncio
import hashlib
import hmac
import json
import time

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.isles_turn_store import IslesTurnStore
from tests.gateway.test_webhook_adapter import _make_adapter, _create_app
from tests.gateway.test_isles_reading_contract import turn


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_first_reply", [False, True])
async def test_signed_reading_http_keeps_three_turns_and_two_discussions(tmp_path, fail_first_reply):
    secret = "isolated-reading-network-fixture"
    received, events = [], []

    async def callback(request):
        raw = await request.read()
        timestamp = request.headers.get("X-Webhook-Timestamp", "")
        expected = hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(request.headers.get("X-Webhook-Signature-V2", ""), expected)
        assert abs(time.time() - int(timestamp)) < 300
        received.append((request.path, json.loads(raw)))
        if fail_first_reply and request.path.endswith('/reply') and sum(path.endswith('/reply') for path, _ in received) == 1:
            return web.json_response({"error": "temporary fixture failure"}, status=503)
        return web.json_response({"ok": True})

    receiver = web.Application()
    receiver.router.add_post("/api/reading/gateway/{kind}", callback)
    async with TestServer(receiver, host="127.0.0.1") as sink:
        adapter = _make_adapter(host="127.0.0.1", routes={"isles-reading": {
            "secret": secret, "deliver": "http_callback",
            "deliver_extra": {"url": str(sink.make_url("/api/reading/gateway/reply"))},
            "reply_delivery": {"segmented": True, "hard_split_marker": "<BREAK>"},
        }})
        adapter._isles_turn_store = IslesTurnStore(tmp_path / "turns")

        async def capture(event):
            events.append(event)
        adapter.handle_message = capture
        async with TestClient(TestServer(_create_app(adapter), host="127.0.0.1")) as client:
            async def post(value, signed=True):
                raw = json.dumps(value, ensure_ascii=False).encode()
                timestamp = str(int(time.time()))
                headers = {"Content-Type": "application/json", "X-Request-ID": value["delivery_id"]}
                if signed:
                    headers.update({"X-Webhook-Timestamp": timestamp, "X-Webhook-Signature-V2": hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()})
                return await client.post("/webhooks/isles-reading", data=raw, headers=headers)

            values = [turn(thread_id=thread, turn_id=f"turn_{n}", delivery_id=f"delivery_{n}", source=None, source_link=None,
                           user_message={"message_id": f"message_{n}", "text": f"我的第{n}句话"})
                      for n, thread in [(1, "thread_a"), (2, "thread_a"), (3, "thread_b")]]
            assert (await post(values[0], signed=False)).status == 401
            for value in values:
                assert (await post(value)).status == 202
            for _ in range(100):
                if len(events) == 3:
                    break
                await asyncio.sleep(0.01)
            assert len(events) == 3
            assert [event.source.chat_id for event in events] == ["webhook:isles-reading:thread_a", "webhook:isles-reading:thread_a", "webhook:isles-reading:thread_b"]
            assert all("岛主" not in event.text and "我说：" in event.text for event in events)
            # Responses deliberately arrive out of order, after session snapshots changed.
            for index in [2, 0, 1]:
                event = events[index]
                adapter.mark_pending_reply_turn(event.message_id, None)
                result = await adapter.send(event.source.chat_id, f"**回复 {index + 1}**<BREAK>> 第二段", reply_to=event.message_id)
                if fail_first_reply and index == 2:
                    assert not result.success
                    record = adapter._isles_turn_store.get(event.message_id)
                    assert record["state"] == "delivery_failed"
                    # Reconstruct an adapter from disk with no in-memory turn snapshot.
                    recovered = _make_adapter(host="127.0.0.1", routes=adapter._routes)
                    recovered._isles_turn_store = IslesTurnStore(tmp_path / "turns")
                    assert not recovered._delivery_info
                    recovered._isles_turn_store.receive("main_fixture", payload_sha256="a" * 64,
                        route="isles-story", process_token="old-process")
                    main_before = recovered._isles_turn_store.get("main_fixture")
                    assert await recovered.connect()
                    try:
                        task = recovered._isles_retry_tasks.get(event.message_id)
                        if task:
                            await asyncio.wait_for(asyncio.shield(task), timeout=5)
                    finally:
                        await recovered.disconnect()
                    assert recovered._isles_turn_store.get(event.message_id)["state"] == "completed"
                    assert recovered._isles_turn_store.get("main_fixture") == main_before
                    assert recovered._isles_turn_store.get("turn_1")["state"] == "interrupted"
                    assert recovered._isles_turn_store.get("turn_1")["retryable"] is True
                    continue
                assert result.success
                assert adapter._isles_turn_store.get(event.message_id)["state"] == "completed"

    replies = [payload for path, payload in received if path.endswith("/reply")]
    if fail_first_reply:
        assert replies[0] == replies[1]
        replies = replies[1:]
    assert len(replies) == 3
    for payload, n in zip(replies, [3, 1, 2]):
        assert payload["turn_id"] == f"turn_{n}"
        assert payload["delivery_id"] == f"delivery_{n}"
        assert payload["thread_id"] == ("thread_b" if n == 3 else "thread_a")
        assert [action["text"] for action in payload["actions"]] == [f"**回复 {n}**", "> 第二段"]
        assert payload["terminal"] == {"status": "completed", "retryable": False}
