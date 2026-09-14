"""Kill an actual Gateway-adapter process, then recover its durable reply."""
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
import time

import pytest
from aiohttp import ClientSession, web
from aiohttp.test_utils import TestServer

from tests.gateway.test_isles_reading_contract import turn


@pytest.mark.asyncio
async def test_killed_process_recovers_complete_signed_reply(tmp_path):
    secret = "isolated-process-fixture"
    replies = []
    first_reply, recovered_reply = asyncio.Event(), asyncio.Event()
    allow_delivery = False

    async def callback(request):
        raw = await request.read()
        timestamp = request.headers["X-Webhook-Timestamp"]
        expected = hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(request.headers["X-Webhook-Signature-V2"], expected)
        if request.path.endswith("/reply"):
            replies.append(json.loads(raw))
            if not allow_delivery:
                first_reply.set()
                return web.json_response({"error": "test outage"}, status=503)
            recovered_reply.set()
        return web.json_response({"ok": True})

    receiver = web.Application()
    receiver.router.add_post("/api/reading/gateway/{kind}", callback)
    processes = []
    env = {**os.environ, "HERMES_HOME": str(tmp_path / "home"), "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("PYTHONPATH", None)
    cwd = Path(__file__).resolve().parents[2]
    async with TestServer(receiver, host="127.0.0.1") as sink:
        async def start():
            process = await asyncio.create_subprocess_exec(sys.executable, "-m", "tests.gateway.reading_process_fixture",
                str(tmp_path), str(sink.make_url("/api/reading/gateway/reply")), cwd=cwd, env=env,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            processes.append(process)
            async def ready():
                while True:
                    line = await process.stdout.readline()
                    if not line:
                        raise AssertionError(f"fixture exited before ready: {process.returncode}")
                    if line.startswith(b"READY "):
                        return int(line.split()[1])
            return process, await asyncio.wait_for(ready(), 40)

        try:
            original, port = await start()
            value = turn(source=None, source_link=None)
            raw = json.dumps(value, ensure_ascii=False).encode()
            timestamp = str(int(time.time()))
            async with ClientSession() as client:
                async with client.post(f"http://127.0.0.1:{port}/webhooks/isles-reading", data=raw, headers={
                    "Content-Type": "application/json", "X-Request-ID": value["delivery_id"],
                    "X-Webhook-Timestamp": timestamp,
                    "X-Webhook-Signature-V2": hmac.new(secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest(),
                }) as response:
                    assert response.status == 202
            await asyncio.wait_for(first_reply.wait(), 10)
            original.kill()
            await asyncio.wait_for(original.wait(), 10)
            attempts_before_restart = len(replies)
            allow_delivery = True
            restarted, _ = await start()
            assert restarted.pid != original.pid
            await asyncio.wait_for(recovered_reply.wait(), 10)
            assert len(replies) > attempts_before_restart
            assert all(reply == replies[0] for reply in replies)
            assert replies[-1]["thread_id"] == "thread_one"
            assert replies[-1]["turn_id"] == "turn_one"
            assert replies[-1]["delivery_id"] == "delivery_one"
            assert [action["text"] for action in replies[-1]["actions"]] == ["**完整的第一段**", "> 第二段也要保留"]
        finally:
            for process in processes:
                if process.returncode is None:
                    process.kill()
                await asyncio.wait_for(process.wait(), 10)
