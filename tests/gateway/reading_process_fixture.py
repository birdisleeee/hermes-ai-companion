"""Loopback-only subprocess fixture; never starts a model or production config."""
import asyncio
import sys
from pathlib import Path
from urllib.parse import urlparse

from gateway.isles_turn_store import IslesTurnStore
from tests.gateway.test_webhook_adapter import _make_adapter


async def main():
    root, callback = sys.argv[1:]
    parsed = urlparse(callback)
    assert parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
    adapter = _make_adapter(host="127.0.0.1", port=0, routes={"isles-reading": {
        "secret": "isolated-process-fixture",
        "deliver": "http_callback", "deliver_extra": {"url": callback},
        "reply_delivery": {"segmented": True, "hard_split_marker": "<BREAK>"},
    }})
    adapter._isles_turn_store = IslesTurnStore(Path(root) / "turns")

    async def respond(event):
        adapter.mark_pending_reply_turn(event.message_id, None)
        await adapter.send(event.source.chat_id, "**完整的第一段**<BREAK>> 第二段也要保留", reply_to=event.message_id)

    adapter.handle_message = respond
    assert await adapter.connect()
    port = next(iter(adapter._runner.sites))._server.sockets[0].getsockname()[1]
    print(f"READY {port}", flush=True)
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
