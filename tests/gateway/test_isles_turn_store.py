"""Restart-safety tests for the Isles durable turn journal."""

from gateway.isles_turn_store import IslesTurnStore


def test_receipt_survives_new_store_instance(tmp_path):
    root = tmp_path / "turns"
    store = IslesTurnStore(root)
    record, created = store.receive(
        "msg_turn_1",
        payload_sha256="a" * 64,
        route="isles-story",
        process_token="pid:one",
    )
    assert created is True
    assert record["state"] == "accepted"
    assert IslesTurnStore(root).get("msg_turn_1")["payload_sha256"] == "a" * 64


def test_completed_turn_drops_private_outbox_copy(tmp_path):
    store = IslesTurnStore(tmp_path / "turns")
    store.receive(
        "msg_turn_2",
        payload_sha256="b" * 64,
        route="isles-story",
        process_token="pid:one",
    )
    store.transition(
        "msg_turn_2",
        "delivering",
        retryable=True,
        outbox=[{"content": "private reply", "meta": {"delivery_key": "msg_turn_2:final"}}],
    )
    assert store.get("msg_turn_2")["outbox"][0]["content"] == "private reply"
    store.transition("msg_turn_2", "completed", retryable=False)
    completed = store.get("msg_turn_2")
    assert completed["state"] == "completed"
    assert "outbox" not in completed


def test_restart_marks_agent_work_interrupted_but_keeps_delivery_outbox(tmp_path):
    store = IslesTurnStore(tmp_path / "turns")
    for turn_id, state in (
        ("msg_processing", "processing"),
        ("msg_delivering", "delivering"),
        ("msg_delivery", "delivery_failed"),
    ):
        store.receive(
            turn_id,
            payload_sha256=(turn_id[-1] * 64),
            route="isles-story",
            process_token="pid:old",
        )
        store.transition(
            turn_id,
            state,
            retryable=state in {"delivering", "delivery_failed"},
            outbox=(
                [{"content": "reply", "meta": {}}]
                if state in {"delivering", "delivery_failed"}
                else None
            ),
        )

    recovered = {record["turn_id"]: record for record in store.recover_after_restart("pid:new")}
    assert recovered["msg_processing"]["state"] == "interrupted"
    assert recovered["msg_processing"]["retryable"] is True
    assert recovered["msg_delivering"]["state"] == "delivery_failed"
    assert recovered["msg_delivering"]["outbox"][0]["content"] == "reply"
    assert recovered["msg_delivery"]["state"] == "delivery_failed"
    assert recovered["msg_delivery"]["outbox"][0]["content"] == "reply"
