"""Small durable journal for Isles webhook turn delivery.

The generic webhook adapter historically kept delivery IDs only in memory.
This journal gives the Isles route a restart-safe receipt and a durable reply
outbox without changing Hermes conversation storage.  Files live below the
active ``HERMES_HOME`` with mode 0600 and never enter Git or logs.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
from typing import Any, Iterable, Mapping

from hermes_constants import get_hermes_home


_RETENTION_SECONDS = 7 * 24 * 60 * 60
_ACTIVE_STATES = frozenset({"accepted", "processing", "compacting", "reply_ready", "delivering"})


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class IslesTurnStore:
    """Thread-safe JSON journal keyed by the opaque Worker turn ID."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = root or (get_hermes_home() / "gateway" / "isles-turns")
        self._lock = threading.RLock()

    @staticmethod
    def payload_fingerprint(body: bytes) -> str:
        return hashlib.sha256(body).hexdigest()

    @staticmethod
    def _file_name(turn_id: str) -> str:
        return hashlib.sha256(turn_id.encode("utf-8")).hexdigest() + ".json"

    def _path(self, turn_id: str) -> Path:
        return self.root / self._file_name(turn_id)

    def get(self, turn_id: str) -> dict[str, Any] | None:
        with self._lock:
            try:
                value = json.loads(self._path(turn_id).read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                return None
            if not isinstance(value, dict) or value.get("turn_id") != turn_id:
                return None
            return value

    def receive(
        self,
        turn_id: str,
        *,
        payload_sha256: str,
        route: str,
        process_token: str,
    ) -> tuple[dict[str, Any], bool]:
        """Persist a receipt and return ``(record, created)``."""

        with self._lock:
            existing = self.get(turn_id)
            if existing is not None:
                return existing, False
            now = utc_now()
            record = {
                "version": 1,
                "turn_id": turn_id,
                "route": route,
                "payload_sha256": payload_sha256,
                "state": "accepted",
                "retryable": False,
                "process_token": process_token,
                "accepted_at": now,
                "updated_at": now,
            }
            self._write(record)
            return record, True

    def transition(
        self,
        turn_id: str,
        state: str,
        *,
        retryable: bool | None = None,
        detail_code: str | None = None,
        process_token: str | None = None,
        outbox: Iterable[Mapping[str, Any]] | None = None,
    ) -> dict[str, Any] | None:
        with self._lock:
            record = self.get(turn_id)
            if record is None:
                return None
            record["state"] = state
            record["updated_at"] = utc_now()
            if retryable is not None:
                record["retryable"] = bool(retryable)
            if detail_code:
                record["detail_code"] = detail_code
            else:
                record.pop("detail_code", None)
            if process_token is not None:
                record["process_token"] = process_token
            if outbox is not None:
                record["outbox"] = [dict(unit) for unit in outbox]
            if state == "completed":
                # Do not retain a second copy of private reply text after the
                # Worker has acknowledged every idempotent unit.
                record.pop("outbox", None)
                record["completed_at"] = record["updated_at"]
            self._write(record)
            return record

    def records(self) -> list[dict[str, Any]]:
        with self._lock:
            if not self.root.exists():
                return []
            values: list[dict[str, Any]] = []
            for path in self.root.glob("*.json"):
                try:
                    value = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, ValueError, TypeError):
                    continue
                if isinstance(value, dict) and isinstance(value.get("turn_id"), str):
                    values.append(value)
            return values

    def recover_after_restart(self, process_token: str) -> list[dict[str, Any]]:
        """Mark unfinished Agent turns interrupted; keep delivery outboxes."""

        recovered: list[dict[str, Any]] = []
        for record in self.records():
            if record.get("process_token") == process_token:
                continue
            state = record.get("state")
            if state in {"delivering", "delivery_failed"} and record.get("outbox"):
                updated = self.transition(
                    record["turn_id"],
                    "delivery_failed",
                    retryable=True,
                    detail_code="gateway_restarted",
                    process_token=process_token,
                )
                if updated:
                    recovered.append(updated)
                continue
            if state in _ACTIVE_STATES:
                updated = self.transition(
                    record["turn_id"],
                    "interrupted",
                    retryable=True,
                    detail_code="gateway_restarted",
                    process_token=process_token,
                )
                if updated:
                    recovered.append(updated)
        self.prune()
        return recovered

    def prune(self, retention_seconds: int = _RETENTION_SECONDS) -> None:
        cutoff = time.time() - max(3600, retention_seconds)
        with self._lock:
            if not self.root.exists():
                return
            for path in self.root.glob("*.json"):
                try:
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                except OSError:
                    continue

    def _write(self, record: Mapping[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        destination = self._path(str(record["turn_id"]))
        descriptor, temporary_name = tempfile.mkstemp(prefix=".turn-", suffix=".tmp", dir=self.root)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(record, handle, ensure_ascii=False, separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_name, 0o600)
            os.replace(temporary_name, destination)
        finally:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
