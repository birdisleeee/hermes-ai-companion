from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import sys


_MODULE_PATH = Path(__file__).parents[2] / "gateway" / "reply_delivery.py"
_SPEC = importlib.util.spec_from_file_location("isles_reply_delivery", _MODULE_PATH)
assert _SPEC is not None and _SPEC.loader is not None
_MODULE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _MODULE
_SPEC.loader.exec_module(_MODULE)
build_context_window = _MODULE.build_context_window
extract_context_window = _MODULE.extract_context_window


def test_context_window_is_bound_to_current_session() -> None:
    measured_at = datetime(2026, 8, 20, 1, 2, 3, tzinfo=timezone.utc)

    context = build_context_window(
        6_000,
        128_000,
        session_id="session-after-reset",
        measured_at=measured_at,
    )

    assert context == {
        "used_tokens": 6_000,
        "limit_tokens": 128_000,
        "remaining_tokens": 122_000,
        "used_percent": 5,
        "remaining_percent": 95,
        "measured_at": "2026-08-20T01:02:03.000Z",
        "source": "provider_usage",
        "session_id": "session-after-reset",
    }


def test_context_window_keeps_legacy_shape_without_session() -> None:
    context = build_context_window(1, 10)

    assert context is not None
    assert "session_id" not in context


def test_extract_context_window_forwards_session_id() -> None:
    class Compressor:
        last_prompt_tokens = 2_000
        context_length = 100_000

    context = extract_context_window(
        Compressor(),
        session_id="session-current",
    )

    assert context is not None
    assert context["session_id"] == "session-current"


def test_context_window_omits_blank_session_id() -> None:
    context = build_context_window(1, 10, session_id="   ")

    assert context is not None
    assert "session_id" not in context
