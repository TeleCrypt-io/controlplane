"""Unit tests for tier_controller using a fake module_api — no live Synapse required.

Run: docker build --target synapse-tier-controller --tag tier-controller:test .
Then: docker run --rm --user 0:0 --entrypoint sh tier-controller:test -c
'python -m pip install pytest==9.0.2 pytest-asyncio==1.4.0 && cd /modules/tier_controller &&
python -m pytest -v test_tier_controller.py'
"""
import time
from types import SimpleNamespace

import pytest

from synapse.api.errors import Codes
from synapse.module_api import NOT_SPAM

from tier_controller import TierController, TierControllerConfig, _DENIAL_MESSAGE


class FakeModuleApi:
    """Duck-typed stand-in for synapse.module_api.ModuleApi."""

    def __init__(self, user_types: dict, room_counts: dict, db_error: bool = False):
        self.user_types = user_types
        self.room_counts = room_counts
        self.db_error = db_error
        self.registered_media = {}
        self.registered_spam = {}

    def register_media_repository_callbacks(self, **callbacks):
        self.registered_media.update(callbacks)

    def register_spam_checker_callbacks(self, **callbacks):
        self.registered_spam.update(callbacks)

    async def run_db_interaction(self, desc, func):
        if self.db_error:
            raise RuntimeError("simulated db failure")
        if desc == "tier_controller_get_user_type":
            return _run_user_type(self, func)
        if desc == "tier_controller_count_created_rooms":
            return _run_room_count(self, func)
        raise AssertionError(f"unexpected desc {desc}")


def _run_user_type(api, func):
    class RecordingCursor:
        def __init__(self, table):
            self.table = table

        def execute(self, sql, args):
            self.user_id = args[0]

        def fetchone(self):
            val = self.table.get(self.user_id, "__missing__")
            if val == "__missing__":
                return None
            return (val,)

    return func(RecordingCursor(api.user_types))


def _run_room_count(api, func):
    class RecordingCursor:
        def __init__(self, table):
            self.table = table

        def execute(self, sql, args):
            self.user_id = args[0]

        def fetchone(self):
            return (self.table.get(self.user_id, 0),)

    return func(RecordingCursor(api.room_counts))


def make_module(user_types=None, room_counts=None, db_error=False, restricted_room_cap=3):
    api = FakeModuleApi(user_types or {}, room_counts or {}, db_error=db_error)
    module = TierController(TierControllerConfig(restricted_room_cap), api)
    return module, api


def make_event(event_type, sender, is_state=True):
    return SimpleNamespace(type=event_type, sender=sender, is_state=lambda: is_state)


@pytest.mark.asyncio
async def test_unverified_denied_upload():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


@pytest.mark.asyncio
async def test_verified_allowed_upload():
    module, _ = make_module(user_types={"@a:x": "verified"})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is True


@pytest.mark.asyncio
async def test_null_type_denied_upload():
    module, _ = make_module(user_types={"@a:x": None})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


@pytest.mark.asyncio
async def test_unknown_legacy_type_denied_upload():
    module, _ = make_module(user_types={"@a:x": "paid_agent"})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


@pytest.mark.asyncio
async def test_restricted_room_cap_denied_at_cap():
    module, _ = make_module(
        user_types={"@a:x": "unverified"}, room_counts={"@a:x": 3}, restricted_room_cap=3
    )
    assert await module.user_may_create_room("@a:x", {}) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


@pytest.mark.asyncio
async def test_restricted_room_cap_allowed_under_cap():
    module, _ = make_module(
        user_types={"@a:x": "unverified"}, room_counts={"@a:x": 2}, restricted_room_cap=3
    )
    assert await module.user_may_create_room("@a:x", {}) is NOT_SPAM


@pytest.mark.asyncio
async def test_unverified_encrypted_initial_state_denied_before_room_creation():
    module, _ = make_module(
        user_types={"@a:x": "unverified"}, room_counts={"@a:x": 0}, restricted_room_cap=3
    )
    room_config = {
        "preset": "private_chat",
        "initial_state": [
            {
                "type": "m.room.encryption",
                "state_key": "",
                "content": {"algorithm": "m.megolm.v1.aes-sha2"},
            }
        ],
    }
    assert await module.user_may_create_room("@a:x", room_config) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


@pytest.mark.asyncio
async def test_verified_encrypted_initial_state_allowed():
    module, _ = make_module(user_types={"@a:x": "verified"})
    room_config = {
        "initial_state": [
            {
                "type": "m.room.encryption",
                "state_key": "",
                "content": {"algorithm": "m.megolm.v1.aes-sha2"},
            }
        ],
    }
    assert await module.user_may_create_room("@a:x", room_config) is NOT_SPAM


@pytest.mark.asyncio
async def test_verified_bypasses_room_cap():
    module, _ = make_module(user_types={"@a:x": "verified"}, room_counts={"@a:x": 999999})
    assert await module.user_may_create_room("@a:x", {}) is NOT_SPAM


@pytest.mark.asyncio
async def test_unverified_encryption_denied():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.check_event_for_spam(make_event("m.room.encryption", "@a:x")) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


@pytest.mark.asyncio
async def test_verified_encryption_allowed():
    module, _ = make_module(user_types={"@a:x": "verified"})
    assert await module.check_event_for_spam(make_event("m.room.encryption", "@a:x")) is NOT_SPAM


@pytest.mark.asyncio
async def test_null_type_encryption_denied():
    module, _ = make_module(user_types={"@a:x": None})
    assert await module.check_event_for_spam(make_event("m.room.encryption", "@a:x")) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


@pytest.mark.asyncio
async def test_non_encryption_event_ignored():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.check_event_for_spam(make_event("m.room.message", "@a:x")) is NOT_SPAM


@pytest.mark.asyncio
async def test_encryption_event_non_state_ignored():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.check_event_for_spam(
        make_event("m.room.encryption", "@a:x", is_state=False)
    ) is NOT_SPAM


@pytest.mark.asyncio
async def test_db_error_fails_closed_on_upload():
    module, _ = make_module(user_types={"@a:x": "verified"}, db_error=True)
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


@pytest.mark.asyncio
async def test_db_error_fails_closed_on_room_create():
    module, _ = make_module(user_types={"@a:x": "verified"}, db_error=True)
    assert await module.user_may_create_room("@a:x", {}) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


@pytest.mark.asyncio
async def test_cache_avoids_second_db_call():
    module, api = make_module(user_types={"@a:x": "unverified"})
    calls = {"n": 0}
    original = api.run_db_interaction

    async def counting(desc, func):
        calls["n"] += 1
        return await original(desc, func)

    api.run_db_interaction = counting
    await module._get_user_type("@a:x")
    await module._get_user_type("@a:x")
    assert calls["n"] == 1


@pytest.mark.asyncio
async def test_cache_expires_after_ttl(monkeypatch):
    module, api = make_module(user_types={"@a:x": "unverified"})
    calls = {"n": 0}
    original = api.run_db_interaction

    async def counting(desc, func):
        calls["n"] += 1
        return await original(desc, func)

    api.run_db_interaction = counting
    now = {"value": 1000.0}
    monkeypatch.setattr(time, "monotonic", lambda: now["value"])
    await module._get_user_type("@a:x")
    now["value"] += 31.0
    await module._get_user_type("@a:x")
    assert calls["n"] == 2


@pytest.mark.asyncio
async def test_db_error_result_not_cached():
    module, api = make_module(user_types={"@a:x": "verified"}, db_error=True)
    await module._get_user_type("@a:x")
    api.db_error = False
    assert await module._get_user_type("@a:x") == "verified"
