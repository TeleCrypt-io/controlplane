"""Unit tests for the installed tier_controller wheel against the exact Synapse runtime."""
import asyncio
import pathlib
import site
import sys
from types import SimpleNamespace

# Running this file from the source checkout would otherwise put the source package ahead of the
# wheel under test. CI mounts this file separately and installs the wheel into site-packages.
source_dir = pathlib.Path(__file__).resolve().parent
sys.path[:] = [entry for entry in sys.path if pathlib.Path(entry or ".").resolve() != source_dir]

from synapse.api.errors import Codes
from synapse.module_api import NOT_SPAM
from synapse.module_api.errors import ConfigError

import tier_controller
from tier_controller import TierController, TierControllerConfig, _DENIAL_MESSAGE

module_path = pathlib.Path(tier_controller.__file__).resolve()
site_packages = {pathlib.Path(path).resolve() for path in site.getsitepackages()}
if not any(root in module_path.parents for root in site_packages):
    raise RuntimeError(f"tier_controller imported outside site-packages: {module_path}")


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


def test_parse_config_rejects_negative_room_cap():
    try:
        TierController.parse_config({"restricted_room_cap": -1})
    except ConfigError as exc:
        assert "must not be negative" in str(exc)
    else:
        raise AssertionError("negative restricted_room_cap unexpectedly accepted")


def test_parse_config_accepts_zero_room_cap():
    assert TierController.parse_config({"restricted_room_cap": 0}).restricted_room_cap == 0


def test_controller_does_not_retain_unused_module_api():
    module, _ = make_module()
    assert not hasattr(module, "api")


def make_event(event_type, sender, is_state=True):
    return SimpleNamespace(type=event_type, sender=sender, is_state=lambda: is_state)


async def test_unverified_denied_upload():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


async def test_verified_allowed_upload():
    module, _ = make_module(user_types={"@a:x": "verified"})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is True


async def test_null_type_denied_upload():
    module, _ = make_module(user_types={"@a:x": None})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


async def test_unknown_legacy_type_denied_upload():
    module, _ = make_module(user_types={"@a:x": "paid_agent"})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


async def test_restricted_room_cap_denied_at_cap():
    module, _ = make_module(
        user_types={"@a:x": "unverified"}, room_counts={"@a:x": 3}, restricted_room_cap=3
    )
    assert await module.user_may_create_room("@a:x", {}) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


async def test_restricted_room_cap_allowed_under_cap():
    module, _ = make_module(
        user_types={"@a:x": "unverified"}, room_counts={"@a:x": 2}, restricted_room_cap=3
    )
    assert await module.user_may_create_room("@a:x", {}) is NOT_SPAM


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


async def test_verified_bypasses_room_cap():
    module, _ = make_module(user_types={"@a:x": "verified"}, room_counts={"@a:x": 999999})
    assert await module.user_may_create_room("@a:x", {}) is NOT_SPAM


async def test_unverified_encryption_denied():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.check_event_for_spam(make_event("m.room.encryption", "@a:x")) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


async def test_verified_encryption_allowed():
    module, _ = make_module(user_types={"@a:x": "verified"})
    assert await module.check_event_for_spam(make_event("m.room.encryption", "@a:x")) is NOT_SPAM


async def test_null_type_encryption_denied():
    module, _ = make_module(user_types={"@a:x": None})
    assert await module.check_event_for_spam(make_event("m.room.encryption", "@a:x")) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


async def test_non_encryption_event_ignored():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.check_event_for_spam(make_event("m.room.message", "@a:x")) is NOT_SPAM


async def test_encryption_event_non_state_ignored():
    module, _ = make_module(user_types={"@a:x": "unverified"})
    assert await module.check_event_for_spam(
        make_event("m.room.encryption", "@a:x", is_state=False)
    ) is NOT_SPAM


async def test_db_error_fails_closed_on_upload():
    module, _ = make_module(user_types={"@a:x": "verified"}, db_error=True)
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


async def test_db_error_fails_closed_on_room_create():
    module, _ = make_module(user_types={"@a:x": "verified"}, db_error=True)
    assert await module.user_may_create_room("@a:x", {}) == (
        Codes.FORBIDDEN,
        {"error": _DENIAL_MESSAGE},
    )


async def test_user_type_grant_and_revocation_are_visible_immediately():
    module, api = make_module(user_types={"@a:x": None})
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False

    api.user_types["@a:x"] = "verified"
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is True

    api.user_types["@a:x"] = None
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False


async def test_db_error_recovers_on_next_decision():
    module, api = make_module(user_types={"@a:x": "verified"}, db_error=True)
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is False

    api.db_error = False
    assert await module.is_user_allowed_to_upload_media_of_size("@a:x", 100) is True


if __name__ == "__main__":
    tests = [value for name, value in globals().items() if name.startswith("test_")]
    failures = 0
    for test in tests:
        try:
            asyncio.run(test())
        except Exception as error:
            failures += 1
            print(f"{test.__name__}: {error}", file=sys.stderr)
    if failures:
        raise SystemExit(f"{failures} of {len(tests)} tests failed")
    print(f"{len(tests)} tests passed")
