# tier_controller — fail-closed capability restrictions for unverified users.
#
# Baked into the controlplane-owned Synapse module image at /modules/tier_controller and loaded by
# the server's `modules:` configuration. Inverted tier model: everyone is RESTRICTED (no uploads,
# a capped number of created rooms, no m.room.encryption) unless user_type == 'verified'.
# NULL/absent user_type (the default for a freshly registered account, agent or human) is
# restricted; only an explicit 'verified' user_type lifts the restriction. There is no second
# tier — 'verified' is uncapped, everything else shares one cap.
#
# Callback signatures + return-value handling verified against the exact Synapse 1.159.0 package:
#   - media_repository_callbacks.is_user_allowed_to_upload_media_of_size(user_id, size) -> bool.
#   - spamchecker_callbacks.user_may_create_room(user_id, room_config) accepts NOT_SPAM, Codes,
#     (Codes, dict), or bool.
#   - spamchecker_callbacks.check_event_for_spam(event) accepts NOT_SPAM, Codes, (Codes, dict),
#     or str. We use the tuple form to provide the client-visible error message.
from __future__ import annotations

import logging
from typing import Any

from synapse.api.errors import Codes
from synapse.module_api import ModuleApi, NOT_SPAM
from synapse.module_api.errors import ConfigError

logger = logging.getLogger(__name__)

VERIFIED = "verified"

_DENIAL_MESSAGE = (
    "This account is unverified. Uploads/room creation/encryption require a verified account "
    "— sign in at https://telecrypt.io with an email address to request verification. "
    "See https://telecrypt.io/llms.txt"
)


class TierControllerConfig:
    def __init__(self, restricted_room_cap: int) -> None:
        self.restricted_room_cap = restricted_room_cap


class TierController:
    def __init__(self, config: TierControllerConfig, api: ModuleApi) -> None:
        self.config = config
        self.api = api

        api.register_media_repository_callbacks(
            is_user_allowed_to_upload_media_of_size=self.is_user_allowed_to_upload_media_of_size,
        )
        api.register_spam_checker_callbacks(
            user_may_create_room=self.user_may_create_room,
            check_event_for_spam=self.check_event_for_spam,
        )

    @staticmethod
    def parse_config(config: dict[str, Any]) -> TierControllerConfig:
        try:
            restricted_room_cap = int(config.get("restricted_room_cap", 3))
        except (TypeError, ValueError) as e:
            raise ConfigError("restricted_room_cap must be an integer") from e
        return TierControllerConfig(restricted_room_cap)

    async def _get_user_type(self, user_id: str) -> str | None:
        def txn(cursor: Any) -> str | None:
            cursor.execute("SELECT user_type FROM users WHERE name = %s", (user_id,))
            row = cursor.fetchone()
            return row[0] if row else None

        try:
            user_type = await self.api.run_db_interaction(
                "tier_controller_get_user_type", txn
            )
        except Exception:
            logger.exception(
                "tier_controller: user_type lookup failed for %s, failing closed", user_id
            )
            return None

        return user_type

    async def _is_restricted(self, user_id: str) -> bool:
        return await self._get_user_type(user_id) != VERIFIED

    async def _count_created_rooms(self, user_id: str) -> int:
        def txn(cursor: Any) -> int:
            cursor.execute("SELECT count(*) FROM rooms WHERE creator = %s", (user_id,))
            row = cursor.fetchone()
            return int(row[0]) if row else 0

        try:
            return await self.api.run_db_interaction(
                "tier_controller_count_created_rooms", txn
            )
        except Exception:
            logger.exception(
                "tier_controller: room count lookup failed for %s, failing closed", user_id
            )
            return self.config.restricted_room_cap

    async def is_user_allowed_to_upload_media_of_size(self, user_id: str, size: int) -> bool:
        return not await self._is_restricted(user_id)

    async def user_may_create_room(self, user_id: str, room_config: dict) -> Any:
        if not await self._is_restricted(user_id):
            return NOT_SPAM
        # Synapse does not run createRoom's initial_state events through check_event_for_spam.
        # The user_may_create_room callback receives the complete request body, so reject an
        # encryption state event here before the room is created.
        initial_state = room_config.get("initial_state", [])
        if isinstance(initial_state, list) and any(
            isinstance(event, dict) and event.get("type") == "m.room.encryption"
            for event in initial_state
        ):
            return Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE}
        count = await self._count_created_rooms(user_id)
        if count >= self.config.restricted_room_cap:
            return Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE}
        return NOT_SPAM

    async def check_event_for_spam(self, event: Any) -> Any:
        if event.type != "m.room.encryption" or not event.is_state():
            return NOT_SPAM
        if await self._is_restricted(event.sender):
            return Codes.FORBIDDEN, {"error": _DENIAL_MESSAGE}
        return NOT_SPAM
