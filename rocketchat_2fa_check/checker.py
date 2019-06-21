from typing import Set

from pymongo import MongoClient
from requests import Session, RequestException


class RC2FAChecker:
    def __init__(
        self,
        mongo_connection_str: str,
        rc_webhook_url: str,
        admin_notification_targets: Set[str] = frozenset(),
        ignored_users: Set[str] = frozenset(),
        mongo_db_name: str = "rocketchat",
    ) -> None:
        self._mongo_db = MongoClient(mongo_connection_str)[mongo_db_name]
        self._rc_webhook_url = rc_webhook_url
        self._admin_notification_targets = admin_notification_targets
        self._ignored_users = ignored_users
        self._session = Session()

    def check_and_notify(self) -> bool:
        users_without_2fa = self._get_users_without_2fa()
        users_without_2fa = users_without_2fa - self._ignored_users

        failed_notifications = set()
        for username in users_without_2fa:
            try:
                self._notify_user(username)
            except RequestException as ex:
                failed_notifications.add(username)
                print(f"Failed to notify user '{username}': {ex}")
        success = not failed_notifications
        success = success and self._notify_admin_targets(users_without_2fa, failed_notifications)
        return success

    def _get_users_without_2fa(self) -> Set[str]:
        results = self._mongo_db.users.find(
            {
                "$or": [
                    {"services.totp": {"$exists": False}},
                    {"services.totp.enabled": False},
                ],
                "active": True,
                "roles": {"$nin": ["bot"]},
            },
            {"username": True, "_id": False},
        )
        return {result['username'] for result in results}

    def _notify_user(self, username: str) -> None:
        response = self._session.post(
            self._rc_webhook_url,
            json={
                "channel": "@ulope",
                "username": "2FA Bot",
                "attachments": [
                    {
                        "title": "Two factor authentication",
                        "text": (
                            f":warning: Please remember to enable 2FA for your RocketChat account "
                            f"(`{username}`)!:warning:\n\n"
                            "(This is an automated message.)"
                        ),
                        "color": "#ff0000",
                    }
                ],
            },
        )
        response.raise_for_status()

    def _notify_admin_targets(
        self, users_without_2fa: Set[str], failed_usernames: Set[str]
    ) -> bool:
        success = True
        formatted_users_without_2fa = "\n- ".join(users_without_2fa)
        for admin_target in self._admin_notification_targets:
            try:
                response = self._session.post(
                    self._rc_webhook_url,
                    json={
                        "channel": admin_target,
                        "username": "2FA Bot",
                        "attachments": [
                            {
                                "title": "RC 2FA Report",
                                "text": (
                                    f"The following users are missing 2FA and have been notified:"
                                    f"\n"
                                    f"- {formatted_users_without_2fa}"
                                ),
                                "color": "#ff0000",
                            }
                        ],
                    },
                )
                response.raise_for_status()
            except RequestException as ex:
                success = False
                print(f"Error notifying admin target '{admin_target}': {ex}")
        return success
