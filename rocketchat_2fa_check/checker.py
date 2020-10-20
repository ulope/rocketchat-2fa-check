import pickle
import shelve
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from pprint import pformat

from pymongo import MongoClient
from requests import RequestException, Session


LIST_SEP = "\n- "


@dataclass
class UserInfo:
    username: str
    failed_since: datetime
    failed_count: int = 0


class RC2FAChecker:
    def __init__(
        self,
        mongo_connection_str: str,
        storage_path: Path,
        rc_webhook_url: str,
        admin_notification_targets: set[str] = frozenset(),
        ignored_users: set[str] = frozenset(),
        ignored_roles: set[str] = frozenset(),
        mongo_db_name: str = "rocketchat",
        dry_run: bool = False,
    ) -> None:
        self._mongo_db = MongoClient(mongo_connection_str)[mongo_db_name]
        self._storage_path = storage_path
        self._rc_webhook_url = rc_webhook_url
        self._admin_notification_targets = admin_notification_targets
        self._ignored_users = ignored_users
        self._ignored_roles = ignored_roles
        self._dry_run = dry_run
        self._session = Session()

    def check_and_notify(self) -> bool:
        with shelve.open(
            str(self._storage_path), protocol=pickle.HIGHEST_PROTOCOL, writeback=True
        ) as storage:
            users_without_2fa = self._get_users_without_2fa()
            users_without_2fa = users_without_2fa - self._ignored_users

            reformed_users = storage.keys() - users_without_2fa - self._ignored_users

            if users_without_2fa:
                print(f"Users without 2FA:\n- {LIST_SEP.join(users_without_2fa)}")
            if reformed_users:
                print(f"Reformed users:\n- {LIST_SEP.join(reformed_users)}")

            failed_notifications = set()
            for username in users_without_2fa:
                user_info = storage.setdefault(username, UserInfo(username, datetime.utcnow()))
                user_info.failed_count += 1
                try:
                    self._notify_user(username, user_info)
                except RequestException as ex:
                    failed_notifications.add(username)
                    print(f"Failed to notify user '{username}': {ex}")

            for username in reformed_users:
                del storage[username]

            success = not failed_notifications
            success = success and self._notify_admin_targets(
                users_without_2fa,
                reformed_users,
                failed_notifications,
                {username: storage[username] for username in users_without_2fa},
            )
            return success

    def _get_users_without_2fa(self) -> set[str]:
        results = self._mongo_db.users.find(
            {
                "$or": [
                    {"services.totp": {"$exists": False}},
                    {"services.totp.enabled": False},
                ],
                "active": True,
                "roles": {"$nin": list(self._ignored_roles)},
            },
            {"username": True, "_id": False},
        )
        return {result["username"] for result in results}

    def _notify_user(self, username: str, user_info: UserInfo) -> None:
        payload = {
            "channel": f"@{username}",
            "username": "2FA Bot",
            "attachments": [
                {
                    "title": "Two factor authentication",
                    "text": (
                        f":warning: Please remember to enable 2FA for your RocketChat account "
                        f"(`{username}`)! :warning:\n"
                        f"You have been notified {user_info.failed_count} times "
                        f"since {user_info.failed_since:'%Y-%m-%d'}.\n\n"
                        "(This is an automated message.)"
                    ),
                    "color": "#ff0000",
                }
            ],
        }
        if self._dry_run:
            print(f"Would post to {self._rc_webhook_url}:\n{pformat(payload)}")
            return
        response = self._session.post(
            self._rc_webhook_url,
            json=payload,
        )
        response.raise_for_status()

    def _notify_admin_targets(
        self,
        users_without_2fa: set[str],
        reformed_users: set[str],
        failed_usernames: set[str],
        user_infos: dict[str, UserInfo],
    ) -> bool:
        success = True
        for admin_target in self._admin_notification_targets:
            try:
                row_template = "`{ui.username}` | {ui.failed_count} | {ui.failed_since:%Y-%m-%d}"
                failed_users_table = "\n".join(
                    row_template.format(ui=user_infos[username])
                    for username in sorted(users_without_2fa)
                )
                attachments = [
                    {
                        "title": "RC 2FA Report",
                        "text": (
                            f"The following users are missing 2FA and have been notified:\n"
                            f"Username | Count | Since\n"
                            f"--- | --- | ---\n"
                            f"{failed_users_table}"
                        ),
                        "color": "#ff0000",
                    }
                ]
                if reformed_users:
                    attachments.append(
                        {
                            "title": "Nice users",
                            "text": (
                                f"The following users have activated 2FA since last time:\n"
                                f"- {LIST_SEP.join(reformed_users)}"
                            ),
                            "color": "#00ff00",
                        }
                    )
                if failed_usernames:
                    attachments.append(
                        {
                            "title": "Notification failures",
                            "text": (
                                f"The following users couldn't be notified:\n"
                                f"- {LIST_SEP.join(failed_usernames)}"
                            ),
                            "color": "#ff4000",
                        }
                    )
                payload = {
                    "channel": admin_target,
                    "username": "2FA Bot",
                    "attachments": attachments,
                }

                if self._dry_run:
                    print(f"Would post to {self._rc_webhook_url}:\n{pformat(payload)}")
                    return True

                response = self._session.post(
                    self._rc_webhook_url,
                    json=payload,
                )
                response.raise_for_status()
            except RequestException as ex:
                success = False
                print(f"Error notifying admin target '{admin_target}': {ex}")
        return success
