from pathlib import Path
from typing import Any

import click
import click_pathlib

from rocketchat_2fa_check.checker import RC2FAChecker


@click.command()
@click.option("--webhook-url", required=True)
@click.option("-m", "--mongo-connection", default="mongodb://localhost:27017", show_default=True)
@click.option(
    "-s",
    "--storage-path",
    type=click_pathlib.Path(
        file_okay=True, dir_okay=False, writable=True, readable=True, resolve_path=True
    ),
    default=Path("storage.db"),
)
@click.option("-u", "--ignore-user", "ignore_users", multiple=True)
@click.option(
    "-t", "--ignore-role", "ignore_roles", multiple=True, default=["bot", "app"], show_default=True
)
@click.option("-a", "--admin-notification-target", "admin_notification_targets", multiple=True)
@click.option("-n", "--dry-run", is_flag=True, help="Only check, don't notify.", show_default=True)
@click.pass_context
def main(
    ctx: Any,
    webhook_url: str,
    mongo_connection: str,
    storage_path: Path,
    ignore_users: list[str],
    ignore_roles: list[str],
    admin_notification_targets: list[str],
    dry_run: bool,
):
    checker = RC2FAChecker(
        mongo_connection_str=mongo_connection,
        storage_path=storage_path,
        rc_webhook_url=webhook_url,
        ignored_users=set(ignore_users),
        ignored_roles=set(ignore_roles),
        admin_notification_targets=set(admin_notification_targets),
        dry_run=dry_run,
    )
    if not checker.check_and_notify():
        ctx.exit(1)
