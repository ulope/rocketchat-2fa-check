import click

from rocketchat_2fa_check.checker import RC2FAChecker


@click.command()
@click.option("--webhook-url", required=True)
@click.option(
    "-m", "--mongo-connection", default="mongodb://localhost:27017", show_default=True
)
@click.option("-i", "--ignore-user", "ignore_users", multiple=True)
@click.option(
    "-a", "--admin-notification-target", "admin_notification_targets", multiple=True
)
@click.pass_context
def main(ctx, webhook_url, mongo_connection, ignore_users, admin_notification_targets):
    checker = RC2FAChecker(
        mongo_connection_str=mongo_connection,
        rc_webhook_url=webhook_url,
        ignored_users=set(ignore_users),
        admin_notification_targets=set(admin_notification_targets),
    )
    if not checker.check_and_notify():
        ctx.exit(1)
