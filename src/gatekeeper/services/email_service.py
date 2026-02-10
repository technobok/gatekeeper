"""Email service for sending magic links."""

import json
import uuid
from datetime import UTC, datetime

from flask import current_app


def _send_via_outbox_local(
    to_email: str, subject: str, body_text: str, body_html: str | None = None
) -> bool:
    """Send email by inserting directly into the outbox SQLite database."""
    import apsw

    db_path = current_app.config.get("OUTBOX_DB_PATH", "")
    mail_sender = current_app.config.get("MAIL_SENDER", "")

    if not db_path or not mail_sender:
        if not db_path:
            current_app.logger.error("OUTBOX_DB_PATH not configured")
        if not mail_sender:
            current_app.logger.error("MAIL_SENDER not configured")
        return False

    now = datetime.now(UTC).isoformat()
    msg_uuid = str(uuid.uuid4())
    body = body_html or body_text
    body_type = "html" if body_html else "plain"

    try:
        conn = apsw.Connection(db_path)
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(
            "INSERT INTO message "
            "(uuid, status, delivery_type, from_address, to_recipients, "
            "subject, body, body_type, source_app, created_at, updated_at) "
            "VALUES (?, 'queued', 'email', ?, ?, ?, ?, ?, 'gatekeeper', ?, ?)",
            (msg_uuid, mail_sender, json.dumps([to_email]), subject, body, body_type, now, now),
        )
        conn.close()
        current_app.logger.info(f"Email queued in outbox DB to {to_email}: {subject}")
        return True
    except Exception as e:
        current_app.logger.error(f"Failed to queue email in outbox DB to {to_email}: {e}")
        return False


def _send_via_outbox(
    to_email: str, subject: str, body_text: str, body_html: str | None = None
) -> bool:
    """Send email via outbox API."""
    import httpx

    outbox_url = current_app.config.get("OUTBOX_URL", "").rstrip("/")
    outbox_api_key = current_app.config.get("OUTBOX_API_KEY", "")
    mail_sender = current_app.config.get("MAIL_SENDER", "")

    payload = {
        "from_address": mail_sender,
        "to": [to_email],
        "subject": subject,
        "body": body_html or body_text,
        "body_type": "html" if body_html else "plain",
        "source_app": "gatekeeper",
    }

    try:
        resp = httpx.post(
            f"{outbox_url}/api/v1/messages",
            json=payload,
            headers={"X-API-Key": outbox_api_key},
            timeout=10.0,
        )
        if resp.status_code == 201:
            current_app.logger.info(f"Email queued via outbox to {to_email}: {subject}")
            return True
        else:
            current_app.logger.error(f"Outbox API error: {resp.status_code} - {resp.text}")
            return False
    except Exception as e:
        current_app.logger.error(f"Failed to send email via outbox to {to_email}: {e}")
        return False


def send_email(to_email: str, subject: str, body_text: str, body_html: str | None = None) -> bool:
    """Send an email. Tries local outbox DB first, then outbox HTTP API."""
    outbox_db_path = current_app.config.get("OUTBOX_DB_PATH")
    if outbox_db_path:
        return _send_via_outbox_local(to_email, subject, body_text, body_html)

    outbox_url = current_app.config.get("OUTBOX_URL")
    outbox_api_key = current_app.config.get("OUTBOX_API_KEY")
    if outbox_url and outbox_api_key:
        return _send_via_outbox(to_email, subject, body_text, body_html)

    current_app.logger.error(
        "Email not configured: OUTBOX_DB_PATH=%r, OUTBOX_URL=%r, OUTBOX_API_KEY=%s",
        outbox_db_path,
        current_app.config.get("OUTBOX_URL"),
        "set" if current_app.config.get("OUTBOX_API_KEY") else "not set",
    )
    return False


def send_magic_link(to_email: str, magic_link: str, app_name: str = "Gatekeeper") -> bool:
    """Send a magic link login email."""
    subject = f"{app_name} - Login Link"

    body_text = f"""You requested to log in to {app_name}.

Click the link below to log in:
{magic_link}

This link will expire shortly.

If you didn't request this, you can safely ignore this email.
"""

    body_html = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family: sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2>Login to {app_name}</h2>
    <p>You requested to log in to {app_name}.</p>
    <p>
        <a href="{magic_link}"
           style="display: inline-block; padding: 12px 24px; background: #1095c1;
                  color: white; text-decoration: none; border-radius: 4px;">
            Log In
        </a>
    </p>
    <p style="color: #666; font-size: 14px;">
        Or copy this link: {magic_link}
    </p>
    <p style="color: #666; font-size: 14px;">
        This link will expire shortly.
    </p>
    <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
    <p style="color: #999; font-size: 12px;">
        If you didn't request this, you can safely ignore this email.
    </p>
</body>
</html>
"""

    return send_email(to_email, subject, body_text, body_html)
