"""Email service for sending magic links."""

import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app


def _try_login(server: smtplib.SMTP, username: str | None, password: str | None) -> None:
    """Attempt SMTP login only if credentials are provided and the server supports AUTH."""
    if not username or not password:
        return
    if server.has_extn("auth"):
        server.login(username, password)


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


def _send_via_smtp(
    to_email: str, subject: str, body_text: str, body_html: str | None = None
) -> bool:
    """Send email via direct SMTP."""
    smtp_server = current_app.config.get("SMTP_SERVER")
    smtp_port = current_app.config.get("SMTP_PORT", 587)
    smtp_use_tls = current_app.config.get("SMTP_USE_TLS", True)
    smtp_username = current_app.config.get("SMTP_USERNAME")
    smtp_password = current_app.config.get("SMTP_PASSWORD")
    mail_sender = current_app.config.get("MAIL_SENDER")

    if not smtp_server or not mail_sender:
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = mail_sender
    msg["To"] = to_email

    msg.attach(MIMEText(body_text, "plain"))
    if body_html:
        msg.attach(MIMEText(body_html, "html"))

    try:
        if smtp_port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
                _try_login(server, smtp_username, smtp_password)
                server.sendmail(mail_sender, to_email, msg.as_string())
        else:
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if smtp_use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                _try_login(server, smtp_username, smtp_password)
                server.sendmail(mail_sender, to_email, msg.as_string())

        current_app.logger.info(f"Email sent to {to_email}: {subject}")
        return True

    except Exception as e:
        current_app.logger.error(f"Failed to send email to {to_email}: {e}")
        return False


def send_email(to_email: str, subject: str, body_text: str, body_html: str | None = None) -> bool:
    """Send an email. Uses outbox API if configured, otherwise direct SMTP."""
    outbox_url = current_app.config.get("OUTBOX_URL")
    outbox_api_key = current_app.config.get("OUTBOX_API_KEY")

    if outbox_url and outbox_api_key:
        return _send_via_outbox(to_email, subject, body_text, body_html)

    if _send_via_smtp(to_email, subject, body_text, body_html):
        return True

    current_app.logger.warning("Email not configured (no outbox or SMTP settings)")
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
