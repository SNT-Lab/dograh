from loguru import logger

from api.constants import AGENTMAIL_API_KEY, AGENTMAIL_INBOX_ID, UI_APP_URL


async def send_password_reset_email(to_email: str, raw_token: str) -> None:
    """Send a password-reset link via AgentMail.

    Falls back to logging the link when credentials are absent (local dev).
    """
    reset_url = f"{UI_APP_URL}/auth/reset-password?token={raw_token}"

    if not AGENTMAIL_API_KEY or not AGENTMAIL_INBOX_ID:
        logger.warning(
            "AgentMail credentials not configured — password reset link: %s", reset_url
        )
        return

    try:
        from agentmail import AgentMail

        client = AgentMail(api_key=AGENTMAIL_API_KEY)
        client.inboxes.messages.send(
            inbox_id=AGENTMAIL_INBOX_ID,
            to=to_email,
            subject="Reset your Health Voice Agents password",
            html=f"""
            <p>Hello,</p>
            <p>We received a request to reset the password for your account.</p>
            <p>
              <a href="{reset_url}" style="
                display:inline-block;
                padding:12px 24px;
                background:#2563eb;
                color:#fff;
                border-radius:6px;
                text-decoration:none;
                font-weight:600;
              ">Reset password</a>
            </p>
            <p>This link expires in <strong>1 hour</strong>. If you did not request a reset, you can safely ignore this email.</p>
            """,
            text=(
                f"Reset your password by visiting the link below (expires in 1 hour):\n\n{reset_url}\n\n"
                "If you did not request a reset, ignore this email."
            ),
        )
        logger.info("Password-reset email sent to %s", to_email)
    except Exception:
        logger.exception("Failed to send password-reset email to %s", to_email)
        raise
