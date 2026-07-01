from typing import Any, Dict, Optional
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.core.config import settings

def send_email(
    email_to: str,
    subject: str = "",
    html_content: str = "",
) -> None:
    """
    Send an email using the configured SMTP server.
    """
    if not settings.SMTP_SERVER or not settings.SMTP_USER:
        print(f"Skipping email to {email_to} (SMTP not configured)")
        return

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{settings.EMAILS_FROM_NAME} <{settings.EMAILS_FROM_EMAIL}>"
    msg["To"] = email_to

    part = MIMEText(html_content, "html")
    msg.attach(part)

    try:
        server = smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT)
        server.starttls()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.EMAILS_FROM_EMAIL, email_to, msg.as_string())
        server.quit()
        print(f"Email sent to {email_to}")
    except Exception as e:
        print(f"Failed to send email: {e}")
        # In production, we might want to raise or log more severely
        # raise e

def send_otp_email(email_to: str, otp: str, purpose: str) -> None:
    subject = f"Genesis security code for {purpose}"
    html_content = f"""
    <html>
        <body>
            <h2>Genesis Security Alert</h2>
            <p>You requested a security code for: <b>{purpose}</b></p>
            <p>Your One-Time Password (OTP) is:</p>
            <h1 style="color: #4ade80; font-family: monospace; letter-spacing: 5px;">{otp}</h1>
            <p>This code will expire in 10 minutes.</p>
            <p>If you did not request this, please ignore this email.</p>
        </body>
    </html>
    """
    send_email(email_to, subject, html_content)
