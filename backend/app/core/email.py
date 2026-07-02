from typing import Any, Dict, Optional
import smtplib
import ssl
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
    Raises an exception on failure so callers can handle it properly.
    """
    if not settings.SMTP_SERVER or not settings.SMTP_USER or not settings.SMTP_PASSWORD:
        missing = []
        if not settings.SMTP_SERVER: missing.append("SMTP_SERVER")
        if not settings.SMTP_USER: missing.append("SMTP_USER")
        if not settings.SMTP_PASSWORD: missing.append("SMTP_PASSWORD")
        error_msg = f"SMTP not configured. Missing env vars: {', '.join(missing)}"
        print(f"[Email] ERROR: {error_msg}")
        raise RuntimeError(error_msg)

    from_email = settings.from_email  # Uses SMTP_USER as default (required for Gmail)

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{settings.EMAILS_FROM_NAME} <{from_email}>"
    msg["To"] = email_to

    part = MIMEText(html_content, "html")
    msg.attach(part)

    def _send_via_starttls():
        """Connect via STARTTLS on port 587 (or configured port)."""
        print(f"[Email] Attempting STARTTLS send to {email_to} via {settings.SMTP_SERVER}:{settings.SMTP_PORT} as {from_email}")
        server = smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT, timeout=15)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(from_email, email_to, msg.as_string())
        server.quit()

    def _send_via_ssl():
        """Connect via implicit SSL on port 465 — fallback if STARTTLS is blocked."""
        ssl_port = 465
        print(f"[Email] Attempting SSL fallback send to {email_to} via {settings.SMTP_SERVER}:{ssl_port} as {from_email}")
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(settings.SMTP_SERVER, ssl_port, context=context, timeout=15) as server:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(from_email, email_to, msg.as_string())

    try:
        _send_via_starttls()
        print(f"[Email] ✓ Successfully sent to {email_to} (STARTTLS)")
    except OSError as e:
        # Network unreachable on port 587 — try SSL port 465 as fallback
        print(f"[Email] ⚠ STARTTLS failed ({e}), retrying with SSL on port 465...")
        try:
            _send_via_ssl()
            print(f"[Email] ✓ Successfully sent to {email_to} (SSL fallback)")
        except OSError as e2:
            print(f"[Email] ✗ SSL fallback also failed: {e2}")
            print(f"[Email] ✗ Both port 587 and 465 are unreachable. Check your server's outbound firewall rules.")
            raise
        except smtplib.SMTPAuthenticationError as e2:
            print(f"[Email] ✗ SSL Authentication failed: {e2} — Check SMTP_USER and SMTP_PASSWORD")
            raise
        except smtplib.SMTPException as e2:
            print(f"[Email] ✗ SSL SMTP error: {e2}")
            raise
    except smtplib.SMTPAuthenticationError as e:
        print(f"[Email] ✗ Authentication failed: {e} — Check SMTP_USER and SMTP_PASSWORD (use App Password for Gmail)")
        raise
    except smtplib.SMTPException as e:
        print(f"[Email] ✗ SMTP error: {e}")
        raise
    except Exception as e:
        print(f"[Email] ✗ Unexpected error: {type(e).__name__}: {e}")
        raise

def send_otp_email(email_to: str, otp: str, purpose: str) -> None:
    subject = f"Genesis security code for {purpose}"
    html_content = f"""
    <html>
        <body style="font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; padding: 30px;">
            <div style="max-width: 500px; margin: 0 auto; background: #1e293b; border-radius: 12px; padding: 30px; border: 1px solid #334155;">
                <h2 style="color: #4ade80; margin-top: 0;">🛡️ Genesis Security Code</h2>
                <p>You requested a security code for: <b style="color: #94a3b8;">{purpose.replace("_", " ").title()}</b></p>
                <p>Your One-Time Password (OTP) is:</p>
                <div style="background: #0f172a; border-radius: 8px; padding: 20px; text-align: center; margin: 20px 0;">
                    <h1 style="color: #4ade80; font-family: monospace; letter-spacing: 10px; font-size: 36px; margin: 0;">{otp}</h1>
                </div>
                <p style="color: #64748b;">⏱️ This code expires in <b>10 minutes</b>.</p>
                <p style="color: #64748b;">If you did not request this, please ignore this email.</p>
                <hr style="border-color: #334155; margin-top: 20px;">
                <p style="color: #475569; font-size: 12px;">Genesis Cybersecurity Dashboard</p>
            </div>
        </body>
    </html>
    """
    send_email(email_to, subject, html_content)
