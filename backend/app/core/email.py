import requests
from app.core.config import settings

# ── Email via Brevo HTTP API ───────────────────────────────────────────────────
# SMTP ports 587 and 465 are blocked on this network.
# Brevo sends via HTTPS (port 443) which is always open.
#
# Setup (free, 300 emails/day, no credit card):
#   1. Register at https://app.brevo.com/account/register
#   2. Go to Profile → SMTP & API → API Keys → Generate a new API key
#   3. Add verified sender: Senders & IPs → Senders → Add sender email
#   4. Paste the key into .env:  BREVO_API_KEY=xkeysib-...
# ─────────────────────────────────────────────────────────────────────────────

BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"


def send_email(
    email_to: str,
    subject: str = "",
    html_content: str = "",
    text_content: str = "",
) -> None:
    """
    Send an email via Brevo HTTP API (port 443).
    Raises RuntimeError on failure so callers can handle it properly.
    """
    api_key = getattr(settings, "BREVO_API_KEY", None)
    sender_email = getattr(settings, "SMTP_USER", None) or "noreply@example.com"
    sender_name = getattr(settings, "EMAILS_FROM_NAME", "Genesis Security") or "Genesis Security"

    if not api_key:
        raise RuntimeError(
            "BREVO_API_KEY is not set in your .env file. "
            "Sign up free at https://app.brevo.com → Profile → SMTP & API → API Keys."
        )

    payload = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": email_to}],
        "replyTo": {"email": sender_email, "name": sender_name},
        "subject": subject,
        "htmlContent": html_content,
        # Plain-text fallback: critical for spam score — mail clients that
        # receive only HTML with no text version rank the message as suspicious.
        "textContent": text_content or _strip_html(html_content),
        # Mark as transactional so Brevo routes it through their highest-
        # reputation sending pool (not the marketing pool).
        "tags": ["transactional", "otp"],
        "headers": {
            # Tells mail clients this is automated/transactional, not bulk.
            "X-Mailer": "Genesis-Security/1.0",
            "Precedence": "transactional",
        },
    }
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "api-key": api_key,
    }

    print(f"[Email] Sending '{subject}' to {email_to} via Brevo HTTPS API ...")
    try:
        resp = requests.post(BREVO_API_URL, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        msg_id = resp.json().get("messageId", "N/A")
        print(f"[Email] ✓ Sent to {email_to}  (messageId={msg_id})")
    except requests.exceptions.ConnectionError as e:
        print(f"[Email] ✗ Cannot reach Brevo API (network error): {e}")
        raise RuntimeError(f"Cannot reach Brevo API: {e}") from e
    except requests.exceptions.HTTPError as e:
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        print(f"[Email] ✗ Brevo API error {resp.status_code}: {body}")
        raise RuntimeError(f"Brevo API {resp.status_code}: {body}") from e
    except requests.exceptions.Timeout:
        print("[Email] ✗ Brevo API request timed out")
        raise RuntimeError("Brevo API request timed out")
    except Exception as e:
        print(f"[Email] ✗ Unexpected error: {type(e).__name__}: {e}")
        raise


def _strip_html(html: str) -> str:
    """Very lightweight HTML → plain-text for the textContent fallback."""
    import re
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def send_otp_email(email_to: str, otp: str, purpose: str) -> None:
    purpose_label = purpose.replace("_", " ").title()
    # Clean subject — no emoji, no "password", no "OTP" (spam trigger words)
    subject = f"Your Genesis verification code – {purpose_label}"

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:40px 0;">
    <tr><td align="center">
      <table width="520" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e2e8f0;">

        <!-- Header -->
        <tr>
          <td style="background:#0f172a;padding:24px 32px;">
            <p style="margin:0;color:#4ade80;font-size:18px;font-weight:bold;letter-spacing:1px;">
              Genesis Cybersecurity Dashboard
            </p>
          </td>
        </tr>

        <!-- Body -->
        <tr>
          <td style="padding:32px;">
            <h1 style="margin:0 0 16px;font-size:22px;color:#0f172a;">Verification Code</h1>
            <p style="margin:0 0 8px;color:#475569;font-size:15px;">
              You requested a verification code for: <strong>{purpose_label}</strong>
            </p>
            <p style="margin:0 0 24px;color:#475569;font-size:15px;">
              Use the code below to complete your request.
            </p>

            <!-- OTP box -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td align="center" style="background:#f8fafc;border:2px solid #e2e8f0;border-radius:8px;padding:24px;">
                  <span style="font-family:Courier New,monospace;font-size:40px;font-weight:bold;
                               letter-spacing:12px;color:#0f172a;">{otp}</span>
                </td>
              </tr>
            </table>

            <p style="margin:24px 0 0;color:#94a3b8;font-size:13px;">
              This code expires in <strong>10 minutes</strong>.
            </p>
            <p style="margin:8px 0 0;color:#94a3b8;font-size:13px;">
              If you did not request this code, you can safely ignore this email.
            </p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#f8fafc;border-top:1px solid #e2e8f0;padding:16px 32px;">
            <p style="margin:0;color:#94a3b8;font-size:12px;">
              This is an automated message from Genesis Cybersecurity Dashboard.
              Please do not reply to this email.
            </p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""

    # Plain-text version — essential for avoiding spam filters
    text_content = f"""Genesis Cybersecurity Dashboard – Verification Code

You requested a verification code for: {purpose_label}

Your code is: {otp}

This code expires in 10 minutes.

If you did not request this, please ignore this email.

-- Genesis Cybersecurity Dashboard (automated message, do not reply)
"""

    send_email(email_to, subject, html_content, text_content)
