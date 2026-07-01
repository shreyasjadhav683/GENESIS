from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from app.api import deps
from app.models.user import User
from sqlmodel import Session, select
from app.core.db import get_session

router = APIRouter()

class PolicyQuery(BaseModel):
    query: str
    context: str = ""
    chat_id: int | None = None


# ── Chat CRUD ──────────────────────────────────────────────

@router.get("/chats")
def get_chats(
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_session)
):
    from app.models.chat import Chat
    statement = select(Chat).where(Chat.user_id == current_user.id).order_by(Chat.created_at.desc())
    chats = db.exec(statement).all()
    return chats

@router.post("/chats")
def create_chat(
    title: str,
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_session)
):
    from app.models.chat import Chat
    chat = Chat(user_id=current_user.id, title=title)
    db.add(chat)
    db.commit()
    db.refresh(chat)
    return chat

@router.delete("/chats/{chat_id}")
def delete_chat(
    chat_id: int,
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_session)
):
    from app.models.chat import Chat, Message
    chat = db.get(Chat, chat_id)
    if not chat or chat.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Chat not found")

    # Delete all messages in the chat first
    msgs = db.exec(select(Message).where(Message.chat_id == chat_id)).all()
    for m in msgs:
        db.delete(m)
    db.delete(chat)
    db.commit()
    return {"status": "deleted", "chat_id": chat_id}

@router.get("/chats/{chat_id}/messages")
def get_chat_messages(
    chat_id: int,
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_session)
):
    from app.models.chat import Chat, Message

    chat = db.get(Chat, chat_id)
    if not chat or chat.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Chat not found")

    statement = select(Message).where(Message.chat_id == chat_id).order_by(Message.created_at)
    messages = db.exec(statement).all()
    return messages


# ── System Prompt ──────────────────────────────────────────

SYSTEM_PROMPT = """You are **Genesis AI** — an expert cybersecurity assistant built into the Genesis Security Dashboard.

Your capabilities:
- Answer questions on offensive & defensive security, threat intelligence, secure coding, compliance (OWASP, NIST, ISO 27001), and incident response.
- Help users understand results from Genesis tools: URL Scanner, IP Scanner, File Integrity Monitor, Code Scanner, Email Header Analyzer, Browser Extension Scanner, Phishing Detector, Metadata Extractor, Password Strength Analyzer, Security Headers Checker, and Ransomware Detector.
- Provide actionable remediation steps, code examples, and tool recommendations.
- Explain vulnerabilities (SQLi, XSS, CSRF, RCE, SSRF, etc.) with clear examples.

Formatting rules:
- Use **Markdown** formatting: headers (##), bold, bullet lists, numbered lists, and fenced code blocks (```language).
- Keep answers concise but thorough. Use structured sections for complex topics.
- When giving code, always specify the language in the code fence.
- For step-by-step guides, use numbered lists.
- For comparisons, use tables.

Personality:
- Professional but approachable. Use clear language, avoid unnecessary jargon.
- If you don't know something, say so honestly rather than guessing.
- Always prioritize security best practices.
"""


# ── Fallback Knowledge Base ────────────────────────────────

KNOWLEDGE_BASE = [
    (
        ["sql", "injection", "sqli"],
        "## SQL Injection (SQLi)\n\nSQL Injection occurs when untrusted data is sent to an interpreter as part of a command.\n\n### Remediation\n1. Use **parameterized queries** (Prepared Statements)\n2. Use **ORMs** (like SQLModel / SQLAlchemy)\n3. **Validate** all user inputs with allowlists\n4. Apply the **Principle of Least Privilege** to database accounts\n\n```python\n# Bad — vulnerable\ncursor.execute(f\"SELECT * FROM users WHERE id = {user_input}\")\n\n# Good — parameterized\ncursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_input,))\n```"
    ),
    (
        ["xss", "cross-site", "scripting"],
        "## Cross-Site Scripting (XSS)\n\nXSS allows attackers to execute scripts in the victim's browser, stealing cookies or session tokens.\n\n### Types\n- **Reflected XSS** — payload is in the URL\n- **Stored XSS** — payload persists in the database\n- **DOM-based XSS** — client-side JavaScript manipulation\n\n### Remediation\n1. **Encode output** (HTML Entity Encoding)\n2. Use **Content Security Policy** (CSP) headers\n3. **Sanitize** input using DOMPurify\n4. Use frameworks with **auto-escaping** (React, Angular)"
    ),
    (
        ["ransomware", "encrypt", "locked", "ransom"],
        "## Ransomware Response\n\nRansomware encrypts files and demands payment for decryption keys.\n\n### Immediate Response\n1. **Isolate** the infected machine from the network\n2. **Do NOT pay** the ransom\n3. **Preserve** evidence for forensic analysis\n4. **Restore** from validated backups\n\n### Prevention\n- Maintain **offline backups** (3-2-1 rule)\n- Keep systems **patched**\n- Use **EDR** solutions\n- Conduct **phishing awareness** training"
    ),
    (
        ["password", "policy", "weak", "strength", "credential"],
        "## Password Security\n\n### Best Practices\n- Minimum **14 characters** (NIST SP 800-63B)\n- Mix uppercase, lowercase, numbers, and symbols\n- Enable **Multi-Factor Authentication** (MFA)\n- Use a **password manager**\n- Never reuse passwords across services\n- Check passwords against **breach databases** (HaveIBeenPwned)"
    ),
    (
        ["phishing", "social engineering", "spear"],
        "## Phishing Prevention\n\n### Detection Signs\n- Urgency / threatening language\n- Mismatched sender address\n- Suspicious links (hover to check)\n- Unexpected attachments\n\n### Organizational Controls\n1. **Email filtering** gateways (SPF, DKIM, DMARC)\n2. **Security awareness training** (quarterly)\n3. **Phishing simulation** campaigns\n4. **Incident reporting** process"
    ),
    (
        ["ddos", "denial", "service", "dos"],
        "## DDoS Mitigation\n\n### Defense Layers\n1. **CDN / WAF** (Cloudflare, Akamai, AWS Shield)\n2. **Rate limiting** at the application level\n3. **Anycast network** distribution\n4. **Traffic analysis** and anomaly detection\n5. **ISP-level** null routing for volumetric attacks\n\n### Application-Level\n- Implement request throttling\n- Use CAPTCHA for suspicious traffic\n- Configure auto-scaling"
    ),
    (
        ["port", "scan", "nmap", "open port"],
        "## Port Security\n\n### Hardening\n1. **Close unused ports** via firewall rules\n2. Use **IDS/IPS** to detect scanning (Snort, Suricata)\n3. **Whitelist** access to management ports (SSH, RDP)\n4. Change **default ports** for common services\n5. Implement **port knocking** for sensitive services\n\n### Common Dangerous Ports\n| Port | Service | Risk |\n|------|---------|------|\n| 22 | SSH | Brute force |\n| 3389 | RDP | BlueKeep, brute force |\n| 445 | SMB | EternalBlue |\n| 3306 | MySQL | Data exfil |"
    ),
    (
        ["csrf", "cross-site request forgery"],
        "## CSRF (Cross-Site Request Forgery)\n\nCSRF tricks a victim's browser into making unwanted requests on an authenticated session.\n\n### Prevention\n1. Use **anti-CSRF tokens** (synchronizer token pattern)\n2. Set **SameSite=Strict** on cookies\n3. Verify **Origin/Referer** headers\n4. Require **re-authentication** for sensitive actions"
    ),
    (
        ["owasp", "top 10", "top ten"],
        "## OWASP Top 10 (2021)\n\n| # | Category |\n|---|----------|\n| A01 | Broken Access Control |\n| A02 | Cryptographic Failures |\n| A03 | Injection |\n| A04 | Insecure Design |\n| A05 | Security Misconfiguration |\n| A06 | Vulnerable Components |\n| A07 | Auth & ID Failures |\n| A08 | Software & Data Integrity |\n| A09 | Logging & Monitoring Failures |\n| A10 | SSRF |"
    ),
    (
        ["zero day", "0day", "zero-day"],
        "## Zero-Day Vulnerabilities\n\n### What It Is\nA vulnerability unknown to the vendor with no available patch.\n\n### Mitigation\n1. **Defense in depth** — multiple security layers\n2. **Network segmentation** to limit blast radius\n3. **EDR / XDR** with behavioral detection\n4. **Virtual patching** via WAF rules\n5. **Threat intelligence** feeds for early warning"
    ),
    (
        ["api", "rest", "endpoint", "api security"],
        "## API Security\n\n### Best Practices\n1. **Authentication** — OAuth 2.0 / JWT with short expiry\n2. **Authorization** — RBAC at every endpoint\n3. **Rate limiting** — prevent abuse\n4. **Input validation** — strict schemas\n5. **TLS everywhere** — encrypt in transit\n6. **Logging** — audit all API calls\n7. **Versioning** — deprecate insecure versions"
    ),
]


# ── Main Assistant Endpoint ────────────────────────────────

@router.post("/assistant")
def policy_assistant(
    query: PolicyQuery,
    current_user: User = Depends(deps.get_current_user),
    db: Session = Depends(get_session)
):
    from app.core.config import settings
    from app.models.chat import Chat, Message

    # Verify chat access
    chat_id = query.chat_id
    if chat_id:
        chat = db.get(Chat, chat_id)
        if not chat or chat.user_id != current_user.id:
            raise HTTPException(status_code=404, detail="Chat not found")

        # Save user message
        user_msg = Message(chat_id=chat_id, role='user', content=query.query)
        db.add(user_msg)
        db.commit()

    response_text = ""
    confidence = "Low"
    source = "System"

    # ── Try Gemini AI ──────────────────────────────────────
    if settings.GEMINI_API_KEY:
        try:
            from google import genai
            from google.genai import types

            client = genai.Client(api_key=settings.GEMINI_API_KEY)

            # Build conversation history for context
            conversation_contents = []
            if chat_id:
                history_msgs = db.exec(
                    select(Message)
                    .where(Message.chat_id == chat_id)
                    .order_by(Message.created_at)
                ).all()
                # Send last 20 messages for context (trim to avoid token limits)
                for msg in history_msgs[-20:]:
                    conversation_contents.append(
                        types.Content(
                            role="user" if msg.role == "user" else "model",
                            parts=[types.Part.from_text(text=msg.content)]
                        )
                    )
            else:
                # No history, just the current query
                conversation_contents.append(
                    types.Content(
                        role="user",
                        parts=[types.Part.from_text(text=query.query)]
                    )
                )

            response = client.models.generate_content(
                model='gemini-2.0-flash',
                contents=conversation_contents,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    temperature=0.7,
                    max_output_tokens=2048,
                )
            )

            response_text = response.text
            confidence = "High"
            source = "Genesis AI (Gemini)"

        except Exception as e:
            print(f"Gemini API Error: {e}")
            # Fall through to rule-based

    # ── Fallback: Rule-Based ───────────────────────────────
    if not response_text:
        q = query.query.lower()

        for keywords, kb_response in KNOWLEDGE_BASE:
            if any(k in q for k in keywords):
                response_text = kb_response
                confidence = "High"
                source = "Genesis Knowledge Base"
                break

        if not response_text:
            if any(g in q for g in ["help", "hello", "hi", "hey", "what can you do"]):
                response_text = (
                    "## Welcome to Genesis AI! 👋\n\n"
                    "I'm your cybersecurity assistant. Here's what I can help with:\n\n"
                    "- **Threat Analysis** — SQL injection, XSS, CSRF, ransomware, and more\n"
                    "- **Security Best Practices** — password policies, API security, network hardening\n"
                    "- **Tool Guidance** — how to use Genesis scanners and their results\n"
                    "- **Compliance** — OWASP Top 10, NIST, ISO 27001\n"
                    "- **Incident Response** — step-by-step response plans\n\n"
                    "Just type your question below!"
                )
                confidence = "High"
                source = "System"

            elif "scan" in q:
                response_text = (
                    "## Genesis Scanning Tools\n\n"
                    "I can help you interpret scan results from:\n\n"
                    "| Tool | Purpose |\n"
                    "|------|---------|\n"
                    "| URL Scanner | Analyze URLs for threats |\n"
                    "| IP Scanner | Deep scan network hosts |\n"
                    "| Code Scanner | Find vulnerabilities in code |\n"
                    "| Email Headers | Check authentication & routing |\n"
                    "| Security Headers | Audit HTTP response headers |\n"
                    "| Phishing Detector | Identify phishing attempts |\n\n"
                    "Upload a file or paste results, and I'll analyze them!"
                )
                confidence = "Medium"
                source = "System"

        if not response_text:
            response_text = (
                "I don't have a specific answer for that yet, but here are some general security recommendations:\n\n"
                "1. Follow the **Principle of Least Privilege**\n"
                "2. Keep all systems **patched and updated**\n"
                "3. Enable **Multi-Factor Authentication**\n"
                "4. Maintain **offline backups**\n\n"
                "Try rephrasing your question, or ask about specific topics like *SQL injection*, *XSS*, *ransomware*, or *password policy*."
            )
            confidence = "Low"

    # Save assistant response
    if chat_id:
        ai_msg = Message(chat_id=chat_id, role='assistant', content=response_text)
        db.add(ai_msg)
        db.commit()

    return {
        "response": response_text,
        "confidence": confidence,
        "source": source
    }
