from fastapi import APIRouter, File, UploadFile, Depends, Request
from typing import Optional
from pydantic import BaseModel
from zxcvbn import zxcvbn
import json
from sqlmodel import Session
from app.core.db import get_session
from app.api import deps
from app.models.user import User
from app.models.scan_history import ScanHistory

router = APIRouter()

class PasswordRequest(BaseModel):
    password: str

@router.post("/password-strength")
def password_strength(
    data: PasswordRequest, 
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    import hashlib
    import requests
    
    # 1. Zxcvbn Analysis
    results = zxcvbn(data.password)
    
    # 2. Breach Detection (HaveIBeenPwned k-Anonymity)
    sha1_password = hashlib.sha1(data.password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    
    breach_count = 0
    try:
        response = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=2)
        if response.status_code == 200:
            hashes = (line.split(':') for line in response.text.splitlines())
            for h, count in hashes:
                if h == suffix:
                    breach_count = int(count)
                    break
    except Exception:
        pass # Fail silently for breach check if API is down
        
    result = {
        "score": results["score"],
        "feedback": results["feedback"],
        "crack_times_display": results["crack_times_display"],
        "breach_count": breach_count,
        "sequence": results.get("sequence", []) # Expose pattern details
    }
    
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="PASSWORD_STRENGTH",
        target="***",
        result=json.dumps(result)
    )
    session.add(scan)
    session.commit()
    
    return result

@router.post("/code")
async def scan_code(
    request: Request,
    file: Optional[UploadFile] = File(None),
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    """Aggressive multi-language SAST analysis"""
    from app.core.code_scanner_service import code_analyzer
    
    code_content = ""
    filename = ""
    language = ""
    
    # Try file upload first
    if file and file.filename:
        content = await file.read()
        code_content = content.decode("utf-8", errors="ignore")
        filename = file.filename
    else:
        # Try JSON body
        try:
            body = await request.json()
            code_content = body.get("code", "")
            language = body.get("language", "")
            filename = body.get("filename", "snippet")
        except Exception:
            return {"error": "No code provided. Send a file upload or JSON body with 'code' field."}
    
    if not code_content.strip():
        return {"error": "Empty code provided"}
    
    result_data = code_analyzer.analyze(code_content, language=language, filename=filename)
    
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="CODE_SCAN",
        target=filename or "snippet",
        result=json.dumps(result_data)
    )
    session.add(scan)
    session.commit()
    
    return result_data

@router.post("/ransomware")
async def detect_ransomware(
    file: UploadFile = File(...),
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    import math

    # Shannon Entropy Calculation
    def calculate_entropy(data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    content = await file.read()
    entropy = calculate_entropy(content)
    
    filename = file.filename.lower()
    ransomware_exts = [".encrypted", ".locked", ".wannacry", ".crypt", ".ryuk"]
    
    # Heuristic Logic
    is_suspicious = False
    details = []

    # 1. Extension Check
    if any(filename.endswith(ext) for ext in ransomware_exts):
        is_suspicious = True
        details.append("File extension associated with known ransomware.")

    # 2. Entropy Check (High entropy > 7.5 usually means encryption or compression)
    if entropy > 7.5:
        # If it's not a known compressed format (zip, rare, 7z, png, jpg), flag it
        safe_exts = ['.zip', '.rar', '.7z', '.png', '.jpg', '.jpeg', '.mp4']
        if not any(filename.endswith(ext) for ext in safe_exts):
             is_suspicious = True
             details.append(f"High entropy ({entropy:.2f}) detected in non-standard format. Possible encrypted payload.")
    
    result = {
        "filename": file.filename,
        "ransomware_detected": is_suspicious,
        "entropy": entropy,
        "details": " ".join(details) if details else "File appears clean.",
        "risk_level": "High" if is_suspicious else "Low"
    }
    
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="RANSOMWARE_SCAN",
        target=file.filename,
        result=json.dumps(result)
    )
    session.add(scan)
    session.commit()
    
    return result


@router.post("/email-headers")
def analyze_email_headers(
    headers: str,
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    """Comprehensive email header security analysis"""
    import re
    from datetime import datetime
    from email.utils import parsedate_to_datetime
    
    if not headers.strip():
        return {"error": "No headers provided"}
    
    lines = headers.split('\n')
    parsed = []
    current_key = ''
    current_value = ''
    
    # Parse headers (RFC 2822 folding)
    for line in lines:
        if re.match(r'^[A-Za-z-]+:', line):
            if current_key:
                parsed.append(analyze_email_header(current_key, current_value.strip()))
            parts = line.split(':', 1)
            current_key = parts[0]
            current_value = parts[1] if len(parts) > 1 else ''
        elif line.startswith(' ') or line.startswith('\t'):
            current_value += ' ' + line.strip()
    
    if current_key:
        parsed.append(analyze_email_header(current_key, current_value.strip()))
    
    # --- Extract key headers ---
    from_header = next((h for h in parsed if h['key'].lower() == 'from'), None)
    to_header = next((h for h in parsed if h['key'].lower() == 'to'), None)
    subject_header = next((h for h in parsed if h['key'].lower() == 'subject'), None)
    date_header = next((h for h in parsed if h['key'].lower() == 'date'), None)
    message_id_header = next((h for h in parsed if h['key'].lower() == 'message-id'), None)
    return_path_header = next((h for h in parsed if h['key'].lower() == 'return-path'), None)
    reply_to_header = next((h for h in parsed if h['key'].lower() == 'reply-to'), None)
    received_headers = [h for h in parsed if h['key'].lower() == 'received']
    
    # Auth headers
    spf_header = next((h for h in parsed if 'spf' in h['key'].lower() or ('spf' in h.get('value','').lower() and 'authentication' in h['key'].lower())), None)
    dkim_header = next((h for h in parsed if 'dkim' in h['key'].lower() or ('dkim' in h.get('value','').lower() and 'authentication' in h['key'].lower())), None)
    dmarc_header = next((h for h in parsed if 'dmarc' in h['key'].lower() or ('dmarc' in h.get('value','').lower() and 'authentication' in h['key'].lower())), None)
    
    # Also check Authentication-Results for combined auth info
    auth_results_header = next((h for h in parsed if h['key'].lower() == 'authentication-results'), None)
    if auth_results_header:
        av = auth_results_header['value'].lower()
        if not spf_header and 'spf=' in av:
            spf_header = {'key': 'Authentication-Results', 'value': auth_results_header['value'], 'analysis': '', 'status': 'info'}
        if not dkim_header and 'dkim=' in av:
            dkim_header = {'key': 'Authentication-Results', 'value': auth_results_header['value'], 'analysis': '', 'status': 'info'}
        if not dmarc_header and 'dmarc=' in av:
            dmarc_header = {'key': 'Authentication-Results', 'value': auth_results_header['value'], 'analysis': '', 'status': 'info'}
    
    def _auth_status(header, keyword):
        if not header:
            return 'Not Found'
        val = header['value'].lower()
        # Check for keyword=pass pattern (Authentication-Results format)
        if f'{keyword}=pass' in val.replace(' ', ''):
            return 'Pass'
        if 'pass' in val and keyword in val:
            return 'Pass'
        if 'fail' in val or 'softfail' in val:
            return 'Fail'
        if 'neutral' in val or 'none' in val:
            return 'Neutral'
        return 'Unknown'
    
    spf_status = _auth_status(spf_header, 'spf')
    dkim_status = _auth_status(dkim_header, 'dkim')
    dmarc_status = _auth_status(dmarc_header, 'dmarc')
    
    # Extract SPF/DKIM/DMARC detail text
    def _auth_detail(header, keyword):
        if not header:
            return None
        val = header['value']
        # Try to extract the relevant part
        parts = val.split(';')
        for part in parts:
            if keyword in part.lower():
                return part.strip()
        return val[:200]
    
    spf_detail = _auth_detail(spf_header, 'spf')
    dkim_detail = _auth_detail(dkim_header, 'dkim')
    dmarc_detail = _auth_detail(dmarc_header, 'dmarc')
    
    # --- Routing trace from Received headers ---
    routing = []
    ip_pattern = re.compile(r'\[?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]?')
    ipv6_pattern = re.compile(r'\[?((?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4})\]?')
    from_by_pattern = re.compile(r'from\s+([\w.\-]+)', re.IGNORECASE)
    by_pattern = re.compile(r'by\s+([\w.\-]+)', re.IGNORECASE)
    
    for idx, rh in enumerate(reversed(received_headers)):  # reverse: bottom = first hop
        val = rh['value']
        
        # Extract from/by hostnames
        from_match = from_by_pattern.search(val)
        by_match = by_pattern.search(val)
        
        # Extract IP
        ip_match = ip_pattern.search(val)
        ipv6_match = ipv6_pattern.search(val)
        ip_addr = ip_match.group(1) if ip_match else (ipv6_match.group(1) if ipv6_match else None)
        
        # Extract timestamp - look for date after semicolon
        timestamp_str = None
        timestamp_dt = None
        if ';' in val:
            ts_part = val.split(';')[-1].strip()
            try:
                timestamp_dt = parsedate_to_datetime(ts_part)
                timestamp_str = timestamp_dt.isoformat()
            except Exception:
                timestamp_str = ts_part[:60]
        
        # Extract protocol info (with ESMTPS, SMTP, etc.)
        proto_match = re.search(r'with\s+(\w+)', val, re.IGNORECASE)
        protocol = proto_match.group(1) if proto_match else None
        tls = bool(protocol and ('tls' in protocol.lower() or protocol.upper() in ('ESMTPS', 'SMTPS')))
        
        hop = {
            'hop': idx + 1,
            'from_host': from_match.group(1) if from_match else None,
            'by_host': by_match.group(1) if by_match else None,
            'ip': ip_addr,
            'timestamp': timestamp_str,
            'protocol': protocol,
            'tls': tls,
            'delay_seconds': None,
            'raw': val[:300]
        }
        routing.append(hop)
    
    # Calculate delays between hops
    for i in range(1, len(routing)):
        prev_ts = routing[i-1].get('timestamp')
        curr_ts = routing[i].get('timestamp')
        if prev_ts and curr_ts:
            try:
                prev_dt = datetime.fromisoformat(prev_ts)
                curr_dt = datetime.fromisoformat(curr_ts)
                delay = (curr_dt - prev_dt).total_seconds()
                routing[i]['delay_seconds'] = max(0, delay)
            except Exception:
                pass
    
    total_delay = sum(h.get('delay_seconds', 0) or 0 for h in routing)
    
    # --- Threat detection ---
    threats = []
    
    # 1. Domain mismatch: From vs Return-Path
    def _extract_domain(addr):
        if not addr:
            return None
        match = re.search(r'@([\w.\-]+)', addr)
        return match.group(1).lower() if match else None
    
    from_domain = _extract_domain(from_header['value'] if from_header else '')
    return_path_domain = _extract_domain(return_path_header['value'] if return_path_header else '')
    reply_to_domain = _extract_domain(reply_to_header['value'] if reply_to_header else '')
    
    if from_domain and return_path_domain and from_domain != return_path_domain:
        threats.append({
            'type': 'DOMAIN_MISMATCH',
            'severity': 'high',
            'description': f'From domain ({from_domain}) differs from Return-Path domain ({return_path_domain}). This may indicate spoofing or a mailing list.'
        })
    
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        threats.append({
            'type': 'REPLY_TO_MISMATCH',
            'severity': 'medium',
            'description': f'Reply-To domain ({reply_to_domain}) differs from From domain ({from_domain}). Replies will go to a different address.'
        })
    
    # 2. Missing authentication
    if spf_status == 'Not Found':
        threats.append({
            'type': 'MISSING_SPF',
            'severity': 'medium',
            'description': 'No SPF authentication found. Cannot verify sender authorization.'
        })
    elif spf_status == 'Fail':
        threats.append({
            'type': 'SPF_FAIL',
            'severity': 'high',
            'description': 'SPF check failed. The sending server is NOT authorized to send from this domain.'
        })
    
    if dkim_status == 'Not Found':
        threats.append({
            'type': 'MISSING_DKIM',
            'severity': 'medium',
            'description': 'No DKIM signature found. Cannot verify message integrity.'
        })
    elif dkim_status == 'Fail':
        threats.append({
            'type': 'DKIM_FAIL',
            'severity': 'high',
            'description': 'DKIM verification failed. The email content may have been tampered with.'
        })
    
    if dmarc_status == 'Not Found':
        threats.append({
            'type': 'MISSING_DMARC',
            'severity': 'low',
            'description': 'No DMARC policy found. Domain owner has not published anti-spoofing policy.'
        })
    elif dmarc_status == 'Fail':
        threats.append({
            'type': 'DMARC_FAIL',
            'severity': 'high',
            'description': 'DMARC check failed. This email violates the domain\'s authentication policy.'
        })
    
    # 3. Suspicious X-Mailer
    xmailer = next((h for h in parsed if h['key'].lower() == 'x-mailer'), None)
    if xmailer:
        suspicious_mailers = ['mass mailer', 'bulk', 'phpmailer', 'swiftmailer']
        if any(sm in xmailer['value'].lower() for sm in suspicious_mailers):
            threats.append({
                'type': 'SUSPICIOUS_MAILER',
                'severity': 'medium',
                'description': f'Suspicious mail client detected: {xmailer["value"][:80]}. Commonly used for bulk/spam.'
            })
    
    # 4. No TLS in routing
    unencrypted_hops = [h for h in routing if not h.get('tls') and h.get('protocol')]
    if unencrypted_hops:
        threats.append({
            'type': 'UNENCRYPTED_HOP',
            'severity': 'low',
            'description': f'{len(unencrypted_hops)} hop(s) used unencrypted transmission ({", ".join(h.get("protocol","?") for h in unencrypted_hops[:3])}). Email content may have been exposed.'
        })
    
    # 5. Excessive hops
    if len(routing) > 8:
        threats.append({
            'type': 'EXCESSIVE_HOPS',
            'severity': 'low',
            'description': f'Email passed through {len(routing)} server hops. Unusually high hop count may indicate relaying.'
        })
    
    # 6. Long delay
    if total_delay > 600:  # > 10 minutes
        threats.append({
            'type': 'DELIVERY_DELAY',
            'severity': 'low',
            'description': f'Total delivery time was {int(total_delay)}s ({int(total_delay/60)} min). Significant delays may indicate greylisting or suspicious routing.'
        })
    
    # 7. X-Spam headers
    spam_header = next((h for h in parsed if 'spam' in h['key'].lower()), None)
    if spam_header and ('yes' in spam_header['value'].lower() or 'true' in spam_header['value'].lower()):
        threats.append({
            'type': 'FLAGGED_SPAM',
            'severity': 'high',
            'description': f'Email was flagged as spam by upstream server ({spam_header["key"]}: {spam_header["value"][:80]})'
        })
    
    # --- Trust score calculation (0-100) ---
    trust_score = 100
    # Auth penalties
    auth_map = {'Pass': 0, 'Fail': -25, 'Not Found': -8, 'Neutral': -5, 'Unknown': -5}
    trust_score += auth_map.get(spf_status, 0)
    trust_score += auth_map.get(dkim_status, 0)
    trust_score += auth_map.get(dmarc_status, 0)
    # Threat penalties
    severity_penalty = {'high': -12, 'medium': -6, 'low': -3}
    for t in threats:
        trust_score += severity_penalty.get(t['severity'], -3)
    trust_score = max(0, min(100, trust_score))
    
    # Grade
    if trust_score >= 90: trust_grade = 'A'
    elif trust_score >= 75: trust_grade = 'B'
    elif trust_score >= 60: trust_grade = 'C'
    elif trust_score >= 40: trust_grade = 'D'
    else: trust_grade = 'F'
    
    # --- Build summary ---
    summary = {
        'from': from_header['value'] if from_header else 'Unknown',
        'to': to_header['value'] if to_header else 'Unknown',
        'subject': subject_header['value'] if subject_header else 'N/A',
        'date': date_header['value'] if date_header else 'Unknown',
        'message_id': message_id_header['value'].strip() if message_id_header else None,
        'return_path': return_path_header['value'] if return_path_header else None,
        'hops': len(received_headers),
        'spf': spf_status,
        'dkim': dkim_status,
        'dmarc': dmarc_status,
        'spf_detail': spf_detail,
        'dkim_detail': dkim_detail,
        'dmarc_detail': dmarc_detail,
        'trust_score': trust_score,
        'trust_grade': trust_grade,
        'total_delay_seconds': total_delay,
    }
    
    result_data = {
        'headers': parsed,
        'summary': summary,
        'routing': routing,
        'threats': threats,
        'total_headers': len(parsed)
    }
    
    # Save to history
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="EMAIL_HEADERS",
        target=summary['from'][:100] if summary['from'] else "Email Analysis",
        result=json.dumps(result_data)
    )
    session.add(scan)
    session.commit()
    
    return result_data


def analyze_email_header(key: str, value: str) -> dict:
    """Comprehensive individual header analysis"""
    key_lower = key.lower()
    status = 'info'
    analysis = ''
    category = 'general'
    
    # --- Sender/Recipient ---
    if key_lower == 'from':
        analysis = 'Sender email address — verify this matches the expected sender domain'
        category = 'sender'
    elif key_lower == 'to':
        analysis = 'Primary recipient(s) of this email'
        category = 'sender'
    elif key_lower == 'cc':
        analysis = 'Carbon copy recipients — visible to all recipients'
        category = 'sender'
    elif key_lower == 'bcc':
        analysis = 'Blind carbon copy — hidden from other recipients. Unusual to see in headers.'
        status = 'warning'
        category = 'sender'
    elif key_lower == 'reply-to':
        analysis = 'Reply address — verify it matches the From address. Mismatches may indicate phishing.'
        status = 'warning'
        category = 'sender'
    elif key_lower == 'return-path':
        analysis = 'Bounce address (envelope sender). Mismatches with From may indicate forwarding or spoofing.'
        category = 'sender'
    elif key_lower == 'sender':
        analysis = 'Actual sender when different from From header (e.g., mailing lists)'
        category = 'sender'
    
    # --- Routing ---
    elif key_lower == 'received':
        analysis = 'Mail server hop in delivery chain — shows the path the email traveled'
        category = 'routing'
    
    # --- Authentication ---
    elif key_lower == 'received-spf' or (key_lower == 'authentication-results' and 'spf' in value.lower()) or 'spf' in key_lower:
        category = 'auth'
        if 'pass' in value.lower():
            status = 'safe'
            analysis = 'SPF check passed — the sending server IS authorized to send for this domain'
        elif 'fail' in value.lower() or 'softfail' in value.lower():
            status = 'danger'
            analysis = 'SPF check FAILED — the sending server is NOT authorized. Possible spoofing!'
        elif 'neutral' in value.lower():
            status = 'warning'
            analysis = 'SPF result neutral — domain does not assert authorization'
        else:
            status = 'warning'
            analysis = 'SPF result inconclusive'
    elif 'dkim' in key_lower or (key_lower == 'authentication-results' and 'dkim' in value.lower()):
        category = 'auth'
        if 'pass' in value.lower():
            status = 'safe'
            analysis = 'DKIM signature verified — message integrity confirmed, not tampered'
        elif 'fail' in value.lower():
            status = 'danger'
            analysis = 'DKIM verification FAILED — the message may have been altered in transit!'
        else:
            status = 'warning'
            analysis = 'DKIM result inconclusive'
    elif 'dmarc' in key_lower or (key_lower == 'authentication-results' and 'dmarc' in value.lower()):
        category = 'auth'
        if 'pass' in value.lower():
            status = 'safe'
            analysis = 'DMARC policy passed — domain authentication policy satisfied'
        elif 'fail' in value.lower():
            status = 'danger'
            analysis = 'DMARC check FAILED — violates domain anti-spoofing policy!'
        else:
            status = 'warning'
            analysis = 'DMARC check did not pass clearly'
    elif key_lower == 'authentication-results':
        category = 'auth'
        analysis = 'Combined authentication results (SPF, DKIM, DMARC) from receiving server'
        if 'fail' in value.lower():
            status = 'danger'
        elif 'pass' in value.lower():
            status = 'safe'
    elif key_lower.startswith('arc-'):
        category = 'auth'
        analysis = 'Authenticated Received Chain — preserves authentication across forwarding'
    
    # --- Content/Structure ---
    elif key_lower == 'subject':
        analysis = 'Email subject line'
        category = 'content'
    elif key_lower == 'date':
        analysis = 'Date and time the email was composed by the sender'
        category = 'content'
    elif key_lower == 'message-id':
        analysis = 'Unique message identifier — can be used to trace the email across servers'
        category = 'content'
    elif key_lower == 'in-reply-to':
        analysis = 'Message-ID of the email this is replying to'
        category = 'content'
    elif key_lower == 'references':
        analysis = 'Thread chain — Message-IDs of previous messages in the conversation'
        category = 'content'
    elif key_lower == 'content-type':
        analysis = 'MIME type of the email content'
        category = 'content'
        if 'multipart/mixed' in value.lower():
            analysis += ' — contains attachments'
        elif 'multipart/alternative' in value.lower():
            analysis += ' — HTML + plaintext versions'
    elif key_lower == 'content-transfer-encoding':
        analysis = 'Encoding used for the email body (base64, quoted-printable, etc.)'
        category = 'content'
    elif key_lower == 'mime-version':
        analysis = 'MIME protocol version used'
        category = 'content'
    
    # --- Security/Spam ---
    elif key_lower == 'x-originating-ip':
        analysis = 'Original sender IP address — may reveal sender\'s true location'
        status = 'warning'
        category = 'security'
    elif key_lower in ('x-spam-status', 'x-spam-flag'):
        category = 'security'
        if 'yes' in value.lower() or 'true' in value.lower():
            status = 'danger'
            analysis = 'This email was FLAGGED AS SPAM by the upstream mail server'
        else:
            status = 'safe'
            analysis = 'Email passed spam check'
    elif key_lower == 'x-spam-score':
        category = 'security'
        analysis = 'Spam score assigned by the mail server'
        try:
            score_val = float(value.strip())
            if score_val > 5:
                status = 'danger'
                analysis += f' — HIGH score ({score_val}), likely spam'
            elif score_val > 2:
                status = 'warning'
                analysis += f' — moderate score ({score_val})'
            else:
                status = 'safe'
                analysis += f' — low score ({score_val}), appears legitimate'
        except ValueError:
            pass
    elif key_lower == 'x-mailer' or key_lower == 'user-agent':
        category = 'security'
        analysis = f'Mail client used to send this email: {value[:60]}'
        suspicious = ['phpmailer', 'swiftmailer', 'mass', 'bulk']
        if any(s in value.lower() for s in suspicious):
            status = 'warning'
            analysis += ' — SUSPICIOUS: commonly used for bulk/spam email'
    elif key_lower == 'x-forefront-antispam-report':
        category = 'security'
        analysis = 'Microsoft Exchange anti-spam report'
    elif key_lower == 'x-ms-exchange-organization-scl':
        category = 'security'
        analysis = 'Microsoft Spam Confidence Level'
        try:
            scl = int(value.strip())
            if scl >= 6:
                status = 'danger'
                analysis += f' — SCL {scl}: High spam probability'
            elif scl >= 3:
                status = 'warning'
                analysis += f' — SCL {scl}: Moderate'
            else:
                status = 'safe'
                analysis += f' — SCL {scl}: Low spam risk'
        except ValueError:
            pass
    
    # --- Mailing list ---
    elif key_lower == 'list-unsubscribe':
        category = 'general'
        analysis = 'Unsubscribe link — indicates this is a mailing list or newsletter'
    elif key_lower == 'list-id':
        category = 'general'
        analysis = 'Mailing list identifier'
    elif key_lower == 'precedence':
        category = 'general'
        analysis = f'Message priority class: {value.strip()}'
    
    # --- Misc ---
    elif key_lower == 'x-google-dkim-signature':
        category = 'auth'
        status = 'safe'
        analysis = 'Google internal DKIM signature for additional verification'
    elif key_lower == 'x-gm-message-state':
        category = 'general'
        analysis = 'Internal Gmail message state tracking'
    elif key_lower == 'x-google-smtp-source':
        category = 'general'
        analysis = 'Google SMTP source identifier'
    elif key_lower == 'x-received':
        category = 'routing'
        analysis = 'Internal Google mail server routing information'
    elif key_lower.startswith('x-'):
        category = 'general'
        analysis = f'Non-standard extension header ({key})'
    
    if not analysis:
        analysis = f'Standard email header'
    
    return {'key': key, 'value': value, 'analysis': analysis, 'status': status, 'category': category}

@router.get("/security-headers")
def check_security_headers(
    url: str,
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    """Check HTTP security headers for a given URL"""
    import requests
    from urllib.parse import urlparse
    
    # Validate URL
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return {"error": "Invalid URL format"}
    except Exception:
        return {"error": "Invalid URL format"}
    
    # Security headers to check
    security_headers = {
        'Strict-Transport-Security': {
            'description': 'Enforces HTTPS connections',
            'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'Content-Security-Policy': {
            'description': 'Prevents XSS and injection attacks',
            'recommendation': "Add CSP header: default-src 'self'"
        },
        'X-Frame-Options': {
            'description': 'Prevents clickjacking attacks',
            'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN'
        },
        'X-Content-Type-Options': {
            'description': 'Prevents MIME-type sniffing',
            'recommendation': 'Add: X-Content-Type-Options: nosniff'
        },
        'X-XSS-Protection': {
            'description': 'Legacy XSS filter',
            'recommendation': 'Add: X-XSS-Protection: 1; mode=block'
        },
        'Referrer-Policy': {
            'description': 'Controls referrer information',
            'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin'
        },
        'Permissions-Policy': {
            'description': 'Controls browser features access',
            'recommendation': 'Add feature restrictions for camera, microphone, geolocation'
        },
        'X-Permitted-Cross-Domain-Policies': {
            'description': 'Controls Adobe Flash/PDF cross-domain access',
            'recommendation': 'Add: X-Permitted-Cross-Domain-Policies: none'
        }
    }
    
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        response = requests.get(url, timeout=20, allow_redirects=True, verify=False, headers=headers)
        headers = response.headers
        
        results = []
        present_count = 0
        
        for header_name, info in security_headers.items():
            value = headers.get(header_name)
            status = 'present' if value else 'missing'
            if status == 'present':
                present_count += 1
            
            results.append({
                'name': header_name,
                'value': value,
                'status': status,
                'description': info['description'],
                'recommendation': info['recommendation'] if not value else None
            })
        
        score = round((present_count / len(security_headers)) * 100)
        
        # Google Safe Browsing check
        google_safe_browsing = {"status": "NOT_CONFIGURED"}
        try:
            from app.core.config import settings
            gsb_key = settings.GOOGLE_SAFE_BROWSING_KEY
            if gsb_key:
                gsb_resp = requests.post(
                    f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb_key}',
                    json={
                        "client": {"clientId": "genesis", "clientVersion": "1.0"},
                        "threatInfo": {
                            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [{"url": url}]
                        }
                    },
                    timeout=5
                )
                if gsb_resp.status_code == 200:
                    gsb_data = gsb_resp.json()
                    if gsb_data.get('matches'):
                        threats_found = [m.get('threatType', 'UNKNOWN') for m in gsb_data['matches']]
                        google_safe_browsing = {"status": "THREAT_FOUND", "threats": threats_found}
                    else:
                        google_safe_browsing = {"status": "CLEAN"}
                else:
                    google_safe_browsing = {"status": "CHECK_FAILED"}
        except Exception as e:
            google_safe_browsing = {"status": "CHECK_FAILED", "error": str(e)[:80]}
        
        result_data = {
            'url': url,
            'final_url': response.url,
            'status_code': response.status_code,
            'headers': results,
            'score': score,
            'present_count': present_count,
            'missing_count': len(security_headers) - present_count,
            'google_safe_browsing': google_safe_browsing
        }
        
        # Save to history
        scan = ScanHistory(
            user_id=current_user.id,
            scan_type="SECURITY_HEADERS",
            target=url,
            result=json.dumps(result_data)
        )
        session.add(scan)
        session.commit()
        
        return result_data
        
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.SSLError:
        return {"error": "SSL certificate verification failed"}
    except requests.exceptions.ConnectionError:
        return {"error": "Could not connect to the URL"}
    except Exception as e:
        return {"error": f"Failed to check headers: {str(e)}"}


@router.get("/phishing-check")
def check_phishing(
    url: str,
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    """Aggressive phishing analysis with 12-phase scanning pipeline"""
    from app.core.phishing_scanner_service import phishing_analyzer
    
    result_data = phishing_analyzer.analyze(url)
    
    # Save to history
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="PHISHING_CHECK",
        target=url,
        result=json.dumps(result_data)
    )
    session.add(scan)
    session.commit()
    
    return result_data


@router.get("/browser-extensions")
def scan_browser_extensions(
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session)
):
    """Scan installed browser extensions and analyze security risks"""
    from datetime import datetime
    from app.core.extension_scanner_service import scan_all_extensions
    
    result = scan_all_extensions()
    result['scan_time'] = datetime.utcnow().isoformat()
    
    # Save to history
    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="BROWSER_EXTENSIONS",
        target=f"Browser Extensions ({result['summary']['total']} found)",
        result=json.dumps(result)
    )
    session.add(scan)
    session.commit()
    
    return result

@router.get("/ssl-check")
def ssl_check(
    domain: str,
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session),
):
    """Check SSL/TLS certificate details for a domain."""
    import ssl
    import socket
    from datetime import datetime
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        parsed = urlparse(domain)
        domain = parsed.netloc or parsed.path.split("/")[0]
    domain = domain.split("/")[0].split(":")[0]

    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.create_connection((domain, 443), timeout=10),
            server_hostname=domain,
        )
        der_cert = conn.getpeercert(binary_form=True)
        conn.close()
    except Exception as e:
        result = {
            "domain": domain, "valid": False, "error": str(e),
            "cert_details": None, "grade": "F",
            "days_remaining": None, "is_expired": None,
        }
        scan = ScanHistory(
            user_id=current_user.id, scan_type="SSL_CHECK",
            target=domain, result=json.dumps(result),
        )
        session.add(scan)
        session.commit()
        return result

    cert = x509.load_der_x509_certificate(der_cert, default_backend())

    not_before = cert.not_valid_before
    not_after  = cert.not_valid_after
    try:
        not_before = cert.not_valid_before_utc.replace(tzinfo=None)
        not_after  = cert.not_valid_after_utc.replace(tzinfo=None)
    except AttributeError:
        pass

    now = datetime.utcnow()
    days_remaining = (not_after - now).days
    is_expired = days_remaining < 0

    def _cn(name_obj):
        try:
            return name_obj.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            return None

    def _org(name_obj):
        try:
            return name_obj.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)[0].value
        except Exception:
            return None

    sans = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = list(san_ext.value.get_values_for_type(x509.DNSName))
    except Exception:
        pass

    try:
        sig_algo = cert.signature_hash_algorithm.name
    except Exception:
        sig_algo = "Unknown"

    if is_expired:
        grade = "F"
    elif days_remaining < 14:
        grade = "D"
    elif days_remaining < 30:
        grade = "C"
    elif days_remaining < 90:
        grade = "B"
    else:
        grade = "A"

    result = {
        "domain": domain,
        "valid": not is_expired,
        "grade": grade,
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "cert_details": {
            "issued_to_cn": _cn(cert.subject),
            "issued_to_org": _org(cert.subject),
            "issued_by_cn": _cn(cert.issuer),
            "issued_by_org": _org(cert.issuer),
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "serial_number": str(cert.serial_number),
            "signature_algorithm": sig_algo,
            "version": str(cert.version),
            "sans": sans[:30],
            "san_count": len(sans),
        },
    }

    scan = ScanHistory(
        user_id=current_user.id, scan_type="SSL_CHECK",
        target=domain, result=json.dumps(result, default=str),
    )
    session.add(scan)
    session.commit()
    return result

