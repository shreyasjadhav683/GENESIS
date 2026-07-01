from fastapi import APIRouter, Depends, HTTPException
import json
from sqlmodel import Session
from app.core.db import get_session
from app.api import deps
from app.models.user import User
from app.models.scan_history import ScanHistory

router = APIRouter()


def _clean(val):
    """Recursively convert non-serializable types to strings."""
    if val is None:
        return None
    if isinstance(val, list):
        return [_clean(v) for v in val]
    if isinstance(val, dict):
        return {k: _clean(v) for k, v in val.items()}
    if isinstance(val, (int, float, bool)):
        return val
    try:
        import datetime
        if isinstance(val, (datetime.datetime, datetime.date)):
            return val.isoformat()
    except Exception:
        pass
    return str(val)


@router.get("/whois")
def whois_lookup(
    domain: str,
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session),
):
    """Perform a WHOIS lookup for a domain."""
    import whois as pythonwhois

    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc or domain

    try:
        w = pythonwhois.whois(domain)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"WHOIS lookup failed: {str(e)}")

    # Normalize multi-value fields
    def _first(v):
        if isinstance(v, list):
            return v[0] if v else None
        return v

    def _list(v):
        if v is None:
            return []
        if isinstance(v, list):
            return v
        return [v]

    import datetime

    creation = _first(w.creation_date)
    expiry = _first(w.expiration_date)
    updated = _first(w.updated_date)

    days_until_expiry = None
    is_expired = False
    if expiry:
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        if isinstance(expiry, datetime.datetime):
            # Ensure both sides are offset-aware
            if expiry.tzinfo is None:
                expiry_aware = expiry.replace(tzinfo=datetime.timezone.utc)
            else:
                expiry_aware = expiry
        else:
            expiry_aware = datetime.datetime(expiry.year, expiry.month, expiry.day, tzinfo=datetime.timezone.utc)
        delta = expiry_aware - now_utc
        days_until_expiry = int(delta.total_seconds() / 86400)
        is_expired = days_until_expiry < 0

    result = {
        "domain": domain,
        "registrar": _first(w.registrar),
        "whois_server": _first(w.whois_server),
        "creation_date": creation.isoformat() if isinstance(creation, (datetime.datetime, datetime.date)) else str(creation) if creation else None,
        "expiration_date": expiry.isoformat() if isinstance(expiry, (datetime.datetime, datetime.date)) else str(expiry) if expiry else None,
        "updated_date": updated.isoformat() if isinstance(updated, (datetime.datetime, datetime.date)) else str(updated) if updated else None,
        "days_until_expiry": days_until_expiry,
        "is_expired": is_expired,
        "name_servers": [str(ns).lower() for ns in _list(w.name_servers)],
        "status": _list(w.status),
        "emails": _list(w.emails),
        "org": _first(w.org),
        "country": _first(w.country),
        "state": _first(w.state),
        "city": _first(w.city),
        "address": _first(w.address),
        "dnssec": str(_first(w.dnssec)) if w.dnssec else None,
        "name": _first(w.name),
    }

    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="WHOIS_LOOKUP",
        target=domain,
        result=json.dumps(_clean(result)),
    )
    session.add(scan)
    session.commit()

    return result


@router.get("/dns")
def dns_lookup(
    domain: str,
    current_user: User = Depends(deps.get_current_user),
    session: Session = Depends(get_session),
):
    """Perform a DNS lookup — resolves A, AAAA, MX, NS, TXT, CNAME, SOA records."""
    import dns.resolver
    import dns.exception

    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc or domain

    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 8

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "MX":
                records[rtype] = [
                    {"preference": r.preference, "exchange": str(r.exchange).rstrip(".")}
                    for r in answers
                ]
            elif rtype == "SOA":
                r = answers[0]
                records[rtype] = [{
                    "mname": str(r.mname).rstrip("."),
                    "rname": str(r.rname).rstrip("."),
                    "serial": r.serial,
                    "refresh": r.refresh,
                    "retry": r.retry,
                    "expire": r.expire,
                    "minimum": r.minimum,
                    "ttl": answers.rrset.ttl if answers.rrset else None,
                }]
            elif rtype == "TXT":
                records[rtype] = [b"".join(r.strings).decode("utf-8", errors="replace") for r in answers]
            else:
                records[rtype] = [{"value": str(r).rstrip("."), "ttl": answers.rrset.ttl if answers.rrset else None} for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            records[rtype] = []
        except Exception:
            records[rtype] = []

    # IP count summary
    total_ips = len(records.get("A", [])) + len(records.get("AAAA", []))
    total_mx = len(records.get("MX", []))
    total_ns = len(records.get("NS", []))

    result = {
        "domain": domain,
        "records": records,
        "summary": {
            "total_a_records": len(records.get("A", [])),
            "total_aaaa_records": len(records.get("AAAA", [])),
            "total_mx_records": total_mx,
            "total_ns_records": total_ns,
            "total_txt_records": len(records.get("TXT", [])),
            "has_cname": len(records.get("CNAME", [])) > 0,
            "has_ipv6": len(records.get("AAAA", [])) > 0,
            "total_ips": total_ips,
        },
    }

    scan = ScanHistory(
        user_id=current_user.id,
        scan_type="DNS_LOOKUP",
        target=domain,
        result=json.dumps(_clean(result)),
    )
    session.add(scan)
    session.commit()

    return result
