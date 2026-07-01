import socket
import requests
import re
import ssl
import datetime
import hashlib
import time
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class PhishingScanResult:
    url: str = ""
    final_url: str = ""
    domain: str = ""
    ip_address: str = ""
    status_code: int = 0
    is_phishing: bool = False
    risk_score: int = 0
    risk_level: str = "LOW"
    verdict: str = ""
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    domain_info: Dict[str, Any] = field(default_factory=dict)
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    content_analysis: Dict[str, Any] = field(default_factory=dict)
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    security_headers: Dict[str, Any] = field(default_factory=dict)
    flags: List[str] = field(default_factory=list)
    scan_phases: List[Dict[str, Any]] = field(default_factory=list)
    timestamp: str = ""


class PhishingAnalyzerService:
    def __init__(self):
        self.suspicious_keywords = [
            "login", "signin", "sign-in", "verify", "account", "banking", "secure",
            "update", "confirm", "wallet", "password", "credential",
            "paypal", "amazon", "microsoft", "apple", "google", "facebook",
            "suspended", "unusual", "alert", "urgent", "click-here",
            "validate", "restore", "unlock", "reactivate", "expire"
        ]

        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work',
            '.click', '.link', '.loan', '.win', '.racing', '.download',
            '.stream', '.party', '.gdn', '.review', '.date', '.trade',
            '.bid', '.webcam', '.science', '.accountant', '.faith',
            '.zip', '.mov', '.php'
        ]

        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'j.mp', 'shorte.st', 'adf.ly',
            'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc'
        ]

        self.phishing_patterns = [
            r'(?:paypal|amazon|apple|google|microsoft|facebook|netflix|bank)[-._]',
            r'(?:secure|verify|update|confirm)[-._](?:account|login|info)',
            r'\d{2,}[-._](?:login|account|verify)',
            r'(?:login|account|verify)[-._]\d{2,}',
        ]

        self.known_brands = {
            'google': ['google.com', 'google.co.in', 'googleapis.com', 'gstatic.com'],
            'facebook': ['facebook.com', 'fb.com', 'fbcdn.net'],
            'amazon': ['amazon.com', 'amazon.in', 'amazonaws.com'],
            'microsoft': ['microsoft.com', 'live.com', 'outlook.com', 'office.com'],
            'apple': ['apple.com', 'icloud.com'],
            'paypal': ['paypal.com', 'paypal.me'],
            'netflix': ['netflix.com'],
            'instagram': ['instagram.com'],
            'twitter': ['twitter.com', 'x.com'],
            'linkedin': ['linkedin.com'],
            'whatsapp': ['whatsapp.com'],
            'dropbox': ['dropbox.com'],
            'chase': ['chase.com'],
            'wellsfargo': ['wellsfargo.com'],
            'bankofamerica': ['bankofamerica.com'],
            'hdfc': ['hdfcbank.com'],
            'sbi': ['sbi.co.in', 'onlinesbi.com'],
            'icici': ['icicibank.com'],
        }

        self.malware_patterns = {
            "crypto_miner": [
                r'coinhive\.min\.js', r'cryptoloot\.pro', r'coin-hive\.com',
                r'jsecoin\.com', r'authedmine\.com', r'crypto-loot\.com',
                r'CryptoNoter', r'minero\.cc', r'webmine\.pro',
                r'new\s+CoinHive', r'miner\.start', r'startMining'
            ],
            "obfuscation": [
                r'eval\s*\(\s*unescape', r'eval\s*\(\s*atob',
                r'document\.write\s*\(\s*unescape', r'String\.fromCharCode\s*\(',
                r'eval\s*\(\s*function\s*\(p,a,c,k,e',
                r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}',
            ],
            "data_exfiltration": [
                r'navigator\.sendBeacon', r'new\s+Image\(\)\.src\s*=',
                r'XMLHttpRequest.*password', r'fetch\(.*credential',
                r'document\.cookie',
            ],
        }

        self.security_headers_checks = {
            'Strict-Transport-Security': {'weight': 15, 'description': 'Enforces HTTPS'},
            'Content-Security-Policy': {'weight': 20, 'description': 'Prevents XSS'},
            'X-Frame-Options': {'weight': 12, 'description': 'Prevents clickjacking'},
            'X-Content-Type-Options': {'weight': 12, 'description': 'Prevents MIME sniffing'},
            'X-XSS-Protection': {'weight': 8, 'description': 'Legacy XSS filter'},
            'Referrer-Policy': {'weight': 10, 'description': 'Controls referrer leakage'},
            'Permissions-Policy': {'weight': 13, 'description': 'Controls browser features'},
        }

        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    # ── public entry point ──────────────────────────────────────────────
    def analyze(self, url: str) -> dict:
        """Performs aggressive, comprehensive phishing analysis of the URL."""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        result = PhishingScanResult()
        result.url = url
        result.timestamp = datetime.datetime.utcnow().isoformat()

        parsed = urlparse(url)
        result.domain = parsed.netloc
        result.final_url = url

        phases = [
            ("URL Structure Analysis", self._analyze_url_structure),
            ("Connection Analysis", self._analyze_connection),
            ("DNS Resolution", self._analyze_dns),
            ("SSL/TLS Inspection", self._analyze_ssl),
            ("Domain Age (WHOIS)", self._check_domain_age),
            ("Security Headers", self._analyze_security_headers),
            ("HTML Content Analysis", self._inspect_html),
            ("Login Form Detection", self._detect_login_forms),
            ("Brand Similarity", self._check_brand_similarity),
            ("Malware Signatures", self._scan_malware_signatures),
            ("Threat Intelligence", self._check_threat_intel),
            ("Google Safe Browsing", self._check_google_safe_browsing),
        ]

        for phase_name, phase_fn in phases:
            start = time.time()
            try:
                phase_fn(url, result)
                elapsed = int((time.time() - start) * 1000)
                result.scan_phases.append({"name": phase_name, "status": "done", "time_ms": elapsed})
            except Exception as e:
                elapsed = int((time.time() - start) * 1000)
                logger.warning(f"Phase '{phase_name}' failed: {e}")
                result.scan_phases.append({"name": phase_name, "status": "error", "time_ms": elapsed, "error": str(e)[:80]})

        self._calculate_risk(result)
        return self._to_dict(result)

    # ── Phase 1: URL Structure ──────────────────────────────────────────
    def _analyze_url_structure(self, url: str, result: PhishingScanResult):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = domain + path

        # Suspicious TLD
        if any(domain.endswith(tld) for tld in self.suspicious_tlds):
            result.indicators.append({
                'name': 'Suspicious TLD',
                'detected': True, 'severity': 'medium', 'category': 'url',
                'description': f'Domain uses a suspicious top-level domain'
            })
            result.risk_score += 20

        # IP address domain
        if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            result.indicators.append({
                'name': 'IP Address Domain',
                'detected': True, 'severity': 'high', 'category': 'url',
                'description': 'URL uses raw IP address instead of domain name'
            })
            result.risk_score += 30

        # Suspicious keywords in URL
        found_keywords = [kw for kw in self.suspicious_keywords if kw in full]
        if found_keywords:
            result.indicators.append({
                'name': 'Suspicious Keywords',
                'detected': True, 'severity': 'medium', 'category': 'url',
                'description': f'Keywords found: {", ".join(found_keywords[:6])}'
            })
            result.risk_score += min(10 * len(found_keywords), 25)

        # Excessive subdomains
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 2:
            result.indicators.append({
                'name': 'Excessive Subdomains',
                'detected': True, 'severity': 'medium', 'category': 'url',
                'description': f'{subdomain_count} subdomains detected'
            })
            result.risk_score += 15

        # URL shortener
        if any(s in domain for s in self.url_shorteners):
            result.indicators.append({
                'name': 'URL Shortener',
                'detected': True, 'severity': 'medium', 'category': 'url',
                'description': 'URL shortener hides final destination'
            })
            result.risk_score += 20

        # @ symbol
        if '@' in url:
            result.indicators.append({
                'name': '@ Symbol in URL',
                'detected': True, 'severity': 'high', 'category': 'url',
                'description': '@ symbol can trick browsers to display a fake domain'
            })
            result.risk_score += 35

        # HTTPS check
        if parsed.scheme != 'https':
            result.indicators.append({
                'name': 'No HTTPS',
                'detected': True, 'severity': 'medium', 'category': 'url',
                'description': 'Site does not use secure HTTPS connection'
            })
            result.risk_score += 15
        else:
            result.indicators.append({
                'name': 'HTTPS Enabled',
                'detected': False, 'severity': 'low', 'category': 'url',
                'description': 'Site uses secure HTTPS connection'
            })

        # Long domain
        if len(domain) > 30:
            result.indicators.append({
                'name': 'Long Domain Name',
                'detected': True, 'severity': 'low', 'category': 'url',
                'description': f'Domain is {len(domain)} characters long'
            })
            result.risk_score += 10

        # Homograph attack
        if not domain.isascii():
            result.indicators.append({
                'name': 'Homograph Attack',
                'detected': True, 'severity': 'high', 'category': 'url',
                'description': 'Non-ASCII characters used (possible lookalike attack)'
            })
            result.risk_score += 40

        # Phishing patterns
        for pattern in self.phishing_patterns:
            if re.search(pattern, domain):
                result.indicators.append({
                    'name': 'Phishing URL Pattern',
                    'detected': True, 'severity': 'high', 'category': 'url',
                    'description': 'Domain matches known phishing patterns'
                })
                result.risk_score += 25
                break

        # Hyphen abuse
        if domain.count('-') >= 3:
            result.indicators.append({
                'name': 'Hyphen Abuse',
                'detected': True, 'severity': 'medium', 'category': 'url',
                'description': f'{domain.count("-")} hyphens in domain name'
            })
            result.risk_score += 10

        # Double extension trick (.com-login, .html.php)
        if re.search(r'\.\w+\.\w+/', path) or re.search(r'\.com[.-]', domain):
            result.indicators.append({
                'name': 'Double Extension Trick',
                'detected': True, 'severity': 'medium', 'category': 'url',
                'description': 'Path or domain uses double extensions to mislead'
            })
            result.risk_score += 15

    # ── Phase 2: Connection Analysis ────────────────────────────────────
    def _analyze_connection(self, url: str, result: PhishingScanResult):
        try:
            headers = {"User-Agent": self.user_agent}
            start = datetime.datetime.now()
            response = requests.get(url, headers=headers, timeout=15, verify=False, allow_redirects=True)
            elapsed = int((datetime.datetime.now() - start).total_seconds() * 1000)

            result.final_url = response.url
            result.status_code = response.status_code
            result.security_headers = dict(response.headers)

            parsed_final = urlparse(result.final_url)
            result.domain = parsed_final.netloc

            result.content_analysis["load_time_ms"] = elapsed
            result.content_analysis["html"] = response.text[:200000]
            result.content_analysis["size"] = len(response.content)
            result.content_analysis["content_type"] = response.headers.get('Content-Type', 'unknown')

            # Redirect chain
            if response.history:
                for resp in response.history:
                    result.redirect_chain.append({
                        "url": resp.url,
                        "status": resp.status_code,
                        "reason": resp.reason
                    })
                    redirect_domain = urlparse(resp.url).netloc
                    if redirect_domain != result.domain:
                        result.flags.append(f"Cross-Domain Redirect: {redirect_domain}")
                        result.risk_score += 10

            if len(result.redirect_chain) > 3:
                result.indicators.append({
                    'name': 'Excessive Redirects',
                    'detected': True, 'severity': 'medium', 'category': 'connection',
                    'description': f'{len(result.redirect_chain)} redirects before landing page'
                })
                result.risk_score += 15

            # Final URL different domain
            original_domain = urlparse(url).netloc
            if original_domain != result.domain:
                result.indicators.append({
                    'name': 'Domain Changed After Redirect',
                    'detected': True, 'severity': 'high', 'category': 'connection',
                    'description': f'Redirected from {original_domain} → {result.domain}'
                })
                result.risk_score += 20

        except requests.exceptions.SSLError:
            result.flags.append("SSL Certificate Error")
            result.indicators.append({
                'name': 'SSL Error',
                'detected': True, 'severity': 'high', 'category': 'connection',
                'description': 'SSL certificate verification failed'
            })
            result.risk_score += 25
        except requests.exceptions.ConnectionError:
            result.flags.append("Connection Failed")
        except requests.exceptions.Timeout:
            result.flags.append("Connection Timeout")

    # ── Phase 3: DNS Resolution ─────────────────────────────────────────
    def _analyze_dns(self, url: str, result: PhishingScanResult):
        try:
            domain_part = result.domain.split(':')[0]
            ip = socket.gethostbyname(domain_part)
            result.ip_address = ip

            # Private IP ranges
            if ip.startswith(('10.', '192.168.', '172.16.')):
                result.indicators.append({
                    'name': 'Private IP Address',
                    'detected': True, 'severity': 'high', 'category': 'dns',
                    'description': 'Domain resolves to a private/internal IP address'
                })
                result.risk_score += 25
        except Exception:
            result.ip_address = "Unresolvable"

    # ── Phase 4: SSL/TLS Inspection ─────────────────────────────────────
    def _analyze_ssl(self, url: str, result: PhishingScanResult):
        if not result.url.startswith('https://'):
            result.ssl_info["valid"] = False
            result.ssl_info["note"] = "Not HTTPS"
            return

        try:
            domain_part = result.domain.split(':')[0]
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain_part, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain_part) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()

                    result.ssl_info["cipher"] = cipher[0] if cipher else "Unknown"
                    result.ssl_info["tls_version"] = cipher[1] if cipher else "Unknown"
                    result.ssl_info["valid"] = True

                    if cert:
                        subject = dict(x[0] for x in cert.get('subject', []))
                        issuer = dict(x[0] for x in cert.get('issuer', []))
                        result.ssl_info["subject"] = subject.get('commonName', 'Unknown')
                        result.ssl_info["issuer"] = issuer.get('organizationName', issuer.get('commonName', 'Unknown'))
                        result.ssl_info["not_before"] = cert.get('notBefore', '')
                        result.ssl_info["not_after"] = cert.get('notAfter', '')

                        san = cert.get('subjectAltName', [])
                        result.ssl_info["san_count"] = len(san)

                        # Self-signed detection
                        if result.ssl_info["subject"] == result.ssl_info["issuer"]:
                            result.indicators.append({
                                'name': 'Self-Signed Certificate',
                                'detected': True, 'severity': 'high', 'category': 'ssl',
                                'description': 'Certificate is self-signed (not trusted CA)'
                            })
                            result.risk_score += 25

                        # Free cert issuers (not bad per se, but common on phishing)
                        free_issuers = ["Let's Encrypt", "ZeroSSL", "Buypass"]
                        if any(fi.lower() in str(result.ssl_info["issuer"]).lower() for fi in free_issuers):
                            result.ssl_info["free_cert"] = True

                    # Weak cipher
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'EXPORT', 'NULL']
                    if cipher and any(wc in cipher[0].upper() for wc in weak_ciphers):
                        result.indicators.append({
                            'name': 'Weak SSL Cipher',
                            'detected': True, 'severity': 'high', 'category': 'ssl',
                            'description': f'Weak cipher: {cipher[0]}'
                        })
                        result.risk_score += 15

            result.indicators.append({
                'name': 'Valid SSL Certificate',
                'detected': False, 'severity': 'low', 'category': 'ssl',
                'description': f'Issued by {result.ssl_info.get("issuer", "Unknown")}'
            })

        except Exception as e:
            result.ssl_info["error"] = str(e)[:100]
            result.ssl_info["valid"] = False
            result.indicators.append({
                'name': 'SSL Connection Failed',
                'detected': True, 'severity': 'high', 'category': 'ssl',
                'description': 'Could not establish SSL connection'
            })
            result.risk_score += 15

    # ── Phase 5: WHOIS / Domain Age ─────────────────────────────────────
    def _check_domain_age(self, url: str, result: PhishingScanResult):
        try:
            import whois
            domain_part = result.domain.split(':')[0]
            parts = domain_part.split('.')
            if len(parts) > 2:
                domain_part = '.'.join(parts[-2:])

            w = whois.whois(domain_part)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if creation_date:
                age_days = (datetime.datetime.now() - creation_date).days
                result.domain_info["creation_date"] = creation_date.strftime("%Y-%m-%d")
                result.domain_info["age_days"] = age_days
                result.domain_info["registrar"] = w.registrar or "Unknown"

                expiration_date = w.expiration_date
                if isinstance(expiration_date, list):
                    expiration_date = expiration_date[0]
                if expiration_date:
                    result.domain_info["expiration_date"] = expiration_date.strftime("%Y-%m-%d")

                result.domain_info["name_servers"] = w.name_servers[:4] if w.name_servers else []

                if age_days < 30:
                    result.indicators.append({
                        'name': 'Newly Registered Domain',
                        'detected': True, 'severity': 'high', 'category': 'domain',
                        'description': f'Domain is only {age_days} days old — extremely suspicious'
                    })
                    result.risk_score += 30
                    result.flags.append(f"CRITICAL: Newly Registered ({age_days} days)")
                elif age_days < 90:
                    result.indicators.append({
                        'name': 'Recently Registered Domain',
                        'detected': True, 'severity': 'medium', 'category': 'domain',
                        'description': f'Domain is {age_days} days old'
                    })
                    result.risk_score += 15
                elif age_days < 365:
                    result.indicators.append({
                        'name': 'Young Domain',
                        'detected': True, 'severity': 'low', 'category': 'domain',
                        'description': f'Domain is {age_days} days old'
                    })
                    result.risk_score += 5
                else:
                    result.indicators.append({
                        'name': 'Established Domain',
                        'detected': False, 'severity': 'low', 'category': 'domain',
                        'description': f'Domain is {age_days} days old ({age_days // 365}+ years)'
                    })
            else:
                result.domain_info["note"] = "Creation date unavailable"
        except Exception as e:
            logger.warning(f"WHOIS check failed: {e}")
            result.domain_info["error"] = "WHOIS lookup failed"

    # ── Phase 6: Security Headers ───────────────────────────────────────
    def _analyze_security_headers(self, url: str, result: PhishingScanResult):
        headers = result.security_headers
        if not headers:
            return

        present = 0
        missing = 0
        header_details = {}

        for header_name, info in self.security_headers_checks.items():
            found = any(h.lower() == header_name.lower() for h in headers.keys())
            header_details[header_name] = {"present": found, "description": info["description"]}
            if found:
                present += 1
            else:
                missing += 1

        result.security_headers = {
            "present": present,
            "missing": missing,
            "total": present + missing,
            "details": header_details
        }

        if missing > 4:
            result.indicators.append({
                'name': 'Missing Security Headers',
                'detected': True, 'severity': 'medium', 'category': 'headers',
                'description': f'{missing} of {present + missing} security headers are missing'
            })
            result.risk_score += 10

    # ── Phase 7: HTML Content Analysis ──────────────────────────────────
    def _inspect_html(self, url: str, result: PhishingScanResult):
        html = result.content_analysis.get("html", "")
        if not html:
            return

        html_lower = html.lower()

        # Title
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        result.content_analysis["title"] = title_match.group(1).strip()[:120] if title_match else "No Title"

        # Link stats
        links = re.findall(r'<a[^>]+href=["\']([^"\']*)["\']', html, re.IGNORECASE)
        external_links = [l for l in links if l.startswith('http') and result.domain not in l]
        result.content_analysis["total_links"] = len(links)
        result.content_analysis["external_links"] = len(external_links)

        # Script & iframe counts
        result.content_analysis["script_count"] = html_lower.count("<script")
        result.content_analysis["iframe_count"] = html_lower.count("<iframe")

        if result.content_analysis["iframe_count"] > 3:
            result.indicators.append({
                'name': 'Excessive Iframes',
                'detected': True, 'severity': 'medium', 'category': 'content',
                'description': f'{result.content_analysis["iframe_count"]} iframes detected'
            })
            result.risk_score += 15

        # Hidden elements
        hidden_count = html_lower.count('display:none') + html_lower.count('visibility:hidden')
        result.content_analysis["hidden_elements"] = hidden_count
        if hidden_count > 5:
            result.indicators.append({
                'name': 'Many Hidden Elements',
                'detected': True, 'severity': 'medium', 'category': 'content',
                'description': f'{hidden_count} hidden elements detected'
            })
            result.risk_score += 10

        # Data URI
        if 'data:text/html' in html_lower:
            result.indicators.append({
                'name': 'Embedded Data URI',
                'detected': True, 'severity': 'high', 'category': 'content',
                'description': 'Data URI can embed hidden malicious content'
            })
            result.risk_score += 20

        # Favicon mismatch (external favicon)
        favicon_match = re.search(r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)', html, re.IGNORECASE)
        if favicon_match:
            fav_url = favicon_match.group(1)
            if fav_url.startswith('http') and result.domain not in fav_url:
                result.indicators.append({
                    'name': 'External Favicon',
                    'detected': True, 'severity': 'medium', 'category': 'content',
                    'description': 'Favicon loaded from external domain (possible brand spoofing)'
                })
                result.risk_score += 10

        # Disabled right-click (anti-inspection)
        if 'oncontextmenu' in html_lower and 'return false' in html_lower:
            result.indicators.append({
                'name': 'Right-Click Disabled',
                'detected': True, 'severity': 'low', 'category': 'content',
                'description': 'Page prevents right-clicking (anti-inspection technique)'
            })
            result.risk_score += 5

    # ── Phase 8: Login Form Detection ───────────────────────────────────
    def _detect_login_forms(self, url: str, result: PhishingScanResult):
        html = result.content_analysis.get("html", "")
        if not html:
            return

        html_lower = html.lower()

        # Password inputs
        password_fields = re.findall(r'<input[^>]*type=["\']password["\']', html, re.IGNORECASE)
        result.content_analysis["password_fields"] = len(password_fields)

        if password_fields:
            result.indicators.append({
                'name': 'Password Input Detected',
                'detected': True, 'severity': 'medium', 'category': 'forms',
                'description': f'{len(password_fields)} password field(s) found'
            })
            result.risk_score += 10

            # Password on HTTP
            if result.final_url.startswith("http://"):
                result.indicators.append({
                    'name': 'Password over HTTP',
                    'detected': True, 'severity': 'high', 'category': 'forms',
                    'description': 'CRITICAL: Password field on unencrypted page'
                })
                result.risk_score += 40
                result.flags.append("CRITICAL: Password Field on HTTP")

        # Form action analysis
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
        result.content_analysis["form_count"] = len(form_actions)

        external_forms = []
        for action in form_actions:
            if action.startswith('http') and result.domain not in action:
                external_forms.append(action)

        if external_forms:
            result.indicators.append({
                'name': 'External Form Action',
                'detected': True, 'severity': 'high', 'category': 'forms',
                'description': f'Form submits data to external domain'
            })
            result.risk_score += 25
            result.flags.append("Form Submits to External Domain")
            result.content_analysis["external_form_targets"] = external_forms[:3]

        # Email input + password = credential harvesting
        email_fields = re.findall(r'<input[^>]*type=["\'](?:email|text)["\']', html, re.IGNORECASE)
        if email_fields and password_fields:
            result.indicators.append({
                'name': 'Credential Harvesting Form',
                'detected': True, 'severity': 'high', 'category': 'forms',
                'description': 'Page contains login form (email + password fields)'
            })
            result.risk_score += 15

    # ── Phase 9: Brand Similarity ───────────────────────────────────────
    def _check_brand_similarity(self, url: str, result: PhishingScanResult):
        domain_lower = result.domain.lower()

        for brand, legit_domains in self.known_brands.items():
            # Brand name in domain but not a legit domain
            if brand in domain_lower and not any(domain_lower.endswith(ld) for ld in legit_domains):
                result.indicators.append({
                    'name': 'Brand Impersonation',
                    'detected': True, 'severity': 'high', 'category': 'brand',
                    'description': f'Possible impersonation of {brand.capitalize()}'
                })
                result.risk_score += 25
                result.flags.append(f"Brand Impersonation: {brand.capitalize()}")
                break

        # Levenshtein distance check for typosquatting
        all_legit = []
        for brand, domains in self.known_brands.items():
            all_legit.extend(domains)

        domain_base = result.domain.split(':')[0].lower()
        parts = domain_base.split('.')
        if len(parts) > 2:
            domain_base = '.'.join(parts[-2:])

        for legit in all_legit:
            distance = self._levenshtein(domain_base, legit)
            if 0 < distance <= 2 and domain_base != legit:
                result.indicators.append({
                    'name': 'Typosquatting Detection',
                    'detected': True, 'severity': 'high', 'category': 'brand',
                    'description': f'Domain is very similar to {legit} (edit distance: {distance})'
                })
                result.risk_score += 30
                result.flags.append(f"Typosquatting: Similar to {legit}")
                break

        # Title-based brand detection
        title = result.content_analysis.get("title", "").lower()
        for brand in self.known_brands:
            if brand in title and not any(result.domain.endswith(ld) for ld in self.known_brands[brand]):
                result.indicators.append({
                    'name': 'Brand Name in Page Title',
                    'detected': True, 'severity': 'medium', 'category': 'brand',
                    'description': f'Page title mentions {brand.capitalize()} but domain doesn\'t match'
                })
                result.risk_score += 15
                break

    def _levenshtein(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self._levenshtein(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr = [i + 1]
            for j, c2 in enumerate(s2):
                curr.append(min(prev[j + 1] + 1, curr[j] + 1, prev[j] + (c1 != c2)))
            prev = curr
        return prev[len(s2)]

    # ── Phase 10: Malware Signatures ────────────────────────────────────
    def _scan_malware_signatures(self, url: str, result: PhishingScanResult):
        html = result.content_analysis.get("html", "")
        if not html:
            return

        found_categories = []
        for category, patterns in self.malware_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    found_categories.append(category)
                    break

        if found_categories:
            result.indicators.append({
                'name': 'Malware Signatures',
                'detected': True, 'severity': 'high', 'category': 'malware',
                'description': f'Detected: {", ".join(c.replace("_", " ").title() for c in found_categories)}'
            })
            result.risk_score += 20 * len(found_categories)
            result.flags.append(f"Malware: {', '.join(found_categories)}")
            result.content_analysis["malware_categories"] = found_categories

        # Base64 obfuscation
        base64_matches = re.findall(r'(?:atob|btoa)\s*\(["\'][A-Za-z0-9+/=]{50,}', html)
        if base64_matches:
            result.indicators.append({
                'name': 'Base64 Obfuscation',
                'detected': True, 'severity': 'medium', 'category': 'malware',
                'description': 'Large Base64 encoded content detected'
            })
            result.risk_score += 15

    # ── Phase 11: Threat Intelligence ───────────────────────────────────
    def _check_threat_intel(self, url: str, result: PhishingScanResult):
        # URLhaus
        try:
            resp = requests.post(
                'https://urlhaus-api.abuse.ch/v1/url/',
                data={'url': result.url},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('query_status') == 'ok':
                    result.threat_intel["urlhaus"] = {
                        "status": "MALICIOUS",
                        "threat": data.get('threat', 'Unknown'),
                        "tags": data.get('tags', [])
                    }
                    result.risk_score += 50
                    result.flags.append(f"URLhaus: Known Malicious ({data.get('threat', 'Unknown')})")
                    result.indicators.append({
                        'name': 'URLhaus: Malicious',
                        'detected': True, 'severity': 'high', 'category': 'threat_intel',
                        'description': f'Listed as malicious: {data.get("threat", "Unknown")}'
                    })
                else:
                    result.threat_intel["urlhaus"] = {"status": "CLEAN"}
        except Exception as e:
            logger.warning(f"URLhaus check failed: {e}")
            result.threat_intel["urlhaus"] = {"status": "CHECK_FAILED"}

        # PhishTank
        try:
            resp = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data={'url': result.url, 'format': 'json'},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('results', {}).get('in_database'):
                    verified = data['results'].get('verified')
                    if verified:
                        result.threat_intel["phishtank"] = {"status": "PHISHING_VERIFIED"}
                        result.risk_score += 60
                        result.flags.append("PhishTank: Verified Phishing Site")
                        result.indicators.append({
                            'name': 'PhishTank: Verified Phishing',
                            'detected': True, 'severity': 'high', 'category': 'threat_intel',
                            'description': 'Confirmed phishing site in PhishTank database'
                        })
                    else:
                        result.threat_intel["phishtank"] = {"status": "SUSPECTED"}
                        result.risk_score += 30
                        result.flags.append("PhishTank: Suspected Phishing")
                else:
                    result.threat_intel["phishtank"] = {"status": "NOT_FOUND"}
            else:
                result.threat_intel["phishtank"] = {"status": "CHECK_FAILED"}
        except Exception as e:
            logger.warning(f"PhishTank check failed: {e}")
            result.threat_intel["phishtank"] = {"status": "CHECK_FAILED"}

    # ── Phase 12: Google Safe Browsing ──────────────────────────────────
    def _check_google_safe_browsing(self, url: str, result: PhishingScanResult):
        try:
            from app.core.config import settings
            api_key = settings.GOOGLE_SAFE_BROWSING_KEY
            if not api_key:
                result.threat_intel["google_safe_browsing"] = {"status": "NO_API_KEY"}
                return
        except Exception:
            result.threat_intel["google_safe_browsing"] = {"status": "NO_API_KEY"}
            return

        try:
            resp = requests.post(
                f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}',
                json={
                    "client": {"clientId": "genesis", "clientVersion": "1.0"},
                    "threatInfo": {
                        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": result.url}]
                    }
                },
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get('matches'):
                    match = data['matches'][0]
                    result.threat_intel["google_safe_browsing"] = {
                        "status": "FLAGGED",
                        "threat_type": match.get('threatType', 'Unknown')
                    }
                    result.risk_score += 50
                    result.flags.append(f"Google Safe Browsing: {match.get('threatType', 'Flagged')}")
                    result.indicators.append({
                        'name': 'Google Safe Browsing Flagged',
                        'detected': True, 'severity': 'high', 'category': 'threat_intel',
                        'description': f'Flagged as {match.get("threatType", "Dangerous")}'
                    })
                else:
                    result.threat_intel["google_safe_browsing"] = {"status": "CLEAN"}
            else:
                result.threat_intel["google_safe_browsing"] = {"status": "CHECK_FAILED"}
        except Exception as e:
            logger.warning(f"Google Safe Browsing check failed: {e}")
            result.threat_intel["google_safe_browsing"] = {"status": "CHECK_FAILED"}

    # ── Risk Calculation ────────────────────────────────────────────────
    def _calculate_risk(self, result: PhishingScanResult):
        # Cap at 100
        result.risk_score = min(result.risk_score, 100)

        # Risk level & verdict
        if result.risk_score >= 75:
            result.risk_level = "CRITICAL"
            result.is_phishing = True
            result.verdict = "Extremely High Phishing Risk"
        elif result.risk_score >= 50:
            result.risk_level = "HIGH"
            result.is_phishing = True
            result.verdict = "Likely Phishing"
        elif result.risk_score >= 30:
            result.risk_level = "MEDIUM"
            result.is_phishing = False
            result.verdict = "Moderate Risk — Exercise Caution"
        elif result.risk_score >= 10:
            result.risk_level = "LOW"
            result.is_phishing = False
            result.verdict = "Low Risk — Minor Concerns"
        else:
            result.risk_level = "SAFE"
            result.is_phishing = False
            result.verdict = "URL Appears Legitimate"

    # ── Serialization ───────────────────────────────────────────────────
    def _to_dict(self, result: PhishingScanResult) -> dict:
        return {
            "url": result.url,
            "final_url": result.final_url,
            "domain": result.domain,
            "ip_address": result.ip_address,
            "status_code": result.status_code,
            "is_phishing": result.is_phishing,
            "risk_score": result.risk_score,
            "risk_level": result.risk_level,
            "verdict": result.verdict,
            "indicators": result.indicators,
            "ssl_info": result.ssl_info,
            "domain_info": result.domain_info,
            "redirect_chain": result.redirect_chain,
            "content_analysis": {k: v for k, v in result.content_analysis.items() if k != "html"},
            "threat_intel": result.threat_intel,
            "security_headers": result.security_headers,
            "flags": result.flags,
            "scan_phases": result.scan_phases,
            "timestamp": result.timestamp,
        }


phishing_analyzer = PhishingAnalyzerService()
