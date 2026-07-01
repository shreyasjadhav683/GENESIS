import socket
import requests
import re
import ssl
import datetime
import hashlib
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class UrlScanResult:
    url: str
    final_url: str
    domain: str
    ip_address: str = ""
    status_code: int = 0
    risk_score: int = 0
    malicious: bool = False
    redirect_chain: List[Dict[str, Any]] = field(default_factory=list)
    dns_info: Dict[str, Any] = field(default_factory=dict)
    content_analysis: Dict[str, Any] = field(default_factory=dict)
    security_headers: Dict[str, str] = field(default_factory=dict)
    security_headers_analysis: Dict[str, Any] = field(default_factory=dict)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    performance: Dict[str, Any] = field(default_factory=dict)
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    domain_info: Dict[str, Any] = field(default_factory=dict)
    malware_signatures: Dict[str, Any] = field(default_factory=dict)
    flags: List[str] = field(default_factory=list)
    timestamp: str = ""

class UrlScannerService:
    def __init__(self):
        self.suspicious_keywords = [
            "login", "signin", "verify", "account", "banking", "secure", 
            "update", "confirm", "wallet", "password", "credential",
            "paypal", "amazon", "microsoft", "apple", "google", "facebook",
            "suspended", "unusual", "alert", "urgent", "click-here"
        ]
        
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', 
            '.click', '.link', '.loan', '.win', '.racing', '.download',
            '.stream', '.party', '.gdn', '.review', '.date', '.trade',
            '.bid', '.webcam', '.science', '.accountant', '.faith'
        ]
        
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 
            'is.gd', 'buff.ly', 'j.mp', 'shorte.st', 'adf.ly',
            'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc'
        ]
        
        # Known phishing patterns
        self.phishing_patterns = [
            r'(?:paypal|amazon|apple|google|microsoft|facebook|netflix|bank)[-._]',
            r'(?:secure|verify|update|confirm)[-._](?:account|login|info)',
            r'\d{2,}[-._](?:login|account|verify)',
            r'(?:login|account|verify)[-._]\d{2,}',
        ]
        
        # Malware / crypto miner patterns
        self.malware_patterns = {
            "crypto_miner": [
                r'coinhive\.min\.js', r'cryptoloot\.pro', r'coin-hive\.com',
                r'jsecoin\.com', r'authedmine\.com', r'crypto-loot\.com',
                r'CryptoNoter', r'minero\.cc', r'webmine\.pro',
                r'new\s+CoinHive', r'miner\.start', r'startMining'
            ],
            "drive_by_download": [
                r'document\.createElement\(["\']iframe["\']\).*display.*none',
                r'window\.location\s*=\s*["\']data:',
                r'\.exe["\']', r'\.scr["\']', r'\.bat["\']', r'\.cmd["\']',
                r'Content-Disposition.*attachment.*\.exe',
            ],
            "obfuscation": [
                r'eval\s*\(\s*unescape', r'eval\s*\(\s*atob',
                r'document\.write\s*\(\s*unescape', r'String\.fromCharCode\s*\(',
                r'eval\s*\(\s*function\s*\(p,a,c,k,e',  # Dean Edwards packer
                r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}',  # Hex encoding
            ],
            "data_exfiltration": [
                r'navigator\.sendBeacon', r'new\s+Image\(\)\.src\s*=',
                r'XMLHttpRequest.*password', r'fetch\(.*credential',
                r'document\.cookie',
            ],
            "exploit_kit": [
                r'exploit[-_]?kit', r'sweetorange', r'angler',
                r'magnitude', r'rig[-_]?ek', r'sundown',
            ]
        }
        
        # Security headers to check (same as Security Headers Checker)
        self.security_headers_checks = {
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'recommendation': 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
                'weight': 15
            },
            'Content-Security-Policy': {
                'description': 'Prevents XSS and injection attacks',
                'recommendation': "Add CSP header: default-src 'self'",
                'weight': 20
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'recommendation': 'Add: X-Frame-Options: DENY or SAMEORIGIN',
                'weight': 12
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME-type sniffing',
                'recommendation': 'Add: X-Content-Type-Options: nosniff',
                'weight': 12
            },
            'X-XSS-Protection': {
                'description': 'Legacy XSS filter (still useful)',
                'recommendation': 'Add: X-XSS-Protection: 1; mode=block',
                'weight': 8
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information leakage',
                'recommendation': 'Add: Referrer-Policy: strict-origin-when-cross-origin',
                'weight': 10
            },
            'Permissions-Policy': {
                'description': 'Controls browser features access',
                'recommendation': 'Restrict camera, microphone, geolocation',
                'weight': 13
            },
            'X-Permitted-Cross-Domain-Policies': {
                'description': 'Controls cross-domain access',
                'recommendation': 'Add: X-Permitted-Cross-Domain-Policies: none',
                'weight': 10
            }
        }
        
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    async def scan_url(self, url: str) -> Dict[str, Any]:
        """
        Performs an aggressive, comprehensive scan of the provided URL.
        """
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        result = UrlScanResult(url=url, final_url=url, domain="")
        result.timestamp = datetime.datetime.now().isoformat()
        
        try:
            # 1. Parse URL & Basic Validation
            parsed = urlparse(url)
            result.domain = parsed.netloc
            
            if not result.domain:
                return {"error": "Invalid URL provided"}

            # 2. URL Structure Analysis (before making requests)
            self._analyze_url_structure(url, result)

            # 3. Redirect Analysis & Content Fetching
            self._analyze_connection(url, result)

            # 4. DNS Forensics
            self._analyze_dns(result)

            # 5. Content Inspection 
            if result.content_analysis.get("html"):
                self._inspect_html(result)

            # 6. SSL Inspection (if HTTPS)
            if url.startswith("https") or result.final_url.startswith("https"):
                self._analyze_ssl(result)

            # 7. Security Headers Analysis (like Security Headers Checker)
            self._analyze_security_headers(result)

            # 8. Domain Age / WHOIS
            self._check_domain_age(result)

            # 9. Malware Signature Scan
            if result.content_analysis.get("html"):
                self._scan_malware_signatures(result)

            # 10. Check against threat intelligence
            self._check_threat_intel(result)

            # 11. Google Safe Browsing
            self._check_google_safe_browsing(result)

            # 12. Risk Calculation (compound scoring)
            self._calculate_risk(result)

            return self._to_dict(result)

        except Exception as e:
            logger.error(f"Scan failed for {url}: {str(e)}")
            return {
                "url": url,
                "error": str(e),
                "malicious": False,
                "risk_score": 0,
                "flags": ["Scan failed due to connection error"]
            }

    def _analyze_url_structure(self, url: str, result: UrlScanResult):
        """Analyzes URL structure for phishing indicators."""
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_url = url.lower()
        
        # Check for IP address as domain
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", domain):
            result.risk_score += 35
            result.flags.append("IP Address Used as Domain")
            result.threat_intel["ip_domain"] = True
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                result.risk_score += 20
                result.flags.append(f"Suspicious TLD: {tld}")
                result.threat_intel["suspicious_tld"] = tld
                break
        
        # Check for URL shorteners
        for shortener in self.url_shorteners:
            if shortener in domain:
                result.risk_score += 15
                result.flags.append("URL Shortener Detected")
                result.threat_intel["url_shortener"] = shortener
                break
        
        # Check for @ symbol (credential harvesting trick)
        if '@' in url:
            result.risk_score += 40
            result.flags.append("@ Symbol in URL (Credential Trick)")
            result.threat_intel["at_symbol_attack"] = True
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.') - 1
        if subdomain_count > 3:
            result.risk_score += 15
            result.flags.append(f"Excessive Subdomains ({subdomain_count})")
        
        # Check for phishing patterns in domain
        for pattern in self.phishing_patterns:
            if re.search(pattern, domain):
                result.risk_score += 30
                result.flags.append("Phishing Pattern in Domain")
                result.threat_intel["phishing_pattern"] = True
                break
        
        # Check for brand impersonation
        brands = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'facebook', 'netflix', 'instagram', 'twitter', 'linkedin']
        for brand in brands:
            if brand in domain and not domain.endswith(f'{brand}.com') and not domain.endswith(f'{brand}.net'):
                result.risk_score += 35
                result.flags.append(f"Possible Brand Impersonation: {brand.capitalize()}")
                result.threat_intel["brand_impersonation"] = brand
                break
        
        # Check for homograph attack (non-ASCII characters)
        if not domain.encode('ascii', errors='ignore').decode() == domain:
            result.risk_score += 45
            result.flags.append("Non-ASCII Characters in Domain (Homograph Attack)")
            result.threat_intel["homograph_attack"] = True
        
        # Long URL check
        if len(url) > 100:
            result.risk_score += 10
            result.flags.append("Suspiciously Long URL")
        
        # Check for double extensions in path
        if re.search(r'\.\w+\.\w+$', path):
            result.risk_score += 15
            result.flags.append("Double File Extension Detected")
        
        # Check for data exfil patterns in URL
        if re.search(r'(?:cmd|exec|system|eval|base64)', full_url):
            result.risk_score += 25
            result.flags.append("Suspicious Command Parameters")
        
        # Check for port in URL (non-standard)
        if ':' in parsed.netloc and not parsed.netloc.endswith(':443') and not parsed.netloc.endswith(':80'):
            port_match = re.search(r':(\d+)', parsed.netloc)
            if port_match:
                port = int(port_match.group(1))
                if port not in [80, 443, 8080, 8443]:
                    result.risk_score += 10
                    result.flags.append(f"Non-Standard Port: {port}")

    def _analyze_connection(self, url: str, result: UrlScanResult):
        """Traces redirects and fetches content."""
        try:
            headers = {"User-Agent": self.user_agent}
            startTime = datetime.datetime.now()
            
            # Allow redirects and capture history
            response = requests.get(url, headers=headers, timeout=15, verify=False) 
            
            endTime = datetime.datetime.now()
            result.performance["load_time_ms"] = int((endTime - startTime).total_seconds() * 1000)

            result.final_url = response.url
            result.status_code = response.status_code
            result.security_headers = dict(response.headers)
            
            parsed_final = urlparse(result.final_url)
            result.domain = parsed_final.netloc

            # Trace redirects
            if response.history:
                for resp in response.history:
                    result.redirect_chain.append({
                        "url": resp.url,
                        "status": resp.status_code,
                        "reason": resp.reason
                    })
                    
                    # Check if redirect goes to different domain
                    redirect_domain = urlparse(resp.url).netloc
                    if redirect_domain != result.domain:
                        result.risk_score += 10
                        result.flags.append(f"Cross-Domain Redirect: {redirect_domain}")
            
            if url != result.final_url:
                result.redirect_chain.append({
                    "url": result.final_url,
                    "status": response.status_code,
                    "reason": response.reason
                })

            # Store content
            result.content_analysis["html"] = response.text[:200000]
            result.content_analysis["size"] = len(response.content)
            result.content_analysis["content_type"] = response.headers.get('Content-Type', 'unknown')

            # Suspicious response time (very fast = possible redirect farm)
            if result.performance["load_time_ms"] < 50 and len(result.redirect_chain) > 1:
                result.flags.append("Suspiciously Fast Response with Redirects")
                result.risk_score += 5

        except requests.exceptions.SSLError:
            result.flags.append("SSL Certificate Error")
            result.risk_score += 25
        except requests.exceptions.ConnectionError:
            result.flags.append("Connection Failed")
        except requests.exceptions.Timeout:
            result.flags.append("Connection Timeout")

    def _analyze_dns(self, result: UrlScanResult):
        """Resolves IP and checks basics."""
        try:
            domain_part = result.domain.split(':')[0]
            ip = socket.gethostbyname(domain_part)
            result.ip_address = ip
            result.dns_info["a_record"] = ip

            try:
                hostname, _, _ = socket.gethostbyaddr(ip)
                result.dns_info["reverse_dns"] = hostname
            except:
                result.dns_info["reverse_dns"] = "Failed to resolve"

            # Check for recently registered or suspicious IP ranges
            # Private IP ranges used maliciously
            private_ranges = [
                (r'^10\.', 'Private IP Range (10.x.x.x)'),
                (r'^192\.168\.', 'Private IP Range (192.168.x.x)'),
                (r'^172\.(1[6-9]|2[0-9]|3[0-1])\.', 'Private IP Range (172.16-31.x.x)'),
            ]
            for pattern, desc in private_ranges:
                if re.match(pattern, ip):
                    result.flags.append(f"Suspicious: {desc}")
                    result.risk_score += 20

        except Exception as e:
            result.dns_info["error"] = str(e)
            result.flags.append("DNS Resolution Failed")
            result.risk_score += 15

    def _analyze_ssl(self, result: UrlScanResult):
        """Fetches certificate details directly."""
        try:
            domain_part = result.domain.split(':')[0]
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain_part, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain_part) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    
                    cipher = ssock.cipher()
                    result.ssl_info["cipher"] = cipher[0]
                    result.ssl_info["version"] = cipher[1]
                    result.ssl_info["valid"] = True

                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'EXPORT', 'NULL']
                    if any(wc in cipher[0].upper() for wc in weak_ciphers):
                        result.flags.append(f"Weak SSL Cipher: {cipher[0]}")
                        result.risk_score += 15

        except Exception as e:
            result.ssl_info["error"] = str(e)
            result.ssl_info["valid"] = False
            result.risk_score += 15
            result.flags.append("SSL Connection Failed")

    def _analyze_security_headers(self, result: UrlScanResult):
        """Analyze security headers — same checks as Security Headers Checker."""
        response_headers = result.security_headers
        if not response_headers:
            result.security_headers_analysis = {
                "score": 0, "grade": "F", "headers": [],
                "present_count": 0, "missing_count": len(self.security_headers_checks)
            }
            return

        headers_results = []
        total_weight = sum(h['weight'] for h in self.security_headers_checks.values())
        earned_weight = 0

        for header_name, info in self.security_headers_checks.items():
            value = response_headers.get(header_name)
            status = 'present' if value else 'missing'
            if status == 'present':
                earned_weight += info['weight']
            
            headers_results.append({
                'name': header_name,
                'value': value,
                'status': status,
                'description': info['description'],
                'recommendation': info['recommendation'] if not value else None
            })

        score = round((earned_weight / total_weight) * 100)
        present_count = sum(1 for h in headers_results if h['status'] == 'present')
        missing_count = len(headers_results) - present_count

        # Grade
        if score >= 90: grade = 'A+'
        elif score >= 80: grade = 'A'
        elif score >= 70: grade = 'B'
        elif score >= 60: grade = 'C'
        elif score >= 50: grade = 'D'
        else: grade = 'F'

        result.security_headers_analysis = {
            "score": score,
            "grade": grade,
            "headers": headers_results,
            "present_count": present_count,
            "missing_count": missing_count
        }

        # Add risk based on missing headers
        if missing_count >= 6:
            result.risk_score += 15
            result.flags.append(f"Poor Security Headers ({missing_count}/8 missing)")
        elif missing_count >= 4:
            result.risk_score += 8
            result.flags.append(f"Weak Security Headers ({missing_count}/8 missing)")

    def _check_domain_age(self, result: UrlScanResult):
        """Check domain registration age via WHOIS."""
        try:
            import whois
            domain_part = result.domain.split(':')[0]
            
            # Remove subdomains to get registrable domain
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
                    result.risk_score += 30
                    result.flags.append(f"CRITICAL: Newly Registered Domain ({age_days} days old)")
                elif age_days < 90:
                    result.risk_score += 15
                    result.flags.append(f"Recently Registered Domain ({age_days} days old)")
                elif age_days < 365:
                    result.risk_score += 5
                    result.flags.append(f"Young Domain ({age_days} days old)")
            else:
                result.domain_info["age_days"] = None
                result.domain_info["note"] = "Creation date unavailable"
        except Exception as e:
            logger.warning(f"WHOIS check failed: {e}")
            result.domain_info["error"] = "WHOIS lookup failed"

    def _scan_malware_signatures(self, result: UrlScanResult):
        """Scan HTML content for malware signatures and suspicious patterns."""
        html = result.content_analysis.get("html", "")
        if not html:
            return

        detections = []
        
        for category, patterns in self.malware_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    detections.append({
                        "category": category.replace("_", " ").title(),
                        "pattern": pattern[:40],
                        "severity": "critical" if category in ["crypto_miner", "exploit_kit"] else "high"
                    })
                    break  # One detection per category is enough

        result.malware_signatures = {
            "scanned": True,
            "detections": detections,
            "clean": len(detections) == 0
        }

        for d in detections:
            result.flags.append(f"Malware: {d['category']} Detected")
            if d["severity"] == "critical":
                result.risk_score += 35
            else:
                result.risk_score += 20

    def _inspect_html(self, result: UrlScanResult):
        """Heuristic analysis of page content."""
        html = result.content_analysis.get("html", "")
        html_lower = html.lower()

        # Metadata
        title_match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE)
        result.content_analysis["title"] = title_match.group(1)[:100] if title_match else "No Title"

        desc_match = re.search(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        result.content_analysis["description"] = desc_match.group(1)[:150] if desc_match else "N/A"
        
        gen_match = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        result.content_analysis["generator"] = gen_match.group(1) if gen_match else "Unknown"

        # Link Stats
        links = re.findall(r'<a[^>]+href=["\']([^"\']*)["\']', html, re.IGNORECASE)
        result.content_analysis["link_count"] = len(links)
        external_links = [l for l in links if l.startswith('http') and result.domain not in l]
        result.content_analysis["external_link_count"] = len(external_links)

        # Password Input Detection
        if '<input type="password"' in html_lower or "type='password'" in html_lower:
            result.flags.append("Password Input Detected")
            if result.final_url.startswith("http://"):
                result.risk_score += 40
                result.flags.append("CRITICAL: Password Field on HTTP (Not Encrypted)")
            else:
                result.risk_score += 10

        # Form action analysis
        form_actions = re.findall(r'<form[^>]*action=["\']([^"\']*)["\']', html, re.IGNORECASE)
        for action in form_actions:
            if action.startswith('http') and result.domain not in action:
                result.flags.append(f"Form Submits to External Domain")
                result.risk_score += 25
                break

        # Suspicious keyword detection
        found_keywords = [kw for kw in self.suspicious_keywords if kw in html_lower]
        if found_keywords:
            result.content_analysis["keywords_found"] = list(set(found_keywords))
            keyword_score = min(len(found_keywords) * 3, 20)
            result.risk_score += keyword_score
            if len(found_keywords) > 3:
                result.flags.append(f"Multiple Suspicious Keywords: {', '.join(found_keywords[:5])}")

        # Script and iframe analysis
        result.content_analysis["script_count"] = html_lower.count("<script")
        result.content_analysis["iframe_count"] = html_lower.count("<iframe")
        
        if result.content_analysis["iframe_count"] > 3:
            result.flags.append("Excessive Iframes Detected")
            result.risk_score += 15

        # Hidden elements
        hidden_count = html_lower.count('style="display:none"') + html_lower.count("style='display:none'")
        hidden_count += html_lower.count('visibility:hidden')
        if hidden_count > 5:
            result.flags.append("Many Hidden Elements Detected")
            result.risk_score += 10

        # Data URI detection (can be used to embed malicious content)
        if 'data:text/html' in html_lower or 'data:application/x-javascript' in html_lower:
            result.flags.append("Embedded Data URI Detected")
            result.risk_score += 20

        # Obfuscated JavaScript detection
        if 'eval(' in html_lower or 'document.write(unescape' in html_lower:
            result.flags.append("Obfuscated JavaScript Detected")
            result.risk_score += 25

        # Base64 encoded content detection
        base64_matches = re.findall(r'(?:atob|btoa)\s*\(["\'][A-Za-z0-9+/=]{50,}', html)
        if base64_matches:
            result.flags.append("Large Base64 Encoded Content Detected")
            result.risk_score += 15

    def _check_threat_intel(self, result: UrlScanResult):
        """Check URL against threat intelligence sources."""
        # URLhaus check (free, no API key required)
        try:
            urlhaus_response = requests.post(
                'https://urlhaus-api.abuse.ch/v1/url/',
                data={'url': result.url},
                timeout=5
            )
            if urlhaus_response.status_code == 200:
                data = urlhaus_response.json()
                if data.get('query_status') == 'ok':
                    result.threat_intel["urlhaus"] = {
                        "status": "MALICIOUS",
                        "threat": data.get('threat', 'Unknown'),
                        "tags": data.get('tags', [])
                    }
                    result.risk_score += 50
                    result.flags.append(f"URLhaus: Known Malicious ({data.get('threat', 'Unknown')})")
                else:
                    result.threat_intel["urlhaus"] = {"status": "CLEAN"}
        except Exception as e:
            logger.warning(f"URLhaus check failed: {e}")
            result.threat_intel["urlhaus"] = {"status": "CHECK_FAILED"}

        # PhishTank check
        try:
            phishtank_response = requests.post(
                'https://checkurl.phishtank.com/checkurl/',
                data={
                    'url': result.url,
                    'format': 'json'
                },
                timeout=5
            )
            if phishtank_response.status_code == 200:
                data = phishtank_response.json()
                if data.get('results', {}).get('in_database'):
                    if data['results'].get('verified'):
                        result.threat_intel["phishtank"] = {"status": "PHISHING_VERIFIED"}
                        result.risk_score += 60
                        result.flags.append("PhishTank: Verified Phishing Site")
                    else:
                        result.threat_intel["phishtank"] = {"status": "SUSPECTED"}
                        result.risk_score += 30
                        result.flags.append("PhishTank: Suspected Phishing")
                else:
                    result.threat_intel["phishtank"] = {"status": "NOT_FOUND"}
        except Exception as e:
            logger.warning(f"PhishTank check failed: {e}")
            result.threat_intel["phishtank"] = {"status": "CHECK_FAILED"}

    def _check_google_safe_browsing(self, result: UrlScanResult):
        """Check URL against Google Safe Browsing API (if key is configured)."""
        try:
            from app.core.config import settings
            api_key = settings.GOOGLE_SAFE_BROWSING_KEY
            if not api_key:
                result.threat_intel["google_safe_browsing"] = {"status": "NOT_CONFIGURED"}
                return

            payload = {
                "client": {"clientId": "genesis", "clientVersion": "1.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": result.url}]
                }
            }

            response = requests.post(
                f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
                json=payload,
                timeout=5
            )

            if response.status_code == 200:
                data = response.json()
                if data.get('matches'):
                    threats = [m.get('threatType', 'UNKNOWN') for m in data['matches']]
                    result.threat_intel["google_safe_browsing"] = {
                        "status": "THREAT_FOUND",
                        "threats": threats
                    }
                    result.risk_score += 60
                    result.flags.append(f"Google Safe Browsing: {', '.join(threats)}")
                else:
                    result.threat_intel["google_safe_browsing"] = {"status": "CLEAN"}
            else:
                result.threat_intel["google_safe_browsing"] = {"status": "CHECK_FAILED"}
        except Exception as e:
            logger.warning(f"Google Safe Browsing check failed: {e}")
            result.threat_intel["google_safe_browsing"] = {"status": "CHECK_FAILED"}

    def _calculate_risk(self, result: UrlScanResult):
        """Finalizes risk score with compound scoring."""
        # Compound scoring: multiple high-severity flags = exponential increase
        critical_flags = [f for f in result.flags if any(kw in f.upper() for kw in ["CRITICAL", "MALICIOUS", "PHISHING", "MALWARE", "EXPLOIT"])]
        high_flags = [f for f in result.flags if any(kw in f.upper() for kw in ["BRAND", "HOMOGRAPH", "PASSWORD", "EXTERNAL DOMAIN"])]
        
        if len(critical_flags) >= 2:
            result.risk_score += 20
            result.flags.append("Compound Threat: Multiple Critical Indicators")
        
        if len(high_flags) >= 3:
            result.risk_score += 10

        # Multiple flags bonus
        flag_count = len(result.flags)
        if flag_count >= 8:
            result.risk_score += 20
            result.flags.append("Extreme Risk: 8+ Risk Indicators")
        elif flag_count >= 5:
            result.risk_score += 10
            result.flags.append("Multiple Risk Indicators Detected")
        
        # Link Density Risk
        if result.content_analysis.get("link_count", 0) > 0:
            ext_ratio = result.content_analysis.get("external_link_count", 0) / result.content_analysis["link_count"]
            if ext_ratio > 0.8 and result.content_analysis["link_count"] > 5:
                result.flags.append("High External Link Density")
                result.risk_score += 10

        # Multiple redirects
        if len(result.redirect_chain) > 3:
            result.risk_score += 20
            result.flags.append("Excessive Redirects")

        # Cap at 100
        result.risk_score = min(result.risk_score, 100)
        
        # Determine malicious status (lowered threshold from 40 to 35)
        result.malicious = result.risk_score >= 35

        # Determine risk level
        if result.risk_score >= 70:
            result.threat_intel["risk_level"] = "CRITICAL"
        elif result.risk_score >= 50:
            result.threat_intel["risk_level"] = "HIGH"
        elif result.risk_score >= 35:
            result.threat_intel["risk_level"] = "MEDIUM"
        elif result.risk_score >= 15:
            result.threat_intel["risk_level"] = "LOW"
        else:
            result.threat_intel["risk_level"] = "SAFE"

    def _to_dict(self, result: UrlScanResult) -> Dict[str, Any]:
        return {
            "url": result.url,
            "final_url": result.final_url,
            "domain": result.domain,
            "ip_address": result.ip_address,
            "status_code": result.status_code,
            "risk_score": result.risk_score,
            "risk_level": result.threat_intel.get("risk_level", "UNKNOWN"),
            "malicious": result.malicious,
            "redirect_chain": result.redirect_chain,
            "dns_info": result.dns_info,
            "content_analysis": {k: v for k, v in result.content_analysis.items() if k != 'html'},
            "ssl_info": result.ssl_info,
            "security_headers_analysis": result.security_headers_analysis,
            "domain_info": result.domain_info,
            "malware_signatures": result.malware_signatures,
            "threat_intel": result.threat_intel,
            "performance": result.performance,
            "security_headers": {k: v for k, v in result.security_headers.items() if k.lower() in ['server', 'x-powered-by', 'strict-transport-security', 'content-security-policy', 'x-frame-options']},
            "flags": result.flags,
            "timestamp": result.timestamp
        }

url_scanner = UrlScannerService()
