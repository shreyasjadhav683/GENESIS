"""
Enhanced IP Scanner Service with Real Threat Intelligence APIs
Integrates AbuseIPDB and IPQualityScore for comprehensive malicious IP detection
"""

import socket
import asyncio
import aiohttp
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
import re
from datetime import datetime
from app.core.config import settings

# Common ports to scan with their service names (reduced set for speed)
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP-Proxy"
}

# High-risk countries (simplified list)
HIGH_RISK_COUNTRIES = ["KP", "IR", "SY", "CU"]
CAUTION_COUNTRIES = ["RU", "CN", "BY", "VE"]

# Known dangerous ports
DANGEROUS_PORTS = [22, 23, 3389, 445]


@dataclass
class ThreatIntelligence:
    is_vpn: bool = False
    is_proxy: bool = False
    is_tor_exit: bool = False
    is_datacenter: bool = False
    is_bot: bool = False
    abuse_reports: int = 0
    abuse_confidence_score: int = 0  # 0-100 from AbuseIPDB
    fraud_score: int = 0  # 0-100 from IPQualityScore
    is_blacklisted: bool = False
    threat_categories: List[str] = field(default_factory=list)
    last_reported: Optional[str] = None
    country_abuse_score: int = 0
    usage_type: str = ""  # Residential, Business, Datacenter, etc.
    isp_name: str = ""
    connection_type: str = ""  # Cable, DSL, Cellular, etc.
    is_public: bool = True
    is_mobile: bool = False


@dataclass
class NetworkInfo:
    asn: str = ""
    asn_name: str = ""
    network_range: str = ""
    organization: str = ""
    isp: str = ""
    domain: str = ""
    

@dataclass
class GeographicDetails:
    country: str = ""
    country_code: str = ""
    region: str = ""
    region_name: str = ""
    city: str = ""
    zip_code: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    timezone: str = ""
    continent: str = ""


@dataclass
class AbuseHistory:
    total_reports: int = 0
    distinct_users: int = 0
    last_reported_at: Optional[str] = None
    report_categories: List[str] = field(default_factory=list)
    abuse_confidence: int = 0
    is_whitelisted: bool = False


@dataclass
class PortScanResult:
    open_ports: List[int] = field(default_factory=list)
    services_detected: Dict[int, str] = field(default_factory=dict)
    scan_completed: bool = True


@dataclass
class DNSInfo:
    reverse_dns: str = ""
    ptr_records: List[str] = field(default_factory=list)


@dataclass
class RiskAssessment:
    score: int = 0
    severity: str = "Low"
    factors: List[Dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""
    is_malicious: bool = False


class IPScannerService:
    """Enhanced IP scanning with real threat intelligence APIs"""
    
    def __init__(self):
        self.port_timeout = 0.5  # Fast 500ms timeout
        self.http_timeout = aiohttp.ClientTimeout(total=5)  # 5 second total timeout

    @property
    def abuseipdb_key(self) -> str:
        """Read API key fresh from settings each time (supports hot-reload of .env)"""
        key = settings.ABUSEIPDB_API_KEY or os.environ.get("ABUSEIPDB_API_KEY", "")
        if not key:
            print("[IP Scanner] WARNING: ABUSEIPDB_API_KEY is not set. Abuse confidence data will be unavailable.")
        return key or ""
    
    @property
    def ipqs_key(self) -> str:
        """Read API key fresh from settings each time (supports hot-reload of .env)"""
        key = settings.IPQUALITYSCORE_API_KEY or os.environ.get("IPQUALITYSCORE_API_KEY", "")
        if not key:
            print("[IP Scanner] WARNING: IPQUALITYSCORE_API_KEY is not set. Fraud score data will be unavailable.")
        return key or ""
    
    async def scan_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Perform comprehensive IP analysis with enhanced threat intelligence
        """
        # Validate IP address format
        if not self._validate_ip(ip_address):
            return {"error": "Invalid IP address format"}
        
        try:
            # Run all scans concurrently with timeout protection
            results = await asyncio.wait_for(
                asyncio.gather(
                    self._get_geolocation(ip_address),
                    self._get_threat_intelligence_enhanced(ip_address),
                    self._scan_ports_fast(ip_address),
                    self._get_dns_info(ip_address),
                    return_exceptions=True
                ),
                timeout=20.0  # Overall 20 second timeout
            )
        except asyncio.TimeoutError:
            results = [{}, ThreatIntelligence(), PortScanResult(scan_completed=False), DNSInfo()]
        
        geolocation = results[0] if not isinstance(results[0], Exception) else {}
        threat_intel = results[1] if not isinstance(results[1], Exception) else ThreatIntelligence()
        port_scan = results[2] if not isinstance(results[2], Exception) else PortScanResult()
        dns_info = results[3] if not isinstance(results[3], Exception) else DNSInfo()
        
        # Extract enhanced data structures
        network_info = self._extract_network_info(geolocation, threat_intel)
        geographic_details = self._extract_geographic_details(geolocation)
        abuse_history = self._extract_abuse_history(threat_intel)
        
        # Calculate enhanced risk assessment
        risk_assessment = self._calculate_risk_enhanced(
            ip_address, geolocation, threat_intel, port_scan, dns_info
        )
        
        return {
            "ip": ip_address,
            "geolocation": geolocation,
            "network_info": asdict(network_info),
            "geographic_details": asdict(geographic_details),
            "threat_intelligence": asdict(threat_intel) if isinstance(threat_intel, ThreatIntelligence) else {},
            "abuse_history": asdict(abuse_history),
            "port_scan": {
                "open_ports": port_scan.open_ports if isinstance(port_scan, PortScanResult) else [],
                "services_detected": port_scan.services_detected if isinstance(port_scan, PortScanResult) else {}
            },
            "dns_info": asdict(dns_info) if isinstance(dns_info, DNSInfo) else {},
            "risk_assessment": asdict(risk_assessment),
            "scan_timestamp": datetime.utcnow().isoformat()
        }
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IPv4 address format"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    def _extract_network_info(self, geolocation: Dict, threat_intel: ThreatIntelligence) -> NetworkInfo:
        """Extract network information from geolocation and threat data"""
        network_info = NetworkInfo()
        if isinstance(geolocation, dict):
            network_info.asn = geolocation.get('as', '')
            network_info.asn_name = geolocation.get('asname', '')
            network_info.organization = geolocation.get('org', '')
            network_info.isp = geolocation.get('isp', '')
        
        if isinstance(threat_intel, ThreatIntelligence):
            network_info.isp = network_info.isp or threat_intel.isp_name
        
        return network_info
    
    def _extract_geographic_details(self, geolocation: Dict) -> GeographicDetails:
        """Extract detailed geographic information"""
        geo_details = GeographicDetails()
        if isinstance(geolocation, dict):
            geo_details.country = geolocation.get('country', '')
            geo_details.country_code = geolocation.get('countryCode', '')
            geo_details.region = geolocation.get('region', '')
            geo_details.region_name = geolocation.get('regionName', '')
            geo_details.city = geolocation.get('city', '')
            geo_details.zip_code = geolocation.get('zip', '')
            geo_details.latitude = geolocation.get('lat', 0.0)
            geo_details.longitude = geolocation.get('lon', 0.0)
            geo_details.timezone = geolocation.get('timezone', '')
        
        return geo_details
    
    def _extract_abuse_history(self, threat_intel: ThreatIntelligence) -> AbuseHistory:
        """Extract abuse history from threat intelligence"""
        abuse_hist = AbuseHistory()
        if isinstance(threat_intel, ThreatIntelligence):
            abuse_hist.total_reports = threat_intel.abuse_reports
            abuse_hist.abuse_confidence = threat_intel.abuse_confidence_score
            abuse_hist.last_reported_at = threat_intel.last_reported
            abuse_hist.report_categories = threat_intel.threat_categories.copy()
        
        return abuse_hist

    
    async def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation data from ip-api.com"""
        try:
            async with aiohttp.ClientSession(timeout=self.http_timeout) as session:
                url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query,hosting,proxy"
                async with session.get(url) as response:
                    data = await response.json()
                    if data.get("status") == "fail":
                        return {"error": data.get("message", "Lookup failed")}
                    return data
        except Exception as e:
            return {"error": str(e)}
    
    async def _get_threat_intelligence_enhanced(self, ip: str) -> ThreatIntelligence:
        """
        Enhanced threat intelligence using multiple APIs:
        - AbuseIPDB for abuse reports and blacklist status
        - IPQualityScore for fraud detection and VPN/proxy/Tor detection
        - ip-api.com for basic hosting/proxy detection
        """
        threat_intel = ThreatIntelligence()
        
        try:
            async with aiohttp.ClientSession(timeout=self.http_timeout) as session:
                # Run all API calls concurrently
                tasks = [
                    self._check_abuseipdb(session, ip, threat_intel),
                    self._check_ipqualityscore(session, ip, threat_intel),
                    self._check_basic_threat(session, ip, threat_intel)
                ]
                await asyncio.gather(*tasks, return_exceptions=True)
                
        except Exception as e:
            print(f"Threat intelligence error: {e}")
        
        # Build comprehensive threat categories
        self._build_threat_categories(threat_intel)
        
        return threat_intel
    
    async def _check_abuseipdb(self, session: aiohttp.ClientSession, ip: str, threat_intel: ThreatIntelligence):
        """Check AbuseIPDB for abuse reports and blacklist status"""
        if not self.abuseipdb_key:
            return  # Skip if no API key
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": self.abuseipdb_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            async with session.get(url, headers=headers, params=params) as response:
                print(f"[IP Scanner] AbuseIPDB response status: {response.status}")
                if response.status != 200:
                    text = await response.text()
                    print(f"[IP Scanner] AbuseIPDB error: {text[:200]}")
                    return
                if response.status == 200:
                    data = await response.json()
                    result = data.get("data", {})
                    print(f"[IP Scanner] AbuseIPDB result: abuse_confidence={result.get('abuseConfidenceScore', 0)}, reports={result.get('totalReports', 0)}")
                    
                    threat_intel.abuse_confidence_score = result.get("abuseConfidenceScore", 0)
                    threat_intel.abuse_reports = result.get("totalReports", 0)
                    threat_intel.is_blacklisted = threat_intel.abuse_confidence_score > 75
                    threat_intel.country_abuse_score = result.get("countryCode", "")
                    
                    # Get last reported date
                    if result.get("lastReportedAt"):
                        threat_intel.last_reported = result["lastReportedAt"]
                    
                    # Extract usage type
                    usage_type = result.get("usageType", "").lower()
                    if usage_type:
                        threat_intel.usage_type = usage_type.title()
                    
                    if "data center" in usage_type or "hosting" in usage_type:
                        threat_intel.is_datacenter = True
                    
                    # Extract ISP name
                    threat_intel.isp_name = result.get("isp", "")
                    
                    # Map abuse categories from report data
                    reports = result.get("reports", [])
                    if reports:
                        category_map = {
                            3: "Fraud",
                            4: "DDoS Attack",
                            9: "Hacking",
                            10: "Spam",
                            14: "Port Scan",
                            15: "Brute Force",
                            18: "Web Spam",
                            19: "Email Spam",
                            20: "Blog Spam",
                            21: "VPN IP",
                            22: "DNS Compromise",
                            23: "Malware"
                        }
                        
                        categories_set = set()
                        for report in reports[:10]:  # Check first 10 reports
                            for cat_id in report.get("categories", []):
                                if cat_id in category_map:
                                    categories_set.add(category_map[cat_id])
                        
                        if categories_set:
                            threat_intel.threat_categories.extend(list(categories_set))
                    
        except Exception as e:
            print(f"AbuseIPDB check error: {e}")
    
    async def _check_ipqualityscore(self, session: aiohttp.ClientSession, ip: str, threat_intel: ThreatIntelligence):
        """Check IPQualityScore for fraud detection and anonymizer detection"""
        if not self.ipqs_key:
            return  # Skip if no API key
        
        try:
            url = f"https://ipqualityscore.com/api/json/ip/{self.ipqs_key}/{ip}"
            params = {
                "strictness": 1,  # 0-2, higher = more strict
                "allow_public_access_points": "true",
                "fast": "true"
            }
            
            async with session.get(url, params=params) as response:
                print(f"[IP Scanner] IPQualityScore response status: {response.status}")
                if response.status != 200:
                    text = await response.text()
                    print(f"[IP Scanner] IPQualityScore error: {text[:200]}")
                    return
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get("success"):
                        print(f"[IP Scanner] IPQualityScore result: fraud_score={data.get('fraud_score', 0)}")
                        threat_intel.fraud_score = data.get("fraud_score", 0)
                        threat_intel.is_vpn = data.get("vpn", False)
                        threat_intel.is_proxy = data.get("proxy", False)
                        threat_intel.is_tor_exit = data.get("tor", False)
                        threat_intel.is_bot = data.get("bot_status", False)
                        
                        # Recent abuse
                        if data.get("recent_abuse", False):
                            threat_intel.threat_categories.append("Recent Abuse")
                        
        except Exception as e:
            print(f"IPQualityScore check error: {e}")
    
    async def _check_basic_threat(self, session: aiohttp.ClientSession, ip: str, threat_intel: ThreatIntelligence):
        """Basic threat check using ip-api.com (fallback)"""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=hosting,proxy,mobile,query,org,isp,as"
            async with session.get(url) as response:
                data = await response.json()
                
                # Check for hosting/datacenter
                if not threat_intel.is_datacenter:
                    threat_intel.is_datacenter = data.get("hosting", False)
                
                # Check for proxy
                if not threat_intel.is_proxy:
                    threat_intel.is_proxy = data.get("proxy", False)
                
                # Check org/ISP/ASN for Tor indicators
                org = data.get("org", "").lower()
                isp = data.get("isp", "").lower()
                asn = data.get("as", "").lower()
                combined_text = f"{org} {isp} {asn}"
                
                # Tor detection keywords
                if any(keyword in combined_text for keyword in ["tor", "torservers", "exit", "relay", "onion", "erneuerbare freiheit"]):
                    threat_intel.is_tor_exit = True
                
                # VPN/Proxy detection keywords
                if any(keyword in combined_text for keyword in ["vpn", "proxy", "anonymizer", "private internet", "mullvad", "nordvpn"]):
                    threat_intel.is_vpn = True
                    
        except:
            pass
    
    def _build_threat_categories(self, threat_intel: ThreatIntelligence):
        """Build comprehensive threat category list"""
        categories = []
        
        if threat_intel.is_vpn:
            categories.append("VPN/Anonymizer")
        if threat_intel.is_proxy:
            categories.append("Proxy Server")
        if threat_intel.is_tor_exit:
            categories.append("Tor Exit Node")
        if threat_intel.is_datacenter:
            categories.append("Datacenter/Hosting")
        if threat_intel.is_bot:
            categories.append("Bot/Automated Traffic")
        if threat_intel.abuse_confidence_score > 50:
            categories.append("High Abuse Confidence")
        if threat_intel.fraud_score > 75:
            categories.append("High Fraud Risk")
        if threat_intel.is_blacklisted:
            categories.append("Blacklisted")
        
        threat_intel.threat_categories = categories
    
    async def _scan_ports_fast(self, ip: str) -> PortScanResult:
        """Fast async port scanning with 500ms timeout"""
        result = PortScanResult()
        
        async def check_port(port: int) -> Optional[int]:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.port_timeout
                )
                writer.close()
                await writer.wait_closed()
                return port
            except:
                return None
        
        # Scan all ports concurrently
        tasks = [check_port(port) for port in COMMON_PORTS.keys()]
        port_results = await asyncio.gather(*tasks)
        
        for port in port_results:
            if port is not None:
                result.open_ports.append(port)
                result.services_detected[port] = COMMON_PORTS.get(port, "Unknown")
        
        result.open_ports.sort()
        return result
    
    async def _get_dns_info(self, ip: str) -> DNSInfo:
        """Get reverse DNS using async resolver"""
        dns_info = DNSInfo()
        
        try:
            # Use socket.gethostbyaddr in executor for async behavior
            loop = asyncio.get_event_loop()
            hostname, _, _ = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=2
            )
            dns_info.reverse_dns = hostname
            dns_info.ptr_records = [hostname]
        except:
            dns_info.reverse_dns = "No PTR record"
        
        return dns_info
    
    def _calculate_risk_enhanced(
        self,
        ip: str,
        geolocation: Dict,
        threat_intel: ThreatIntelligence,
        port_scan: PortScanResult,
        dns_info: DNSInfo
    ) -> RiskAssessment:
        """
        Enhanced risk calculation with abuse and fraud scores
        """
        score = 0
        factors = []
        
        # Factor 1: Abuse Confidence Score (0-40 points)
        if isinstance(threat_intel, ThreatIntelligence):
            if threat_intel.abuse_confidence_score > 0:
                abuse_score = min(int(threat_intel.abuse_confidence_score * 0.4), 40)
                score += abuse_score
                factors.append({
                    "name": "Abuse Reports",
                    "impact": abuse_score,
                    "description": f"Abuse confidence: {threat_intel.abuse_confidence_score}% ({threat_intel.abuse_reports} reports)"
                })
            
            # Factor 2: Fraud Score (0-30 points)
            if threat_intel.fraud_score > 50:
                fraud_impact = min(int(threat_intel.fraud_score * 0.3), 30)
                score += fraud_impact
                factors.append({
                    "name": "Fraud Risk",
                    "impact": fraud_impact,
                    "description": f"Fraud score: {threat_intel.fraud_score}% - High likelihood of fraudulent activity"
                })
            
            # Factor 3: Blacklisted (+25)
            if threat_intel.is_blacklisted:
                score += 25
                factors.append({
                    "name": "Blacklisted IP",
                    "impact": 25,
                    "description": "IP is on known blacklists due to malicious activity"
                })
            
            # Factor 4: Tor Exit Node (50 points) - CRITICAL RISK
            if threat_intel.is_tor_exit:
                score += 50
                factors.append({
                    "name": "Tor Exit Node",
                    "impact": 50,
                    "description": "IP is a Tor exit node - commonly used for anonymization and malicious activity"
                })
            # VPN/Proxy Detection (50 points if not Tor) - HIGH RISK
            elif threat_intel.is_vpn or threat_intel.is_proxy:
                anonymizer_type = []
                if threat_intel.is_vpn:
                    anonymizer_type.append("VPN")
                if threat_intel.is_proxy:
                    anonymizer_type.append("Proxy")
                
                score += 50
                factors.append({
                    "name": "Anonymization Detected",
                    "impact": 50,
                    "description": f"IP is associated with {', '.join(anonymizer_type)} services"
                })
            
            # Factor 5: Bot Detection (+10)
            if threat_intel.is_bot:
                score += 10
                factors.append({
                    "name": "Bot Activity",
                    "impact": 10,
                    "description": "IP shows characteristics of automated/bot traffic"
                })
            
            # Factor 6: Datacenter IP (+8)
            if threat_intel.is_datacenter and not threat_intel.is_vpn:
                score += 8
                factors.append({
                    "name": "Datacenter IP",
                    "impact": 8,
                    "description": "IP belongs to a hosting/datacenter provider"
                })
        
        # Factor 7: High-risk country (+10-20)
        country_code = geolocation.get("countryCode", "") if isinstance(geolocation, dict) else ""
        if country_code in HIGH_RISK_COUNTRIES:
            score += 20
            factors.append({
                "name": "High-Risk Country",
                "impact": 20,
                "description": f"IP originates from high-risk region: {geolocation.get('country', 'Unknown')}"
            })
        elif country_code in CAUTION_COUNTRIES:
            score += 10
            factors.append({
                "name": "Caution Region",
                "impact": 10,
                "description": f"IP originates from region requiring caution: {geolocation.get('country', 'Unknown')}"
            })
        
        # Factor 8: Dangerous ports open (+10 each, max 30)
        if isinstance(port_scan, PortScanResult):
            dangerous_open = [p for p in port_scan.open_ports if p in DANGEROUS_PORTS]
            if dangerous_open:
                port_score = min(len(dangerous_open) * 10, 30)
                score += port_score
                factors.append({
                    "name": "Dangerous Ports Open",
                    "impact": port_score,
                    "description": f"Risky ports detected: {', '.join(f'{p} ({COMMON_PORTS[p]})' for p in dangerous_open)}"
                })
        
        # Factor 9: No reverse DNS (+5)
        if isinstance(dns_info, DNSInfo):
            if not dns_info.reverse_dns or dns_info.reverse_dns == "No PTR record":
                score += 5
                factors.append({
                    "name": "No Reverse DNS",
                    "impact": 5,
                    "description": "IP has no PTR record, may indicate temporary or malicious infrastructure"
                })
        
        # Cap score at 100
        score = min(score, 100)
        
        # Determine severity (AGGRESSIVE THRESHOLDS)
        is_malicious = False
        if score <= 20:
            severity = "Low"
            recommendation = "✅ This IP appears to be safe. No immediate action required, but maintain standard security practices."
        elif score <= 35:
            severity = "Medium"
            recommendation = "⚡ MONITOR CAREFULLY. Some risk indicators present. Implement logging and rate limiting."
        elif score <= 60:
            severity = "High"
            recommendation = "⚠️ EXERCISE EXTREME CAUTION. Significant risk detected. Consider blocking or strict access controls."
            is_malicious = True
        else:
            severity = "Critical"
            recommendation = "⛔ BLOCK IMMEDIATELY. High likelihood of malicious activity. Do not allow connections from this source."
            is_malicious = True
        
        # Override for specific threats
        if threat_intel.is_blacklisted or threat_intel.is_tor_exit or threat_intel.abuse_confidence_score > 75:
            is_malicious = True
        
        return RiskAssessment(
            score=score,
            severity=severity,
            factors=factors,
            recommendation=recommendation,
            is_malicious=is_malicious
        )


# Singleton instance for use in API
ip_scanner = IPScannerService()
