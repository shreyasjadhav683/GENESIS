"""
Browser Extension Scanner Service
Scans installed browser extensions from Chrome, Edge, and Firefox and analyzes their security risk.
"""

import os
import json
import glob
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

# Dangerous permissions that indicate high risk
DANGEROUS_PERMISSIONS = {
    # Critical - can access all data
    "<all_urls>": {"risk": "CRITICAL", "description": "Access to all websites and data"},
    "http://*/*": {"risk": "HIGH", "description": "Access to all HTTP websites"},
    "https://*/*": {"risk": "HIGH", "description": "Access to all HTTPS websites"},
    "*://*/*": {"risk": "CRITICAL", "description": "Access to all websites"},
    
    # High risk permissions
    "cookies": {"risk": "HIGH", "description": "Can read and modify cookies"},
    "webRequest": {"risk": "HIGH", "description": "Can intercept and modify network requests"},
    "webRequestBlocking": {"risk": "CRITICAL", "description": "Can block and modify all network traffic"},
    "proxy": {"risk": "HIGH", "description": "Can control proxy settings"},
    "nativeMessaging": {"risk": "HIGH", "description": "Can communicate with native applications"},
    "debugger": {"risk": "CRITICAL", "description": "Full debugging access to browser"},
    "management": {"risk": "HIGH", "description": "Can manage other extensions"},
    "privacy": {"risk": "HIGH", "description": "Can modify privacy settings"},
    "downloads": {"risk": "MEDIUM", "description": "Can manage downloads"},
    "history": {"risk": "MEDIUM", "description": "Can read browsing history"},
    "bookmarks": {"risk": "LOW", "description": "Can access bookmarks"},
    
    # Medium risk
    "tabs": {"risk": "MEDIUM", "description": "Can access browser tabs info"},
    "activeTab": {"risk": "LOW", "description": "Access to active tab only"},
    "storage": {"risk": "LOW", "description": "Can store local data"},
    "clipboardRead": {"risk": "MEDIUM", "description": "Can read clipboard"},
    "clipboardWrite": {"risk": "LOW", "description": "Can write to clipboard"},
    "geolocation": {"risk": "MEDIUM", "description": "Can access location"},
    "notifications": {"risk": "LOW", "description": "Can show notifications"},
    "contentSettings": {"risk": "MEDIUM", "description": "Can modify content settings"},
    "browsingData": {"risk": "MEDIUM", "description": "Can delete browsing data"},
    "topSites": {"risk": "MEDIUM", "description": "Can access most visited sites"},
    
    # Web accessible content permissions
    "webNavigation": {"risk": "MEDIUM", "description": "Can track navigation events"},
    "declarativeNetRequest": {"risk": "MEDIUM", "description": "Can modify network requests"},
}


@dataclass
class ExtensionInfo:
    """Represents a browser extension with its metadata and risk assessment"""
    id: str
    name: str
    version: str
    description: str
    browser: str
    manifest_version: int
    permissions: List[str]
    host_permissions: List[str]
    risk_level: str
    risk_score: int
    risk_factors: List[Dict[str, str]]
    author: Optional[str] = None
    homepage_url: Optional[str] = None
    update_url: Optional[str] = None
    enabled: bool = True
    path: str = ""


def get_chrome_extensions_path() -> List[str]:
    """Get paths to Chrome extension directories"""
    paths = []
    
    # Windows paths
    if os.name == 'nt':
        local_app_data = os.environ.get('LOCALAPPDATA', '')
        
        # Chrome
        chrome_path = os.path.join(local_app_data, 'Google', 'Chrome', 'User Data', 'Default', 'Extensions')
        if os.path.exists(chrome_path):
            paths.append(('Chrome', chrome_path))
        
        # Check other Chrome profiles
        chrome_base = os.path.join(local_app_data, 'Google', 'Chrome', 'User Data')
        if os.path.exists(chrome_base):
            for item in os.listdir(chrome_base):
                if item.startswith('Profile '):
                    profile_ext_path = os.path.join(chrome_base, item, 'Extensions')
                    if os.path.exists(profile_ext_path):
                        paths.append((f'Chrome ({item})', profile_ext_path))
        
        # Edge
        edge_path = os.path.join(local_app_data, 'Microsoft', 'Edge', 'User Data', 'Default', 'Extensions')
        if os.path.exists(edge_path):
            paths.append(('Edge', edge_path))
        
        # Edge profiles
        edge_base = os.path.join(local_app_data, 'Microsoft', 'Edge', 'User Data')
        if os.path.exists(edge_base):
            for item in os.listdir(edge_base):
                if item.startswith('Profile '):
                    profile_ext_path = os.path.join(edge_base, item, 'Extensions')
                    if os.path.exists(profile_ext_path):
                        paths.append((f'Edge ({item})', profile_ext_path))
        
        # Brave
        brave_path = os.path.join(local_app_data, 'BraveSoftware', 'Brave-Browser', 'User Data', 'Default', 'Extensions')
        if os.path.exists(brave_path):
            paths.append(('Brave', brave_path))
    
    # Linux paths
    else:
        home = os.path.expanduser('~')
        
        chrome_path = os.path.join(home, '.config', 'google-chrome', 'Default', 'Extensions')
        if os.path.exists(chrome_path):
            paths.append(('Chrome', chrome_path))
        
        chromium_path = os.path.join(home, '.config', 'chromium', 'Default', 'Extensions')
        if os.path.exists(chromium_path):
            paths.append(('Chromium', chromium_path))
    
    return paths


def get_firefox_extensions_path() -> List[str]:
    """Get paths to Firefox extension directories"""
    paths = []
    
    if os.name == 'nt':
        app_data = os.environ.get('APPDATA', '')
        firefox_profiles = os.path.join(app_data, 'Mozilla', 'Firefox', 'Profiles')
    else:
        home = os.path.expanduser('~')
        firefox_profiles = os.path.join(home, '.mozilla', 'firefox')
    
    if os.path.exists(firefox_profiles):
        for profile in os.listdir(firefox_profiles):
            profile_path = os.path.join(firefox_profiles, profile)
            extensions_path = os.path.join(profile_path, 'extensions')
            if os.path.isdir(extensions_path):
                paths.append(('Firefox', extensions_path))
    
    return paths


def calculate_risk(permissions: List[str], host_permissions: List[str] = []) -> tuple:
    """Calculate risk level and score based on permissions"""
    all_perms = permissions + host_permissions
    risk_score = 0
    risk_factors = []
    
    for perm in all_perms:
        perm_lower = perm.lower() if isinstance(perm, str) else str(perm)
        
        # Check for URL patterns
        if perm in DANGEROUS_PERMISSIONS:
            perm_info = DANGEROUS_PERMISSIONS[perm]
            risk_factors.append({
                "permission": perm,
                "risk": perm_info["risk"],
                "description": perm_info["description"]
            })
            if perm_info["risk"] == "CRITICAL":
                risk_score += 40
            elif perm_info["risk"] == "HIGH":
                risk_score += 25
            elif perm_info["risk"] == "MEDIUM":
                risk_score += 10
            else:
                risk_score += 3
        
        # Check for URL pattern permissions
        elif any(x in perm for x in ["://*", "://", "/*"]):
            if "*://*/*" in perm or "<all_urls>" in perm:
                risk_score += 40
                risk_factors.append({
                    "permission": perm,
                    "risk": "CRITICAL",
                    "description": "Access to all websites"
                })
            elif "://*/*" in perm:
                risk_score += 25
                risk_factors.append({
                    "permission": perm,
                    "risk": "HIGH", 
                    "description": f"Broad website access: {perm[:50]}..."
                })
            else:
                risk_score += 5
    
    # Determine risk level
    if risk_score >= 60:
        risk_level = RiskLevel.CRITICAL
    elif risk_score >= 40:
        risk_level = RiskLevel.HIGH
    elif risk_score >= 20:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW
    
    return risk_level.value, min(risk_score, 100), risk_factors


def parse_chrome_extension(ext_id: str, ext_path: str, browser: str) -> Optional[ExtensionInfo]:
    """Parse a Chrome/Edge extension directory"""
    try:
        # Find the latest version directory
        versions = [d for d in os.listdir(ext_path) if os.path.isdir(os.path.join(ext_path, d))]
        if not versions:
            return None
        
        # Sort versions and get the latest
        versions.sort(reverse=True)
        version_path = os.path.join(ext_path, versions[0])
        manifest_path = os.path.join(version_path, 'manifest.json')
        
        if not os.path.exists(manifest_path):
            return None
        
        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
            manifest = json.load(f)
        
        # Extract permissions
        permissions = manifest.get('permissions', [])
        host_permissions = manifest.get('host_permissions', [])
        
        # For manifest v2, optional_permissions might also contain host patterns
        optional_permissions = manifest.get('optional_permissions', [])
        
        # Some extensions put host permissions in content_scripts
        content_scripts = manifest.get('content_scripts', [])
        for script in content_scripts:
            matches = script.get('matches', [])
            host_permissions.extend(matches)
        
        # Calculate risk
        risk_level, risk_score, risk_factors = calculate_risk(permissions, host_permissions)
        
        return ExtensionInfo(
            id=ext_id,
            name=manifest.get('name', 'Unknown'),
            version=manifest.get('version', '0.0.0'),
            description=manifest.get('description', 'No description'),
            browser=browser,
            manifest_version=manifest.get('manifest_version', 2),
            permissions=permissions,
            host_permissions=list(set(host_permissions)),  # Remove duplicates
            risk_level=risk_level,
            risk_score=risk_score,
            risk_factors=risk_factors,
            author=manifest.get('author', manifest.get('developer', {}).get('name') if isinstance(manifest.get('developer'), dict) else None),
            homepage_url=manifest.get('homepage_url'),
            update_url=manifest.get('update_url'),
            path=version_path
        )
    except Exception as e:
        print(f"Error parsing extension {ext_id}: {e}")
        return None


def parse_firefox_extension(ext_file: str, browser: str) -> Optional[ExtensionInfo]:
    """Parse a Firefox extension (XPI file or directory)"""
    try:
        import zipfile
        
        if ext_file.endswith('.xpi'):
            # XPI is a ZIP file
            with zipfile.ZipFile(ext_file, 'r') as z:
                manifest_data = z.read('manifest.json')
                manifest = json.loads(manifest_data)
        elif os.path.isdir(ext_file):
            manifest_path = os.path.join(ext_file, 'manifest.json')
            if not os.path.exists(manifest_path):
                return None
            with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                manifest = json.load(f)
        else:
            return None
        
        ext_id = os.path.basename(ext_file).replace('.xpi', '')
        
        permissions = manifest.get('permissions', [])
        host_permissions = manifest.get('host_permissions', [])
        
        risk_level, risk_score, risk_factors = calculate_risk(permissions, host_permissions)
        
        return ExtensionInfo(
            id=ext_id,
            name=manifest.get('name', 'Unknown'),
            version=manifest.get('version', '0.0.0'),
            description=manifest.get('description', 'No description'),
            browser=browser,
            manifest_version=manifest.get('manifest_version', 2),
            permissions=permissions,
            host_permissions=host_permissions,
            risk_level=risk_level,
            risk_score=risk_score,
            risk_factors=risk_factors,
            author=manifest.get('author'),
            homepage_url=manifest.get('homepage_url'),
            path=ext_file
        )
    except Exception as e:
        print(f"Error parsing Firefox extension {ext_file}: {e}")
        return None


def scan_all_extensions() -> Dict[str, Any]:
    """Scan all browser extensions and return analysis results"""
    extensions = []
    browsers_scanned = []
    
    # Scan Chrome/Edge/Brave extensions
    for browser, ext_path in get_chrome_extensions_path():
        browsers_scanned.append(browser)
        try:
            for ext_id in os.listdir(ext_path):
                ext_dir = os.path.join(ext_path, ext_id)
                if os.path.isdir(ext_dir):
                    ext_info = parse_chrome_extension(ext_id, ext_dir, browser)
                    if ext_info:
                        extensions.append(ext_info)
        except Exception as e:
            print(f"Error scanning {browser} extensions: {e}")
    
    # Scan Firefox extensions
    for browser, ext_path in get_firefox_extensions_path():
        if browser not in browsers_scanned:
            browsers_scanned.append(browser)
        try:
            for item in os.listdir(ext_path):
                item_path = os.path.join(ext_path, item)
                ext_info = parse_firefox_extension(item_path, browser)
                if ext_info:
                    extensions.append(ext_info)
        except Exception as e:
            print(f"Error scanning Firefox extensions: {e}")
    
    
    # Calculate summary statistics
    total = len(extensions)
    critical_count = len([e for e in extensions if e.risk_level == "CRITICAL"])
    high_count = len([e for e in extensions if e.risk_level == "HIGH"])
    medium_count = len([e for e in extensions if e.risk_level == "MEDIUM"])
    low_count = len([e for e in extensions if e.risk_level == "LOW"])
    
    # Remediation Steps per Browser
    remediation_steps = {
        "Chrome": [
            "1. Open Chrome and go to 'chrome://extensions'",
            "2. Find the extension in the list",
            "3. Click 'Remove'",
            "4. Confirm removal in the popup dialog"
        ],
        "Edge": [
            "1. Open Edge and go to 'edge://extensions'",
            "2. Find the extension in the list",
            "3. Click 'Remove'",
            "4. Click 'Remove' again to confirm"
        ],
        "Firefox": [
            "1. Open Firefox and go to 'about:addons'",
            "2. Click 'Extensions' in the left menu",
            "3. Find the extension and click the three-dot menu (...) next to it",
            "4. Select 'Remove'"
        ],
        "Brave": [
            "1. Open Brave and go to 'brave://extensions'",
            "2. Find the extension in the list",
            "3. Click 'Remove'",
            "4. Confirm removal"
        ],
        "Chromium": [
            "1. Open the browser and go to 'chrome://extensions'",
            "2. Find the extension",
            "3. Click 'Remove'"
        ]
    }

    # Convert extensions to dicts and add remediation
    extensions_data = []
    for ext in extensions:
        # Determine recommended action
        if ext.risk_level in ["CRITICAL", "HIGH"]:
            action = "REMOVE"
            action_desc = "Highly recommended to remove this extension immediately due to critical security risks."
        elif ext.risk_level == "MEDIUM":
            action = "REVIEW"
            action_desc = "Review permissions. Remove if not absolutely necessary."
        else:
            action = "KEEP"
            action_desc = "Safe to keep. Basic permissions only."

        # specific remediation for this browser
        steps = remediation_steps.get(ext.browser.split(' ')[0], remediation_steps.get("Chrome"))

        extensions_data.append({
            "id": ext.id,
            "name": ext.name,
            "version": ext.version,
            "description": ext.description,
            "browser": ext.browser,
            "manifest_version": ext.manifest_version,
            "permissions": ext.permissions,
            "host_permissions": ext.host_permissions,
            "risk_level": ext.risk_level,
            "risk_score": ext.risk_score,
            "risk_factors": ext.risk_factors,
            "author": ext.author,
            "homepage_url": ext.homepage_url,
            "path": ext.path,
            "remediation": {
                "action": action,
                "description": action_desc,
                "steps": steps
            }
        })
    
    # Sort by risk score (highest first)
    extensions_data.sort(key=lambda x: x["risk_score"], reverse=True)
    
    return {
        "extensions": extensions_data,
        "summary": {
            "total": total,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "browsers_scanned": browsers_scanned
        },
        "scan_time": None  # Will be set by the endpoint
    }

