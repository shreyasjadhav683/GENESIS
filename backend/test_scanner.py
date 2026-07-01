"""
Quick test script to verify IP scanner works
"""
import asyncio
import sys
sys.path.insert(0, 'app')

from app.core.ip_scanner_service import ip_scanner

async def test_scan():
    print("Testing IP scanner with 8.8.8.8...")
    result = await ip_scanner.scan_ip("8.8.8.8")
    
    if "error" in result:
        print(f"[ERROR] Error: {result['error']}")
        return False
    
    print(f"[SUCCESS] Scan Complete!")
    print(f"   IP: {result.get('ip')}")
    print(f"   Risk Score: {result.get('risk_assessment', {}).get('score')}")
    print(f"   Severity: {result.get('risk_assessment', {}).get('severity')}")
    print(f"   Country: {result.get('geolocation', {}).get('country')}")
    return True

if __name__ == "__main__":
    success = asyncio.run(test_scan())
    sys.exit(0 if success else 1)
