
import requests
import json
import sys

BASE_URL = "http://127.0.0.1:8000/api/v1"
USERNAME = "testuser"
PASSWORD = "testpassword"

def login():
    print(f"[*] Logging in as {USERNAME}...")
    try:
        response = requests.post(
            f"{BASE_URL}/auth/login/access-token", 
            data={"username": USERNAME, "password": PASSWORD}
        )
        if response.status_code == 200:
            token = response.json()["access_token"]
            print("[+] Login successful.")
            return token
        else:
            print(f"[-] Login failed: {response.text}")
            sys.exit(1)
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        print("Ensure the backend server is running.")
        sys.exit(1)

def test_ip_scanner(headers, ip="8.8.8.8"):
    print(f"\n[*] Testing IP Scanner with {ip}...")
    response = requests.get(f"{BASE_URL}/ip/{ip}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(f"[+] Success. IP: {data['ip']}")
        print(f"    - Org: {data.get('org')}")
        print(f"    - Country: {data.get('country')}")
        if data.get('geolocation') and 'lat' in data.get('geolocation'):
            print("    - Real Geolocation Data confirmed.")
        else:
            print("    - [!] Geo data missing or mocked.")
    else:
        print(f"[-] Failed: {response.text}")

def test_url_scanner(headers, url):
    print(f"\n[*] Testing URL Scanner with {url}...")
    # URL Scanner is mounted under /ip/url because it's in ip_tools which is prefix='/ip'
    response = requests.get(f"{BASE_URL}/ip/url", params={"url": url}, headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(f"[DEBUG] Response Data: {data}")
        print(f"[+] Success. URL: {data['url']}")
        print(f"    - Malicious: {data['malicious']}")
        print(f"    - Risk Score: {data['risk_score']}")
        print(f"    - Flags: {data['flags']}")
    else:
        print(f"[-] Failed: {response.text}")

def test_ai_assistant(headers, query):
    print(f"\n[*] Testing AI Assistant with query '{query}'...")
    response = requests.post(f"{BASE_URL}/ai/assistant", json={"query": query}, headers=headers)
    if response.status_code == 200:
        data = response.json()
        print(f"[+] Success.")
        print(f"    - Response Preview: {data['response'][:100]}...")
        print(f"    - Confidence: {data.get('confidence')}")
        print(f"    - Source: {data.get('source')}")
    else:
        print(f"[-] Failed: {response.text}")

if __name__ == "__main__":
    token = login()
    headers = {"Authorization": f"Bearer {token}"}
    
    test_ip_scanner(headers, "8.8.8.8")
    
    # Test a suspicious URL
    suspicious_url = "http://192.168.1.1/login.php?update=true"
    test_url_scanner(headers, suspicious_url)
    
    test_ai_assistant(headers, "How do I fix SQL Injection?")
