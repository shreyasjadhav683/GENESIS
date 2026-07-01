
import requests
import sys
import time

# Constants
BASE_URL = "http://127.0.0.1:8000/api/v1"

def main():
    print("[*] Starting Verification (Synchronous)...")
    
    # 1. Login/Register
    import random
    r_id = random.randint(1000, 9999)
    test_email = f"history_test_{r_id}@example.com"
    test_pass = "securepass123"
    
    print(f"[*] Registering user {test_email}...")
    reg_data = {
       "email": test_email,
       "password": test_pass,
       "username": f"history_user_{r_id}",
       "security_question": "Pet?",
       "security_answer": "Dog"
    }
    
    try:
        resp = requests.post(f"{BASE_URL}/auth/signup", json=reg_data)
        if resp.status_code not in [200, 201]:
             print(f"[!] Registration note: {resp.status_code} {resp.text}")
    except Exception as e:
        print(f"[ERROR] Connection failed: {str(e)}")
        return

    print(f"[*] Logging in...")
    login_data = {
        "username": test_email,
        "password": test_pass
    }
    resp = requests.post(f"{BASE_URL}/auth/login", data=login_data)
    if resp.status_code != 200:
        print(f"[ERROR] Login failed: {resp.status_code} {resp.text}")
        return
        
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"[SUCCESS] Got token.")
    
    # 2. Trigger Scans
    print("[*] Triggering URL Scan...")
    resp = requests.get(f"{BASE_URL}/ip/url?url=https://example.com", headers=headers)
    # 200 is OK
    
    print("[*] Triggering IP Scan...")
    resp = requests.post(f"{BASE_URL}/ip/scan?ip_address=1.1.1.1", headers=headers)
    
    # 3. Check History
    print("[*] Fetching History...")
    resp = requests.get(f"{BASE_URL}/history/", headers=headers)
    if resp.status_code != 200:
         print(f"[ERROR] Get History failed: {resp.status_code} {resp.text}")
         return
        
    history = resp.json()
    print(f"[*] History items count: {len(history)}")
    
    found_url = any(h.get('scan_type') == 'URL_AGGRESSIVE_SCAN' for h in history)
    found_ip = any(h.get('scan_type') == 'IP_COMPREHENSIVE_SCAN' for h in history)
    
    if found_url and found_ip:
         print("[SUCCESS] Both URL and IP scans found in history.")
    else:
         print(f"[ERROR] Missing history items. URL: {found_url}, IP: {found_ip}")
         print(history)

    # 4. Test Deletion
    if len(history) > 0:
        item_id = history[0]['id']
        print(f"[*] Deleting history item {item_id}...")
        resp = requests.delete(f"{BASE_URL}/history/{item_id}", headers=headers)
        if resp.status_code == 200:
            print("[SUCCESS] Item deleted.")
        else:
             print(f"[ERROR] Delete failed: {resp.status_code} {resp.text}")
             
        # Verify deletion
        resp = requests.get(f"{BASE_URL}/history/", headers=headers)
        new_history = resp.json()
        if len(new_history) == len(history) - 1:
             print("[SUCCESS] Count decremented correctly.")
        else:
             print(f"[ERROR] Count mismatch after delete. Before: {len(history)}, After: {len(new_history)}")

    print("[*] Verification Complete.")

if __name__ == "__main__":
    main()
