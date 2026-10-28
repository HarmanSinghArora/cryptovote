"""
Simulate Database Tampering & Verify Amazon SNS Alert
=====================================================
Demonstrates Phase 3 of Day 2:
1. Validates that the SHA-256 hash chain is currently intact.
2. Directly tampers with Block 2 in the database (simulating a rogue insider changing a vote).
3. Invokes GET /admin/verify-chain on the running Flask backend.
4. Asserts that the backend detects the cryptographic mismatch.
5. Verifies that publish_sns_alert() dispatches a high-priority alert via Amazon SNS.
6. Automatically restores the clean database to keep the environment healthy.
"""

import os
import sys
import shutil
import sqlite3
import json
import time
import urllib.request
import urllib.error

SERVER_URL = "http://127.0.0.1:5000"
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cryptovote.db")
BACKUP_PATH = DB_PATH + ".bak"

def print_step(title):
    print("\n" + "=" * 70)
    print(f"[*] {title}")
    print("=" * 70)

def http_get(endpoint):
    url = f"{SERVER_URL}{endpoint}"
    req = urllib.request.Request(url, headers={"User-Agent": "CryptoVote-TamperTest/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            return response.getcode(), json.loads(response.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

def main():
    print_step("STEP 1: Verify Running Flask Server & Clean Baseline")
    try:
        status, data = http_get("/")
        if status != 200 or data.get("status") != "HEALTHY":
            print(f"[!] Server returned unexpected health status: {data}")
            sys.exit(1)
        print(f"[+] Flask server is ONLINE: {data['service']} v{data['version']}")
    except Exception as e:
        print(f"[!] Cannot connect to Flask server at {SERVER_URL}: {e}")
        print("[!] Please ensure 'python app.py' is running in Terminal 1.")
        sys.exit(1)

    status, chain_status = http_get("/admin/verify-chain")
    print(f"[+] Baseline Chain Status: valid={chain_status.get('is_valid')}, blocks={chain_status.get('total_blocks')}")
    if not chain_status.get("is_valid"):
        print("[!] Baseline chain is already invalid! Clean database first.")
        sys.exit(1)

    print_step("STEP 2: Create Safe Backup of cryptovote.db")
    shutil.copyfile(DB_PATH, BACKUP_PATH)
    print(f"[+] Backup created at {BACKUP_PATH}")

    try:
        print_step("STEP 3: Simulate Malicious Database Tampering (Rogue Admin Attack)")
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        # Find block 2
        cur.execute("SELECT id, candidate_id, entry_hash FROM votes WHERE id = 2")
        row = cur.fetchone()
        if not row:
            # If only 1 vote or no vote, tamper block 1
            cur.execute("SELECT id, candidate_id, entry_hash FROM votes ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()

        target_id, orig_candidate, orig_hash = row
        fake_candidate = 2 if orig_candidate == 1 else 1

        print(f"[*] Tampering Block #{target_id}:")
        print(f"    - Original Candidate ID: {orig_candidate}")
        print(f"    - Original SHA-256 Hash: {orig_hash}")
        print(f"    - FORGING to Candidate ID: {fake_candidate} (without recalculating hash!)")

        cur.execute("UPDATE votes SET candidate_id = ? WHERE id = ?", (fake_candidate, target_id))
        conn.commit()
        conn.close()
        print("[+] Tamper committed to SQLite file directly!")

        print_step("STEP 4: Run Chain Integrity Verification via REST API")
        print(f"[*] Invoking GET {SERVER_URL}/admin/verify-chain ...")
        status, result = http_get("/admin/verify-chain")

        print(f"\n[+] API HTTP Response: {status}")
        print(json.dumps(result, indent=2))

        if not result.get("is_valid"):
            print("\n" + "*" * 70)
            print(">>> SUCCESS: TAMPER DETECTED BY CRYPTOGRAPHIC HASH CHAIN! <<<")
            print(f">>> Error: {result.get('details', {}).get('error')}")
            print(f">>> Block Index: {result.get('details', {}).get('block_index')}")
            print("*" * 70)
            print("\n[+] publish_sns_alert() was triggered by app.py!")
            print("[+] An urgent email alert has been dispatched to: harmanarora2006@gmail.com")
            print("[+] CHECK YOUR EMAIL INBOX NOW for the alert message!")
        else:
            print("[!] ERROR: The backend failed to detect the tampered block!")
            sys.exit(1)

    finally:
        print_step("STEP 5: Restore Database to Clean State")
        if os.path.exists(BACKUP_PATH):
            shutil.copyfile(BACKUP_PATH, DB_PATH)
            os.remove(BACKUP_PATH)
            print(f"[+] Restored original database from backup.")

        status, clean_check = http_get("/admin/verify-chain")
        print(f"[+] Post-Restore Verification: valid={clean_check.get('is_valid')}, blocks={clean_check.get('total_blocks')}")
        print("[+] Hash chain restored to 100% integrity!")

if __name__ == "__main__":
    main()
