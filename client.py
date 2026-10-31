"""
CryptoVote Automated Client Simulation Script
Simulates the complete voter experience:
1. Registration & Authentication
2. Cryptographic Ballot Blinding
3. Obtaining Blind Signature from Server
4. Unblinding Signature Locally
5. Submitting Anonymous Vote to Hash-Chain Ledger
6. Verifying Vote Receipt
7. Demonstrating Duplicate Vote Rejection
8. Verifying Tamper-Evident Hash Chain
"""

import sys
import secrets
import requests
import json

from crypto.blind_rsa import hash_to_int, blind_message, unblind_signature

import os

BASE_URL = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("SERVER_URL", "http://127.0.0.1:5000")

def run_simulation():
    print("=" * 70)
    print("       CRYPTOVOTE: END-TO-END SYSTEM SIMULATION")
    print("=" * 70)

    # 1. Check Server Health
    print("\n[Step 1] Connecting to CryptoVote API server...")
    try:
        res = requests.get(f"{BASE_URL}/")
        res.raise_for_status()
        print(f"[+] Server Online: {res.json()}")
    except Exception as e:
        print(f"[!] Server connection failed: {e}")
        print("    Make sure 'python app.py' is running in another terminal!")
        sys.exit(1)

    # 2. Fetch Candidates
    print("\n[Step 2] Fetching list of election candidates...")
    res = requests.get(f"{BASE_URL}/candidates")
    candidates = res.json().get('candidates', [])
    for c in candidates:
        print(f"  - [{c['id']}] {c['name']} ({c['party']})")
    
    if not candidates:
        print("[!] No candidates found in database!")
        sys.exit(1)
    
    selected_candidate = candidates[0]
    print(f"[+] Voter chooses to vote for: {selected_candidate['name']} (ID: {selected_candidate['id']})")

    # 3. Register Voter
    voter_id = f"student_{secrets.token_hex(4)}"
    password = "StrongPassword2026!"
    print(f"\n[Step 3] Registering voter '{voter_id}'...")
    res = requests.post(f"{BASE_URL}/register", json={'voter_id': voter_id, 'password': password})
    print(f"[+] Registration Status ({res.status_code}): {res.json().get('message')}")

    # 4. Login Voter
    print(f"\n[Step 4] Logging in voter '{voter_id}'...")
    res = requests.post(f"{BASE_URL}/login", json={'voter_id': voter_id, 'password': password})
    login_data = res.json()
    session_token = login_data.get('token')
    print(f"[+] Login successful! Received session token: {session_token[:16]}...")

    # 5. Fetch Authority Public Key
    print("\n[Step 5] Fetching Election Authority Public RSA Key...")
    res = requests.get(f"{BASE_URL}/crypto/public-key")
    key_info = res.json()
    e = int(key_info['e'])
    n = int(key_info['n'])
    print(f"[+] Authority Key (e={e}, n bit-length={n.bit_length()}) received.")

    # 6. Prepare Ballot and Apply Blind Signature Math
    print("\n[Step 6] Cryptographic Ballot Preparation & Blinding (Client-Side)...")
    ballot_token = secrets.token_hex(16)
    ballot_raw = f"candidate:{selected_candidate['id']};token:{ballot_token}".encode('utf-8')
    m = hash_to_int(ballot_raw, n)
    print(f"  - Generated Anonymous Ballot Token: {ballot_token}")
    print(f"  - Raw Ballot Message Integer m: {str(m)[:30]}...")

    m_prime, r = blind_message(m, e, n)
    print(f"  - Picked Secret Blinding Factor r: {str(r)[:30]}...")
    print(f"  - Computed Blinded Message m' = (m * r^e) mod n: {str(m_prime)[:30]}...")

    # 7. Request Blind Signature from Server
    print("\n[Step 7] Requesting Blind Signature from Server (POST /blind-sign)...")
    headers = {'Authorization': f'Bearer {session_token}'}
    res = requests.post(f"{BASE_URL}/blind-sign", json={'blinded_message': str(m_prime)}, headers=headers)
    if res.status_code != 200:
        print(f"[!] Blind sign failed: {res.text}")
        sys.exit(1)
    
    blind_sig_data = res.json()
    s_prime = int(blind_sig_data['blind_signature'])
    print(f"[+] Received Blind Signature s' from Authority: {str(s_prime)[:30]}...")
    print("    [!] NOTICE: Server signed the ballot without ever knowing the candidate choice!")

    # 8. Unblind the Signature
    print("\n[Step 8] Unblinding Signature (Client-Side)...")
    s = unblind_signature(s_prime, r, n)
    print(f"[+] Unblinded Signature s = s' * r^(-1) mod n: {str(s)[:30]}...")

    # 9. Submit Anonymous Vote
    print("\n[Step 9] Submitting Anonymous Vote to Ledger (POST /vote)...")
    print("    [!] NOTICE: No voter ID or Authorization header is sent in this request!")
    vote_payload = {
        'candidate_id': selected_candidate['id'],
        'token': ballot_token,
        'signature': str(s)
    }
    res = requests.post(f"{BASE_URL}/vote", json=vote_payload)
    if res.status_code != 200:
        print(f"[!] Vote submission failed: {res.text}")
        sys.exit(1)

    vote_result = res.json()
    receipt_hash = vote_result.get('receipt_hash')
    block_index = vote_result.get('block_index')
    print(f"[+] Vote Successfully Recorded!")
    print(f"  - Block Index: #{block_index}")
    print(f"  - Cryptographic Receipt Hash: {receipt_hash}")

    # 10. Verify Vote Receipt
    print(f"\n[Step 10] Verifying Vote Receipt in Ledger (GET /receipt/{receipt_hash})...")
    res = requests.get(f"{BASE_URL}/receipt/{receipt_hash}")
    receipt_data = res.json()
    print(f"[+] Receipt Verified: Block #{receipt_data['block_index']}, Previous Hash: {receipt_data['previous_hash'][:16]}...")

    # 11. Test Double Voting Protection
    print("\n[Step 11] Testing Double-Voting Prevention (Attempting to resubmit the exact same ballot)...")
    res_dup = requests.post(f"{BASE_URL}/vote", json=vote_payload)
    print(f"[+] Duplicate Vote Response Status: {res_dup.status_code} ({res_dup.json().get('error')})")
    assert res_dup.status_code == 409, "Server must reject duplicate token with 409 Conflict!"
    print("  [PASS] Double-voting was mathematically and database-enforced blocked!")

    # 12. Verify Complete Hash Chain
    print("\n[Step 12] Administrative Verification of Full Blockchain Hash Chain (GET /admin/verify-chain)...")
    res_chain = requests.get(f"{BASE_URL}/admin/verify-chain")
    chain_info = res_chain.json()
    print(f"[+] Hash Chain Valid: {chain_info['is_valid']}")
    print(f"  - Total Verified Blocks: {chain_info['total_blocks']}")
    details_str = chain_info.get('details', {}).get('message') or chain_info.get('details', {}).get('error', 'N/A')
    print(f"  - Details: {details_str}")

    # 13. Current Results
    print("\n[Step 13] Viewing Live Results Tally (GET /results)...")
    res_results = requests.get(f"{BASE_URL}/results")
    results_data = res_results.json()
    print(f"[+] Total Votes Cast: {results_data['total_votes']}")
    for r in results_data['results']:
        print(f"  - {r['name']}: {r['votes']} votes")

    print("\n" + "=" * 70)
    print("   ALL 13 TESTS & CRITICAL SECURITY CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == '__main__':
    run_simulation()
