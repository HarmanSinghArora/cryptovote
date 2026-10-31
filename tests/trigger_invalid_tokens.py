"""
Test Script: Submit 3 Invalid Tokens to trigger CloudWatch Metric Filter and Alarm
Target: http://15.206.173.159/vote
"""

import sys
import json
import time
import urllib.request
import urllib.error

SERVER_URL = sys.argv[1] if len(sys.argv) > 1 else "http://15.206.173.159"

print(f"[*] Target Server: {SERVER_URL}")
print("[*] Submitting 3 forged ballot tokens to test CloudWatch Alarm detection...")

for i in range(1, 4):
    payload = {
        "candidate_id": 1,
        "token": f"forged_token_{int(time.time())}_{i}",
        "signature": "999999999999999999999999999999" # Invalid signature
    }
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(
        f"{SERVER_URL}/vote",
        data=data,
        headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req) as res:
            print(f"[!] Warning: Request {i} was accepted unexpectedly!")
    except urllib.error.HTTPError as e:
        body = json.loads(e.read().decode('utf-8'))
        print(f"[+] Request {i}: Rejected as expected with HTTP {e.code} | Code: {body.get('code')} | Error: {body.get('error')}")
    time.sleep(1)

print("\n[+] Successfully submitted 3 invalid tokens!")
print("[*] Check /var/log/cryptovote.log and CloudWatch log group /cryptovote/application.")
