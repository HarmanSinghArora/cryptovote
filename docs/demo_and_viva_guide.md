# 🎤 CryptoVote: 5-Minute Final Demonstration Script & Viva Defense Guide
**Project:** CryptoVote – Secure Online Voting System  
**Team Members:**  
- **Person A (Infrastructure & Frontend):** `sara21-g`  
- **Person B (Application Backend, Database & Cryptography):** Harman Singh Arora  
**Course:** Cloud Computing Laboratory Mini Project  

---

## ⏱️ Part 1: The 5-Minute Demonstration Walkthrough (11-Step Rubric Order)

This script is structured to be delivered collaboratively within **5 minutes (300 seconds)**. Keep the transitions sharp and confident!

```
[0:00 - 0:45] Step 1: Architecture & Cloud Infrastructure (Person A)
[0:45 - 1:15] Steps 2 & 3: Voter Registration & Login (Person B)
[1:15 - 1:55] Step 4: Blind Signature & Anonymous Vote Casting (Person B)
[1:55 - 2:20] Steps 5 & 6: Receipt Verification & Double-Voting Prevention (Person B)
[2:20 - 3:00] Step 7: Database Tampering & Hash-Chain Verification Failure (Person B)
[3:00 - 3:45] Steps 8 & 9: CloudWatch Metric Alarm & Email Alert Notification (Person A)
[3:45 - 4:25] Step 10: AWS Lambda Election Closure Execution (Person B)
[4:25 - 5:00] Step 11: Amazon S3 Immutable Audit Archives & Conclusion (Person A & B)
```

---

### Step 1: Show the Architecture Diagram (0:00 – 0:45)
- **Speaker:** **Person A**
- **Action on Screen:** Display the Mermaid Architecture Diagram from [README.md](file:///README.md).
- **Speaking Script (Person A):**  
  > *"Good morning professor. Welcome to our demonstration of **CryptoVote**, a secure, privacy-preserving digital voting system.  
  > Here is our AWS architecture: we built a Custom VPC across two Availability Zones in `ap-south-1` Mumbai. We placed our EC2 web server in the public subnet running Gunicorn and Flask, while completely isolating our Amazon RDS MySQL database in private subnets where it has no public IP.  
  > All sensitive credentials are encrypted using AWS Systems Manager Parameter Store. We integrated Amazon S3 for immutable audit storage, AWS Lambda for serverless election closure, and Amazon CloudWatch with SNS for real-time tamper and anomaly alerts.  
  > My partner Harman will now demonstrate the voting and cryptography engine."*

---

### Steps 2 & 3: Register a Voter & Log In (0:45 – 1:15)
- **Speaker:** **Person B (Harman)**
- **Action on Screen:** Open Web UI or run terminal command for registration:
  ```bash
  curl -X POST http://<IP>/register -H "Content-Type: application/json" -d "{\"voter_id\": \"voter_demo\", \"password\": \"VoterPass2026!\"}"
  curl -X POST http://<IP>/login -H "Content-Type: application/json" -d "{\"voter_id\": \"voter_demo\", \"password\": \"VoterPass2026!\"}"
  ```
- **Speaking Script (Person B):**  
  > *"Thank you. First, we register an authorized voter. Notice that the voter's password is never stored in plaintext. We hash it using **PBKDF2 with HMAC-SHA256, 100,000 iterations, and a unique 16-byte random salt** stored in the database.  
  > Upon login, the backend verifies the credentials using constant-time evaluation to prevent timing attacks, and issues an active session token authorizing this voter to request exactly one blind signature."*

---

### Step 4: Blind Signature Issuance & Anonymous Ballot Submission (1:15 – 1:55)
- **Speaker:** **Person B (Harman)**
- **Action on Screen:** Run `python client.py` (or click Vote in Frontend):
- **Speaking Script (Person B):**  
  > *"Now comes the core cryptographic innovation: **David Chaum's RSA Blind Signatures**.  
  > The voter wants to vote for Candidate #1. Before sending anything to the server, the client selects a secret random blinding factor $r$ and computes $m' = m \cdot r^e \pmod N$.  
  > The client sends only $m'$ to the server. The server verifies that the voter is registered and hasn't voted yet, and signs the blinded value: $s' = (m')^d \pmod N$. Notice that the server signs without ever learning the voter's candidate choice!  
  > The client then unblinds the signature locally: $s = s' \cdot r^{-1} \pmod N$.  
  > Finally, the ballot is submitted through an anonymous channel with zero voter identity. The server verifies $s^e \equiv m \pmod N$ and appends the vote to our blockchain-inspired ledger."*

---

### Steps 5 & 6: Check Receipt & Attempt Double-Voting (1:55 – 2:20)
- **Speaker:** **Person B (Harman)**
- **Action on Screen:**
  1. Show receipt lookup: `GET /receipt/<receipt_hash>` returns `verified: true`.
  2. Resubmit the exact same ballot:
     ```bash
     curl -X POST http://<IP>/vote -H "Content-Type: application/json" -d "..."
     ```
- **Speaking Script (Person B):**  
  > *"Every voter receives an immutable cryptographic receipt hash. Querying `/receipt/<hash>` verifies that their vote is permanently anchored in the ledger.  
  > If a voter attempts to submit the same ballot twice, our system looks up the anonymous token in the `used_tokens` table. Because that column has a `UNIQUE` database constraint, the server immediately rejects the replay attempt with an **HTTP 409 Conflict**, completely preventing double voting while preserving anonymity."*

---

### Step 7: Database Tampering & Hash Chain Failure (2:20 – 3:00)
- **Speaker:** **Person B (Harman)**
- **Action on Screen:** Run `python tests/simulate_tamper_and_alert.py` (or show MySQL update):
- **Speaking Script (Person B):**  
  > *"What if a malicious database administrator attempts to change a vote directly in MySQL?  
  > We implemented an append-only **SHA-256 Hash Chain**. Every vote block embeds the SHA-256 hash of the previous block, starting from a 64-zero Genesis hash.  
  > Here, we simulate a rogue admin modifying Candidate ID 1 to Candidate ID 2. When `/admin/verify-chain` runs, it recalculates every hash from Genesis. As you can see, the stored hash fails to match the recalculated hash: **Block #2 data tampered!**  
  > The server immediately fires an alert to Amazon SNS!"*

---

### Steps 8 & 9: CloudWatch Metric Alarm & Email Alert Received (3:00 – 3:45)
- **Speaker:** **Person A**
- **Action on Screen:**
  1. Open AWS CloudWatch Console showing the Metric Filter on `INVALID_TOKEN` and Alarm state.
  2. Open email inbox showing the AWS SNS notification:  
     `CRITICAL ALERT: CryptoVote Hash Chain Tampering Detected!`
- **Speaking Script (Person A):**  
  > *"On the infrastructure side, our CloudWatch Agent streams all application logs in real time. We configured a metric filter that scans for `INVALID_TOKEN` events. When 3 forged tokens are submitted in 5 minutes, CloudWatch automatically transitions the alarm to `ALARM` state.  
  > Furthermore, as Harman demonstrated, when hash-chain tampering occurs, our Amazon SNS topic `cryptovote-alerts` instantly delivers this high-priority alert email directly to the security team's inbox!"*

---

### Step 10: AWS Lambda Election Closure Execution (3:45 – 4:25)
- **Speaker:** **Person B (Harman)**
- **Action on Screen:** Show AWS Lambda Console or execute `aws lambda invoke`:
- **Speaking Script (Person B):**  
  > *"To close the election, we engineered an **AWS Lambda function (`close_election`)**.  
  > Lambda runs completely serverless outside the VPC to eliminate cold-start latency and avoid expensive NAT Gateway fees.  
  > When invoked, the Lambda execution role retrieves the administrative secret directly from encrypted Parameter Store, authenticates with the backend, tallies the election results, verifies the entire hash chain, and locks the voting endpoints against any further submissions."*

---

### Step 11: Amazon S3 Audit Archives & Conclusion (4:25 – 5:00)
- **Speaker:** **Person A & B (Tag Team)**
- **Action on Screen:** Open Amazon S3 Console showing bucket `cryptovote-audit-882478410161` containing `results.json` and `chain.json`. Open `results.json` to show final candidate counts.
- **Speaking Script (Person A & B):**  
  - **Person A:** *"Upon closure, the backend automatically packages the final tally and the full blockchain ledger, uploading `results.json` and `chain.json` directly to Amazon S3. S3 enforces 11 9's of durability and strict public access blocks to ensure permanent auditability."*
  - **Person B:** *"In conclusion, CryptoVote proves that true voter privacy, rigorous fraud prevention, and cloud-native auditability can be successfully unified using David Chaum RSA signatures, SHA-256 hash chaining, and AWS cloud architecture. Thank you, and we are now ready for your questions!"*

---

## 🎓 Part 2: Viva Defense Q&A Cheat Sheet (Guaranteed Professor Questions)

### Category A: Cryptography & Application (Person B Focus)

1. **Q: Why can't the server just promise not to look at who voted for whom? Why do we need Blind RSA?**  
   *Answer:* A software promise relies on trust. In security, we follow the principle of *\"Verify, don't trust.\"* Without blind signatures, any rogue developer, DBA, or subpoena could correlate voter logins to vote records. David Chaum's blinding factor $r^e \pmod N$ acts as a mathematical carbon-paper envelope: the server signs the mathematical validity of the ballot while being mathematically blind to its contents.

2. **Q: What is the exact mathematical property that allows unblinding?**  
   *Answer:* It relies on Euler's Totient Theorem: $(r^e)^d \equiv r^{ed} \equiv r^1 \equiv r \pmod N$. When the server signs $s' \equiv (m')^d \equiv (m \cdot r^e)^d \equiv m^d \cdot r \pmod N$, multiplying by the modular multiplicative inverse $r^{-1} \pmod N$ cancels out $r$, leaving $s \equiv m^d \pmod N$, which is a valid RSA signature over cleartext $m$.

3. **Q: If the vote is anonymous, how do you stop a voter from voting 10 times?**  
   *Answer:* We decouple voter eligibility from ballot uniqueness:
   - Eligibility is enforced at the blind-signing stage: `has_requested_ballot` is marked `True`, so each voter gets only one blind signature.
   - Replay is blocked at the voting stage: each ballot contains a 256-bit anonymous token. When submitted, its SHA-256 hash is inserted into the `used_tokens` table. Because that column has a `UNIQUE` constraint, a second submission throws an `IntegrityError` and is rejected with HTTP 409 Conflict.

4. **Q: How does the SHA-256 hash chain detect if an admin edits row 5 of 10?**  
   *Answer:* Block 5's hash is $H_5 = \text{SHA-256}(5 \parallel \text{Candidate} \parallel \text{Timestamp} \parallel H_4)$. If the candidate is altered, $H_5$ changes completely due to SHA-256's avalanche effect. Moreover, Block 6 stores the old $H_5$ as its `previous_hash`. Therefore, both Block 5's recalculation and Block 6's linkage fail immediately.

5. **Q: Why PBKDF2 with 100,000 rounds instead of MD5 or plain SHA-256 for passwords?**  
   *Answer:* Plain SHA-256 can compute billions of hashes per second on a modern GPU, enabling rapid offline dictionary attacks. PBKDF2 applies 100,000 rounds of HMAC-SHA256, adding intentional computational cost ($\approx 80\text{ms}$) that makes GPU cracking computationally infeasible. The 16-byte random salt invalidates pre-computed rainbow tables.

---

### Category B: AWS Infrastructure & Cloud Architecture (Person A Focus)

1. **Q: Why did you place RDS in private subnets? How does it communicate with EC2?**  
   *Answer:* Databases should never have public IP addresses or direct internet routes. Our RDS instance resides in private subnets across two AZs. Communication is routed internally within the VPC CIDR (`10.0.0.0/16`), and `cryptovote-db-sg` allows inbound TCP port 3306 exclusively from the Web Security Group (`sg-0b6b4c13f32db1a3d`).

2. **Q: Why does Lambda run outside the VPC rather than inside?**  
   *Answer:* If Lambda is inside a private subnet, it cannot access public internet endpoints or SSM without a NAT Gateway ($32/month) or VPC Endpoints. By running Lambda outside the VPC, it accesses Parameter Store and reaches the EC2 public IP directly with zero NAT cost and zero VPC cold starts.

3. **Q: Why Gunicorn and systemd instead of `flask run`?**  
   *Answer:* Flask's built-in WSGI server is single-threaded, intended purely for development, and crashes under concurrent voter requests. Gunicorn is an enterprise production WSGI server running multiple pre-forked worker processes. `systemd` acts as the Linux supervisor, ensuring that if Gunicorn ever crashes, it is automatically resurrected in 5 seconds (`Restart=always`).

4. **Q: How does the application access database passwords without exposing them in GitHub?**  
   *Answer:* We store them as encrypted `SecureString` types in AWS Systems Manager Parameter Store. The EC2 instance retrieves them at startup using an attached IAM Instance Profile with temporary, rotating STS credentials. No passwords exist in source code or git history.
