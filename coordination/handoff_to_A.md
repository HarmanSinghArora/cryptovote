# Coordination Handoff to Person A (Cloud Infrastructure & Frontend)
**Project:** CryptoVote – Secure Online Voting System  
**From:** Person B (Backend, Database & Cryptography)  
**Date:** October 28, 2026  

---

## 1. Questions & Immediate Action Items for Person A

Please review the following checkpoints and share the requested details as soon as they are configured in AWS:

### A. AWS Account Access & Budget
1. **IAM User for Person B:**
   - Has the IAM user with `PowerUserAccess` (or necessary lab permissions) been created for Person B in your AWS account?
   - Region agreed: `ap-south-1` (Mumbai).
2. **AWS Budget:**
   - Has the AWS Budget ($5 USD cap) with email notifications to both team members been created?

### B. GitHub Repository
1. **Repository Setup:**
   - Repository Name: `cryptovote` (Private).
   - Collaborators: Both Person A and Person B added.
   - Branches:
     - `main` (production / merged code)
     - `person-b-backend` (Person B's active branch)
     - `person-a-infra` (Person A's active branch)

### C. AWS Infrastructure Parameters (Once Deployed in Hours 1–4)
Please fill out and return the following variables so Person B can configure the backend connection:

```env
# AWS Infrastructure Config Needed by Person B
AWS_REGION=ap-south-1
RDS_MYSQL_HOST=<your-rds-endpoint.ap-south-1.rds.amazonaws.com>
RDS_MYSQL_PORT=3306
RDS_MYSQL_DB=cryptovote_db
RDS_MYSQL_USER=<db-master-username>
RDS_MYSQL_PASSWORD=<db-master-password>

S3_BUCKET_NAME=<your-s3-bucket-name>
PARAMETER_STORE_PREFIX=/cryptovote/
EC2_PUBLIC_IP=<ec2-public-ip-for-frontend-testing>
```

---

## 2. Agreed API JSON Contract (Person B is implementing these)

Person A can build the frontend (HTML/JS) against these exact endpoints and JSON schemas:

### 1. `GET /candidates`
- **Purpose:** Fetches the list of active election candidates.
- **Request:** None
- **Response `200 OK`:**
```json
{
  "candidates": [
    {"id": 1, "name": "Alice Green", "party": "Forward Party"},
    {"id": 2, "name": "Bob Stone", "party": "Unity Alliance"}
  ]
}
```

### 2. `POST /register`
- **Purpose:** Registers an eligible voter with a salted PBKDF2 hashed password.
- **Request Body:**
```json
{
  "voter_id": "VOTER101",
  "password": "SecurePassword123"
}
```
- **Response `201 Created`:**
```json
{
  "message": "Voter registered successfully",
  "voter_id": "VOTER101"
}
```

### 3. `POST /login`
- **Purpose:** Authenticates voter credentials and returns a session token.
- **Request Body:**
```json
{
  "voter_id": "VOTER101",
  "password": "SecurePassword123"
}
```
- **Response `200 OK`:**
```json
{
  "message": "Login successful",
  "token": "session_uuid_or_jwt_token",
  "voter_id": "VOTER101",
  "has_voted": false
}
```

### 4. `POST /blind-sign`
- **Purpose:** Signs a blinded vote message without revealing the voter's candidate choice.
- **Headers:** `Authorization: Bearer <session_token>`
- **Request Body:**
```json
{
  "blinded_message": "<integer or hex string representing m * r^e mod N>"
}
```
- **Response `200 OK`:**
```json
{
  "blind_signature": "<integer or hex string representing s' = (m*r^e)^d mod N>"
}
```

### 5. `POST /vote`
- **Purpose:** Verifies unblinded signature, checks against duplicate tokens, and appends the vote to the SHA-256 hash chain.
- **Request Body (Anonymous submission - no voter identity):**
```json
{
  "candidate_id": 1,
  "token": "<unique anonymous token generated during blinding>",
  "signature": "<unblinded signature s = m^d mod N>"
}
```
- **Response `200 OK`:**
```json
{
  "message": "Vote recorded successfully",
  "receipt_hash": "sha256_entry_hash_of_this_vote",
  "timestamp": "2026-10-28T15:00:00Z"
}
```

### 6. `GET /receipt/<receipt_hash>`
- **Purpose:** Verifies that a vote exists in the ledger/hash chain.
- **Response `200 OK`:**
```json
{
  "verified": true,
  "block_index": 4,
  "timestamp": "2026-10-28T15:00:00Z",
  "receipt_hash": "sha256_entry_hash_of_this_vote",
  "previous_hash": "sha256_prev_hash"
}
```

### 7. `GET /results`
- **Purpose:** Returns total vote tallies per candidate.
- **Response `200 OK`:**
```json
{
  "election_status": "OPEN",
  "total_votes": 42,
  "results": [
    {"candidate_id": 1, "name": "Alice Green", "votes": 25},
    {"candidate_id": 2, "name": "Bob Stone", "votes": 17}
  ]
}
```

### 8. `GET /admin/verify-chain`
- **Purpose:** Recalculates every SHA-256 hash in the chain from genesis to the latest block and proves tamper-evidence.
- **Response `200 OK`:**
```json
{
  "is_valid": true,
  "total_blocks": 43,
  "message": "Hash chain verified. All cryptographic links are intact."
}
```

### 9. `POST /admin/close`
- **Purpose:** Closes election, triggers S3 upload of `results.json` and `chain.json`, and sends SNS notification.
- **Request Body:**
```json
{
  "admin_secret": "<ADMIN_SECRET_KEY>"
}
```
- **Response `200 OK`:**
```json
{
  "message": "Election closed successfully",
  "s3_results_url": "s3://cryptovote-bucket/results.json",
  "s3_chain_url": "s3://cryptovote-bucket/chain.json"
}
```

---

## 3. Deliverables Person B Will Provide to Person A

1. **`db/schema.sql`**: Complete MySQL DDL script with initial candidate seeds, ready to be executed on RDS.
2. **`crypto/blind_rsa.py` & `crypto/hashchain.py`**: Tested cryptographic modules.
3. **`client.py`**: A standalone test client demonstrating voter blinding, signing, unblinding, and voting.
4. **Flask Application (`backend/`)**: Packaged with `requirements.txt` and systemd/gunicorn instructions for EC2.
