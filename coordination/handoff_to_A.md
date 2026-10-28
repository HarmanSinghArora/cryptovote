# Live Coordination Handoff to Person A (Infrastructure & Frontend)
**Project:** CryptoVote – Secure Online Voting System  
**Team:** Person A (Cloud Infra & Frontend) & Person B (Backend & Database)  
**Last Updated:** October 28, 2026  
**Status:** Backend & Database & Cryptography 100% Complete & Tested!  

---

## 1. Cloud Resources Configured by Person B (Ready for Person A)

The backend and database components are fully provisioned and tested:

| Service / Resource | Name / ID | Purpose |
|---|---|---|
| **AWS Region** | `ap-south-1` (Mumbai) | Target deployment region |
| **AWS Account ID** | `882478410161` | Main project account |
| **Custom VPC** | `vpc-061f4fe33deb982d5` (10.0.0.0/16) | Isolated application VPC |
| **Public Subnet A** | `subnet-0d56b8940e2f2a83f` (10.0.1.0/24) | For EC2 Web Server |
| **Private Subnet A** | `subnet-019d8efc766323b78` (10.0.11.0/24) | RDS MySQL Primary |
| **Private Subnet B** | `subnet-0b12ef6ddb3a17e81` (10.0.12.0/24) | RDS MySQL Secondary |
| **Web Security Group** | `sg-0b6b4c13f32db1a3d` (`Public-EC2-SG`) | Port 80 (HTTP) & 22 (SSH) |
| **DB Security Group** | `sg-00c338d5b5ef3594e` (`cryptovote-db-sg`) | Port 3306 open ONLY to `Public-EC2-SG` |
| **Amazon RDS MySQL** | `cryptovote-mysql.cto2m08cuqe2.ap-south-1.rds.amazonaws.com` | Managed MySQL Database (`cryptovote_db`, Port 3306) |
| **Amazon S3 Bucket** | `cryptovote-audit-882478410161` | Audit storage for `results.json` & `chain.json` |

---

## 2. AWS Parameter Store Paths Created

All configuration is managed securely in Systems Manager Parameter Store:

- `/cryptovote/s3_bucket`: `cryptovote-audit-882478410161`
- `/cryptovote/admin_secret`: `AdminSecretCryptoVote2026!` *(SecureString)*
- `/cryptovote/aws_region`: `ap-south-1`
- `/cryptovote/db_name`: `cryptovote_db`
- `/cryptovote/db_user`: `admin`
- `/cryptovote/db_password`: `CryptoVoteDBPass2026!` *(SecureString)*
- `/cryptovote/database_url`: `mysql+pymysql://admin:CryptoVoteDBPass2026!@cryptovote-mysql.cto2m08cuqe2.ap-south-1.rds.amazonaws.com:3306/cryptovote_db` *(SecureString)*

---

## 3. Person A's Action Items (Frontend & EC2 Deployment)

### Task A: Frontend Development
1. Place all your frontend files in the `static/` directory:
   - `static/index.html`
   - `static/style.css`
   - `static/app.js`
2. Flask will automatically serve these static files.
3. The frontend should call the 9 REST endpoints listed below using standard `fetch()` calls.

### Task B: EC2 Launch & Gunicorn Service
1. Launch a `t3.micro` EC2 instance in **Public Subnet A** (`subnet-0d56b8940e2f2a83f`).
2. Attach the Web Security Group (`sg-0b6b4c13f32db1a3d`).
3. Attach an IAM Instance Profile Role with policies:
   - `AmazonSSMManagedInstanceCore`
   - `ssm:GetParametersByPath` on `/cryptovote/*`
   - `s3:PutObject` on `arn:aws:s3:::cryptovote-audit-882478410161/*`
4. On the EC2 instance, clone the repository and run:
```bash
sudo yum install -y git python3 python3-pip
git clone https://github.com/HarmanSinghArora/cryptovote.git
cd cryptovote
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run RDS Migration script to load db/schema.sql into MySQL
python db/migrate_to_rds.py

# Install systemd service for production background running
sudo cp cryptovote.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cryptovote
```

---

## 4. Complete API Contract for Frontend Integration

### 1. `GET /candidates`
- **Response `200 OK`:**
```json
{
  "candidates": [
    {"id": 1, "name": "Alice Green", "party": "Cyber Security Party"},
    {"id": 2, "name": "Bob Stone", "party": "Cloud Computing Alliance"},
    {"id": 3, "name": "Charlie Vance", "party": "Innovation Coalition"}
  ]
}
```

### 2. `POST /register`
- **Request Body:**
```json
{"voter_id": "VOTER101", "password": "SecurePassword123"}
```
- **Response `201 Created`:**
```json
{"message": "Voter registered successfully", "voter_id": "VOTER101"}
```

### 3. `POST /login`
- **Request Body:**
```json
{"voter_id": "VOTER101", "password": "SecurePassword123"}
```
- **Response `200 OK`:**
```json
{"message": "Login successful", "token": "session_token_hex", "voter_id": "VOTER101"}
```

### 4. `GET /crypto/public-key`
- **Response `200 OK`:**
```json
{"e": "65537", "n": "<2048-bit modulus integer>", "algorithm": "RSA-2048-Blind-Signature"}
```

### 5. `POST /blind-sign`
- **Header:** `Authorization: Bearer <session_token>`
- **Request Body:** `{"blinded_message": "<m' integer string>"}`
- **Response `200 OK`:** `{"blind_signature": "<s' integer string>"}`

### 6. `POST /vote` (ANONYMOUS - No voter ID or auth token!)
- **Request Body:**
```json
{"candidate_id": 1, "token": "anonymous_ballot_token", "signature": "<unblinded signature s>"}
```
- **Response `200 OK`:**
```json
{"message": "Vote recorded successfully", "receipt_hash": "sha256_entry_hash", "block_index": 1}
```

### 7. `GET /receipt/<receipt_hash>`
- **Response `200 OK`:**
```json
{"verified": true, "block_index": 1, "candidate_id": 1, "receipt_hash": "...", "previous_hash": "..."}
```

### 8. `GET /results`
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

### 9. `GET /admin/verify-chain`
- **Response `200 OK`:**
```json
{"is_valid": true, "total_blocks": 43, "details": {"message": "Complete hash chain successfully verified."}}
```

### 10. `POST /admin/close`
- **Request Body:**
```json
{"admin_secret": "AdminSecretCryptoVote2026!"}
```
- **Response `200 OK`:**
```json
{"message": "Election closed successfully", "s3_status": "Successfully uploaded results.json and chain.json to s3://cryptovote-audit-882478410161"}
```
