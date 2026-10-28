# Day 2 Coordination Handoff to Person A
**Project:** CryptoVote – Secure Online Voting System  
**From:** Person B (Backend, Database & Cryptography)  
**Date:** Day 2 (Hours 24–48)  
**Status:** Backend & Database 100% Tested; AWS S3 & RDS MySQL Live!  

---

## 1. Current Cloud Infrastructure Status (Delivered by Person B)

| Resource | Status | Value / ARN |
|---|---|---|
| **Amazon RDS MySQL** | **AVAILABLE** | `cryptovote-mysql.cto2m08cuqe2.ap-south-1.rds.amazonaws.com:3306` |
| **Amazon S3 Bucket** | **ACTIVE** | `s3://cryptovote-audit-882478410161` |
| **Parameter Store** | **7 PARAMETERS STORED** | `/cryptovote/*` (`database_url`, `admin_secret`, `s3_bucket`, etc.) |
| **Backend Code** | **PUSHED TO GITHUB** | Branch: `person-b-backend` |
| **Gunicorn Service** | **READY** | `cryptovote.service` and `wsgi.py` |
| **RDS Migration** | **READY** | `db/migrate_to_rds.py` |

---

## 2. Roadblocks & Immediate Action Items for Person A

To begin Phase 1 (Live Deployment Verification), Person B needs Person A to complete these 5 steps on EC2:

### 1. Attach IAM Role to EC2
The EC2 instance (`i-02e17e6932c778adb` / `Public-EC2-Test`) needs an IAM Instance Profile containing:
- `AmazonSSMManagedInstanceCore` (so you can connect via Session Manager without SSH)
- `CloudWatchAgentServerPolicy` (for logs/metrics)
- Policy for SSM Parameter Store: `ssm:GetParametersByPath` on `arn:aws:ssm:ap-south-1:882478410161:parameter/cryptovote/*`
- Policy for S3: `s3:PutObject` on `arn:aws:s3:::cryptovote-audit-882478410161/*`
- Policy for SNS: `sns:Publish` on `arn:aws:sns:ap-south-1:882478410161:cryptovote-alerts`

### 2. Start EC2 & Share Public IP
- Start the EC2 instance in **Public Subnet A** (`subnet-0d56b8940e2f2a83f`).
- Make sure an Elastic IP or Auto-assigned Public IP is active.
- **Share the EC2 Public IP with Person B** so we can run automated verification tests!

### 3. Deploy Code on EC2
Connect to EC2 via AWS Systems Manager Session Manager (or SSH) and run:
```bash
sudo yum update -y
sudo yum install -y git python3 python3-pip

# Clone Person B's repository
git clone https://github.com/HarmanSinghArora/cryptovote.git
cd cryptovote
git checkout person-b-backend

# Set up virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run RDS Migration (creates tables & seeds candidates in RDS MySQL!)
python db/migrate_to_rds.py

# Install and start Gunicorn systemd service
sudo cp cryptovote.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now cryptovote
sudo systemctl status cryptovote
```

### 4. Frontend Placement
- Place your HTML, CSS, and JS files in `/home/ec2-user/cryptovote/static/`
- Gunicorn/Flask will serve them directly on `http://<EC2_PUBLIC_IP>/`.

---

## 3. What Person B is Working On Right Now (No Idle Time!)
While Person A completes the EC2 startup and deployment:
1. Developing the **`close_election` AWS Lambda function** (Phase 2).
2. Implementing **Amazon SNS tamper alerting** on `GET /admin/verify-chain` (Phase 3).
3. Writing the comprehensive **Cryptography Write-up & Project Documentation** (Phase 5).
