# CryptoVote: Cloud Architecture & System Design Specification
**Project:** CryptoVote – Secure Online Voting System  
**Region:** `ap-south-1` (Mumbai)  
**Author:** Solo Cloud Architect & DevOps Lead (Harman Singh Arora)  
**Course:** Cloud Computing Laboratory Mini Project 2026  

---

## 1. High-Level AWS Cloud Architecture

CryptoVote is built upon a defense-in-depth, decoupled cloud architecture following the AWS Well-Architected Framework:

```mermaid
graph TD
    subgraph ClientLayer["Voter & Admin Clients"]
        Browser["Modern Web Browser (JavaScript + BigInt)"]
        CLI["Python CLI Simulation (client.py)"]
    end

    subgraph AWSCloud["AWS Cloud (Region: ap-south-1 Mumbai)"]
        IGW["Internet Gateway: StudentLab-IGW"]

        subgraph CustomVPC["Custom VPC: StudentLab-VPC (10.0.0.0/16)"]
            
            subgraph PublicSubnets["Public Subnets (Route Table: Public-RT -> 0.0.0.0/0 to IGW)"]
                subgraph SubnetA["Public Subnet A (10.0.1.0/24 - ap-south-1a)"]
                    EC2["Amazon EC2: Public-EC2-Test (t3.micro)<br>• Public IP: 15.206.173.159<br>• Gunicorn WSGI (Port 80)<br>• Flask Application Backend<br>• systemd: cryptovote.service<br>• CloudWatch Agent"]
                end
                subgraph SubnetB["Public Subnet B (10.0.2.0/24 - ap-south-1b)"]
                    SparePub["Public Subnet Standby"]
                end
            end

            subgraph PrivateSubnets["Private Subnets (Route Table: Private-RT -> Local 10.0.0.0/16 Only)"]
                subgraph PrivSubA["Private Subnet A (10.0.11.0/24 - ap-south-1a)"]
                    RDSPrimary["Amazon RDS MySQL 8.0: cryptovote-mysql<br>• Port 3306 (No Public IP)<br>• Single-AZ Primary DB"]
                end
                subgraph PrivSubB["Private Subnet B (10.0.12.0/24 - ap-south-1b)"]
                    RDSStandby["DB Subnet Group Member"]
                end
            end

            WebSG["Security Group: Public-EC2-SG<br>Inbound: Port 80 (0.0.0.0/0)<br>No open SSH port"]
            DBSG["Security Group: cryptovote-db-sg<br>Inbound: Port 3306 exclusively from Public-EC2-SG"]

            WebSG -.->|Authorize Traffic| EC2
            DBSG -.->|Restrict Access| RDSPrimary
        end

        subgraph ManagedServices["AWS Managed Serverless Services (Outside VPC)"]
            SSM["AWS Systems Manager Parameter Store<br>• /cryptovote/* (KMS Encrypted)"]
            S3["Amazon S3 Audit Bucket<br>• s3://cryptovote-audit-882478410161<br>• results.json & chain.json"]
            SNS["Amazon SNS Topic<br>• arn:aws:sns:...:cryptovote-alerts<br>• Email to harmanarora2006@gmail.com"]
            CWLogs["CloudWatch Logs<br>• Log Group: /cryptovote/application<br>• Metric Filter: INVALID_TOKEN"]
            CWAlarm["CloudWatch Alarm<br>• CryptoVote-InvalidTokenAlarm<br>• >= 3 events in 5 minutes"]
            LAMBDA["AWS Lambda: close_election<br>• Python 3.12 (128 MB)<br>• Role: CryptoVoteLambdaRole"]
        end
    end

    Browser -->|HTTP Port 80| IGW
    CLI -->|HTTP Port 80| IGW
    IGW --> EC2

    EC2 -->|TCP Port 3306 Private| RDSPrimary
    EC2 -->|Fetch Secrets on Boot| SSM
    EC2 -->|Upload Audit Files| S3
    EC2 -->|Stream /var/log/cryptovote.log| CWLogs
    EC2 -->|Publish Hash-Chain Tamper Alert| SNS

    CWLogs -->|Extract Metric| CWAlarm
    CWAlarm -->|Trigger Notification| SNS
    SNS -->|Push Email Alert| Email["Security Administrator Inbox<br>(harmanarora2006@gmail.com)"]

    LAMBDA -->|Fetch Admin Secret| SSM
    LAMBDA -->|POST /admin/close| EC2
```

---

## 2. End-to-End Cryptographic Data Flow

### A. David Chaum RSA Blind Signature & Anonymous Voting Protocol

```mermaid
sequenceDiagram
    autonumber
    actor Voter as Voter Client (Browser / CLI)
    participant Server as Flask Backend (EC2)
    participant DB as RDS MySQL (Private)
    participant SNS as Amazon SNS Topic

    Note over Voter,Server: Phase 1: Authentication & Ballot Blinding
    Voter->>Server: POST /login {voter_id, password}
    Server->>DB: Query voter & verify PBKDF2 hash (100k rounds)
    Server-->>Voter: HTTP 200 {token: session_token, has_requested_ballot: false}

    Voter->>Server: GET /crypto/public-key
    Server-->>Voter: HTTP 200 {e: 65537, n: 2048-bit modulus}

    Note over Voter: Client generates ballot token T and secret blinding factor r<br/>m = SHA256(candidate:1; token:T) mod N<br/>m' = (m * r^e) mod N

    Note over Voter,Server: Phase 2: Blind Signing (Identity Known, Vote Choice HIDDEN)
    Voter->>Server: POST /blind-sign {blinded_message: m'} (Bearer session_token)
    Server->>DB: Check voter.has_requested_ballot == false
    Server->>DB: Update voter.has_requested_ballot = true
    Note over Server: Server computes: s' = (m')^d mod N<br/>Server signs without ever viewing message m!
    Server-->>Voter: HTTP 200 {blind_signature: s'}

    Note over Voter: Phase 3: Client-Side Unblinding<br/>s = (s' * r^-1) mod N = m^d mod N

    Note over Voter,Server: Phase 4: Anonymous Ballot Submission
    Voter->>Server: POST /vote {candidate_id: 1, token: T, signature: s}<br/>(Zero voter ID or session headers sent!)
    Server->>Server: Verify RSA signature: s^e mod N == m
    Server->>DB: Check token T in used_tokens (UNIQUE constraint)
    Server->>DB: Append block to SHA-256 hash chain in votes table
    Server-->>Voter: HTTP 200 {receipt_hash: Block Hash, block_index: 1}

    Note over Voter,Server: Phase 5: Tampering Detection & SNS Alerting
    actor Auditor as Security Auditor
    Auditor->>Server: GET /admin/verify-chain
    Server->>DB: Recalculate SHA-256 hashes from Genesis
    alt Hash Chain Intact
        Server-->>Auditor: HTTP 200 {is_valid: true, total_blocks: N}
    else Tampering Detected (Block hash mismatch)
        Server->>SNS: Publish urgent security alert
        SNS-->>Auditor: Push Email: "CRITICAL: Hash Chain Tampering Detected!"
        Server-->>Auditor: HTTP 200 {is_valid: false, details: {block_index: X}}
    end
```

---

## 3. Component Network Placement & Boundaries

| Component | Network Domain | Subnet & CIDR | Public Route? | Security Boundary |
|---|---|---|---|---|
| **EC2 Web Server** | Custom VPC | `Public-Subnet-A` (`10.0.1.0/24`) | **Yes** (via IGW) | Port 80 open; no inbound SSH; outgoing access via IGW. |
| **Amazon RDS MySQL** | Custom VPC | `Private-Subnet-A` (`10.0.11.0/24`) & `Private-Subnet-B` (`10.0.12.0/24`) | **No** (Local only) | Inbound Port 3306 restricted strictly to `Public-EC2-SG`. No public IP. |
| **AWS Systems Manager** | AWS Managed Endpoint | Outside VPC | Public AWS API | Encrypted HTTPS (TLS 1.3), authenticated via IAM STS temporary credentials. |
| **Amazon S3** | AWS Storage Tier | Outside VPC | Public AWS API | S3 Public Access Blocked; restricted to IAM PutObject policies. |
| **AWS Lambda** | AWS Serverless | Outside VPC | Public AWS API | Serverless microVM container with `CryptoVoteLambdaRole`. |
| **Amazon SNS** | AWS Messaging Tier | Outside VPC | Public AWS API | Topic restricted to IAM publishers; email push over TLS. |
| **CloudWatch Logs** | AWS Management Tier | Outside VPC | Public AWS API | CloudWatch Agent pushes encrypted log streams from `/var/log/cryptovote.log`. |

---

## 4. Verification Checklist
- [x] All 12 required AWS services depicted with actual IDs and configuration.
- [x] Clear separation between Custom VPC internal subnets and AWS serverless tiers.
- [x] Zero open SSH ports (management via AWS Systems Manager Session Manager).
- [x] Database completely shielded in multi-AZ private subnets with zero internet ingress.
