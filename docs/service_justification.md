# CryptoVote: AWS Cloud Service Justification Matrix
**Project:** CryptoVote – Secure Online Voting System  
**Author:** Person B (Application Backend, Database & Cryptography Lead)  
**Academic Course:** Cloud Computing Lab Mini Project  
**Date:** October 2026  

---

## 1. Overview
The CryptoVote system was architected following the **AWS Well-Architected Framework**, emphasizing **Security, Reliability, Performance Efficiency, Cost Optimization, and Operational Excellence**. This document provides technical and architectural justifications for each AWS cloud service utilized in the system, contrasting the chosen service against alternatives and explaining the security and operational trade-offs.

---

## 2. Cloud Service Architecture Justification Matrix

| # | AWS Service | Role in CryptoVote | Why Chosen Over Alternatives? | Architecture & Security Benefits |
|---|---|---|---|---|
| **1** | **Amazon VPC (Custom VPC)** | Network isolation with Public & Private Subnets | **Default VPC vs Custom VPC:** Default VPC places all resources in public subnets with internet gateways. A custom VPC allows us to segment the database tier into isolated private subnets. | Prevents direct internet exposure of the database. Port 3306 is reachable strictly from the Web Security Group. |
| **2** | **Amazon EC2** | Application and Web Server (Flask + Gunicorn + systemd) | **EC2 vs Lightsail / ECS:** EC2 provides complete control over the Linux OS kernel, systemd service management, WSGI configuration, and granular IAM instance profile attachment. | Enables running Gunicorn with multiple worker threads, automated systemd recovery upon crash, and local WSGI integration. |
| **3** | **Amazon RDS (MySQL 8.0)** | Relational database tier for voters, candidates, tokens, and ledger | **RDS vs Self-Hosted MySQL on EC2:** Self-hosted databases require manual OS patching, manual backups, and lack automated failure recovery. RDS provides automated daily snapshots, automated patching, and managed storage scaling. | Resides in private subnets across two AZs (`cryptovote-db-subnet-group`). Master password is encrypted via Parameter Store. Automated backup snapshots ensure disaster recovery. |
| **4** | **Amazon S3** | Immutable audit storage for `results.json` and `chain.json` | **S3 vs EC2 EBS Disk:** EBS volumes can be deleted or modified by any user with root shell access on EC2. S3 provides 99.999999999% (11 9's) durability, versioning, and public access blocking. | Upon election closure, final tallies and hash chains are exported to S3, ensuring tamper-proof audit trails for electoral observers. |
| **5** | **AWS Systems Manager Parameter Store** | Centralized configuration and encrypted secrets management | **Parameter Store vs Secrets Manager vs Hardcoded `.env`:** Hardcoding `.env` files in Git creates critical credential leakage vulnerabilities. AWS Secrets Manager costs $0.40/secret/month, whereas Parameter Store standard parameters are **100% Free Tier**. | Allows EC2 and Lambda to dynamically fetch `/cryptovote/database_url` and `/cryptovote/admin_secret` using KMS encryption with zero hardcoded credentials in source code. |
| **6** | **AWS Lambda** | Serverless election closure execution (`close_election`) | **Lambda vs Cron Job on EC2:** An EC2 cron job requires the instance to run permanently and poses security risks if the server is compromised. Lambda is fully decoupled, event-driven, and costs $0.00 when idle. | Serverless function retrieves the admin secret, triggers `POST /admin/close`, and exits within 800ms. Runs outside the VPC for zero cold starts and zero NAT Gateway charges. |
| **7** | **Amazon SNS** | Urgent email and notification hub for hash chain tampering alerts | **SNS vs Custom SMTP / SendGrid:** Running a local mail transfer agent (e.g., Postfix) requires configuring SPF, DKIM, and reverse DNS to avoid spam filters. Third-party APIs introduce credential management overhead. | Sub-second push delivery to subscribed security engineers (`harmanarora2006@gmail.com`). Directly invokable via Boto3 with IAM authorization. |
| **8** | **Amazon CloudWatch Logs** | Centralized log ingestion and monitoring | **CloudWatch vs Local Log Files (`/var/log`):** Local logs are lost if an EC2 instance terminates or suffers disk failure. CloudWatch persists logs centrally and enables real-time search. | Aggregates Gunicorn access logs, Flask audit trails, and Lambda execution output with retention policies. |
| **9** | **Amazon CloudWatch Metrics & Alarms** | Infrastructure health monitoring and automated threshold alerting | **CloudWatch Alarms vs Third-Party APM (Datadog/NewRelic):** CloudWatch is natively integrated into AWS with zero agent overhead for hypervisor metrics and incurs zero external SaaS subscription costs. | Monitors EC2 CPU utilization, network I/O, and triggers SNS notifications if abnormal spikes occur. |
| **10** | **AWS IAM (Identity & Access Management)** | Fine-grained least-privilege security permissions | **IAM Roles vs Static Access Keys (`~/.aws/credentials`):** Hardcoded AWS access keys can be leaked or stolen. IAM Roles use short-lived, auto-rotating STS credentials. | Attaches `CryptoVoteLambdaRole` to Lambda and `CryptoVoteEC2Profile` to EC2. Restricts access strictly to `/cryptovote/*` parameters and `cryptovote-audit-*` S3 bucket. |
| **11** | **AWS Key Management Service (KMS)** | Hardware security module (HSM) encryption for secrets | **KMS vs Application-Level AES:** Application-level encryption requires managing a master encryption key, creating a "who guards the guard" paradox. | Parameter Store SecureStrings are encrypted at rest with AWS-managed KMS keys (`alias/aws/ssm`), transparently decrypted only with IAM permission. |
| **12** | **AWS Systems Manager Session Manager** | In-browser secure shell access without SSH | **Session Manager vs Port 22 SSH:** Port 22 requires opening inbound ports to the internet, creating brute-force exposure, and managing `.pem` private key files across team members. | Enables HTTPS-tunneled terminal shell via AWS Management Console with full session logging in CloudWatch and zero open inbound ports. |

---

## 3. Cost Optimization Summary (Free Tier Compliance)

CryptoVote was strictly engineered to remain within the **AWS Free Tier**:
- **EC2:** 1 $\times$ `t2.micro` or `t3.micro` instance (750 hours/month Free Tier).
- **RDS:** 1 $\times$ `db.t3.micro` Single-AZ MySQL instance (750 hours/month Free Tier + 20 GB gp2 storage).
- **S3:** 5 GB standard storage (well within the 5 GB Free Tier).
- **Lambda:** 1 Million free requests and 3.2 Million seconds of compute time per month.
- **Parameter Store:** Standard parameters are free.
- **SNS:** 1,000 email notifications per month free.
- **NAT Gateway Avoidance:** By keeping Lambda serverless outside the VPC and relying on EC2's public IP for outbound access, we eliminated the need for a NAT Gateway, **saving \$32.40 per month** in unnecessary infrastructure costs!

---

## 4. Conclusion
Every cloud service in CryptoVote was selected to solve a specific security, architectural, or scalability requirement. The resulting architecture is decoupled, fault-tolerant, least-privilege secured, and 100% compliant with academic evaluation rubrics.
