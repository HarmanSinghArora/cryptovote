# CryptoVote: AWS Cost Documentation & Financial Optimization Report
**Project:** CryptoVote – Secure Online Voting System  
**Region:** `ap-south-1` (Mumbai)  
**Author:** Solo Cloud Architect & DevOps Lead (Harman Singh Arora)  
**Course:** Cloud Computing Laboratory Mini Project 2026  

---

## 1. Executive Summary & Financial Strategy

The CryptoVote architecture was intentionally designed to achieve enterprise-grade security and reliability while strictly remaining within the **AWS Free Tier** and college budget thresholds. 

A monthly budget of **$5.00 USD** (`CryptoVote-Monthly-Budget`) was established in AWS Budgets with automated email alert notifications at 80% ($4.00) and 100% ($5.00). Through disciplined architectural decisions—such as eliminating NAT Gateways and utilizing Single-AZ private RDS—the running operational cost of the entire production deployment is **$0.00 / month (100% Free Tier covered)** during normal evaluation periods.

---

## 2. Cloud Service Cost & Optimization Matrix

| AWS Service | Exact Project Configuration | Estimated Monthly Cost | Free Tier Allowance | Cost-Saving Architecture Measure |
|---|---|---|---|---|
| **Amazon EC2** | 1 $\times$ `t3.micro` (Linux, 2 vCPUs, 1 GB RAM) | **$0.00** ($7.60 without Free Tier) | 750 hours/month of `t2.micro` or `t3.micro` free for 12 months. | Stopped when not undergoing evaluation; Gunicorn systemd daemon configured with automated recovery instead of expensive auto-scaling groups. |
| **Amazon EBS** | 1 $\times$ 8 GB General Purpose SSD (`gp3`/`gp2`) | **$0.00** ($0.80 without Free Tier) | 30 GB/month free storage. | Kept at minimal 8 GB volume size; unneeded snapshots removed. |
| **Amazon RDS** | 1 $\times$ `db.t3.micro` Single-AZ MySQL 8.0, 20 GB gp2 storage | **$0.00** ($12.41 without Free Tier) | 750 hours/month of `db.t2.micro`/`db.t3.micro` + 20 GB storage free. | Avoided Multi-AZ deployment (saved $14.50/mo); placed in private subnets with automated 1-day backup retention. |
| **Amazon S3** | Standard storage in `cryptovote-audit-882478410161` | **$0.00** (< $0.01) | 5 GB standard storage, 20,000 GET, 2,000 PUT requests free. | Only final election tallies (`results.json`) and ledger blocks (`chain.json`) are stored; public access blocked. |
| **Systems Manager Parameter Store** | 8 $\times$ Standard Parameters (`SecureString` KMS encrypted) | **$0.00** ($0.00 standard) | Standard parameters are free. No storage or API charges. | Used Parameter Store instead of AWS Secrets Manager ($0.40/secret/month), saving $3.20/month across 8 secrets! |
| **AWS Lambda** | Python 3.12, 128 MB memory, execution duration $\approx 800\text{ms}$ | **$0.00** (< $0.001) | 1,000,000 requests & 3.2M seconds of compute free every month. | Runs serverless outside VPC: executes in < 1 second on demand; zero idle compute cost. |
| **Amazon SNS** | 1 $\times$ Standard Topic (`cryptovote-alerts`), Email protocol | **$0.00** (< $0.001) | 1,000 email notifications free per month. | Alerts sent only on ledger tampering and CloudWatch alarms; no SMS protocol utilized ($0.05/SMS avoided). |
| **Amazon CloudWatch** | 1 $\times$ Log Group (`/cryptovote/application`), 1 Metric Filter, 1 Alarm | **$0.00** ($0.10 without Free Tier) | 10 custom metrics, 10 alarms, and 5 GB log ingestion free. | Configured 1 targeted metric filter (`INVALID_TOKEN`) and 1 alarm; log retention set to prevent disk accumulation. |
| **AWS KMS** | AWS Managed Key (`alias/aws/ssm`) | **$0.00** | Free tier for default AWS-managed KMS keys. | Default AWS service keys used instead of Customer Managed Keys ($1.00/key/month avoided). |
| **Data Transfer** | In-VPC internal communication (EC2 $\leftrightarrow$ RDS) | **$0.00** | Ingress data transfer is free; 100 GB/month internet egress free. | All database queries remain inside local private subnets ($0.00 transfer fees). |
| **NAT Gateway** | **OMITTED BY DESIGN** | **$0.00** ($32.40 without optimization) | No free tier for NAT Gateways ($0.045/hour + $0.045/GB). | **Eliminated completely!** Lambda placed outside VPC and EC2 communicates via public subnet, saving **$32.40/month**! |
| **TOTAL** | **Full Production Deployment** | **$0.00** (Free Tier) | **Full compliance** | **Total savings: ~ $58.50 / month!** |

---

## 3. High-Impact Architectural Decisions (Why We Avoided Expensive Services)

### 1. Avoidance of AWS NAT Gateway ($32.40 / month saved)
In standard corporate architectures, serverless Lambdas that interact with RDS are often placed inside private subnets, requiring a NAT Gateway to reach external AWS endpoints (like Parameter Store or S3). A NAT Gateway incurs a fixed hourly charge of \$0.045/hour ($\approx \$32.40/\text{month}$), plus data processing charges.  
**Our Solution:** We decoupled election closure so that the Lambda function runs outside the VPC. Lambda invokes the EC2 application over HTTPS/HTTP via EC2's public IP, while EC2 communicates with RDS locally. This eliminated the need for a NAT Gateway entirely.

### 2. Parameter Store vs. AWS Secrets Manager ($3.20 / month saved)
AWS Secrets Manager charges \$0.40 per secret per month plus \$0.05 per 10,000 API calls. With 8 parameters in our application (`database_url`, `admin_secret`, `db_password`, etc.), Secrets Manager would cost \$3.20/month.  
**Our Solution:** We stored all secrets in AWS Systems Manager Parameter Store as KMS-encrypted `SecureString` types. Standard parameters in Parameter Store are **100% free of charge**.

### 3. Single-AZ vs. Multi-AZ RDS ($14.50 / month saved)
Multi-AZ RDS provisions a synchronous standby replica in a second Availability Zone, effectively doubling instance and storage costs ($\approx \$26.90/\text{month}$).  
**Our Solution:** For our laboratory prototype, we utilized Single-AZ deployment in private subnets with automated daily snapshot backups enabled. This remains 100% Free Tier eligible.

---

## 4. Cost Behavior: Running vs. Stopped Resources

| Resource | When Running | When Stopped | Billing Behavior Notes |
|---|---|---|---|
| **EC2 Instance** | Billed per second of compute | **$0.00 compute charges** | **Important:** The attached 8 GB EBS volume continues to incur minimal storage charges ($\approx \$0.64/\text{month}$ if exceeding 30 GB free allowance). |
| **RDS MySQL** | Free Tier (750 hrs/mo) | **Free Tier (750 hrs/mo)** | **Caution:** AWS automatically restarts stopped RDS instances after 7 consecutive days to perform maintenance. Monitor via AWS Budgets! |
| **S3 Storage** | $0.023 / GB / month | N/A (Static objects) | Negligible for JSON audit files (< 1 MB total). |
| **Lambda & SNS** | $0.00 when idle | $0.00 | Event-driven: billed only during execution milliseconds. |

---

## 5. Budget Verification & Monitoring Guide

1. **AWS Budgets Console:**
   - Name: `CryptoVote-Monthly-Budget`
   - Budget Amount: `$5.00`
   - Notifications: Dispatches automated email alerts when actual expenditure exceeds **$4.00 (80%)** and **$5.00 (100%)**.
2. **AWS Cost Explorer:**
   - Filter by Service: EC2, RDS, and CloudWatch.
   - Granularity: Daily tracking to confirm zero unexpected spikes.
