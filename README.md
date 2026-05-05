# CloudForge-Auditor

**Automated AWS Cloud Security & Compliance Auditor**

CloudForge-Auditor is a Python-based security auditing tool that connects to an AWS environment using read-only access, audits configurations across core services, compares them against CIS Benchmark best practices, and generates professional audit reports.

> **Disclaimer:** This tool is for security auditing and compliance learning purposes only. It performs **read-only** checks and does not modify any AWS resources.

---

## Services Covered

| Service | Checks Performed |
|---------|-----------------|
| **IAM** | Root MFA, User MFA, Access Key Rotation (90-day), AdministratorAccess detection, Root usage |
| **S3** | Public Access Block, Default Encryption, Versioning |
| **EC2** | Security Groups: SSH (22), RDP (3389), Database ports (3306, 5432, 1433) open to 0.0.0.0/0 |
| **CloudTrail** | Trail enabled, Logging active, Multi-region logging, Log file validation |

---

## How to Run

### Prerequisites

1. **Python 3.7+** installed
2. **AWS CLI** configured with read-only credentials
3. **Boto3** library installed

### Setup

```bash
# Clone the repository
git clone https://github.com/SonOfTroll/CloudForge-Auditor.git
cd CloudForge-Auditor

# Install dependencies
pip install -r requirements.txt

# Configure AWS CLI (if not already done)
aws configure
```

### Running the Audit

```bash
# Full audit
python main.py

# Demo mode (no AWS access needed - generates sample report)
python main.py --demo

# Custom output directory
python main.py --output-dir my_reports

# Skip specific modules
python main.py --skip-iam --skip-ec2

# See all options
python main.py --help
```

### Required AWS Permissions

The tool requires **read-only** access. The following AWS managed policy is sufficient:

- `arn:aws:iam::aws:policy/SecurityAudit`

Or at minimum, these permissions:
- `iam:GetAccountSummary`
- `iam:ListUsers`
- `iam:ListMFADevices`
- `iam:GetLoginProfile`
- `iam:ListAccessKeys`
- `iam:ListAttachedUserPolicies`
- `iam:GenerateCredentialReport`
- `iam:GetCredentialReport`
- `s3:ListAllMyBuckets`
- `s3:GetBucketPublicAccessBlock`
- `s3:GetBucketEncryption`
- `s3:GetBucketVersioning`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeRegions`
- `cloudtrail:DescribeTrails`
- `cloudtrail:GetTrailStatus`
- `sts:GetCallerIdentity`

---

## Project Structure

```
CloudForge-Auditor/
├── main.py                 # Entry point - orchestrates audit
├── iam_audit.py            # IAM security checks
├── s3_audit.py             # S3 bucket security checks
├── ec2_audit.py            # EC2 security group checks
├── cloudtrail_audit.py     # CloudTrail logging checks
├── report_generator.py     # CSV and HTML report generation
├── utils.py                # Shared utilities and helpers
├── requirements.txt        # Python dependencies
├── README.md               # This file
└── sample_output/          # Generated reports go here
    ├── sample_report.csv
    └── sample_report.html
```

---

## Sample Findings

The tool generates findings in the following format:

| Resource ID | Risk Area | Finding | Severity | Recommendation |
|---|---|---|---|---|
| Root Account | IAM - Root MFA | Root account does NOT have MFA enabled | CRITICAL | Enable MFA on root account immediately |
| S3: my-bucket | S3 - Public Access | Bucket has public access block disabled | CRITICAL | Enable Block Public Access |
| SG: sg-12345 | EC2 - Security Groups | SSH (port 22) open to 0.0.0.0/0 | HIGH | Restrict to specific IP ranges |
| CloudTrail | CloudTrail - Logging | No CloudTrail trails configured | CRITICAL | Create a CloudTrail trail immediately |

### Severity Levels

- **CRITICAL** — Immediate action required. Direct path to compromise.
- **HIGH** — Should be addressed within 24-48 hours.
- **MEDIUM** — Should be addressed within 1 week.
- **LOW** — Informational or best practice improvement.

---

## Remediation Guide

### 1. MFA Enforcement
- Enable MFA on the root account using a hardware token (YubiKey recommended)
- Enforce MFA for all IAM users with console access
- Consider using AWS SSO with mandatory MFA

### 2. Least Privilege Access
- Remove directly attached `AdministratorAccess` policies
- Use IAM groups with scoped permissions
- Implement AWS Organizations SCPs for guardrails
- Regularly review and remove unused permissions

### 3. Access Key Management
- Rotate access keys every 90 days maximum
- Delete inactive and unused access keys
- Prefer IAM Roles over long-lived access keys
- Use AWS Secrets Manager for application credentials

### 4. S3 Security
- Enable "Block Public Access" on all buckets
- Enable default encryption (SSE-S3 or SSE-KMS)
- Enable versioning for critical data buckets
- Use S3 bucket policies to enforce encryption in transit

### 5. Network Security
- Never expose SSH (22) or RDP (3389) to 0.0.0.0/0
- Use AWS Systems Manager Session Manager instead of direct SSH
- Place databases in private subnets with no public access
- Use Security Group references instead of CIDR blocks where possible

### 6. Logging & Monitoring
- Enable CloudTrail in all regions (multi-region trail)
- Enable log file validation to detect tampering
- Send CloudTrail logs to a centralized S3 bucket with restricted access
- Set up CloudWatch Alarms for critical API calls

---

## Limitations

- **Read-only auditing** — This tool does not make any changes to your AWS environment
- **Point-in-time assessment** — Results reflect the state at the time of the scan
- **Not real-time monitoring** — For continuous monitoring, use AWS Config Rules or AWS Security Hub
- **Single account** — Currently audits one AWS account at a time (no multi-account/Organization support)
- **Default region** — Some checks use the default region from AWS CLI configuration
- **API rate limits** — Large environments with many resources may hit AWS API throttling

---

