# CloudForge-Auditor — Full Project Explanation

## What Is This Project?

CloudForge-Auditor is an **automated security auditing tool for Amazon Web Services (AWS)**. Think of it like a security inspector that walks through your entire AWS cloud setup, checks for common mistakes and vulnerabilities, and then writes up a professional report telling you what's wrong and how to fix it.

It does **not** change anything in your AWS account — it only **reads** configurations and flags problems. This is the same type of work that Big Four consulting firms (Deloitte, PwC, EY, KPMG) do when they audit a company's cloud infrastructure, except this tool automates it.

---

## How Does It Work? (The Big Picture)

When you run `python main.py`, here's what happens step by step:

```
1. main.py starts up and prints a banner
2. It connects to your AWS account using your AWS CLI credentials
3. It runs 4 audit modules one after another:
     → IAM Audit       (checks user/access security)
     → S3 Audit        (checks storage bucket security)
     → EC2 Audit       (checks network/firewall security)
     → CloudTrail Audit (checks if logging is turned on)
4. Each module returns a list of "findings" (things it checked)
5. All findings are collected together
6. report_generator.py creates two report files:
     → A CSV file (spreadsheet format)
     → An HTML file (professional web page with dark theme)
7. A summary is printed to the terminal
```

You can also run `python main.py --demo` which skips the AWS connection entirely and generates a report with **fake sample data** so you can see what the output looks like.

---

## File-by-File Breakdown

### 1. `main.py` — The Entry Point

**What it does:** This is the file you actually run. It orchestrates everything.

- Prints a fancy ASCII banner to the terminal
- Parses command-line arguments (like `--demo`, `--skip-iam`, `--output-dir`)
- Calls each audit module in sequence
- Collects all findings into one big list
- Passes that list to the report generator
- Prints a final summary table showing how many CRITICAL/HIGH/MEDIUM/LOW issues were found

**Key features:**
- `--demo` flag: Generates a report with 19 realistic fake findings (no AWS account needed)
- `--skip-iam`, `--skip-s3`, `--skip-ec2`, `--skip-cloudtrail`: Skip specific modules
- `--output-dir`: Choose where reports get saved (defaults to `sample_output/`)

---

### 2. `iam_audit.py` — IAM Security Checks

**What it does:** Audits Identity and Access Management — basically, who has access to what in your AWS account.

**5 checks it performs:**

| Check | What It Does | Why It Matters |
|-------|-------------|----------------|
| **Root MFA** | Checks if the root account (the "god account") has Multi-Factor Authentication enabled | If someone steals the root password and there's no MFA, they own your entire AWS account |
| **User MFA** | Checks if every IAM user with console (web login) access has MFA | Same idea — stolen password without MFA = unauthorized access |
| **Access Key Age** | Finds access keys older than 90 days | Old keys that were leaked months ago could still work. Rotating keys limits the damage window |
| **Admin Access** | Finds users with `AdministratorAccess` policy directly attached to them | Users with full admin rights are dangerous — if one gets compromised, the attacker can do anything. Best practice is to use groups instead |
| **Root Usage** | Checks when the root account was last used | Root should almost never be used day-to-day. If it's being used regularly, that's a red flag |

**How it works technically:**
- Uses `boto3` (AWS SDK) to call IAM APIs like `get_account_summary()`, `list_users()`, `list_mfa_devices()`, `list_access_keys()`, etc.
- Paginates through users (handles accounts with lots of users)
- Generates a credential report to check root account activity
- Each check returns a list of "finding" dictionaries with resource ID, severity, recommendation, etc.

---

### 3. `s3_audit.py` — S3 Bucket Security Checks

**What it does:** Audits all S3 storage buckets in the account for common misconfigurations.

**3 checks it performs:**

| Check | What It Does | Why It Matters |
|-------|-------------|----------------|
| **Public Access Block** | Checks if all 4 public access block settings are enabled on each bucket | Public S3 buckets are the #1 cause of cloud data breaches. Companies have leaked millions of records because a bucket was accidentally public |
| **Default Encryption** | Checks if data stored in the bucket is automatically encrypted | Unencrypted data at rest is a compliance violation (SOC2, HIPAA, etc.) and a risk if storage is ever compromised |
| **Versioning** | Checks if bucket versioning is turned on | Without versioning, if someone deletes a file (accidentally or via ransomware), it's gone forever. Versioning keeps old copies |

**How it works technically:**
- Calls `list_buckets()` to get all buckets
- For each bucket, calls `get_public_access_block()`, `get_bucket_encryption()`, and `get_bucket_versioning()`
- Handles exceptions like `NoSuchPublicAccessBlockConfiguration` (means no protection at all)

---

### 4. `ec2_audit.py` — EC2 / Security Group Checks

**What it does:** Audits security groups (AWS firewalls) for dangerous rules that expose services to the entire internet.

**What it looks for:**

| Port | Service | Why It's Dangerous If Open to 0.0.0.0/0 |
|------|---------|------------------------------------------|
| 22 | SSH | Attackers can brute-force login to your servers |
| 3389 | RDP (Remote Desktop) | Same as SSH but for Windows servers |
| 3306 | MySQL | Direct access to your database = data theft |
| 5432 | PostgreSQL | Same as MySQL |
| 1433 | Microsoft SQL Server | Same as MySQL |
| 27017 | MongoDB | Same as MySQL |

It also flags security groups that allow **ALL traffic** from `0.0.0.0/0` (the entire internet).

**How it works technically:**
- Calls `describe_security_groups()` with pagination
- For each security group, iterates through inbound rules (`IpPermissions`)
- Checks if any rule's CIDR range is `0.0.0.0/0` (IPv4) or `::/0` (IPv6) — both mean "open to the world"
- Cross-references the port range against the list of dangerous ports

---

### 5. `cloudtrail_audit.py` — CloudTrail Logging Checks

**What it does:** Checks if AWS CloudTrail (the audit log service) is properly configured.

**3 checks it performs:**

| Check | What It Does | Why It Matters |
|-------|-------------|----------------|
| **Trail Exists** | Checks if any CloudTrail trail is configured | No trail = no record of who did what. Like having a bank with no security cameras |
| **Logging Active** | Checks if the trail is actually recording (not just configured but stopped) | A trail that exists but isn't logging is useless |
| **Multi-Region** | Checks if the trail covers ALL AWS regions, not just one | An attacker could spin up resources in a region you're not monitoring. Multi-region ensures full visibility |

**Bonus check:** Also flags if log file validation is disabled (this detects if someone tampered with the log files).

**How it works technically:**
- Calls `describe_trails()` to list all trails
- For each trail, calls `get_trail_status()` to check if `IsLogging` is true
- Checks the `IsMultiRegionTrail` and `LogFileValidationEnabled` properties

---

### 6. `report_generator.py` — Report Output

**What it does:** Takes all the findings from every module and generates two professional reports.

**CSV Report:**
- Simple spreadsheet format with columns: Resource ID, Risk Area, Finding, Severity, Status, Recommendation, Timestamp
- Can be opened in Excel, Google Sheets, etc. for further analysis or filtering

**HTML Report:**
- Professional dark-themed web page that looks like a real audit deliverable
- Features:
  - Gradient header with project branding
  - Summary cards showing total counts by severity (CRITICAL, HIGH, MEDIUM, LOW) and status (PASS, FAIL)
  - "Failed Checks" table sorted by severity (most critical first)
  - "Passed Checks" table showing what's configured correctly
  - Color-coded severity badges
  - Hover effects on cards and table rows
  - Responsive design (works on mobile)
  - Disclaimer notice
  - Footer with copyright

**How it works technically:**
- CSV is generated using Python's built-in `csv` module
- HTML is built as a large f-string with inline CSS (no external dependencies needed)
- All user-provided text is HTML-escaped to prevent XSS
- Reports are saved to the `sample_output/` directory with a timestamp in the filename

---

### 7. `utils.py` — Shared Utilities

**What it does:** Contains helper functions and constants used by all other modules.

**What's in it:**

| Function/Constant | Purpose |
|-------------------|---------|
| `SEVERITY_CRITICAL/HIGH/MEDIUM/LOW` | String constants for severity levels |
| `STATUS_PASS/STATUS_FAIL` | String constants for check results |
| `get_aws_client()` | Creates a boto3 client for any AWS service |
| `get_aws_resource()` | Creates a boto3 resource (higher-level API) |
| `get_account_id()` | Gets the current AWS account ID via STS |
| `days_since()` | Calculates days between a date and now (used for key age checks) |
| `create_finding()` | Factory function that creates a standardized finding dictionary |
| `print_progress()` | Prints formatted progress messages |
| `print_finding_summary()` | Prints a single finding with ✅/❌ icon |
| `get_all_regions()` | Gets list of all AWS regions (with fallback defaults) |

---

## What Does a "Finding" Look Like?

Every check in every module produces findings in this exact format:

```python
{
    "resource_id": "S3: my-bucket",           # What resource was checked
    "risk_area": "S3 - Public Access",         # Category of the check
    "finding": "Bucket has public access...",   # What was found
    "severity": "CRITICAL",                    # CRITICAL / HIGH / MEDIUM / LOW
    "recommendation": "Enable Block Public..",  # How to fix it
    "status": "FAIL",                          # PASS or FAIL
    "timestamp": "2026-05-04 23:44:58 UTC"     # When the check ran
}
```

---

## Severity Levels Explained

| Level | Meaning | Example |
|-------|---------|---------|
| **CRITICAL** | Immediate action needed. Direct path to full compromise | Root account has no MFA, S3 bucket is public, database port open to internet |
| **HIGH** | Should fix within 24-48 hours | IAM user without MFA, access key older than 90 days, SSH open to internet |
| **MEDIUM** | Should fix within a week | S3 versioning disabled, CloudTrail log validation off |
| **LOW** | Informational / best practice | Inactive old access keys, root account appears unused |

---

## Project Dependencies

| Package | What It Does |
|---------|-------------|
| `boto3` | AWS SDK for Python — lets the code talk to AWS APIs |
| `botocore` | Low-level core of boto3 (installed automatically with boto3) |
| `jinja2` | Template engine (listed as dependency but HTML is currently built with f-strings) |

---

## How to Run

```bash
# Demo mode (no AWS account needed):
python main.py --demo

# Real audit (needs AWS CLI configured with read-only credentials):
python main.py

# Skip specific modules:
python main.py --skip-ec2 --skip-cloudtrail

# Custom output directory:
python main.py --output-dir my_reports
```

---

## What This Project Does NOT Do

- ❌ Does NOT modify, delete, or create any AWS resources
- ❌ Does NOT perform penetration testing or exploitation
- ❌ Does NOT provide real-time monitoring (it's a point-in-time scan)
- ❌ Does NOT support multi-account / AWS Organizations scanning
- ❌ Does NOT replace professional security auditing tools like AWS Security Hub

This is strictly a **read-only, educational compliance auditing tool**.
