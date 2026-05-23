#!/usr/bin/env python3
"""
CloudForge-Auditor - AWS Cloud Security & Compliance Auditor
=============================================================
Main entry point for the audit tool.

This script connects to an AWS environment using read-only access,
audits configurations across IAM, S3, EC2, and CloudTrail,
compares them against CIS Benchmark best practices,
and generates a professional audit report.

Usage:
    python main.py
    python main.py --output-dir custom_output
    python main.py --skip-iam --skip-s3

Author: CloudForge Security Team
Version: 1.0.0
"""

import sys
import os
import argparse
from datetime import datetime

# import our audit modules
from iam_audit import run_iam_audit
from s3_audit import run_s3_audit
from ec2_audit import run_ec2_audit
from cloudtrail_audit import run_cloudtrail_audit
from report_generator import generate_reports
from utils import print_progress, get_account_id


def print_banner():
    """Print the cool banner - makes it look professional"""
    banner = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        ☁️  CloudForge-Auditor v1.0.0                      ║
    ║        AWS Cloud Security & Compliance Auditor             ║
    ║                                                           ║
    ║        Automated CIS Benchmark Assessment                 ║
    ║        IAM | S3 | EC2 | CloudTrail                        ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    print(banner)


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='CloudForge-Auditor - AWS Cloud Security & Compliance Auditor'
    )
    parser.add_argument(
        '--output-dir', '-o',
        default='sample_output',
        help='Directory for output reports (default: sample_output)'
    )
    parser.add_argument('--skip-iam', action='store_true', help='Skip IAM audit')
    parser.add_argument('--skip-s3', action='store_true', help='Skip S3 audit')
    parser.add_argument('--skip-ec2', action='store_true', help='Skip EC2 audit')
    parser.add_argument('--skip-cloudtrail', action='store_true', help='Skip CloudTrail audit')
    parser.add_argument('--demo', action='store_true', help='Run in demo mode with sample data')
    
    return parser.parse_args()


def run_demo_mode():
    """
    Demo mode - generates a sample report with fake findings.
    Useful for testing the report generator without AWS access.
    
    # added this so people can see what the output looks like without needing AWS creds
    """
    print_progress("Running in DEMO mode - using sample findings")
    
    from utils import create_finding, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, STATUS_PASS
    
    # generate some realistic-looking sample findings
    sampleFindings = [
        # IAM findings
        create_finding(
            "Root Account", "IAM - Root MFA",
            "Root account does NOT have MFA enabled",
            SEVERITY_CRITICAL,
            "Enable MFA on root account immediately. Use a hardware MFA device if possible."
        ),
        create_finding(
            "IAM User: dev-intern", "IAM - User MFA",
            "IAM user 'dev-intern' has console access but no MFA enabled",
            SEVERITY_HIGH,
            "Enable MFA for user 'dev-intern'. Consider enforcing MFA via IAM policy."
        ),
        create_finding(
            "IAM User: legacy-deploy", "IAM - User MFA",
            "IAM user 'legacy-deploy' has console access but no MFA enabled",
            SEVERITY_HIGH,
            "Enable MFA for user 'legacy-deploy'. Consider enforcing MFA via IAM policy."
        ),
        create_finding(
            "Access Key: AKIAIOSFODNN7EXAMPLE (User: dev-ops)",
            "IAM - Key Rotation",
            "Access key 'AKIAIOSFODNN7EXAMPLE' for user 'dev-ops' is 142 days old (exceeds 90-day limit)",
            SEVERITY_HIGH,
            "Rotate access key for user 'dev-ops'. Create new key, update apps, deactivate old key."
        ),
        create_finding(
            "IAM User: admin-user", "IAM - Least Privilege",
            "User 'admin-user' has AdministratorAccess policy directly attached",
            SEVERITY_HIGH,
            "Remove direct AdministratorAccess from 'admin-user'. Use groups with specific permissions."
        ),
        create_finding(
            "Root Account", "IAM - Root Usage",
            "Root account was used 5 days ago (within last 30 days)",
            SEVERITY_HIGH,
            "Avoid using root account. Create IAM users with appropriate permissions."
        ),
        # some passing IAM checks
        create_finding(
            "IAM Access Keys", "IAM - Key Rotation",
            "Checked 12 users - rotation policy partially compliant",
            SEVERITY_MEDIUM, "Continue monitoring key ages",
            status=STATUS_PASS
        ),
        
        # S3 findings
        create_finding(
            "S3: company-public-assets", "S3 - Public Access",
            "Bucket 'company-public-assets' has public access block disabled: BlockPublicAcls, IgnorePublicAcls",
            SEVERITY_CRITICAL,
            "Enable all public access blocks for bucket 'company-public-assets'."
        ),
        create_finding(
            "S3: dev-logs-bucket", "S3 - Encryption",
            "Bucket 'dev-logs-bucket' does not have default encryption enabled",
            SEVERITY_HIGH,
            "Enable default encryption (AES-256 or KMS) on bucket 'dev-logs-bucket'."
        ),
        create_finding(
            "S3: production-data", "S3 - Public Access",
            "Bucket 'production-data' has all public access blocks enabled",
            SEVERITY_CRITICAL, "No action needed",
            status=STATUS_PASS
        ),
        create_finding(
            "S3: production-data", "S3 - Encryption",
            "Bucket 'production-data' has default encryption enabled (aws:kms)",
            SEVERITY_HIGH, "No action needed - encryption is enabled",
            status=STATUS_PASS
        ),
        create_finding(
            "S3: backups-2024", "S3 - Versioning",
            "Bucket 'backups-2024' does not have versioning enabled",
            SEVERITY_MEDIUM,
            "Enable versioning on bucket 'backups-2024' to protect against accidental deletion."
        ),
        create_finding(
            "S3: production-data", "S3 - Versioning",
            "Bucket 'production-data' has versioning enabled",
            SEVERITY_MEDIUM, "No action needed",
            status=STATUS_PASS
        ),
        
        # EC2 findings
        create_finding(
            "SG: sg-0a1b2c3d4e (web-servers-sg)", "EC2 - Security Groups",
            "Security group 'web-servers-sg' (sg-0a1b2c3d4e) allows SSH (port 22) from 0.0.0.0/0",
            SEVERITY_HIGH,
            "Restrict port 22 (SSH) to specific IP ranges. Never expose SSH access to the internet."
        ),
        create_finding(
            "SG: sg-9f8e7d6c5b (windows-rdp-sg)", "EC2 - Security Groups",
            "Security group 'windows-rdp-sg' (sg-9f8e7d6c5b) allows RDP (port 3389) from 0.0.0.0/0",
            SEVERITY_HIGH,
            "Restrict port 3389 (RDP) to specific IP ranges. Use a VPN or bastion host instead."
        ),
        create_finding(
            "SG: sg-1122334455 (db-access-sg)", "EC2 - Security Groups",
            "Security group 'db-access-sg' (sg-1122334455) allows MySQL (port 3306) from 0.0.0.0/0",
            SEVERITY_CRITICAL,
            "Restrict port 3306 (MySQL) to specific IP ranges. Never expose MySQL database to the internet."
        ),
        create_finding(
            "EC2 Security Group Map", "EC2 - Network Map",
            "Mapped 3 security groups and 3 inbound relationships",
            SEVERITY_LOW,
            "Use the HTML report map to review public paths and security group to security group access.",
            status=STATUS_PASS,
            metadata={
                "network_map": {
                    "nodes": [
                        {
                            "id": "sg-0a1b2c3d4e",
                            "name": "web-servers-sg",
                            "vpc": "vpc-demo",
                            "used": True,
                            "publicly_reachable": True,
                            "resources": [
                                {"name": "EC2 i-webdemo", "subnet": "subnet-public-a", "publicly_reachable": True}
                            ],
                        },
                        {
                            "id": "sg-1122334455",
                            "name": "db-access-sg",
                            "vpc": "vpc-demo",
                            "used": True,
                            "publicly_reachable": False,
                            "resources": [
                                {"name": "RDS-like database interface", "subnet": "subnet-private-a", "publicly_reachable": False}
                            ],
                        },
                        {
                            "id": "sg-app-private",
                            "name": "app-private-sg",
                            "vpc": "vpc-demo",
                            "used": True,
                            "publicly_reachable": False,
                            "resources": [
                                {"name": "EC2 i-appdemo", "subnet": "subnet-private-a", "publicly_reachable": False}
                            ],
                        },
                    ],
                    "edges": [
                        {"source": "Internet", "target": "sg-0a1b2c3d4e", "port": "22", "protocol": "SSH", "risk": "HIGH", "exposure": "attached to public subnet resources with public IPs"},
                        {"source": "Internet", "target": "sg-1122334455", "port": "3306", "protocol": "MySQL", "risk": "CRITICAL", "exposure": "attached only to private subnet resources"},
                        {"source": "sg-app-private", "target": "sg-1122334455", "port": "3306", "protocol": "tcp", "risk": "reference"},
                    ],
                }
            }
        ),
        
        # CloudTrail findings
        create_finding(
            "CloudTrail: management-trail", "CloudTrail - Logging",
            "CloudTrail trail 'management-trail' is active and logging",
            SEVERITY_CRITICAL, "No action needed - logging is active",
            status=STATUS_PASS
        ),
        create_finding(
            "CloudTrail: management-trail", "CloudTrail - Multi-Region",
            "Trail 'management-trail' has multi-region logging enabled",
            SEVERITY_HIGH, "No action needed",
            status=STATUS_PASS
        ),
        create_finding(
            "CloudTrail: management-trail", "CloudTrail - Log Validation",
            "Trail 'management-trail' does NOT have log file validation enabled",
            SEVERITY_MEDIUM,
            "Enable log file validation to detect tampering with CloudTrail logs."
        ),
    ]
    
    return sampleFindings


def main():
    """
    Main function - orchestrates the entire audit.
    Runs each module, collects findings, generates report.
    """
    print_banner()
    args = parse_args()
    
    startTime = datetime.now()
    allFindings = []
    
    # demo mode - skip AWS connection, use sample data
    if args.demo:
        allFindings = run_demo_mode()
        csv_path, html_path = generate_reports(allFindings, args.output_dir)
        _print_summary(allFindings, startTime, csv_path, html_path)
        return
    
    # verify AWS connectivity first
    print_progress("Verifying AWS connectivity...")
    try:
        accountId = get_account_id()
        print(f"  Connected to AWS Account: {accountId}")
    except Exception as e:
        print(f"\n  [ERROR] Could not connect to AWS: {e}")
        print("  Make sure AWS CLI is configured or environment variables are set.")
        print("  You can also run: python main.py --demo  (for demo mode)")
        sys.exit(1)
    
    # --- Run each audit module ---
    
    # 1. IAM Audit
    if not args.skip_iam:
        print_progress("Checking IAM configurations...")
        try:
            iam_findings = run_iam_audit()
            allFindings.extend(iam_findings)
        except Exception as e:
            print(f"  [ERROR] IAM audit module failed: {e}")
    else:
        print_progress("Skipping IAM audit (--skip-iam)")
    
    # 2. S3 Audit
    if not args.skip_s3:
        print_progress("Scanning S3 buckets...")
        try:
            s3_findings = run_s3_audit()
            allFindings.extend(s3_findings)
        except Exception as e:
            print(f"  [ERROR] S3 audit module failed: {e}")
    else:
        print_progress("Skipping S3 audit (--skip-s3)")
    
    # 3. EC2 / Security Groups
    if not args.skip_ec2:
        print_progress("Auditing EC2 security groups...")
        try:
            ec2_findings = run_ec2_audit()
            allFindings.extend(ec2_findings)
        except Exception as e:
            print(f"  [ERROR] EC2 audit module failed: {e}")
    else:
        print_progress("Skipping EC2 audit (--skip-ec2)")
    
    # 4. CloudTrail
    if not args.skip_cloudtrail:
        print_progress("Verifying CloudTrail logging...")
        try:
            ct_findings = run_cloudtrail_audit()
            allFindings.extend(ct_findings)
        except Exception as e:
            print(f"  [ERROR] CloudTrail audit module failed: {e}")
    else:
        print_progress("Skipping CloudTrail audit (--skip-cloudtrail)")
    
    # --- Generate Reports ---
    print_progress("Generating audit reports...")
    csv_path, html_path = generate_reports(allFindings, args.output_dir)
    
    # --- Print Summary ---
    _print_summary(allFindings, startTime, csv_path, html_path)


def _print_summary(allFindings, startTime, csv_path, html_path):
    """Print the final summary to terminal."""
    endTime = datetime.now()
    duration = (endTime - startTime).total_seconds()
    
    # count by severity
    criticalCount = sum(1 for f in allFindings if f['severity'] == 'CRITICAL' and f['status'] == 'FAIL')
    highCount = sum(1 for f in allFindings if f['severity'] == 'HIGH' and f['status'] == 'FAIL')
    mediumCount = sum(1 for f in allFindings if f['severity'] == 'MEDIUM' and f['status'] == 'FAIL')
    lowCount = sum(1 for f in allFindings if f['severity'] == 'LOW' and f['status'] == 'FAIL')
    passCount = sum(1 for f in allFindings if f['status'] == 'PASS')
    failCount = sum(1 for f in allFindings if f['status'] == 'FAIL')
    
    print(f"""
    ┌─────────────────────────────────────────────────┐
    │           AUDIT SUMMARY                         │
    ├─────────────────────────────────────────────────┤
    │  Total Findings:  {len(allFindings):<29}│
    │  ❌ Failed:        {failCount:<29}│
    │  ✅ Passed:        {passCount:<29}│
    │                                                 │
    │  🔴 Critical:      {criticalCount:<29}│
    │  🟠 High:          {highCount:<29}│
    │  🟡 Medium:        {mediumCount:<29}│
    │  🟢 Low:           {lowCount:<29}│
    │                                                 │
    │  Duration: {duration:.1f}s{' ' * (37 - len(f'{duration:.1f}s'))}│
    ├─────────────────────────────────────────────────┤
    │  Reports:                                       │""")
    
    if csv_path:
        # pad the path display
        csvDisplay = csv_path[:43]
        print(f"    │  📄 CSV:  {csvDisplay:<39}│")
    if html_path:
        htmlDisplay = html_path[:43]
        print(f"    │  🌐 HTML: {htmlDisplay:<39}│")
    
    print("    └─────────────────────────────────────────────────┘")
    print()


if __name__ == "__main__":
    main()
