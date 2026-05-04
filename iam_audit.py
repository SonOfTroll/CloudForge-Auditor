"""
iam_audit.py - IAM Security Audit Module
Checks IAM configurations against CIS Benchmark best practices.

Covers:
- Root account MFA status
- User MFA enforcement  
- Access key rotation (90-day policy)
- Overprivileged users (AdministratorAccess)
- Root account recent usage

Why IAM auditing matters:
IAM is the first line of defense in AWS. Misconfigured IAM can lead to
unauthorized access, privilege escalation, and full account compromise.
"""

from utils import (
    get_aws_client, create_finding, days_since,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
    STATUS_PASS, STATUS_FAIL
)
from datetime import datetime, timezone
import time
import csv
from io import StringIO


def run_iam_audit():
    """Main function to run all IAM checks. Returns a list of findings."""
    print("  Starting IAM audit checks...")
    findings = []
    
    iam_client = get_aws_client('iam')
    if iam_client is None:
        print("  [ERROR] Could not create IAM client, skipping IAM audit")
        findings.append(create_finding(
            "IAM", "IAM", "Could not connect to IAM service",
            SEVERITY_HIGH, "Check AWS credentials and permissions"
        ))
        return findings
    
    # Run each check - if one fails others still run
    checks = [
        ("Root MFA", check_root_mfa),
        ("User MFA", check_users_mfa),
        ("Access Key Age", check_old_access_keys),
        ("Admin Access", check_admin_access),
        ("Root Usage", check_root_usage),
    ]
    
    for name, check_fn in checks:
        try:
            result = check_fn(iam_client)
            findings.extend(result)
        except Exception as e:
            print(f"  [ERROR] {name} check failed: {e}")
            findings.append(create_finding(
                "IAM", f"IAM - {name}",
                f"{name} check failed: {str(e)}", SEVERITY_HIGH,
                f"Manually verify {name} in AWS console"
            ))
    
    print(f"  IAM audit complete. {len(findings)} findings generated.")
    return findings


def check_root_mfa(iam_client):
    """
    CIS 1.5 - Check if root account has MFA enabled.
    RISK: Complete account takeover if root is compromised without MFA
    """
    findings = []
    print("    Checking root account MFA...")
    
    try:
        summary = iam_client.get_account_summary()
        summaryMap = summary['SummaryMap']
        rootMfaEnabled = summaryMap.get('AccountMFAEnabled', 0)
        
        if rootMfaEnabled == 1:
            findings.append(create_finding(
                "Root Account", "IAM - Root MFA",
                "Root account has MFA enabled",
                SEVERITY_CRITICAL, "No action needed - MFA is enabled",
                status=STATUS_PASS
            ))
            print("    ✅ Root MFA is enabled")
        else:
            # this is really bad - should be critical
            findings.append(create_finding(
                "Root Account", "IAM - Root MFA",
                "Root account does NOT have MFA enabled",
                SEVERITY_CRITICAL,
                "Enable MFA on root account immediately. Use a hardware MFA device if possible."
            ))
            print("    ❌ Root MFA is NOT enabled - CRITICAL!")
    except Exception as e:
        print(f"    [WARN] Could not check root MFA: {e}")
        findings.append(create_finding(
            "Root Account", "IAM - Root MFA",
            f"Unable to verify root MFA status: {str(e)}",
            SEVERITY_HIGH, "Manually check root MFA in AWS Console"
        ))
    
    return findings


def check_users_mfa(iam_client):
    """
    CIS 1.2 - Check if all IAM users have MFA enabled.
    RISK: Unauthorized access through compromised credentials
    """
    findings = []
    print("    Checking user MFA status...")
    
    try:
        # get all users - using paginator for large accounts
        userList = []
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                userList.append(user)
        
        print(f"    got {len(userList)} users, checking MFA...")
        usersWithoutMfa = []
        
        for user in userList:
            userName = user['UserName']
            try:
                mfa_response = iam_client.list_mfa_devices(UserName=userName)
                mfaDevices = mfa_response.get('MFADevices', [])
                
                if len(mfaDevices) == 0:
                    # only flag if user has console password
                    try:
                        iam_client.get_login_profile(UserName=userName)
                        usersWithoutMfa.append(userName)
                    except iam_client.exceptions.NoSuchEntityException:
                        pass  # API-only user, MFA less critical
                    except Exception:
                        # not the cleanest way but works
                        usersWithoutMfa.append(userName)
            except Exception as e:
                print(f"    [WARN] Could not check MFA for {userName}: {e}")
        
        if len(usersWithoutMfa) > 0:
            for u in usersWithoutMfa:
                findings.append(create_finding(
                    f"IAM User: {u}", "IAM - User MFA",
                    f"IAM user '{u}' has console access but no MFA enabled",
                    SEVERITY_HIGH,
                    f"Enable MFA for user '{u}'. Consider enforcing MFA via IAM policy."
                ))
            print(f"    ❌ {len(usersWithoutMfa)} users without MFA")
        else:
            findings.append(create_finding(
                "IAM Users", "IAM - User MFA",
                "All IAM users with console access have MFA enabled",
                SEVERITY_HIGH, "No action needed",
                status=STATUS_PASS
            ))
            print("    ✅ All console users have MFA")
    except Exception as e:
        print(f"    [ERROR] MFA check failed: {e}")
        findings.append(create_finding(
            "IAM Users", "IAM - User MFA",
            f"Could not check user MFA status: {str(e)}",
            SEVERITY_MEDIUM, "Check IAM permissions for auditing"
        ))
    
    return findings


def check_old_access_keys(iam_client):
    """
    CIS 1.4 - Check for access keys older than 90 days.
    RISK: Long-lived credentials increase impact of credential compromise
    """
    findings = []
    print("    Checking access key age...")
    
    try:
        tempList = []
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                tempList.append(user)
        
        oldKeyCount = 0
        
        for user in tempList:
            userName = user['UserName']
            try:
                keys_response = iam_client.list_access_keys(UserName=userName)
                accessKeys = keys_response.get('AccessKeyMetadata', [])
                
                for key in accessKeys:
                    keyId = key['AccessKeyId']
                    createDate = key['CreateDate']
                    keyStatus = key['Status']
                    age_days = days_since(createDate)
                    
                    # TODO: maybe flag inactive old keys as LOW severity too
                    if age_days > 90 and keyStatus == 'Active':
                        oldKeyCount += 1
                        findings.append(create_finding(
                            f"Access Key: {keyId} (User: {userName})",
                            "IAM - Key Rotation",
                            f"Access key '{keyId}' for user '{userName}' is {age_days} days old (exceeds 90-day limit)",
                            SEVERITY_HIGH,
                            f"Rotate access key for user '{userName}'. Create new key, update apps, deactivate old key."
                        ))
                    elif age_days > 90 and keyStatus == 'Inactive':
                        findings.append(create_finding(
                            f"Access Key: {keyId} (User: {userName})",
                            "IAM - Key Rotation",
                            f"Inactive access key '{keyId}' for user '{userName}' is {age_days} days old",
                            SEVERITY_LOW,
                            f"Delete inactive access key '{keyId}' to reduce attack surface."
                        ))
            except Exception as e:
                print(f"    [WARN] Could not check keys for {userName}: {e}")
        
        if oldKeyCount == 0:
            findings.append(create_finding(
                "IAM Access Keys", "IAM - Key Rotation",
                "No active access keys older than 90 days found",
                SEVERITY_HIGH, "No action needed - key rotation is on track",
                status=STATUS_PASS
            ))
            print("    ✅ No old active access keys found")
        else:
            print(f"    ❌ Found {oldKeyCount} active keys older than 90 days")
    except Exception as e:
        print(f"    [ERROR] Access key check failed: {e}")
        findings.append(create_finding(
            "IAM Access Keys", "IAM - Key Rotation",
            f"Could not check access key ages: {str(e)}",
            SEVERITY_MEDIUM, "Verify IAM read permissions"
        ))
    
    return findings


def check_admin_access(iam_client):
    """
    Check for users with AdministratorAccess policy directly attached.
    RISK: Overprivileged users increase blast radius of account compromise
    """
    findings = []
    print("    Checking for users with direct AdministratorAccess...")
    
    try:
        userList = []
        paginator = iam_client.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                userList.append(user)
        
        adminUsers = []
        for user in userList:
            userName = user['UserName']
            try:
                attached = iam_client.list_attached_user_policies(UserName=userName)
                attachedPolicies = attached.get('AttachedPolicies', [])
                for policy in attachedPolicies:
                    policyName = policy['PolicyName']
                    if policyName == 'AdministratorAccess':
                        adminUsers.append(userName)
                        findings.append(create_finding(
                            f"IAM User: {userName}", "IAM - Least Privilege",
                            f"User '{userName}' has AdministratorAccess policy directly attached",
                            SEVERITY_HIGH,
                            f"Remove direct AdministratorAccess from '{userName}'. Use groups with specific permissions."
                        ))
                        break
            except Exception as e:
                print(f"    [WARN] Could not check policies for {userName}: {e}")
        
        if len(adminUsers) == 0:
            findings.append(create_finding(
                "IAM Users", "IAM - Least Privilege",
                "No users have AdministratorAccess directly attached",
                SEVERITY_HIGH, "Good practice - continue using group-based access",
                status=STATUS_PASS
            ))
            print("    ✅ No users with direct admin access")
        else:
            print(f"    ❌ {len(adminUsers)} users with direct AdministratorAccess")
    except Exception as e:
        print(f"    [ERROR] Admin access check failed: {e}")
    
    return findings


def check_root_usage(iam_client):
    """
    Check if root account has been used recently.
    RISK: Frequent root usage increases exposure of the most privileged account
    """
    findings = []
    print("    Checking root account recent usage...")
    
    try:
        # generate credential report - might take a moment
        try:
            iam_client.generate_credential_report()
        except Exception:
            pass  # might already be generated
        
        time.sleep(2)  # wait for report - not ideal but API is async
        
        try:
            report_response = iam_client.get_credential_report()
            report_content = report_response['Content'].decode('utf-8')
            reader = csv.DictReader(StringIO(report_content))
            
            for row in reader:
                if row['user'] == '<root_account>':
                    passwordLastUsed = row.get('password_last_used', 'N/A')
                    
                    if passwordLastUsed and passwordLastUsed not in ('N/A', 'no_information', 'not_supported'):
                        try:
                            lastUsedDate = datetime.strptime(passwordLastUsed, '%Y-%m-%dT%H:%M:%S+00:00')
                            daysSinceUse = days_since(lastUsedDate)
                            
                            if daysSinceUse <= 30:
                                findings.append(create_finding(
                                    "Root Account", "IAM - Root Usage",
                                    f"Root account was used {daysSinceUse} days ago (within last 30 days)",
                                    SEVERITY_HIGH,
                                    "Avoid using root account. Create IAM users with appropriate permissions."
                                ))
                                print(f"    ❌ Root used {daysSinceUse} days ago")
                            else:
                                findings.append(create_finding(
                                    "Root Account", "IAM - Root Usage",
                                    f"Root account last used {daysSinceUse} days ago",
                                    SEVERITY_LOW, "Continue avoiding root account usage",
                                    status=STATUS_PASS
                                ))
                                print(f"    ✅ Root last used {daysSinceUse} days ago")
                        except ValueError:
                            print(f"    [WARN] Could not parse root last used date")
                    else:
                        findings.append(create_finding(
                            "Root Account", "IAM - Root Usage",
                            "Root account password has never been used or info not available",
                            SEVERITY_LOW, "Good - root account appears unused",
                            status=STATUS_PASS
                        ))
                        print("    ✅ Root account appears unused")
                    break
        except Exception as e:
            print(f"    [WARN] Could not get credential report: {e}")
            findings.append(create_finding(
                "Root Account", "IAM - Root Usage",
                "Could not generate credential report to check root usage",
                SEVERITY_MEDIUM, "Manually check root account usage in CloudTrail"
            ))
    except Exception as e:
        print(f"    [ERROR] Root usage check failed: {e}")
    
    return findings
