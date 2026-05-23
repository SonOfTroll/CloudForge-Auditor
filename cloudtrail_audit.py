"""
cloudtrail_audit.py - CloudTrail Audit Module
Checks if CloudTrail is properly configured for logging.

Covers:
- CloudTrail enabled check
- Multi-region logging verification

Why CloudTrail auditing matters:
CloudTrail is the audit log for AWS. Without it, you have no visibility
into who did what in your account. If CloudTrail is off, an attacker
can make changes without leaving the evidence teams need for investigation.
"""

from utils import (
    get_aws_client, create_finding,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM,
    STATUS_PASS
)


def run_cloudtrail_audit():
    """Main function to run CloudTrail checks. Returns list of findings."""
    print("  Starting CloudTrail audit...")
    findings = []
    
    ct_client = get_aws_client('cloudtrail')
    if ct_client is None:
        print("  [ERROR] Could not create CloudTrail client")
        findings.append(create_finding(
            "CloudTrail", "CloudTrail", "Could not connect to CloudTrail service",
            SEVERITY_HIGH, "Check AWS credentials and permissions"
        ))
        return findings
    
    # Logging status and regional coverage are separate checks.
    try:
        enabled_findings = check_cloudtrail_enabled(ct_client)
        findings.extend(enabled_findings)
    except Exception as e:
        print(f"  [ERROR] CloudTrail enabled check failed: {e}")
        findings.append(create_finding(
            "CloudTrail", "CloudTrail",
            f"CloudTrail check failed: {str(e)}",
            SEVERITY_HIGH, "Manually verify CloudTrail status"
        ))
    
    try:
        region_findings = check_multiregion_logging(ct_client)
        findings.extend(region_findings)
    except Exception as e:
        print(f"  [ERROR] Multi-region check failed: {e}")
    
    print(f"  CloudTrail audit complete. {len(findings)} findings generated.")
    return findings


def check_cloudtrail_enabled(ct_client):
    """
    CIS 2.1 - Check if CloudTrail is enabled and logging.
    
    WHY THIS MATTERS:
    CloudTrail records API calls made in your AWS account.
    Without it, you have zero visibility into account activity.
    This is required for incident response and compliance.
    
    RISK: No audit trail = no way to detect or investigate breaches
    """
    findings = []
    print("    Checking if CloudTrail is enabled...")
    
    try:
        trails_response = ct_client.describe_trails()
        trailList = trails_response.get('trailList', [])
        
        if len(trailList) == 0:
            findings.append(create_finding(
                "CloudTrail", "CloudTrail - Logging",
                "No CloudTrail trails configured in this account",
                SEVERITY_CRITICAL,
                "Create a CloudTrail trail immediately. Enable logging to S3 with multi-region support."
            ))
            print("    ❌ No CloudTrail trails found - CRITICAL!")
            return findings
        
        print(f"    Found {len(trailList)} CloudTrail trail(s)")
        
        # check each trail's logging status
        hasActiveTrail = False
        
        for trail in trailList:
            trailName = trail.get('Name', 'unnamed')
            trailArn = trail.get('TrailARN', 'N/A')
            
            try:
                status = ct_client.get_trail_status(Name=trailArn)
                isLogging = status.get('IsLogging', False)
                
                if isLogging:
                    hasActiveTrail = True
                    findings.append(create_finding(
                        f"CloudTrail: {trailName}", "CloudTrail - Logging",
                        f"CloudTrail trail '{trailName}' is active and logging",
                        SEVERITY_CRITICAL, "No action needed - logging is active",
                        status=STATUS_PASS
                    ))
                    print(f"    ✅ Trail '{trailName}' is logging")
                else:
                    findings.append(create_finding(
                        f"CloudTrail: {trailName}", "CloudTrail - Logging",
                        f"CloudTrail trail '{trailName}' exists but logging is STOPPED",
                        SEVERITY_CRITICAL,
                        f"Start logging for CloudTrail trail '{trailName}' immediately."
                    ))
                    print(f"    ❌ Trail '{trailName}' exists but NOT logging!")
            
            except Exception as e:
                print(f"    [WARN] Could not get status for trail {trailName}: {e}")
        
        if not hasActiveTrail:
            findings.append(create_finding(
                "CloudTrail", "CloudTrail - Logging",
                "No CloudTrail trails are actively logging",
                SEVERITY_CRITICAL,
                "Enable logging on at least one CloudTrail trail."
            ))
    
    except Exception as e:
        print(f"    [ERROR] Could not describe trails: {e}")
        findings.append(create_finding(
            "CloudTrail", "CloudTrail - Logging",
            f"Failed to check CloudTrail status: {str(e)}",
            SEVERITY_HIGH, "Verify CloudTrail read permissions"
        ))
    
    return findings


def check_multiregion_logging(ct_client):
    """
    CIS 2.1 - Check if CloudTrail has multi-region logging enabled.
    
    WHY THIS MATTERS:
    AWS operates in multiple regions. An attacker could spin up resources
    in a region you're not monitoring. Multi-region trails ensure you see
    activity across ALL regions, not just your primary one.
    
    RISK: Blind spots in regions without logging = undetected malicious activity
    """
    findings = []
    print("    Checking multi-region logging...")
    
    try:
        trails_response = ct_client.describe_trails()
        trailList = trails_response.get('trailList', [])
        
        hasMultiRegion = False
        
        for trail in trailList:
            trailName = trail.get('Name', 'unnamed')
            isMultiRegion = trail.get('IsMultiRegionTrail', False)
            
            if isMultiRegion:
                hasMultiRegion = True
                # also check if log file validation is on - good practice
                logValidation = trail.get('LogFileValidationEnabled', False)
                
                findings.append(create_finding(
                    f"CloudTrail: {trailName}", "CloudTrail - Multi-Region",
                    f"Trail '{trailName}' has multi-region logging enabled",
                    SEVERITY_HIGH, "No action needed",
                    status=STATUS_PASS
                ))
                
                # bonus check: log file validation
                if logValidation:
                    findings.append(create_finding(
                        f"CloudTrail: {trailName}", "CloudTrail - Log Validation",
                        f"Trail '{trailName}' has log file validation enabled",
                        SEVERITY_MEDIUM, "No action needed",
                        status=STATUS_PASS
                    ))
                else:
                    findings.append(create_finding(
                        f"CloudTrail: {trailName}", "CloudTrail - Log Validation",
                        f"Trail '{trailName}' does NOT have log file validation enabled",
                        SEVERITY_MEDIUM,
                        "Enable log file validation to detect tampering with CloudTrail logs."
                    ))
        
        if not hasMultiRegion:
            findings.append(create_finding(
                "CloudTrail", "CloudTrail - Multi-Region",
                "No CloudTrail trail has multi-region logging enabled",
                SEVERITY_HIGH,
                "Enable multi-region logging on at least one CloudTrail trail to ensure full visibility."
            ))
            print("    ❌ No multi-region logging configured")
        else:
            print("    ✅ Multi-region logging is enabled")
    
    except Exception as e:
        print(f"    [ERROR] Multi-region check failed: {e}")
    
    return findings
