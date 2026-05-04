"""
utils.py - Utility functions for CloudForge-Auditor
Helper stuff used across different audit modules
"""

import boto3
from datetime import datetime, timezone
import sys

# severity levels - using strings for now, maybe make an enum later?
# TODO: consider using enum for severity levels
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"

# status constants
STATUS_PASS = "PASS"
STATUS_FAIL = "FAIL"


def get_aws_client(service_name, region=None):
    """
    Create a boto3 client for the given AWS service.
    Uses default credentials from AWS CLI or environment variables.
    
    # this is basically a wrapper so we don't repeat boto3.client() everywhere
    # not the cleanest way but works for our use case
    """
    try:
        if region:
            client = boto3.client(service_name, region_name=region)
        else:
            client = boto3.client(service_name)
        return client
    except Exception as e:
        print(f"[ERROR] Failed to create client for {service_name}: {e}")
        return None


def get_aws_resource(service_name, region=None):
    """Get a boto3 resource - sometimes easier to work with than client"""
    try:
        if region:
            resource = boto3.resource(service_name, region_name=region)
        else:
            resource = boto3.resource(service_name)
        return resource
    except Exception as e:
        print(f"[ERROR] Failed to create resource for {service_name}: {e}")
        return None


def get_account_id():
    """Get the current AWS account ID - needed for some checks"""
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        return identity['Account']
    except Exception as e:
        print(f"[ERROR] Could not get account ID: {e}")
        return "UNKNOWN"


def days_since(date_obj):
    """
    Calculate days between a given date and now.
    Used for checking key age, last login, etc.
    
    # quick helper - handles timezone stuff which is annoying
    """
    if date_obj is None:
        return -1  # return -1 if no date, caller can handle this
    
    now = datetime.now(timezone.utc)
    
    # make sure the date is timezone aware
    if date_obj.tzinfo is None:
        date_obj = date_obj.replace(tzinfo=timezone.utc)
    
    delta = now - date_obj
    return delta.days


def create_finding(resource_id, risk_area, finding, severity, recommendation, status="FAIL"):
    """
    Create a standardized finding dictionary.
    Every audit check should return findings in this format.
    
    # keeping it as a dict for simplicity - could be a dataclass but this works fine
    """
    finding_dict = {
        "resource_id": resource_id,
        "risk_area": risk_area,
        "finding": finding,
        "severity": severity,
        "recommendation": recommendation,
        "status": status,
        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    }
    return finding_dict


def print_progress(message):
    """
    Print a progress message with a prefix.
    Makes the output look more professional.
    """
    print(f"\n[CloudForge-Auditor] {message}")
    sys.stdout.flush()  # make sure it prints immediately


def print_finding_summary(finding):
    """Quick print of a finding - useful for debugging"""
    status_icon = "✅" if finding["status"] == STATUS_PASS else "❌"
    print(f"  {status_icon} [{finding['severity']}] {finding['finding']}")


def get_all_regions():
    """
    Get list of all AWS regions.
    Needed for multi-region checks like CloudTrail.
    
    # this might fail if AWS adds/removes regions but should be fine for now
    """
    try:
        ec2 = boto3.client('ec2')
        regions_response = ec2.describe_regions()
        region_list = []
        for r in regions_response['Regions']:
            region_list.append(r['RegionName'])
        return region_list
    except Exception as e:
        print(f"[WARN] Could not fetch regions, using defaults: {e}")
        # fallback list - not complete but covers the main ones
        return [
            'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
            'eu-west-1', 'eu-central-1', 'ap-southeast-1', 'ap-northeast-1'
        ]
