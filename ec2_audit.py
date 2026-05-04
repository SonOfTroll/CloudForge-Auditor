"""
ec2_audit.py - EC2 & Security Group Audit Module
Checks EC2 security group configurations for common misconfigurations.

Covers:
- SSH (port 22) open to 0.0.0.0/0
- RDP (port 3389) open to 0.0.0.0/0
- Database ports (3306, 5432, 1433) exposed publicly

Why Security Group auditing matters:
Security groups are the firewall for EC2 instances. Overly permissive rules
allow anyone on the internet to attempt connections. Open SSH/RDP = brute force target.
Open database ports = direct data theft risk.
"""

from utils import (
    get_aws_client, create_finding,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
    STATUS_PASS, STATUS_FAIL
)


# ports we care about - could add more later
# TODO: make this configurable via a config file
DANGEROUS_PORTS = {
    22: {"name": "SSH", "severity": SEVERITY_HIGH, "desc": "SSH access"},
    3389: {"name": "RDP", "severity": SEVERITY_HIGH, "desc": "Remote Desktop access"},
    3306: {"name": "MySQL", "severity": SEVERITY_CRITICAL, "desc": "MySQL database"},
    5432: {"name": "PostgreSQL", "severity": SEVERITY_CRITICAL, "desc": "PostgreSQL database"},
    1433: {"name": "MSSQL", "severity": SEVERITY_CRITICAL, "desc": "Microsoft SQL Server"},
    27017: {"name": "MongoDB", "severity": SEVERITY_CRITICAL, "desc": "MongoDB database"},
}

# these CIDR ranges mean "open to the world"
OPEN_CIDRS = ['0.0.0.0/0', '::/0']


def run_ec2_audit():
    """Main function to run EC2/Security Group checks. Returns list of findings."""
    print("  Starting EC2/Security Group audit...")
    findings = []
    
    ec2_client = get_aws_client('ec2')
    if ec2_client is None:
        print("  [ERROR] Could not create EC2 client, skipping EC2 audit")
        findings.append(create_finding(
            "EC2", "EC2", "Could not connect to EC2 service",
            SEVERITY_HIGH, "Check AWS credentials and permissions"
        ))
        return findings
    
    try:
        sg_findings = check_security_groups(ec2_client)
        findings.extend(sg_findings)
    except Exception as e:
        print(f"  [ERROR] Security group audit failed: {e}")
        findings.append(create_finding(
            "EC2 Security Groups", "EC2 - Security Groups",
            f"Security group audit failed: {str(e)}",
            SEVERITY_HIGH, "Verify EC2 read permissions"
        ))
    
    print(f"  EC2 audit complete. {len(findings)} findings generated.")
    return findings


def check_security_groups(ec2_client):
    """
    Check all security groups for dangerous open ports.
    
    WHY THIS MATTERS:
    Security groups with 0.0.0.0/0 on sensitive ports expose services to the entire internet.
    This is the most common network misconfiguration in AWS.
    Attackers constantly scan for open SSH, RDP, and database ports.
    
    RISK: Unauthorized access, brute force attacks, data exfiltration
    """
    findings = []
    
    try:
        # get all security groups
        # using paginator in case there are lots of SGs
        allSecurityGroups = []
        paginator = ec2_client.get_paginator('describe_security_groups')
        
        for page in paginator.paginate():
            for sg in page['SecurityGroups']:
                allSecurityGroups.append(sg)
        
        print(f"  Found {len(allSecurityGroups)} security groups to check")
        
        dangerousCount = 0
        
        for sg in allSecurityGroups:
            sgId = sg['GroupId']
            sgName = sg.get('GroupName', 'unnamed')
            vpcId = sg.get('VpcId', 'N/A')
            
            # check inbound rules (ingress)
            inboundRules = sg.get('IpPermissions', [])
            
            for rule in inboundRules:
                # get port range - some rules don't have ports (like -1 for all traffic)
                fromPort = rule.get('FromPort', -1)
                toPort = rule.get('ToPort', -1)
                protocol = rule.get('IpProtocol', 'unknown')
                
                # check if the rule allows all traffic (protocol = -1)
                if protocol == '-1':
                    # all traffic allowed - check if its open to world
                    isPublic = _check_if_public(rule)
                    if isPublic:
                        dangerousCount += 1
                        findings.append(create_finding(
                            f"SG: {sgId} ({sgName})",
                            "EC2 - Security Groups",
                            f"Security group '{sgName}' ({sgId}) allows ALL traffic from 0.0.0.0/0 in VPC {vpcId}",
                            SEVERITY_CRITICAL,
                            f"Restrict security group '{sgId}' to specific ports and IP ranges. Remove 0.0.0.0/0 rule."
                        ))
                    continue
                
                # check if any dangerous port is in the range
                for port, portInfo in DANGEROUS_PORTS.items():
                    if fromPort <= port <= toPort or (fromPort == port and toPort == port):
                        # this port is in the rule - check if it's open to the world
                        isPublic = _check_if_public(rule)
                        if isPublic:
                            dangerousCount += 1
                            findings.append(create_finding(
                                f"SG: {sgId} ({sgName})",
                                "EC2 - Security Groups",
                                f"Security group '{sgName}' ({sgId}) allows {portInfo['name']} (port {port}) from 0.0.0.0/0",
                                portInfo['severity'],
                                f"Restrict port {port} ({portInfo['name']}) to specific IP ranges. Never expose {portInfo['desc']} to the internet."
                            ))
        
        if dangerousCount == 0:
            findings.append(create_finding(
                "EC2 Security Groups", "EC2 - Security Groups",
                "No security groups with dangerous ports open to 0.0.0.0/0 found",
                SEVERITY_HIGH, "Continue following least-privilege network access",
                status=STATUS_PASS
            ))
            print("    ✅ No dangerous open ports found")
        else:
            print(f"    ❌ Found {dangerousCount} dangerous security group rules")
    
    except Exception as e:
        print(f"  [ERROR] Failed to check security groups: {e}")
        findings.append(create_finding(
            "EC2 Security Groups", "EC2 - Security Groups",
            f"Failed to audit security groups: {str(e)}",
            SEVERITY_HIGH, "Check EC2 describe permissions"
        ))
    
    return findings


def _check_if_public(rule):
    """
    Helper to check if a security group rule allows public access.
    Checks both IPv4 and IPv6 CIDR ranges.
    
    # quick helper - checks if any IP range in the rule is 0.0.0.0/0 or ::/0
    """
    # check IPv4 ranges
    ipRanges = rule.get('IpRanges', [])
    for ipRange in ipRanges:
        cidr = ipRange.get('CidrIp', '')
        if cidr in OPEN_CIDRS:
            return True
    
    # check IPv6 ranges too
    ipv6Ranges = rule.get('Ipv6Ranges', [])
    for ipRange in ipv6Ranges:
        cidr = ipRange.get('CidrIpv6', '')
        if cidr in OPEN_CIDRS:
            return True
    
    return False
