"""
s3_audit.py - S3 Bucket Security Audit Module
Checks S3 bucket configurations against security best practices.

Covers:
- Public access block settings
- Default encryption
- Versioning status

Why S3 auditing matters:
S3 buckets are one of the most common sources of data breaches in AWS.
Misconfigured buckets have exposed sensitive data countless times.
Public buckets without encryption or versioning are a high-risk pattern.
"""

from utils import (
    get_aws_client, create_finding,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
    STATUS_PASS
)


def run_s3_audit():
    """Main function to run all S3 checks. Returns list of findings."""
    print("  Starting S3 audit checks...")
    findings = []
    
    s3_client = get_aws_client('s3')
    if s3_client is None:
        print("  [ERROR] Could not create S3 client, skipping S3 audit")
        findings.append(create_finding(
            "S3", "S3", "Could not connect to S3 service",
            SEVERITY_HIGH, "Check AWS credentials and permissions"
        ))
        return findings
    
    # Start with the account-level bucket list, then check each bucket in turn.
    try:
        response = s3_client.list_buckets()
        bucketList = response.get('Buckets', [])
        print(f"  Found {len(bucketList)} S3 buckets to audit")
        
        if len(bucketList) == 0:
            print("  No S3 buckets found - nothing to audit")
            findings.append(create_finding(
                "S3", "S3 - General",
                "No S3 buckets found in this account",
                SEVERITY_LOW, "No action needed",
                status=STATUS_PASS
            ))
            return findings
        
        # check each bucket
        for bucket in bucketList:
            bucketName = bucket['Name']
            print(f"    Scanning bucket: {bucketName}...")
            
            try:
                pubAccess = check_public_access(s3_client, bucketName)
                findings.extend(pubAccess)
            except Exception as e:
                print(f"    [WARN] Public access check failed for {bucketName}: {e}")
            
            try:
                encFindings = check_encryption(s3_client, bucketName)
                findings.extend(encFindings)
            except Exception as e:
                print(f"    [WARN] Encryption check failed for {bucketName}: {e}")
            
            try:
                verFindings = check_versioning(s3_client, bucketName)
                findings.extend(verFindings)
            except Exception as e:
                print(f"    [WARN] Versioning check failed for {bucketName}: {e}")
    
    except Exception as e:
        print(f"  [ERROR] Could not list S3 buckets: {e}")
        findings.append(create_finding(
            "S3", "S3", f"Could not list S3 buckets: {str(e)}",
            SEVERITY_HIGH, "Check S3 read permissions"
        ))
    
    print(f"  S3 audit complete. {len(findings)} findings generated.")
    return findings


def check_public_access(s3_client, bucketName):
    """
    Check if public access block is properly configured.
    
    WHY THIS MATTERS:
    Public S3 buckets are the #1 cause of cloud data leaks.
    All four public access block settings should be enabled.
    Even one disabled setting can expose data to the internet.
    
    RISK: Data exposure, regulatory violations, reputational damage
    """
    findings = []
    
    try:
        pubBlock = s3_client.get_public_access_block(Bucket=bucketName)
        config = pubBlock['PublicAccessBlockConfiguration']
        
        # AWS exposes four public access block switches; full protection needs all of them.
        blockPublicAcls = config.get('BlockPublicAcls', False)
        ignorePublicAcls = config.get('IgnorePublicAcls', False)
        blockPublicPolicy = config.get('BlockPublicPolicy', False)
        restrictPublicBuckets = config.get('RestrictPublicBuckets', False)
        
        # all four need to be true for full protection
        allBlocked = blockPublicAcls and ignorePublicAcls and blockPublicPolicy and restrictPublicBuckets
        
        if allBlocked:
            findings.append(create_finding(
                f"S3: {bucketName}", "S3 - Public Access",
                f"Bucket '{bucketName}' has all public access blocks enabled",
                SEVERITY_CRITICAL, "No action needed",
                status=STATUS_PASS
            ))
        else:
            # figure out which ones are missing - helpful for remediation
            missingBlocks = []
            if not blockPublicAcls:
                missingBlocks.append("BlockPublicAcls")
            if not ignorePublicAcls:
                missingBlocks.append("IgnorePublicAcls")
            if not blockPublicPolicy:
                missingBlocks.append("BlockPublicPolicy")
            if not restrictPublicBuckets:
                missingBlocks.append("RestrictPublicBuckets")
            
            findings.append(create_finding(
                f"S3: {bucketName}", "S3 - Public Access",
                f"Bucket '{bucketName}' has public access block disabled: {', '.join(missingBlocks)}",
                SEVERITY_CRITICAL,
                f"Enable all public access blocks for bucket '{bucketName}'. Missing: {', '.join(missingBlocks)}"
            ))
    
    except s3_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        # no public access block at all - bad
        findings.append(create_finding(
            f"S3: {bucketName}", "S3 - Public Access",
            f"Bucket '{bucketName}' has NO public access block configured",
            SEVERITY_CRITICAL,
            f"Configure public access block for bucket '{bucketName}' with all settings enabled."
        ))
    except Exception as e:
        # this might fail if AWS response changes or permissions issue
        print(f"      [WARN] Could not check public access for {bucketName}: {e}")
    
    return findings


def check_encryption(s3_client, bucketName):
    """
    Check if default encryption is enabled on the bucket.
    
    WHY THIS MATTERS:
    Data at rest should always be encrypted. Without default encryption,
    objects uploaded without explicit encryption settings will be stored unencrypted.
    This is a basic security hygiene requirement for compliance (SOC2, HIPAA, etc.)
    
    RISK: Unencrypted data exposure if storage is compromised
    """
    findings = []
    
    try:
        enc = s3_client.get_bucket_encryption(Bucket=bucketName)
        rules = enc.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
        
        if len(rules) > 0:
            # check what type of encryption is used
            encType = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', 'unknown')
            findings.append(create_finding(
                f"S3: {bucketName}", "S3 - Encryption",
                f"Bucket '{bucketName}' has default encryption enabled ({encType})",
                SEVERITY_HIGH, "No action needed - encryption is enabled",
                status=STATUS_PASS
            ))
        else:
            findings.append(create_finding(
                f"S3: {bucketName}", "S3 - Encryption",
                f"Bucket '{bucketName}' does not have default encryption enabled",
                SEVERITY_HIGH,
                f"Enable default encryption (AES-256 or KMS) on bucket '{bucketName}'."
            ))
    
    except s3_client.exceptions.ClientError as e:
        error_code = e.response.get('Error', {}).get('Code', '')
        if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
            findings.append(create_finding(
                f"S3: {bucketName}", "S3 - Encryption",
                f"Bucket '{bucketName}' does not have default encryption enabled",
                SEVERITY_HIGH,
                f"Enable default encryption on bucket '{bucketName}'. Use SSE-S3 (AES-256) at minimum."
            ))
        else:
            print(f"      [WARN] Encryption check error for {bucketName}: {e}")
    except Exception as e:
        print(f"      [WARN] Could not check encryption for {bucketName}: {e}")
    
    return findings


def check_versioning(s3_client, bucketName):
    """
    Check if versioning is enabled on the bucket.
    
    WHY THIS MATTERS:
    Versioning protects against accidental deletion and overwrites.
    Without versioning, ransomware or accidental deletion can cause data loss.
    It also supports compliance requirements for data retention.
    
    RISK: Permanent data loss from accidental or malicious deletion
    """
    findings = []
    
    try:
        ver = s3_client.get_bucket_versioning(Bucket=bucketName)
        versioningStatus = ver.get('Status', 'Disabled')
        
        # quick check for now - versioning can be Enabled, Suspended, or not set
        if versioningStatus == 'Enabled':
            findings.append(create_finding(
                f"S3: {bucketName}", "S3 - Versioning",
                f"Bucket '{bucketName}' has versioning enabled",
                SEVERITY_MEDIUM, "No action needed",
                status=STATUS_PASS
            ))
        elif versioningStatus == 'Suspended':
            findings.append(create_finding(
                f"S3: {bucketName}", "S3 - Versioning",
                f"Bucket '{bucketName}' has versioning SUSPENDED",
                SEVERITY_MEDIUM,
                f"Re-enable versioning on bucket '{bucketName}'. Suspended versioning still has old versions but new objects won't be versioned."
            ))
        else:
            findings.append(create_finding(
                f"S3: {bucketName}", "S3 - Versioning",
                f"Bucket '{bucketName}' does not have versioning enabled",
                SEVERITY_MEDIUM,
                f"Enable versioning on bucket '{bucketName}' to protect against accidental deletion."
            ))
    except Exception as e:
        print(f"      [WARN] Could not check versioning for {bucketName}: {e}")
    
    return findings
