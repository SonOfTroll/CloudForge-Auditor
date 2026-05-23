"""
ec2_audit.py - EC2 & Security Group Audit Module
Checks EC2 security group configurations with VPC-aware exposure context.

Covers:
- SSH (22), RDP (3389), and database ports exposed publicly
- Whether exposed groups are attached to public resources or private-only resources
- Broad VPC CIDR rules where a source security group would be safer
- Security group to security group relationships for visual reporting
- Unused security groups
"""

from utils import (
    get_aws_client, create_finding,
    SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW,
    STATUS_PASS
)


DANGEROUS_PORTS = {
    22: {"name": "SSH", "severity": SEVERITY_HIGH, "desc": "SSH access"},
    3389: {"name": "RDP", "severity": SEVERITY_HIGH, "desc": "Remote Desktop access"},
    3306: {"name": "MySQL", "severity": SEVERITY_CRITICAL, "desc": "MySQL database"},
    5432: {"name": "PostgreSQL", "severity": SEVERITY_CRITICAL, "desc": "PostgreSQL database"},
    1433: {"name": "MSSQL", "severity": SEVERITY_CRITICAL, "desc": "Microsoft SQL Server"},
    27017: {"name": "MongoDB", "severity": SEVERITY_CRITICAL, "desc": "MongoDB database"},
}

WEB_PORTS = {
    80: {"name": "HTTP", "severity": SEVERITY_LOW},
    443: {"name": "HTTPS", "severity": SEVERITY_LOW},
}

OPEN_IPV4 = "0.0.0.0/0"
OPEN_IPV6 = "::/0"
OPEN_CIDRS = [OPEN_IPV4, OPEN_IPV6]


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
    Check all security groups for dangerous open ports and VPC-aware exposure.

    A rule is more severe when the security group is attached to resources that
    sit in public subnets and have public addresses. Private-only resources are
    still flagged, but as internal exposure instead of direct internet exposure.
    """
    findings = []

    try:
        context = _build_network_context(ec2_client)
        security_groups = context["security_groups"]
        sg_usage = context["sg_usage"]
        print(f"  Found {len(security_groups)} security groups to check")

        risky_rule_count = 0
        map_edges = []

        for sg in security_groups:
            sg_id = sg['GroupId']
            sg_name = sg.get('GroupName', 'unnamed')
            vpc_id = sg.get('VpcId', 'N/A')
            usage = sg_usage.get(sg_id, [])

            if not usage:
                findings.append(create_finding(
                    f"SG: {sg_id} ({sg_name})",
                    "EC2 - Security Groups",
                    f"Security group '{sg_name}' ({sg_id}) is not attached to any network interface",
                    SEVERITY_LOW,
                    f"Review and delete unused security group '{sg_id}' if it is no longer needed."
                ))

            for rule in sg.get('IpPermissions', []):
                rule_ports = _ports_for_rule(rule)
                public_sources = _public_sources(rule)
                broad_vpc_sources = _broad_vpc_sources(rule, context["vpc_cidrs"].get(vpc_id, []))
                referenced_groups = _referenced_groups(rule)

                for ref_sg in referenced_groups:
                    map_edges.append({
                        "source": ref_sg,
                        "target": sg_id,
                        "port": _format_port_range(rule),
                        "protocol": rule.get('IpProtocol', 'unknown'),
                        "risk": "reference"
                    })

                if public_sources:
                    if rule.get('IpProtocol') == '-1':
                        risky_rule_count += 1
                        severity = _severity_for_exposure(SEVERITY_CRITICAL, usage)
                        findings.append(_public_rule_finding(
                            sg_id, sg_name, vpc_id, "ALL traffic", "all ports",
                            severity, usage,
                            f"Restrict security group '{sg_id}' to specific ports and trusted sources. Prefer a source security group for internal service-to-service access."
                        ))
                        map_edges.append(_internet_edge(sg_id, "all", "ALL", severity, usage))
                        continue

                    for port, port_info in DANGEROUS_PORTS.items():
                        if _rule_allows_port(rule_ports, port):
                            risky_rule_count += 1
                            severity = _severity_for_exposure(port_info["severity"], usage)
                            findings.append(_public_rule_finding(
                                sg_id, sg_name, vpc_id, port_info["name"], f"port {port}",
                                severity, usage,
                                f"Restrict port {port} ({port_info['name']}) to a VPN, corporate IP range, bastion, or a specific source security group."
                            ))
                            map_edges.append(_internet_edge(sg_id, port, port_info["name"], severity, usage))

                    for port, port_info in WEB_PORTS.items():
                        if _rule_allows_port(rule_ports, port):
                            map_edges.append(_internet_edge(sg_id, port, port_info["name"], port_info["severity"], usage))

                if broad_vpc_sources:
                    for port, port_info in DANGEROUS_PORTS.items():
                        if _rule_allows_port(rule_ports, port):
                            risky_rule_count += 1
                            findings.append(create_finding(
                                f"SG: {sg_id} ({sg_name})",
                                "EC2 - Security Groups",
                                f"Security group '{sg_name}' ({sg_id}) allows {port_info['name']} (port {port}) from broad VPC CIDR {', '.join(broad_vpc_sources)}",
                                SEVERITY_MEDIUM,
                                f"Replace broad VPC CIDR access with a specific source security group for only the workloads that need {port_info['name']} access."
                            ))

        map_metadata = _build_map_metadata(security_groups, sg_usage, map_edges)
        findings.append(create_finding(
            "EC2 Security Group Map", "EC2 - Network Map",
            f"Mapped {len(security_groups)} security groups and {len(map_edges)} inbound relationships",
            SEVERITY_LOW,
            "Use the HTML report map to review public paths and security group to security group access.",
            status=STATUS_PASS,
            metadata={"network_map": map_metadata}
        ))

        if risky_rule_count == 0:
            findings.append(create_finding(
                "EC2 Security Groups", "EC2 - Security Groups",
                "No high-risk public or broad internal security group rules found",
                SEVERITY_HIGH,
                "Continue using least-privilege inbound rules and source security groups",
                status=STATUS_PASS
            ))
            print("    ✅ No high-risk security group rules found")
        else:
            print(f"    ❌ Found {risky_rule_count} risky security group rules")

    except Exception as e:
        print(f"  [ERROR] Failed to check security groups: {e}")
        findings.append(create_finding(
            "EC2 Security Groups", "EC2 - Security Groups",
            f"Failed to audit security groups: {str(e)}",
            SEVERITY_HIGH, "Check EC2 describe permissions"
        ))

    return findings


def _build_network_context(ec2_client):
    security_groups = _paginate(ec2_client, 'describe_security_groups', 'SecurityGroups')
    subnets = _paginate(ec2_client, 'describe_subnets', 'Subnets')
    route_tables = _paginate(ec2_client, 'describe_route_tables', 'RouteTables')
    network_interfaces = _paginate(ec2_client, 'describe_network_interfaces', 'NetworkInterfaces')
    vpcs = _paginate(ec2_client, 'describe_vpcs', 'Vpcs')

    subnet_public_map = _build_subnet_public_map(subnets, route_tables)
    vpc_cidrs = _build_vpc_cidr_map(vpcs)
    sg_usage = _build_security_group_usage(network_interfaces, subnet_public_map)

    return {
        "security_groups": security_groups,
        "subnet_public_map": subnet_public_map,
        "vpc_cidrs": vpc_cidrs,
        "sg_usage": sg_usage,
    }


def _paginate(client, operation_name, result_key):
    paginator = client.get_paginator(operation_name)
    results = []
    for page in paginator.paginate():
        results.extend(page.get(result_key, []))
    return results


def _build_vpc_cidr_map(vpcs):
    vpc_cidrs = {}
    for vpc in vpcs:
        cidrs = []
        if vpc.get('CidrBlock'):
            cidrs.append(vpc['CidrBlock'])
        for assoc in vpc.get('CidrBlockAssociationSet', []):
            cidr = assoc.get('CidrBlock')
            if cidr and cidr not in cidrs:
                cidrs.append(cidr)
        vpc_cidrs[vpc.get('VpcId')] = cidrs
    return vpc_cidrs


def _build_subnet_public_map(subnets, route_tables):
    subnet_to_vpc = {s['SubnetId']: s.get('VpcId') for s in subnets}
    subnet_public = {s['SubnetId']: False for s in subnets}
    main_tables = {}

    for table in route_tables:
        is_public = _route_table_has_igw(table)
        for assoc in table.get('Associations', []):
            if assoc.get('Main'):
                main_tables[table.get('VpcId')] = is_public
            subnet_id = assoc.get('SubnetId')
            if subnet_id:
                subnet_public[subnet_id] = is_public

    for subnet_id, vpc_id in subnet_to_vpc.items():
        if subnet_public.get(subnet_id) is False and vpc_id in main_tables:
            subnet_public[subnet_id] = main_tables[vpc_id]

    return subnet_public


def _route_table_has_igw(route_table):
    for route in route_table.get('Routes', []):
        gateway_id = route.get('GatewayId', '')
        destination = route.get('DestinationCidrBlock') or route.get('DestinationIpv6CidrBlock')
        if destination in OPEN_CIDRS and gateway_id.startswith('igw-'):
            return True
    return False


def _build_security_group_usage(network_interfaces, subnet_public_map):
    usage = {}
    for eni in network_interfaces:
        subnet_id = eni.get('SubnetId', 'N/A')
        is_public_subnet = subnet_public_map.get(subnet_id, False)
        has_public_ip = bool(eni.get('Association', {}).get('PublicIp'))
        resource_label = _resource_label_for_eni(eni)

        for group in eni.get('Groups', []):
            sg_id = group.get('GroupId')
            if not sg_id:
                continue
            usage.setdefault(sg_id, []).append({
                "resource": resource_label,
                "interface": eni.get('NetworkInterfaceId', 'N/A'),
                "subnet": subnet_id,
                "public_subnet": is_public_subnet,
                "public_ip": has_public_ip,
                "publicly_reachable": is_public_subnet and has_public_ip,
            })
    return usage


def _resource_label_for_eni(eni):
    description = eni.get('Description') or ''
    attachment = eni.get('Attachment', {})
    instance_id = attachment.get('InstanceId')
    interface_type = eni.get('InterfaceType', 'interface')

    if instance_id:
        return f"EC2 {instance_id}"
    if description:
        return description[:80]
    return f"{interface_type} {eni.get('NetworkInterfaceId', 'unknown')}"


def _ports_for_rule(rule):
    protocol = rule.get('IpProtocol', 'unknown')
    if protocol == '-1':
        return [("all", "all")]
    return [(rule.get('FromPort'), rule.get('ToPort'))]


def _format_port_range(rule):
    ports = _ports_for_rule(rule)[0]
    if ports == ("all", "all"):
        return "all"
    from_port, to_port = ports
    if from_port == to_port:
        return str(from_port)
    return f"{from_port}-{to_port}"


def _rule_allows_port(rule_ports, port):
    for from_port, to_port in rule_ports:
        if from_port == "all" or to_port == "all":
            return True
        if from_port is None or to_port is None:
            continue
        if from_port <= port <= to_port:
            return True
    return False


def _public_sources(rule):
    sources = []
    for ip_range in rule.get('IpRanges', []):
        cidr = ip_range.get('CidrIp', '')
        if cidr == OPEN_IPV4:
            sources.append(cidr)
    for ip_range in rule.get('Ipv6Ranges', []):
        cidr = ip_range.get('CidrIpv6', '')
        if cidr == OPEN_IPV6:
            sources.append(cidr)
    return sources


def _broad_vpc_sources(rule, vpc_cidrs):
    sources = []
    for ip_range in rule.get('IpRanges', []):
        cidr = ip_range.get('CidrIp', '')
        if cidr in vpc_cidrs:
            sources.append(cidr)
    return sources


def _referenced_groups(rule):
    groups = []
    for pair in rule.get('UserIdGroupPairs', []):
        group_id = pair.get('GroupId')
        if group_id:
            groups.append(group_id)
    return groups


def _severity_for_exposure(base_severity, usage):
    if _has_publicly_reachable_usage(usage):
        return base_severity
    if base_severity == SEVERITY_CRITICAL:
        return SEVERITY_HIGH
    if base_severity == SEVERITY_HIGH:
        return SEVERITY_MEDIUM
    return base_severity


def _has_publicly_reachable_usage(usage):
    return any(item.get("publicly_reachable") for item in usage)


def _public_rule_finding(sg_id, sg_name, vpc_id, service_name, port_label, severity, usage, recommendation):
    exposure = _exposure_label(usage)
    return create_finding(
        f"SG: {sg_id} ({sg_name})",
        "EC2 - Security Groups",
        f"Security group '{sg_name}' ({sg_id}) allows {service_name} ({port_label}) from the internet in VPC {vpc_id}. Exposure: {exposure}",
        severity,
        recommendation
    )


def _exposure_label(usage):
    if not usage:
        return "unused security group"
    if _has_publicly_reachable_usage(usage):
        return "attached to public subnet resources with public IPs"
    if any(item.get("public_subnet") for item in usage):
        return "attached in public subnets, but no public IP detected"
    return "attached only to private subnet resources"


def _internet_edge(sg_id, port, service_name, severity, usage):
    return {
        "source": "Internet",
        "target": sg_id,
        "port": str(port),
        "protocol": service_name,
        "risk": severity,
        "exposure": _exposure_label(usage)
    }


def _build_map_metadata(security_groups, sg_usage, map_edges):
    nodes = []
    for sg in security_groups:
        sg_id = sg.get('GroupId')
        usage = sg_usage.get(sg_id, [])
        resources = []
        for item in usage[:5]:
            resources.append({
                "name": item.get("resource", "unknown"),
                "subnet": item.get("subnet", "N/A"),
                "publicly_reachable": item.get("publicly_reachable", False),
            })
        nodes.append({
            "id": sg_id,
            "name": sg.get('GroupName', 'unnamed'),
            "vpc": sg.get('VpcId', 'N/A'),
            "used": bool(usage),
            "publicly_reachable": _has_publicly_reachable_usage(usage),
            "resources": resources,
        })

    return {
        "nodes": nodes,
        "edges": map_edges[:80],
    }
