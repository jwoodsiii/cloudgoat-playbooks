#!/usr/bin/env python3
"""
aws_iam_enumeration — CloudGoat attack playbook.

Basic IAM user permissions enumeration. Given an AKID, answers the question:
what can this user do? Maps managed/inline policies, group memberships, and
assumable roles to uncover five hidden flags.

Attack path:
  1. Attached policies (managed) — list managed policies; flag in description
  2. Inline policies — read inline policy documents; flag in document body
  3. Group permissions — discover group memberships; flag in group metadata
  4. Assumable roles — scan all roles for flag4 target; flag in role details
  5. Managed policy deep dive — pull versioned policy document; flag in JSON

Usage:
    python attack.py --start-file ./start.txt [--region us-east-1]
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from shared.auth import get_session
from shared.utils import load_start, step, info, finding, error, write_findings


def _contains_flag(s: str) -> bool:
    s_upper = s.upper()
    return "HSM{" in s_upper or "HSM-" in s_upper or "HSM_" in s_upper or "HSM" in s_upper

def main():
    parser = argparse.ArgumentParser(description="iam_enum_basics attack playbook")
    parser.add_argument("--start-file", default="./start.txt")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--role-arn", default=None,
                        help="Optional role ARN to assume before running")
    args = parser.parse_args()
    
    # start.txt for this scenario only contains AKID/secret
    # username is resolved via sts, keeping load_start() for consistency
    # cfg = load_start(args.start_file)
    session = get_session(role_arn=args.role_arn, region=args.region)
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    arn = identity["Arn"]
    username = arn.split("/")[-1]
    info(f"Running as: {arn}")
    iam = session.client("iam")
    findings = []

    # --- Step 1: Attached policies (managed) ---
    step("Attached policies (managed)")
    managed_policy_arn = None
    managed_policy_version = "v1"
    try:
        paginator = iam.get_paginator("list_attached_user_policies")
        attached = []
        for page in paginator.paginate(UserName=username):
            attached.extend(page["AttachedPolicies"])

        info(f"Found {len(attached)} attached managed policy/policies")
        for policy in attached:
            info(f"Policy: {policy['PolicyName']}  ARN: {policy['PolicyArn']}")
            try:
                detail = iam.get_policy(PolicyArn=policy["PolicyArn"])["Policy"]
                desc = detail.get("Description", "")
                path = detail.get("Path", "")
                info(f"  Description: {desc!r}  Path: {path!r}")
                for field_name, field_val in [("description", desc), ("path", path)]:
                    if _contains_flag(field_val):
                        finding(f"Flag1 in policy {field_name}: {field_val}")
                        findings.append({
                            "title": "Attached managed policy — metadata field",
                            "detail": f"Policy {field_name} field contains flag: {field_val}",
                            "resource": policy["PolicyArn"],
                            "severity": "low",
                        })
                if not policy["PolicyArn"].startswith("arn:aws:iam::aws:"):        
                    managed_policy_arn = policy["PolicyArn"]
                    managed_policy_version = detail.get("DefaultVersionId", "v1")
            except Exception as e:
                error(f"get_policy({policy['PolicyArn']}) failed: {e}")
    except Exception as e:
        error(f"list_attached_user_policies failed: {e}", fatal=True)

    # --- Step 2: Inline policies ---
    step("Inline policies")
    try:
        policy_names = iam.list_user_policies(UserName=username)["PolicyNames"]
        info(f"Found {len(policy_names)} inline policy/policies: {policy_names}")
        for name in policy_names:
            try:
                doc = iam.get_user_policy(UserName=username, PolicyName=name)["PolicyDocument"]
                doc_str = json.dumps(doc)
                info(f"  {name}: {doc_str[:300]}")
                if _contains_flag(doc_str):
                    finding(f"Flag2 in inline policy document ({name}): {doc_str}")
                    findings.append({
                        "title": "Inline policy — policy document",
                        "detail": f"Inline policy document for {name} contains a flag",
                        "resource": f"user/{username}/policy/{name}",
                        "severity": "low",
                    })
            except Exception as e:
                error(f"get_user_policy({name}) failed: {e}")
    except Exception as e:
        error(f"list_user_policies failed: {e}")

    # --- Step 3: Group permissions ---
    step("Group permissions")
    try:
        paginator = iam.get_paginator("list_groups_for_user")
        groups = []
        for page in paginator.paginate(UserName=username):
            groups.extend(page["Groups"])

        info(f"Found {len(groups)} group(s)")
        for group in groups:
            gname = group["GroupName"]
            gpath = group.get("Path", "")
            info(f"  Group: {gname}  Path: {gpath!r}  ARN: {group['Arn']}")
            for field_name, field_val in [("name", gname), ("path", gpath)]:
                if _contains_flag(field_val):
                    finding(f"Flag3 in group {field_name}: {field_val}")
                    findings.append({
                        "title": "Group membership — group metadata",
                        "detail": f"Group {field_name} field contains flag: {field_val}",
                        "resource": group["Arn"],
                        "severity": "low",
                    })
            try:
                inline = iam.list_group_policies(GroupName=gname)["PolicyNames"]
                attached_gp = iam.list_attached_group_policies(GroupName=gname)["AttachedPolicies"]
                info(f"  Group inline policies: {inline}")
                info(f"  Group attached policies: {[p['PolicyName'] for p in attached_gp]}")
            except Exception as e:
                error(f"Group policy enumeration for {gname} failed: {e}")
    except Exception as e:
        error(f"list_groups_for_user failed: {e}")

    # --- Step 4: Assumable roles ---
    step("Assumable roles")
    try:
        paginator = iam.get_paginator("list_roles")
        roles = []
        for page in paginator.paginate():
            roles.extend(page["Roles"])

        info(f"Total roles in account: {len(roles)}")
        for role in roles:
            rname = role["RoleName"]
            info(f"Target role: {rname} ARN: {role['Arn']}")
            role_detail = iam.get_role(RoleName=rname)["Role"]
            try:
                role_detail = iam.get_role(RoleName=rname)["Role"]
                tags_resp = iam.list_role_tags(RoleName=rname)
                for tag in tags_resp["Tags"]:
                    tag_str = f"{tag['Key']}={tag['Value']}"
                    info(f"  Tag: {tag_str}")
                    if _contains_flag(tag_str):
                        finding(f"Flag4 in role tag: {tag_str}")
                        findings.append({
                            "title": "Assumable role — role tag",
                            "detail": f"Role tag contains flag: {tag_str}",
                            "resource": role_detail["Arn"],
                            "severity": "low",
                        })
            except Exception as e:
                error(f"list_role_tags({rname}) failed: {e}")
    except Exception as e:
        error(f"list_roles failed: {e}")

    # --- Step 5: Managed policy deep dive ---
    step("Managed policy deep dive (versioned document)")
    if not managed_policy_arn:
        error("No managed policy ARN from step 1 — skipping", fatal=False)
    else:
        try:
            doc = iam.get_policy_version(
                PolicyArn=managed_policy_arn,
                VersionId=managed_policy_version,
            )["PolicyVersion"]["Document"]
            doc_str = json.dumps(doc, indent=2)
            info(f"Policy version {managed_policy_version} document:\n{doc_str}")

            # Walk each Statement and check every Resource value individually —
            # flags are often embedded in Resource ARNs, not the top-level keys.
            for stmt in doc.get("Statement", []):
                resources = stmt.get("Resource", [])
                if isinstance(resources, str):
                    resources = [resources]
                for resource in resources:
                    if _contains_flag(resource):
                        finding(f"Flag5 in policy Resource field: {resource}")
                        findings.append({
                            "title": "Managed policy version — Resource field",
                            "detail": f"Policy v{managed_policy_version} Resource contains flag: {resource}",
                            "resource": managed_policy_arn,
                            "severity": "low",
                        })
        except Exception as e:
            error(f"get_policy_version failed: {e}")

    write_findings(findings, scenario="iam_enum_basics", path="findings.json")


if __name__ == "__main__":
    main()
