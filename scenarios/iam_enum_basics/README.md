# aws_iam_enumeration

## Summary

Basic IAM user permissions enumeration. Given an AKID, answers the question: what can this user do? Maps managed/inline policies, group memberships, and assumable roles to uncover five hidden flags.

## Misconfiguration

The scenario grants the starting user broad IAM read permissions (`iam:Get*` / `iam:List*`), allowing full enumeration of policies, groups, and roles across the account. Flags are embedded in policy descriptions, inline policy documents, group metadata, role trust policies, and versioned policy documents — all accessible to any principal with read-only IAM access.

## Attack Path

### Step 1: Attached policies (managed)

An IAM user's managed policy list reveals attached policy names and ARNs. Calling `get-policy` exposes the policy metadata object, including the `Description` field where the first flag is stored.

**AWS CLI:**
```
aws iam list-attached-user-policies --user-name <username>
aws iam get-policy --policy-arn <policy-arn>
```
**boto3:** `iam.list_attached_user_policies(UserName=username)` → `iam.get_policy(PolicyArn=arn)["Policy"]["Description"]`

**Flag:** `HSM{m4n4g3d_p0l1cy_m4st3r}`

---

### Step 2: Inline policies

Users can have policies attached directly to them (not via a managed policy). Listing then retrieving the inline policy document reveals the second flag embedded in the policy JSON body.

**AWS CLI:**
```
aws iam list-user-policies --user-name <username>
aws iam get-user-policy --user-name <username> --policy-name <name>
```
**boto3:** `iam.list_user_policies(UserName=username)` → `iam.get_user_policy(UserName=username, PolicyName=name)["PolicyDocument"]`

**Flag:** `HSM1nl1n3p0l1cyd1sc0v3r3d`

---

### Step 3: Group permissions

IAM users inherit all permissions from every group they belong to. Listing group memberships reveals the user is in a group whose name or path encodes the third flag.

**AWS CLI:**
```
aws iam list-groups-for-user --user-name <username>
```
**boto3:** `iam.list_groups_for_user(UserName=username)["Groups"]`

**Flag:** `HSM_gr0up_m3mb3rsh1p_f0und`

---

### Step 4: Assumable roles

Listing all roles in the account and filtering for `cg-flag4` reveals a role whose tags contain the fourth flag.

**AWS CLI:**
```
aws iam list-roles
aws iam get-role --role-name cg-flag4-role-<cgid>
```
**boto3:** `iam.get_paginator("list_roles")` → `iam.list_role_tags(RoleName=name)["Tags"]`


**Flag:** `HSM-r0l3_trus1_f0und`

---

### Step 5: Managed policy deep dive

Managed policies are versioned — `get-policy` returns only metadata. Fetching the actual versioned document via `get-policy-version` exposes the full JSON permission statement, which contains the fifth flag.

**AWS CLI:**
```
aws iam get-policy-version --policy-arn <arn> --version-id v1
```
**boto3:** `iam.get_policy_version(...)["PolicyVersion"]["Document"]["Statement"][0]["Resource"]`

**Flag:** `HSM{s3cr3t_js0n_str1ng}`

---

## What Detection Would Look Like

This attack generates a tight sequence of read-only IAM CloudTrail events under `iam.amazonaws.com`: `ListAttachedUserPolicies`, `GetPolicy`, `ListUserPolicies`, `GetUserPolicy`, `ListGroupsForUser`, `ListGroupPolicies`, `ListAttachedGroupPolicies`, `ListRoles`, `GetRole`, and `GetPolicyVersion` — all issued by the same principal within seconds. A detection rule would key on a single principal issuing five or more distinct IAM enumeration calls in a short window. High-fidelity signal: `GetPolicyVersion` called by a non-CI identity is rare in normal operations and almost always indicates reconnaissance.

## References

- [CloudGoat scenario](https://github.com/RhinoSecurityLabs/cloudGoat)
