# CLI to boto3 Reference

Common AWS CLI → boto3 mappings for CloudGoat attack playbooks.
Add new entries here as new scenarios introduce new API calls.

## IAM

| AWS CLI | boto3 |
|---|---|
| `aws iam list-attached-user-policies --user-name X` | `iam.list_attached_user_policies(UserName=X)` → `resp["AttachedPolicies"]` |
| `aws iam list-user-policies --user-name X` | `iam.list_user_policies(UserName=X)` → `resp["PolicyNames"]` |
| `aws iam get-user-policy --user-name X --policy-name Y` | `iam.get_user_policy(UserName=X, PolicyName=Y)` → `resp["PolicyDocument"]` |
| `aws iam get-policy --policy-arn ARN` | `iam.get_policy(PolicyArn=ARN)` → `resp["Policy"]` |
| `aws iam get-policy-version --policy-arn ARN --version-id VID` | `iam.get_policy_version(PolicyArn=ARN, VersionId=VID)` → `resp["PolicyVersion"]["Document"]` |
| `aws iam list-groups-for-user --user-name X` | `iam.list_groups_for_user(UserName=X)` → `resp["Groups"]` |
| `aws iam list-group-policies --group-name X` | `iam.list_group_policies(GroupName=X)` → `resp["PolicyNames"]` |
| `aws iam list-attached-group-policies --group-name X` | `iam.list_attached_group_policies(GroupName=X)` → `resp["AttachedPolicies"]` |
| `aws iam list-roles` | `iam.list_roles()` → `resp["Roles"]` (paginate with `get_paginator("list_roles")`) |
| `aws iam get-role --role-name X` | `iam.get_role(RoleName=X)` → `resp["Role"]` |
| `aws iam list-role-policies --role-name X` | `iam.list_role_policies(RoleName=X)` → `resp["PolicyNames"]` |
| `aws iam get-role-policy --role-name X --policy-name Y` | `iam.get_role_policy(RoleName=X, PolicyName=Y)` → `resp["PolicyDocument"]` |
| `aws iam list-users` | `iam.list_users()` → `resp["Users"]` (paginate) |
| `aws iam get-user --user-name X` | `iam.get_user(UserName=X)` → `resp["User"]` |
| `aws iam list-user-tags --user-name X` | `iam.list_user_tags(UserName=X)` → `resp["Tags"]` |
| `aws iam list-role-tags --role-name X` | `iam.list_role_tags(RoleName=X)` → `resp["Tags"]` |

## STS

| AWS CLI | boto3 |
|---|---|
| `aws sts get-caller-identity` | `sts.get_caller_identity()` → `resp["UserId"]`, `resp["Account"]`, `resp["Arn"]` |
| `aws sts assume-role --role-arn ARN --role-session-name NAME` | `sts.assume_role(RoleArn=ARN, RoleSessionName=NAME)` → `resp["Credentials"]` |

## EC2

| AWS CLI | boto3 |
|---|---|
| `aws ec2 describe-instances` | `ec2.describe_instances()` → `resp["Reservations"]` |
| `aws ec2 describe-instances --instance-ids ID` | `ec2.describe_instances(InstanceIds=[ID])` |
| `aws ec2 describe-security-groups` | `ec2.describe_security_groups()` → `resp["SecurityGroups"]` |
| `aws ec2 describe-iam-instance-profile-associations` | `ec2.describe_iam_instance_profile_associations()` → `resp["IamInstanceProfileAssociations"]` |

## S3

| AWS CLI | boto3 |
|---|---|
| `aws s3 ls` | `s3.list_buckets()` → `resp["Buckets"]` |
| `aws s3 ls s3://BUCKET` | `s3.list_objects_v2(Bucket=BUCKET)` → `resp["Contents"]` |
| `aws s3 cp s3://BUCKET/KEY ./local` | `s3.download_file(BUCKET, KEY, local_path)` |
| `aws s3api get-bucket-policy --bucket BUCKET` | `s3.get_bucket_policy(Bucket=BUCKET)` → `resp["Policy"]` |

## Pagination pattern

For any list call that may return >100 results, use a paginator:

```python
paginator = iam.get_paginator("list_roles")
roles = []
for page in paginator.paginate():
    roles.extend(page["Roles"])
```

Paginatable IAM calls: `list_roles`, `list_users`, `list_policies`,
`list_attached_user_policies`, `list_groups_for_user`.
