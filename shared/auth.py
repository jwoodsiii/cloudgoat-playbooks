"""
auth.py — boto3 session factory with STS assume-role support.

Usage:
    from shared.auth import get_session

    # From environment (pre-assumed creds)
    session = get_session()

    # From explicit assume-role
    session = get_session(role_arn="arn:aws:iam::123456789012:role/target-role")

    # With a named profile as the source identity
    session = get_session(
        role_arn="arn:aws:iam::123456789012:role/target-role",
        profile="boot"
    )
"""

import boto3
from botocore.exceptions import ClientError


def get_session(
    role_arn: str | None = None,
    profile: str | None = None,
    region: str = "us-east-1",
    session_name: str = "cloudgoat-playbook",
    aws_access_key_id=None,
    aws_secret_access_key=None,
) -> boto3.Session:
    """
    Returns a boto3 Session.

    If role_arn is provided, assumes that role via STS and returns a session
    using the resulting short-lived credentials. The source identity for the
    assume-role call is either the named profile or ambient env credentials.

    If role_arn is None, returns a session using ambient credentials (env vars,
    ~/.aws/credentials, or instance profile) — useful when you've already
    pre-assumed a role via assume-aws in your shell.

    Args:
        role_arn:     ARN of the role to assume. None = use ambient creds.
        profile:      AWS credentials profile to use as the source identity.
        region:       AWS region for the session.
        session_name: RoleSessionName passed to STS — appears in CloudTrail.

    Returns:
        boto3.Session with credentials scoped to the target role (or ambient).

    Raises:
        RuntimeError: if STS assume-role fails.
    """

    if aws_access_key_id and aws_secret_access_key:
        return boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=region,
            )

    if role_arn is None:
        return boto3.Session(profile_name=profile, region_name=region)

    # Use profile as source identity if provided, otherwise ambient creds
    source_session = boto3.Session(profile_name=profile, region_name=region)
    sts = source_session.client("sts")

    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=session_name,
        )
    except ClientError as e:
        raise RuntimeError(
            f"Failed to assume role {role_arn}: {e.response['Error']['Message']}"
        ) from e

    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
