"""What the fixture report's Findings look like from outside: the tuples tests compare."""

from __future__ import annotations


def observed(finding: dict[str, object]) -> tuple[object, ...]:
    return (
        finding["severity"],
        finding["rule_id"],
        finding["file"],
        finding["line"],
        finding["resource_type"],
        finding["resource_name"],
    )


PUBLIC_BUCKET = (
    "critical",
    "iac/0d0b5a6e-7f9c-4a1e-9b3f-2c6d8e1f4a70",
    "main.tf",
    12,
    "aws_s3_bucket",
    "public_assets",
)
UNENCRYPTED_PUBLIC_BUCKET = (
    "high",
    "iac/3f2a9c51-8b4d-4c7e-a1f6-5e9d0b2c7a84",
    "main.tf",
    12,
    "aws_s3_bucket",
    "public_assets",
)
UNENCRYPTED_LOGS_BUCKET = (
    "high",
    "iac/3f2a9c51-8b4d-4c7e-a1f6-5e9d0b2c7a84",
    "logging.tf",
    4,
    "aws_s3_bucket",
    "logs",
)
HARDCODED_ACCESS_KEY = ("high", "secret/AWS Access Key ID", "variables.tf", 7, None, None)
PUBLIC_ACCESS_BLOCK_POLICY = ("high", "policy/pv-s3-public-access-block", None, None, None, None)
LOGS_BUCKET_WITHOUT_LOGGING = (
    "medium",
    "iac/9c7e2b14-6a3f-4d58-b2e9-1f0a4c8d6e35",
    "logging.tf",
    4,
    "aws_s3_bucket",
    "logs",
)
UNTAGGED_PUBLIC_BUCKET = (
    "informational",
    "iac/b4d81e6f-2c9a-4f03-8e57-7a1b3c5d9f26",
    "main.tf",
    12,
    "aws_s3_bucket",
    "public_assets",
)
