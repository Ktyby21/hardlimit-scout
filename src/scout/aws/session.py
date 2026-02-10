from __future__ import annotations

import os
import boto3
from scout.config import get_aws_profile, get_aws_region

def _is_lambda() -> bool:
    return bool(os.getenv("AWS_LAMBDA_FUNCTION_NAME"))

def base_session() -> boto3.Session:
    """
    Base boto3 session:
    - In Lambda: uses execution role
    - Locally: uses AWS_PROFILE (default: 'default')
    """
    region = get_aws_region()
    if _is_lambda():
        return boto3.Session(region_name=region)

    profile = get_aws_profile()
    return boto3.Session(profile_name=profile, region_name=region)

def scanner_session() -> boto3.Session:
    """
    Customer-hosted core:
    scan ONLY current account using the same session as the runtime.
    """
    return base_session()

# Backward compatible alias (so old imports won't break immediately)
def assume_scanner_role() -> boto3.Session:
    return scanner_session()
