import os
try:
    from dotenv import load_dotenv  # type: ignore
except Exception:
    load_dotenv = None

def load_env() -> None:
    """
    local load .env. In lambda do nothing.
    """
    if load_dotenv is not None:
        load_dotenv()

def get_aws_profile() -> str:
    return os.getenv("AWS_PROFILE", "default")

def get_aws_region() -> str:
    return os.getenv("AWS_REGION", "us-east-1")

def get_scanner_role_arn() -> str:
    return os.getenv("SCANNER_ROLE_ARN")

def get_scanner_external_id() -> str:
    return os.getenv("SCANNER_EXTERNAL_ID")