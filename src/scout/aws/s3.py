from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

import botocore
import os
from boto3.session import Session

S3_BUCKET_POLICY_MAX_BYTES = 20 * 1024 # 20 KB limit bucket policy

@dataclass
class S3BucketPolicyFinding:
    bucket: str
    policy_bytes: int
    max_bytes: int
    percent_used: float
    collected_at: datetime

def _percent(used:int, maxv: int) -> float:
    if maxv <= 0:
        return 0.0
    return round((used / maxv) * 100.0, 2)

def scan_s3_bucket_policies(session: Session) -> List[S3BucketPolicyFinding]:
    """ 
    Scan S3 buckets policies sizes.
    Restricted mode:
        if env S3_BUCKETS is set (comma-separated), we DO NOT call ListBuckets.
        we only scan listed buckets, so ListAllMyBuckets permission is not requared.
    """
    s3 = session.client("s3")
    out: List[S3BucketPolicyFinding] = []

    raw = (os.getenv("S3_BUCKETS", "") or "").strip()
    now = datetime.now(timezone.utc)

    if raw:
        bucket_names = [x.strip() for x in raw.split(",") if x.strip()]
    else:
        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("AccessDenied","AccessDeniedException"):
                raise
            raise
        bucket_names = [b["Name"] for b in buckets]


    for name in bucket_names:
        try:
            resp = s3.get_bucket_policy(Bucket = name)
            policy_str: str = resp["Policy"]
            size = len(policy_str.encode("utf-8"))
            out.append(
                S3BucketPolicyFinding(
                    bucket=name,
                    policy_bytes=size,
                    max_bytes=S3_BUCKET_POLICY_MAX_BYTES,
                    percent_used=_percent(size,S3_BUCKET_POLICY_MAX_BYTES),
                    collected_at=now,
                )
            )
        except botocore.exceptions.ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code in ("NoSuchBucketPolicy", "NoSuchPolicy", "NoSuchBucketPolicyException"):
                continue
            if raw and code in ("AccessDenied", "AccessDeniedException"):
                continue
            raise
    
    out.sort(key=lambda x: x.percent_used, reverse= True)
    return out
