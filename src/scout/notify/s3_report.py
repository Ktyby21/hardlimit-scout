from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any,Dict

import boto3

def write_report_json(
    session: boto3.Session,
    bucket: str,
    prefix: str,
    account_id: str,
    report: Dict[str, Any],
) -> Dict[str, str]:
    """
    Writes: 
        - {prefix}/{account_id}/{timestamp}.json
        - {prefix}/{account_id}/latest.json
        Returns keys: {"timestamp_key": "...", "latest_key": "..."}
    """
    s3 = session.client("s3")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    prefix = (prefix or "").lstrip("/")
    if prefix and not prefix.endswith("/"):
        prefix += "/"

    key = f"{prefix}{account_id}/{ts}.json"
    latest_key = f"{prefix}{account_id}/latest.json"
    body = json.dumps(report, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")

    for k in (key, latest_key):
        s3.put_object(
            Bucket=bucket,
            Key=k,
            Body=body,
            ContentType="application/json; charset=utf-8"
        )
    return {"timestamp_key": key, "latest_key":latest_key}