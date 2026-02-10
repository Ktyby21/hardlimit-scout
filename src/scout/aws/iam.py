from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime,timezone
from typing import List

import urllib.parse
import json

from boto3.session import Session

#AWS LIMIT: IAM managed policy document  = 6144 characters (not bytes)
I_AM_MANAGED_POLICY_MAX_CHARS = 6144

@dataclass
class IamManagedPolicyFinding:
    policy_arn: str
    policy_name: str
    chars: int
    max_chars: int
    percent_used: float
    collected_at: datetime

def _percent (used:int, maxv:int) -> float:
    if maxv <= 0:
        return 0.0
    return round((used/ maxv) * 100.00, 2)

def _to_compact_json_str(doc) -> str:
    """
    Normalize policy document into a compact JSON string and count characters.
    AWS sometimes returns dict, sometimes URL-encoded JSON string.
    """
    if isinstance(doc, str):
        decoded = urllib.parse.unquote(doc)
        try:
            obj = json.loads(decoded)
            return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
        except Exception:
            return decoded
    else:
        return json.dumps(doc, separators=(",", ":"), ensure_ascii=False)

def scan_iam_managed_policy_sizes(session: Session) -> List[IamManagedPolicyFinding]:
    """
    Scan customer managed policies (Scope = Local) and count policy size in characters.
    """
    iam = session.client("iam")
    now = datetime.now(timezone.utc)

    findings: List[IamManagedPolicyFinding] = []

    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope = "Local"):
        for p in page.get("Policies", []):
            policy_arn = p["Arn"]
            policy_name = p["PolicyName"]

            meta = iam.get_policy(PolicyArn=policy_arn)["Policy"]
            ver_id = meta["DefaultVersionId"]

            ver = iam.get_policy_version(PolicyArn=policy_arn, VersionId=ver_id)["PolicyVersion"]
            doc = ver["Document"]

            json_str = _to_compact_json_str(doc)
            chars = len(json_str)

            findings.append(
                IamManagedPolicyFinding(
                    policy_arn=policy_arn,
                    policy_name=policy_name,
                    chars=chars,
                    max_chars=I_AM_MANAGED_POLICY_MAX_CHARS,
                    percent_used=_percent(chars, I_AM_MANAGED_POLICY_MAX_CHARS),
                    collected_at= now,
                )
            )
    findings.sort(key=lambda x: x.percent_used, reverse=True)
    return findings