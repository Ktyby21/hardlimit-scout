from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List
import json
import urllib.parse

from boto3.session import Session

# Inline policy limit varies by entity; for roles it's commonly 10, 240 characters ( check AWS docs) 
# For MVP taking fact size as 10240 (without max)

ROLE_INLINE_POLICY_MAX_CHARS = 10240
@dataclass
class IamRoleInlinePolicyFinding:
    role_name: str
    policy_name: str
    chars: int
    max_chars: int
    percent_used: float
    collected_at: datetime

def _percent(used:int, maxv:int) -> float:
    if maxv <= 0 :
        return 0.0
    return round((used / maxv) * 100.0, 2)

def scan_iam_role_inline_policy_sizes(session: Session, max_roles : int = 300) -> List[IamRoleInlinePolicyFinding]:
    """
    Scan inline policies at IAM Roles.
    max_roles - border, to awoiding very large lists at Big accounts(not MVP)
    """
    iam = session.client("iam")
    now = datetime.now(timezone.utc)

    findings: List[IamRoleInlinePolicyFinding] = []

    paginator = iam.get_paginator("list_roles")
    seen_roles = 0

    for page in paginator.paginate():
        for role in page.get("Roles", []):
            role_name = role["RoleName"]
            # if role_name.startswith("HardlimitScout-"):
            #     continue
            seen_roles += 1
            if seen_roles > max_roles:
                return sorted(findings, key=lambda x: x.percent_used, reverse=True)
            
            # list of inline policies for roles
            pols = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])
            for policy_name in pols:
                resp = iam.get_role_policy(RoleName=role_name,PolicyName=policy_name)
                doc = resp["PolicyDocument"]

                # PolicyDocument usualy dict; normalizing to compact string and counting characters
                if isinstance(doc, str):
                    decoded = urllib.parse.unquote(doc)
                    try:
                        obj = json.loads(decoded)
                        json_str = json.dumps(obj, separators=(",", ":"), ensure_ascii=False)
                    except Exception:
                        json_str = decoded
                else:
                    json_str = json.dumps(doc, separators=(",", ":"), ensure_ascii=False)

                chars = len(json_str)

                findings.append(
                    IamRoleInlinePolicyFinding(
                        role_name=role_name,
                        policy_name=policy_name,
                        chars=chars,
                        max_chars=ROLE_INLINE_POLICY_MAX_CHARS,
                        percent_used=_percent(chars, ROLE_INLINE_POLICY_MAX_CHARS),
                        collected_at=now,
                    )
                )
    findings.sort(key=lambda x: x.percent_used, reverse=True)
    return findings