from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime,timezone
from typing import List
from boto3.session import Session

SCP_MAX_CHARS = 5120 # Limit SCP by chars 

@dataclass
class OrgsScpFinding:
    policy_id: str
    policy_name: str
    chars: int
    max_chars: int
    percent_used: float
    collected_at: datetime

def _percent(used: int, maxv: int) -> float:
    if maxv <= 0:
        return 0.0
    return round((used / maxv) * 100.00 , 2)

def scan_orgs_scp_sizes(session: Session) -> List[OrgsScpFinding]:
    """
    Scan AWS Organizations SCPs and count size of Policy.Content in characters.
    If Organizations is not enabled / missing petmissions - caller handles ClientError.
    """
    orgs = session.client("organizations")
    now = datetime.now(timezone.utc)

    findings: List[OrgsScpFinding] = []

    paginator = orgs.get_paginator("list_policies")
    for page in paginator.paginate(Filter="SERVICE_CONTROL_POLICY"):
        for p in page.get("Policies", []):
            policy_id = p["Id"]
            policy_name = p["Name"]

            desc = orgs.describe_policy(PolicyId=policy_id)["Policy"]
            content = desc["Content"]
            chars = len(content)

            findings.append(
                OrgsScpFinding(
                    policy_id=policy_id,
                    policy_name=policy_name,
                    chars=chars,
                    max_chars=SCP_MAX_CHARS,
                    percent_used=_percent(chars, SCP_MAX_CHARS),
                    collected_at=now,
                )
            )
    findings.sort(key=lambda x: x.percent_used, reverse= True)
    return findings