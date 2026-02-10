from __future__ import annotations
from typing import List,Any
from boto3.session import Session
import base64
from dataclasses import dataclass
from datetime import datetime,timezone

EC2_USERDATA_MAX_BYTES = 16 * 1024 # 16 KB

@dataclass
class Ec2LaunchTemplateUserdataFinding:
    template_id: str
    template_name: str
    version: str
    user_data_bytes: int
    max_bytes: int
    percent_used: float
    collected_at: datetime

def _percent(used: int, maxv: int) -> float:
    if maxv <= 0:
        return 0.0
    return round((used/maxv) * 100.00, 2)

def _decode_user_data(user_data_b64:str) -> bytes:
    # AWS returning base64, sometimes without padding - let's protect ourselves from this
    s = user_data_b64.strip()
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    return base64.b64decode(s.encode("utf-8"))

def scan_ec2_launch_template_userdata_sizes(session:Session) -> List[Ec2LaunchTemplateUserdataFinding]:
    """
    Scan EC2 Launch Templates and count user-data size AFTER base64 decode (bytes).
    Uses DefaultVersionNumber of each Lauch Template.
    """
    ec2 = session.client("ec2")
    now = datetime.now(timezone.utc)
    findings: List[Ec2LaunchTemplateUserdataFinding] = []

    paginator = ec2.get_paginator("describe_launch_templates")
    for page in paginator.paginate():
        for lt in page.get("LaunchTemplates", []):
            lt_id = lt["LaunchTemplateId"]
            lt_name = lt.get("LaunchTemplateName", lt_id)
            default_ver = str(lt.get("DefaultVersionNumber", "1"))

            # Using the default version (usually used most often)
            resp = ec2.describe_launch_templates_versions(
                LaunchTemplateId = lt_id,
                Versions = [default_ver],
            )

            vers = resp.get("LaunchTemplateVersions", [])

            if not vers:
                continue

            v = vers[0]
            data = v.get("LaunchTemplateData", {})
            user_data_b64 = data.get("UserData")

            if not user_data_b64:
                continue

            raw = _decode_user_data(user_data_b64)
            size = len(raw)

            findings.append(
                Ec2LaunchTemplateUserdataFinding(
                    template_id=lt_id,
                    template_name=lt_name,
                    version=default_ver,
                    user_data_bytes=size,
                    max_bytes=EC2_USERDATA_MAX_BYTES,
                    percent_used=_percent(size,EC2_USERDATA_MAX_BYTES),
                    collected_at=now
                )
            )
    findings.sort(key=lambda x: x.percent_used, reverse=True)

    return findings

