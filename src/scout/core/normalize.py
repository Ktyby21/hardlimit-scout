from __future__ import annotations
from dataclasses import dataclass
from typing import Any, List, Iterable, Optional

@dataclass
class NormalizedFinding:
    check: str
    fid: str
    title: str
    current: int
    maximum: int
    percent: float

def normalize_findings( check: str, findings: Iterable[Any]) -> List[NormalizedFinding]:
    out: List[NormalizedFinding] =[]
    for f in findings:
        # IAM inline roles
        if hasattr(f, "role_name") and hasattr(f, "policy_name") and hasattr(f, "chars"):
            fid = f"iam-inline-role:{f.role_name}:{f.policy_name}"
            out.append(NormalizedFinding(
                check=check,
                fid=fid,
                title=f"{f.role_name}/{f.policy_name}",
                current=int(f.chars),
                maximum=int(getattr(f,"max_chars", 0) or 0),
                percent=float(getattr(f, "percent_used", 0.0) or 0.0),
            ))
            continue

        # S3 bucket policy
        if hasattr(f, "bucket") and hasattr(f, "policy_bytes"):
            fid = f"s3-bucket-policy:{f.bucket}"
            out.append(NormalizedFinding(
                check=check,
                fid=fid,
                title=f.bucket,
                current=int(f.policy_bytes),
                maximum=int(getattr(f , "max_bytes", 0) or 0),
                percent=float(getattr(f, "percent_used", 0.0) or 0.0),
            ))
            continue

        # EC2 launch template user-data
        if hasattr(f, "template_id") and hasattr(f, "user_data_bytes"):
            fid = f"ec2-lt-userdata:{f.template_id}:{getattr(f, 'version', '')}"
            out.append(NormalizedFinding(
                check=check,
                fid=fid,
                title=f"{f.template_name} (v{f.version})",
                current=int(f.user_data_bytes),
                maximum=int(getattr(f, "max_bytes", 0) or 0),
                percent=float(getattr(f, "percent_used", 0.0) or 0.0),
            ))
        # ORGS SCP
            continue

        if hasattr(f, "policy_id") and hasattr(f, "chars") and hasattr(f, "policy_name"):
            fid = f"orgs-scp:{f.policy_id}"
            out.append(NormalizedFinding(
                check=check,
                fid=fid,
                title=f.policy_name,
                current=int(f.chars),
                maximum=int(getattr(f, "max_chars", 0) or 0),
                percent=float(getattr(f, "percent_used", 0.0) or 0.0),
            ))
            continue
        
        # IAM managed policy
        if hasattr(f, "policy_arn") and hasattr(f, "chars") and hasattr(f, "policy_name"):
            fid = f"iam-managed:{f.policy_arn}"
            out.append(NormalizedFinding(
                check=check,
                fid=fid,
                title=f.policy_name,
                current=int(f.chars),
                maximum=int(getattr(f, "max_chars", 0) or 0),
                percent=float(getattr(f, "percent_used", 0.0) or 0.0),
            ))
            continue
        continue
    return out
