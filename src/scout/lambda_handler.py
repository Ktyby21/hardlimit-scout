from __future__ import annotations

import os

from scout.aws.session import base_session
from scout.core.modules import run_module
from scout.core.normalize import normalize_findings
from scout.core.thresholds import compute_alerts, load_thresholds_from_env
from scout.notify.slack import send_slack
from scout.storage.dynamodb_state import DynamoDbStateStore
from scout.aws.iam import scan_iam_managed_policy_sizes
from scout.aws.iam_inline import scan_iam_role_inline_policy_sizes
from scout.aws.orgs import scan_orgs_scp_sizes
from scout.aws.ec2 import scan_ec2_launch_template_userdata_sizes
from scout.aws.s3 import scan_s3_bucket_policies
from scout.core.severity import severity_for_percent, severity_rank


def handler(event, context):
    # 1) base session = Lambda execution role (for DynamoDB/Slack)
    base = base_session()

    base_account_id = base.client("sts").get_caller_identity()["Account"]

    table_name = os.environ["STATE_TABLE"]
    store = DynamoDbStateStore(base, table_name)


    thresholds = load_thresholds_from_env()
    max_roles = int(os.getenv("MAX_ROLES", "300"))
    webhook = os.getenv("SLACK_WEBHOOK_URL", "").strip()

    channels = {c.strip().lower() for c in os.getenv("NOTIFY_CHANNELS", "s3,slack").split(",") if c.strip()}
    report_bucket = os.getenv("REPORT_BUCKET", "").strip()
    report_prefix = os.getenv("REPORT_PREFIX", "").strip()

    # 2) scanner session = assume ScannerRole (or scans)
    scanner = base
    target_account_id = base_account_id

    results = []
    results.append(run_module("IAM managed policy size", lambda: scan_iam_managed_policy_sizes(scanner)))
    results.append(run_module("IAM inline role policy size", lambda: scan_iam_role_inline_policy_sizes(scanner, max_roles=max_roles)))
    results.append(run_module("S3 bucket policy size", lambda: scan_s3_bucket_policies(scanner)))
    results.append(run_module("EC2 launch template user-data size", lambda: scan_ec2_launch_template_userdata_sizes(scanner)))
    results.append(run_module("Organizations SCP size", lambda: scan_orgs_scp_sizes(scanner)))

    
    all_norm = []
    for r in results:
        if getattr(r, "findings", None):
            all_norm.extend(normalize_findings(r.name, r.findings))

    findings_json = []
    for f in all_norm:
        findings_json.append({
            "fid":f.fid,
            "check":f.check,
            "title":f.title,
            "current":f.current,
            "maximum":f.maximum,
            "percent":f.percent,
            "severity":severity_for_percent(f.percent),
        })

    findings_json.sort(key=lambda x: float(x.get("percent", 0.0)), reverse=True)
    last_sent = store.load_last_sent(target_account_id)
    events, updated = compute_alerts(all_norm, last_sent, thresholds=thresholds)

    items = []
    for f in all_norm:
        sev = severity_for_percent(f.percent)
        items.append({
            "fid": f.fid,
            "check": f.check,
            "title": f.title,
            "current": f.current,
            "maximum": f.maximum,
            "percent": round(float(f.percent), 2),
            "severity": sev,
        })

    items.sort(key=lambda x: x["percent"], reverse=True)

    severity_counts = {"info": 0, "warn": 0, "critical":0}
    for it in items:
        severity_counts[it["severity"]] = severity_counts.get(it["severity"], 0) + 1

    highest_severity = "info"
    for it in items:
        if severity_rank(it["severity"]) > severity_rank(highest_severity):
            highest_severity = it["severity"]
    top_n =int(os.getenv("TOP_N", "10"))
    top = items[:top_n]
    reco = []
    # simple per-check suggestions
    checks = {it["check"] for it in items}
    if "IAM inline role policy size" in checks or "IAM managed policy size" in checks:
        reco.append("IAM: if policies become to large , split them into several policies, use managed policies and group/roles instead of huge inline ones.")
    if "S3 bucket policy size" in checks:
        reco.append("S3: if the bucket policy is close to the limit, move some of the rules to IAM, use Access Points, and reduce duplicates")
    if "EC2 launch template user-data size" in checks:
        reco.append("EC2: Move user-data to SSM Parametr Store / S3 + bootstrap to avoid hitting the 16KB limit")
    if "Organizations SCP size" in checks:
        reco.append("Orgs: Break SCPs down by OU, avoid monolithic policies, document exceptions.")


    slack_status = "not_configured"
    if "slack" in channels:
        if webhook and events:
            try:
                send_slack(webhook, events)
                slack_status = f"sent_{len(events)}"
            except Exception as e:
                slack_status = f"failed:{type(e).__name__}:{e}"
        elif webhook:
            slack_status = "no_alerts"
        else:
            slack_status = "not_configured"
    else: slack_status = "disabled"

    store.save_last_sent(target_account_id, updated)

    report = {
        "ok": True,
        "collector_account_id": target_account_id,
        "service_account_id": base_account_id,
        "thresholds": thresholds,
        "normalized_findings": len(all_norm),
        "new_events": len(events),
        "slack": slack_status,
        "notify_channels": sorted(list(channels)),
        "summary": [{"name": r.name, "status": r.status, "message": r.message, "count": r.count} for r in results],
        "findings": findings_json,
        "top": top,
        "severity_counts": severity_counts,
        "highest_severity": highest_severity,
        "recommendations": reco,
    }

    if "s3" in channels and report_bucket:
        from scout.notify.s3_report import write_report_json
        report_keys = write_report_json(base, report_bucket, report_prefix, target_account_id, report)
        report["report_s3_timestamp"] = report_keys["timestamp_key"]
        report["report_s3_latest"] = report_keys["latest_key"]
    else:
        report["report_s3_timestamp"] = None
        report["report_s3_latest"] = None

    return report
