import typer
import botocore
import os

from scout.core.normalize import normalize_findings
from scout.core.thresholds import compute_alerts, load_thresholds_from_env
from scout.storage.stage_file import load_last_sent, save_last_sent
from scout.notify.slack import send_slack
from scout.core.modules import run_module
from scout.aws.iam import scan_iam_managed_policy_sizes
from scout.aws.session import scanner_session
from scout.aws.s3 import scan_s3_bucket_policies
from scout.aws.iam_inline import scan_iam_role_inline_policy_sizes
from scout.config import load_env
load_env()

app = typer.Typer(no_args_is_help=True)

def _print_result(r):
    if r.status == "ok":
        typer.echo(f"✅ {r.name} : {r.message}")
    elif r.status == "info":
        typer.echo(f"ℹ️  {r.name} : {r.message}")
    elif r.status == "skipped":
        typer.echo(f"⚠️  {r.name} : {r.message}")
    else :
        typer.echo(f"❌ {r.name} : {r.message}")


@app.command("scan-all")
def scan_all(
    min_percent: float = typer.Option(0.0, help="Filter by % (currently affects printing of parts in individual commands)"),
    max_roles: int = typer.Option(300, help="How much roles for max scan (MVP safety)")
    ):
    """
     Combined module run. Nothing falls: it will be +, !, skip, -
    """
    session = scanner_session()
    result =[]
    # 1) IAM managed policy size (might be empty - !)
    result.append(
        run_module("IAM managed policy size", lambda:scan_iam_managed_policy_sizes(session))
    )

    # 2) IAM inline policies on roles
    result.append(
        run_module("IAM inline role policy size", lambda:scan_iam_role_inline_policy_sizes(session))
    )

    # 3) S3 bucket policy size (often prohibits listing buckets - will be "skip")
    result.append(
        run_module("S3 bucket policy size", lambda:scan_s3_bucket_policies(session))
    )

    # 4) EC2 Launch template user-data size
    def _ec2():
        from scout.aws.ec2 import scan_ec2_launch_template_userdata_sizes  # type: ignore
        return scan_ec2_launch_template_userdata_sizes(session)

    result.append(run_module("EC2 launch template user-data size", _ec2))

    # 5) Organizations SCP size
    def _orgs():
        from scout.aws.orgs import scan_orgs_scp_sizes  # type: ignore
        return scan_orgs_scp_sizes(session)

    result.append(run_module("Organizations SCP size", _orgs))
    
    typer.echo("=== SUMMARY ===")
    for r in result:
        _print_result(r)

    # 6) collect all findings from modules with ok/info
    all_norm = []
    for r in result:
        if getattr(r, "findings", None):
            all_norm.extend(normalize_findings(r.name, r.findings))



    # Count new allers 
    last_sent = load_last_sent()
    thresholds = load_thresholds_from_env()

    events, updated = compute_alerts(all_norm, last_sent, thresholds=thresholds)


    webhook = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    try:
        if webhook and events:
            try:
                send_slack(webhook, events)
                typer.echo(f" Sent {len(events)} alert(s) to Slack.")
            except Exception as e:
                typer.echo(f"⚠️  Slack send failed: {type(e).__name__}: {e}")
        elif webhook:
            typer.echo(" No alerts to send.")
        else:
            typer.echo(" Slack webhook not set; alerts computed but not sent.")
    finally:
        save_last_sent(updated)
        typer.echo(" State saved to .scout_state.json")


@app.command("scan-iam")
def scan_iam(min_percent: float = typer.Option(0.0, help="Threshold in %, e.g. 80")):
    """IAM cutomer-managed policies sizes"""
    session = scanner_session()
    findings = scan_iam_managed_policy_sizes(session)

    if not findings:
        typer.echo("No IAM managed policies found.")
        raise typer.Exit()

    shown = 0
    for f in findings:
        if f.percent_used < min_percent:
            continue
        shown += 1 
        typer.echo(f"{f.policy_name}: {f.chars} chars ({f.percent_used}% of {f.max_chars})")

    if shown == 0:
        typer.echo(f"No Iam findings >= {min_percent}%")


@app.command("scan-s3")
def scan_s3(min_percent: float = typer.Option(0.0, help="Threshold in %, e.g. 80")):
    """
    Print sizes of bucket policies (S3).
    min_percent - filter (for example 80 shows only near limit values)
    """
    session = scanner_session()
    try:
        findings = scan_s3_bucket_policies(session)
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if code in ("AccessDenied", "AccessDeniedException"):
            typer.echo("!!! S3 module skipped: missing permission s3:ListAllMyBuckets and/or s3:GetBucketPolicy")
            raise typer.Exit(code=0)
        raise

    if not findings:
        typer.echo("No S3 bucket policies found.")
        raise typer.Exit(code=0)

    shown = 0
    for f in findings:
        if f.percent_used < min_percent:
            continue
        shown += 1
        typer.echo(
            f"{f.bucket}: {f.policy_bytes} bytes "
            f"({f.percent_used}% of {f.max_bytes} bytes)"
        )
    if shown == 0:
        typer.echo(f"No findings >= {min_percent}%")

@app.command("whoami")
def whoami():
    session = scanner_session()
    ident = session.client("sts").get_caller_identity()
    typer.echo(ident["Arn"])

@app.command("scan-iam-inline-roles")
def scan_iam_inline_roles(
    min_percent: float = typer.Option(0.0, help="Threshold in %, e.g. 80"),
    max_roles: int = typer.Option(300, help="How much roles for max scan (MVP safety)")
):
    """IAM: sizes inline policy for roles."""
    session = scanner_session()
    try:
      findings = scan_iam_role_inline_policy_sizes(session, max_roles=max_roles)
    except botocore.exceptions.ClientError as e:
        code = e.response.get("Error", {}).get("Code", "Unknown")
        if code in ("AccessDenied", "AccessDeniedException", "UnauthorizedOperation"):
            typer.echo("!!! IAM inline roles skipped: missing iam:ListRoles/iam:ListRolePolicies/iam:GetRolePolicy")
            raise typer.Exit(code=0)
        raise
    if not findings:
        typer.echo("No IAM role inline pilicies found.")
        raise typer.Exit()

    shown = 0
    for f in findings:
        if f.percent_used < min_percent:
            continue
        
        shown += 1
        typer.echo(f"{f.role_name}/{f.policy_name} : {f.chars} chars "
        f"({f.percent_used}% of {f.max_chars})")

    if shown == 0:
        typer.echo(f"No inline role policy findings >= {min_percent}%")

def main():
    app()

if __name__ == "__main__":
    main()