````md
<div align="center">

# Hardlimit Scout 🛰️
**Predict AWS “hard limits” before they break production.**

<!-- Replace with your repo once published -->
<!--
[![CI](https://img.shields.io/github/actions/workflow/status/<YOU>/<REPO>/ci.yml?branch=main)](../../actions)
-->
[![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)](#)
[![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20DynamoDB%20%7C%20EventBridge-orange)](#)

</div>

---

## Why Hardlimit Scout?

AWS Service Quotas and Trusted Advisor cover many **count-based** limits.  
But some of the most painful limits are *size-based* and usually show up only when it’s too late:

- IAM policy **document size** limits (managed + inline role policies)
- S3 bucket policy **size** limit
- EC2 Launch Template **user-data** limit (16 KB decoded)
- Organizations **SCP** size limit (when Organizations is enabled)

Hardlimit Scout scans these limits, stores state to avoid alert spam, and can write a JSON report to S3.

---

## What you get (MVP)

✅ Scheduled scans (EventBridge)  
✅ Lambda scanner + DynamoDB state (anti-spam thresholds)  
✅ JSON reports to S3 (`latest.json` + timestamped history) *(optional)*  
✅ Slack alerts *(optional)*  
✅ CLI for local debugging (`scout …`)

---

## Repository layout

- `src/scout/` — scanner + CLI + Lambda handler
- `cfn/hardlimit-scout-mvp.yaml` — customer-hosted CloudFormation/SAM template
- `tests/` — minimal sanity tests

---

## Install (local dev / testers)

This project supports editable install, so you can run `scout` directly.

```bash
python -m venv venv
source venv/bin/activate

pip install -e .[dev]
scout --help
````

### Quick local check

```bash
scout whoami
scout scan-all
```

---

## Deploy (customer-hosted, AWS)

### Prerequisites

* AWS credentials configured (`aws sts get-caller-identity` works)
* Region selected (examples use `us-east-1`)
* An S3 bucket for packaging artifacts (CloudFormation `package` step)

### 1) Package the template

```bash
export AWS_REGION=us-east-1
export ARTIFACT_BUCKET=<your-artifact-bucket-name>

aws --region "$AWS_REGION" s3api head-bucket --bucket "$ARTIFACT_BUCKET"
aws --region "$AWS_REGION" cloudformation package \
  --template-file cfn/hardlimit-scout-mvp.yaml \
  --s3-bucket "$ARTIFACT_BUCKET" \
  --output-template-file cfn/packaged.yaml
```

### 2) Deploy

```bash
aws --region "$AWS_REGION" cloudformation deploy \
  --template-file cfn/packaged.yaml \
  --stack-name hardlimit-scout-mvp \
  --capabilities CAPABILITY_NAMED_IAM
```

### 3) Run a test scan

```bash
aws --region "$AWS_REGION" lambda invoke \
  --function-name hardlimit-scout-scan out.json >/dev/null

cat out.json | head -c 800; echo
```

---

## Optional: enable S3 reports

Create a report bucket and pass it into the stack:

```bash
export REPORT_BUCKET=<your-report-bucket>

aws --region "$AWS_REGION" s3api create-bucket --bucket "$REPORT_BUCKET" || true
aws --region "$AWS_REGION" s3api head-bucket --bucket "$REPORT_BUCKET"

aws --region "$AWS_REGION" cloudformation deploy \
  --template-file cfn/packaged.yaml \
  --stack-name hardlimit-scout-mvp \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    ReportBucket="$REPORT_BUCKET" \
    ReportPrefix="reports/" \
    NotifyChannels="s3,slack"
```

After a run, you’ll get:

* `reports/<account_id>/latest.json`
* `reports/<account_id>/<timestamp>.json`

---

## Optional: Slack alerts

Set `SlackWebhookUrl` parameter (Incoming Webhook URL).
Alerts are triggered when a finding crosses a new threshold (default: `80,90,95`).

---

## Configuration

Environment variables used by Lambda/CLI:

* `SCOUT_THRESHOLDS` — comma-separated thresholds, e.g. `80,90,95`
* `MAX_ROLES` — safety limit for IAM role scan (default: `300`)
* `S3_BUCKETS` — comma-separated bucket names to scan (avoids `ListAllMyBuckets`)
* `SLACK_WEBHOOK_URL` — optional
* `REPORT_BUCKET`, `REPORT_PREFIX` — optional
* `NOTIFY_CHANNELS` — comma-separated: `s3,slack`

---

## Checks included

* IAM managed policy document size
* IAM inline role policy size
* S3 bucket policy size
* EC2 Launch Template user-data size
* Organizations SCP size *(skips gracefully if not enabled or no permissions)*

---

## Security & permissions

Hardlimit Scout is designed for **customer-hosted** usage (your AWS account, your data).
The CloudFormation role in `cfn/hardlimit-scout-mvp.yaml` grants **read-only** permissions needed by the checks,
plus write access to DynamoDB (state) and optional S3 (reports).

Tip for least privilege:

* If you don’t want `s3:ListAllMyBuckets`, set `S3_BUCKETS` to a specific list.

---

## Development

Run tests and template lint:

```bash
pytest
cfn-lint cfn/hardlimit-scout-mvp.yaml
```

---

## Contributing

Issues and PRs are welcome.

* Please include: AWS service, reproduction steps, and a redacted example of output.
* No secrets in issues/logs.

---

## License

Hardlimit Scout is licensed under **GNU AGPLv3**.
See [LICENSE](./LICENSE).

```
::contentReference[oaicite:0]{index=0}
```
>>>>>>> 80f9fae (Initial public MVP (AGPLv3): lambda + cfn + cli + tests)
