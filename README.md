<<<<<<< HEAD
# hardlimit-scout
=======
<div align="center">

# Hardlimit Scout 🛰️  
**Predict hard AWS hard-limits before they break production.**

[![CI](https://img.shields.io/github/actions/workflow/status/<YOU>/<REPO>/ci.yml?branch=main)](../../actions)
[![License: AGPL v3](https://img.shields.io/badge/license-AGPLv3-blue.svg)](./LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB)](#)
[![AWS](https://img.shields.io/badge/AWS-Lambda%20%7C%20DynamoDB%20%7C%20EventBridge-orange)](#)

</div>

---

## Why Hardlimit Scout?

AWS Service Quotas and Trusted Advisor cover many **count-based** limits.  
But some of the most painful limits are “in the shadows”:

- IAM policy document size limits (managed/inline)  
- S3 bucket policy size limits  
- EC2 User Data limit (16KB)  
- Organizations SCP size limits (where available)

Hardlimit Scout scans these **hard limits**, stores state to avoid alert spam, and writes a JSON report to S3.

---

## What you get (Core)

✅ Scheduled scans (EventBridge)  
✅ Lambda scanner + DynamoDB state (anti-spam)  
✅ S3 JSON reports (`latest.json` + timestamped history)  
✅ Slack alerts (optional)  
✅ CLI for local debugging

---

## Quickstart (Customer-hosted, 10 minutes)

### 1) Deploy the stack
You can deploy via CloudFormation (packaged template) or your preferred pipeline.

**Required parameters**:
- `ScoutThresholds` (default: `80,90,95`)
- `ReportBucket` (recommended)
- `NotifyChannels` (e.g. `s3,slack`)
- `SlackWebhookUrl` (optional)

### 2) Run a test scan
Invoke the Lambda once and confirm S3 report is created.

Expected output:
- `reports/<account_id>/latest.json`
- `reports/<account_id>/<timestamp>.json`

---

## Report format
Each run produces a JSON summary:
- module statuses
- normalized findings (percent used)
- top-N risks
- recommendations

---

## Security model

Hardlimit Scout is designed for **least privilege**:
- The scanner only needs read access to specific AWS APIs used by checks.
- Reports are stored in your S3 bucket (you own the data).

---

## Hard limits checks included (Core)

- IAM managed policy document size
- IAM inline role policy size
- S3 bucket policy size
- EC2 Launch Template user-data size
- Organizations SCP size (when Organizations is enabled & permitted)

---

## Hardlimit Scout Pro (private)

Want **multi-account**, **dashboards**, **trends**, and **predictive ETA** to the limit?  
Hardlimit Scout Pro adds:

- multi-account scanning (AWS Organizations fan-out)
- web dashboard + history + forecasting
- remediation playbooks and “one-click” actions
- Jira / PagerDuty / ServiceNow integrations
- enterprise auth (SSO/RBAC)

Contact: (add your email / landing page)

---

## Contributing

We welcome issues and PRs!  
See [CONTRIBUTING.md](./CONTRIBUTING.md).

---

## License

Hardlimit Scout Core is licensed under **GNU AGPLv3**.  
See [LICENSE](./LICENSE).
>>>>>>> 80f9fae (Initial public MVP (AGPLv3): lambda + cfn + cli + tests)
