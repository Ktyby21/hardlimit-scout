from __future__ import annotations
import json
import urllib.request
from urllib.parse import urlparse
from typing import List
from scout.core.thresholds import AlertEvent

def _is_valid_url(url:str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False

def send_slack(webhook_url: str, events: List[AlertEvent]) -> None:
    if not events:
        return

    webhook_url = (webhook_url or "").strip()
    if not webhook_url:
        return

    if not _is_valid_url(webhook_url):
        raise ValueError("SLACK_WEBHOOK_URL is not a valid http(s) URL")

    lines = ["*Hardlimit Scout alerts:*"]
    for e in events:
        lines.append(f"- '{e.check}': *{e.title}* reached *{e.threshold}%* (now {e.percent}%)")

    payload = {"text": "\n".join(lines)}
    req = urllib.request.Request(
        webhook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()