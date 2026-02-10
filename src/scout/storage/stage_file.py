from __future__ import annotations
import json
from pathlib import Path
from typing import Dict

STATE_PATH = Path(".scout_state.json")

def load_last_sent() -> Dict[str, float]:
    if not STATE_PATH.exists():
        return {}
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
        return {str(k): float(v) for k, v in data.items()}
    except Exception:
        return {}

def save_last_sent(last_sent: Dict[str, float]) -> None:
    STATE_PATH.write_text(json.dumps(last_sent, indent=2, sort_keys=True), encoding="utf-8")