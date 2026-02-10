from __future__ import annotations

def severity_for_percent(p: float) -> str:
    if p >= 90.0:
        return "critical"
    if p >= 70.0:
        return "warn"
    return "info"

def severity_rank(s: str) -> int:
    return {"info": 0, "warn": 1, "critical": 2}.get(s, 0)