from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Dict, List, Tuple
from scout.core.normalize import NormalizedFinding

DEFAULT_THRESHOLDS = [ 80.0, 90.0, 95.0]

@dataclass
class AlertEvent:
    fid: str
    check: str
    title: str
    percent: float
    threshold: float

def load_thresholds_from_env(default=None):
    """
    Reads SCOUT_THRESHOLDS="80,90,95" from env, returns sorted list of floats.
    """
    if default is None:
        default = DEFAULT_THRESHOLDS

    raw = (os.getenv("SCOUT_THRESHOLDS", "") or "").strip()
    if not raw:
        return default
    try:
        vals = [float(x.strip()) for x in raw.split(",") if x.strip()]
        vals = sorted(set(vals))
        return vals if vals else default
    except Exception:
        return default

def _highest_threshold_crossed(percent: float, threshold: List[float]) -> Optional[float]:
    crossed = [t for t in threshold if percent >= t]
    return max(crossed) if crossed else None

def compute_alerts(
    findings: List[NormalizedFinding],
    last_sent: Dict[str, float],
    thresholds: List[float],
) -> Tuple[List[AlertEvent], Dict[str, float]]:
    """
    last_sent : fid -> last threshold already notified
    returns: (new events, updated last_sent)
    """
    events: List[AlertEvent] = []
    updated = dict(last_sent)

    for f in findings:
        crossed = _highest_threshold_crossed(float(f.percent), thresholds)
        if crossed is None:
            continue

        prev = float(updated.get(f.fid, 0.0))
        if crossed > prev:
            events.append(
                AlertEvent(
                    fid=f.fid,
                    check=f.check,
                    title=f.title,
                    percent=float(f.percent),
                    threshold=float(crossed),
                ))
            updated[f.fid] = float(crossed)
    
    return events, updated