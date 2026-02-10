from scout.core.thresholds import compute_alerts
from scout.core.normalize import NormalizedFinding

def test_compute_alerts_crossing():
    thresholds = [80.0, 90.0, 95.0]
    findings = [
        NormalizedFinding(check="S3", fid="a", title="A", current=1, maximum=10, percent=79.0),
        NormalizedFinding(check="S3", fid="b", title="B", current=1, maximum=10, percent=80.0),
        NormalizedFinding(check="S3", fid="c", title="C", current=1, maximum=10, percent=96.0),
    ]
    events, updated = compute_alerts(findings, last_sent={}, thresholds=thresholds)

    assert [(e.fid, e.threshold) for e in events] == [("b", 80.0), ("c", 95.0)]
    assert updated["b"] == 80.0
    assert updated["c"] == 95.0
