def test_imports():
    import scout
    from scout.core.thresholds import load_thresholds_from_env, compute_alerts
    from scout.core.normalize import normalize_findings
    assert callable(load_thresholds_from_env)
    assert callable(compute_alerts)
    assert callable(normalize_findings)
