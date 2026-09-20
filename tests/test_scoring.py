"""Lightweight smoke tests for core scoring behavior.
Run from src-aware environment: PYTHONPATH=src pytest -q
"""
import os
from function_app import empty_profile, score_event, update_profile

os.environ.setdefault("MIN_BASELINE_EVENTS", "1")

def test_first_device_code_scores_high():
    base_event = {
        "userId": "u1", "userPrincipalName": "u@x", "createdDateTime": "2026-01-01T12:00:00Z",
        "statusErrorCode": 0, "authenticationProtocol": "oAuth2", "appId": "a", "country": "US"
    }
    p = empty_profile(base_event)
    update_profile(p, base_event)
    event = dict(base_event)
    event["createdDateTime"] = "2026-02-01T12:00:00Z"
    event["authenticationProtocol"] = "deviceCode"
    score, reasons = score_event(p, event)
    assert score >= 55
    assert any(r["code"] == "never_seen_device_code" for r in reasons)
