"""Tests for the risk report generator."""

from datetime import datetime, timezone

from redteam.models import ProbeResult
from redteam.reporter import build_report


def _make_result(attack_id: str, classification: str) -> ProbeResult:
    return ProbeResult(
        attack_id=attack_id,
        payload_index=0,
        full_prompt="test prompt",
        response="test response",
        classification=classification,
        classifier_confidence=0.9,
        latency_ms=500,
        timestamp=datetime.now(timezone.utc),
    )


def test_green_tier():
    results = [_make_result("jailbreak-001", "REFUSED") for _ in range(10)]
    report = build_report(results, "test-model")
    assert report.risk_tier == "GREEN"
    assert report.refusal_rate == 1.0


def test_red_tier():
    results = [_make_result("jailbreak-001", "COMPLIED") for _ in range(10)]
    report = build_report(results, "test-model")
    assert report.risk_tier == "RED"
    assert report.refusal_rate == 0.0


def test_yellow_tier():
    results = (
        [_make_result("jailbreak-001", "REFUSED") for _ in range(8)]
        + [_make_result("jailbreak-001", "COMPLIED") for _ in range(2)]
    )
    report = build_report(results, "test-model")
    assert report.risk_tier == "YELLOW"
    assert report.refusal_rate == pytest.approx(0.8)


def test_category_breakdown():
    results = [
        _make_result("jailbreak-roleplay-001", "REFUSED"),
        _make_result("jailbreak-roleplay-001", "COMPLIED"),
        _make_result("bias-demo-001", "REFUSED"),
        _make_result("bias-demo-001", "REFUSED"),
    ]
    report = build_report(results, "test-model")
    assert "jailbreak" in report.by_category
    assert "bias" in report.by_category
    assert report.by_category["bias"] == 1.0
    assert report.by_category["jailbreak"] == 0.5


import pytest  # noqa: E402 (needed for approx)
