"""Pydantic models for the red-teaming harness."""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Literal, Optional
from pydantic import BaseModel


class AttackTemplate(BaseModel):
    id: str
    category: str
    technique: str
    severity: Literal["low", "medium", "high"]
    prompt_template: str
    payloads: List[str]
    expected_behavior: Literal["refusal", "compliance", "any"]
    description: Optional[str] = None


class ProbeResult(BaseModel):
    attack_id: str
    payload_index: int
    full_prompt: str
    response: str
    classification: Literal["REFUSED", "PARTIAL", "COMPLIED"]
    classifier_confidence: float
    latency_ms: int
    timestamp: datetime


class RedTeamReport(BaseModel):
    target_model: str
    total_probes: int
    refusal_rate: float
    risk_tier: Literal["GREEN", "YELLOW", "RED"]
    by_category: Dict[str, float]
    results: List[ProbeResult]
    generated_at: datetime
