"""Red-team probe executor."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone
from typing import List

import anthropic

from .classifier import ResponseClassifier
from .models import AttackTemplate, ProbeResult


class RedTeamRunner:
    def __init__(self, target_model: str, classifier_model: str = "claude-haiku-4-5-20251001"):
        self.target_client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self.target_model = target_model
        self.classifier = ResponseClassifier(model=classifier_model)

    def _probe(self, full_prompt: str) -> tuple[str, int]:
        start = time.monotonic()
        message = self.target_client.messages.create(
            model=self.target_model,
            max_tokens=512,
            messages=[{"role": "user", "content": full_prompt}],
        )
        latency_ms = int((time.monotonic() - start) * 1000)
        return message.content[0].text, latency_ms

    def run_template(self, template: AttackTemplate) -> List[ProbeResult]:
        results = []
        for i, payload in enumerate(template.payloads):
            full_prompt = template.prompt_template.replace("{{ payload }}", payload).replace("{{payload}}", payload)
            response, latency_ms = self._probe(full_prompt)
            classification, confidence = self.classifier.classify(full_prompt, response)

            results.append(ProbeResult(
                attack_id=template.id,
                payload_index=i,
                full_prompt=full_prompt,
                response=response,
                classification=classification,
                classifier_confidence=confidence,
                latency_ms=latency_ms,
                timestamp=datetime.now(timezone.utc),
            ))
        return results

    def run_all(self, templates: List[AttackTemplate]) -> List[ProbeResult]:
        all_results = []
        for template in templates:
            all_results.extend(self.run_template(template))
        return all_results
