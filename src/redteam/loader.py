"""Attack template loader from YAML files."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import yaml

from .models import AttackTemplate


def load_template(path: Path) -> List[AttackTemplate]:
    """Load all templates from a single YAML file (may define multiple)."""
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [AttackTemplate(**item) for item in raw]
    return [AttackTemplate(**raw)]


def load_all_templates(
    attacks_dir: Path,
    categories: Optional[List[str]] = None,
    severity: Optional[str] = None,
) -> List[AttackTemplate]:
    """Recursively load all YAML attack templates, with optional filtering."""
    templates = []
    for yaml_file in sorted(attacks_dir.rglob("*.yaml")):
        for template in load_template(yaml_file):
            if categories and template.category not in categories:
                continue
            if severity and template.severity != severity:
                continue
            templates.append(template)
    return templates
