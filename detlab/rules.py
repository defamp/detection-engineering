"""Load the rule set: every *.yml under rules/, with correlation references resolved."""

from __future__ import annotations

from pathlib import Path

from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
SAMPLES_DIR = ROOT / "tests" / "samples"


def rule_files() -> list[Path]:
    return sorted(RULES_DIR.rglob("*.yml"))


def load_collection() -> SigmaCollection:
    collection = SigmaCollection.load_ruleset([RULES_DIR])
    collection.resolve_rule_references()
    return collection


def rule_by_file() -> dict[Path, object]:
    """Map each rule file to its parsed rule (one rule per file)."""
    collection = load_collection()
    out = {}
    for rule in collection.rules:
        path = Path(rule.source.path).resolve() if rule.source and rule.source.path else None
        if path is None:
            raise ValueError(f"rule {rule.title!r} has no source path")
        if path in out:
            raise ValueError(f"{path}: only one rule per file is allowed")
        out[path] = rule
    return out


def sample_file(rule_path: Path) -> Path:
    return SAMPLES_DIR / rule_path.relative_to(RULES_DIR)
