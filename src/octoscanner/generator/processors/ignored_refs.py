"""Drop generated rules whose ref is listed in ``ignored_refs.yaml``.

Some refs produce rules that are known false positives and cannot be avoided
while generating them. Instead of filtering at generation time, every rule is
built normally and this pass removes the ignored ones afterwards.
"""

from __future__ import annotations

import fnmatch
import functools
from pathlib import Path

import yaml

from ..models import PipelineState, RuleFile
from ..rules import ref_from_rule
from .base import Processor


@functools.cache
def _load_ignored_refs() -> dict[str, list[str]]:
    """Load ignored refs from the configuration file `ignored_refs.yaml`.

    Returns:
        dict[str, list[str]]: Mapping of rules path to list of ref patterns.
    """
    patterns_file = Path(__file__).parent.parent / "ignored_refs.yaml"

    if not patterns_file.exists():
        return {}

    with open(patterns_file) as f:
        return yaml.safe_load(f) or {}


def _is_ignored_ref(ref: str, rule_file: RuleFile) -> bool:
    """Check if a ref matches any ignored pattern for the given rule file.

    Patterns are keyed by a path relative to the rules directory: a directory
    key (e.g. ``removal``) covers every rule file below it, a file key
    (e.g. ``removal/python_removal.yaml``) covers that file alone.

    Supports wildcards:
      - ``*`` matches any single path component
      - ``**`` matches any number of path components

    Args:
        ref (str): The ref to check (FQN, dotted settings path, etc.).
        rule_file (RuleFile): The rule file the ref produced a rule in.

    Returns:
        bool: True if the ref matches any ignored pattern.
    """
    rules_path = rule_file.value.path
    patterns = [
        pattern
        for selector, selector_patterns in _load_ignored_refs().items()
        if rules_path == selector or rules_path.startswith(f"{selector}/")
        for pattern in selector_patterns
    ]

    for pattern in patterns:
        # Convert ** to placeholder, * to single-component match, then ** to multi-component
        glob_pattern = pattern.replace("**", "\x00").replace("*", "[^.]*").replace("\x00", "*")
        if fnmatch.fnmatch(ref, glob_pattern):
            return True

    return False


def _drop_ignored_rules(rules: list[dict], rule_file: RuleFile) -> tuple[list[dict], list[tuple[str, str]]]:
    """Split a rule list into the rules to keep and the ignored ones.

    Args:
        rules (list[dict]): Rules to filter.
        rule_file (RuleFile): Rule file the rules belong to.

    Returns:
        tuple[list[dict], list[tuple[str, str]]]: A ``(kept_rules, dropped)``
        tuple where ``dropped`` lists ``(rule_id, ref)`` for each ignored rule.
    """
    kept_rules, dropped = [], []

    for rule in rules:
        ref = ref_from_rule(rule)
        if _is_ignored_ref(ref, rule_file):
            dropped.append((rule.get("id"), ref))
        else:
            kept_rules.append(rule)

    return kept_rules, dropped


class IgnoredRefsProcessor(Processor):
    title = "Applying ignored refs"

    def run(self, state: PipelineState) -> list[str]:
        output_lines = []

        total_dropped = 0
        for rule_file in RuleFile:
            kept_rules, dropped = _drop_ignored_rules(state.rules[rule_file], rule_file)
            state.rules[rule_file] = kept_rules
            total_dropped += len(dropped)

            if dropped:
                output_lines.append(f"  {rule_file.value.path}: {len(dropped)} ignored")
                output_lines.extend(f"    {rule_id} ({ref})" for rule_id, ref in dropped)
            else:
                output_lines.append(f"  {rule_file.value.path}: nothing ignored")

        output_lines.append("  ---")
        output_lines.append(f"  Total: {total_dropped} ignored")

        return output_lines
