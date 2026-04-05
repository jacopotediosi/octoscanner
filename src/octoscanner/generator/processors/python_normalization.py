"""Post-generation normalization of Semgrep rules.

Two cleanup passes:

1. **Superseded deprecations**: remove deprecation rules for symbols that
   were later fully removed (a removal rule replaces the deprecation).
2. **Stale deprecations**: remove deprecation rules for symbols that exist
   in the latest OctoPrint version but are no longer marked as deprecated.
   This handles cases where deprecations were reverted in a later version.
"""

from __future__ import annotations

from ..models import Deprecation, PipelineState, RuleFile
from ..rules import symbol_sig_earliest_since_map, symbol_sig_from_rule
from .base import Processor


def _clean_superseded_deprecations(
    deprecation_rules: list[dict],
    removal_rules: list[dict],
) -> tuple[list[dict], list[tuple[str, str]]]:
    """Remove deprecation rules superseded by a corresponding removal rule.

    **Same-version exception**: if deprecated and removed in the same version,
    keeps the deprecation rule - the symbol was reorganised (e.g. moved to a
    new class with a ``@deprecated`` wrapper) but is still callable.

    Args:
        deprecation_rules (list[dict]): List of deprecation rule dicts.
        removal_rules (list[dict]): List of removal rule dicts.

    Returns:
        tuple[list[dict], list[tuple[str, str]]]: A
        ``(cleaned_rules, removed_pairs)`` tuple where ``cleaned_rules``
        is the filtered list of deprecation rules and ``removed_pairs`` is
        a list of ``(dep_rule_id, superseding_rem_rule_id)`` for each removed pair.

    Examples:
        >>> cleaned_rules, removed_pairs = _clean_superseded_deprecations(dep_rules, rem_rules)
        >>> removed_pairs
        [('DEP-0003', 'REM-0015')]
    """
    cleaned_rules, removed_pairs = [], []

    # Index removal rules by signature for fast lookup
    removal_by_sig = {}
    removal_since_by_sig = {}
    for rem_rule in removal_rules:
        rem_rule_sig = symbol_sig_from_rule(rem_rule)
        removal_by_sig[rem_rule_sig] = rem_rule.get("id")
        removal_since_by_sig[rem_rule_sig] = rem_rule.get("metadata", {}).get("since")

    # Filter deprecation rules
    for dep_rule in deprecation_rules:
        dep_rule_sig = symbol_sig_from_rule(dep_rule)

        # No matching removal rule - keep the deprecation
        if dep_rule_sig not in removal_by_sig:
            cleaned_rules.append(dep_rule)
            continue

        dep_since = dep_rule.get("metadata", {}).get("since")
        rem_since = removal_since_by_sig[dep_rule_sig]

        # Same-version exception: deprecated and removed in the same version
        # means the symbol was reorganised (moved/renamed) but is still callable
        if dep_since and rem_since and dep_since == rem_since:
            cleaned_rules.append(dep_rule)
        else:
            removed_pairs.append((dep_rule.get("id"), removal_by_sig[dep_rule_sig]))

    return cleaned_rules, removed_pairs


def _clean_stale_deprecations(
    deprecation_rules: list[dict],
    latest_deprecations: list[Deprecation],
) -> tuple[list[dict], list[str]]:
    """Remove deprecation rules for symbols that exist in the latest OctoPrint version
    but are no longer marked as deprecated.

    Args:
        deprecation_rules (list[dict]): List of deprecation rule dicts.
        latest_deprecations (list[Deprecation]): Deprecations found in
            the latest OctoPrint version.

    Returns:
        tuple[list[dict], list[str]]: A ``(kept_rules, removed_ids)`` tuple
        where ``kept_rules`` is the filtered list and ``removed_ids`` the
        IDs of removed rules.

    Examples:
        >>> kept, stale_ids = _clean_stale_deprecations(dep_rules, latest_deps)
        >>> stale_ids
        ['DEP-0007', 'DEP-0019']
    """
    kept_rules, removed_ids = [], []

    latest_sigs = set(symbol_sig_earliest_since_map(latest_deprecations))
    for deprecation_rule in deprecation_rules:
        deprecation_rule_sig = symbol_sig_from_rule(deprecation_rule)
        if deprecation_rule_sig in latest_sigs:
            kept_rules.append(deprecation_rule)
        else:
            removed_ids.append(deprecation_rule.get("id"))

    return kept_rules, removed_ids


class PythonNormalizationProcessor(Processor):
    title = "Python rules normalization"

    def run(self, state: PipelineState) -> list[str]:
        dep_rules = state.rules[RuleFile.python_deprecation]
        rem_rules = state.rules[RuleFile.python_removal]
        output_lines: list[str] = []

        cleaned_dep, removed_deps_pairs = _clean_superseded_deprecations(dep_rules, rem_rules)
        if removed_deps_pairs:
            output_lines.append(
                f"  Deprecation -> Removal ({len(removed_deps_pairs)} deprecated APIs removed in later versions):"
            )
            for dep_id, rem_id in removed_deps_pairs:
                output_lines.append(f"    {dep_id} -> {rem_id}")
        else:
            output_lines.append("  No superseded deprecations found")

        cleaned_dep, stale_ids = _clean_stale_deprecations(
            cleaned_dep,
            state.python_analysis_results[state.versions[-1]].deprecations,
        )
        if stale_ids:
            output_lines.append(f"  Stale ({len(stale_ids)} rules no longer deprecated in {state.versions[-1]}):")
            for stale_id in stale_ids:
                output_lines.append(f"    {stale_id}")
        else:
            output_lines.append("  No stale deprecations found")

        state.rules[RuleFile.python_deprecation] = cleaned_dep
        return output_lines
