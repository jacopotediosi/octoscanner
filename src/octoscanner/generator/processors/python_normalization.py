"""Post-generation normalization of Semgrep rules.

Three cleanup passes:

1. **Superseded deprecations**: remove deprecation rules for symbols that
   were later fully removed (a removal rule replaces the deprecation).
2. **Stale deprecations**: remove deprecation rules for symbols that exist
   in the latest OctoPrint version but are no longer marked as deprecated.
   This handles cases where deprecations were reverted in a later version.
3. **Superseded settings**: remove settings removal rules whose path is
   covered by a more general ancestor rule (e.g. ``serial.capabilities.foo``
   is redundant if ``serial`` is already covered).
"""

from __future__ import annotations

from ..models import Deprecation, PipelineState, RuleFile
from ..rules import ref_earliest_since_map, ref_from_rule
from .base import Processor


def _clean_superseded_deprecations(
    deprecation_rules: list[dict],
    removal_rules: list[dict],
) -> tuple[list[dict], list[tuple[str, str]]]:
    """Remove deprecation rules superseded by a corresponding removal rule.

    Same-version exception: if deprecated and removed in the same version,
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

    # Index removal rules by ref for fast lookup
    removal_by_ref = {}
    removal_since_by_ref = {}
    for rem_rule in removal_rules:
        rem_rule_ref = ref_from_rule(rem_rule)
        removal_by_ref[rem_rule_ref] = rem_rule.get("id")
        removal_since_by_ref[rem_rule_ref] = rem_rule.get("metadata", {}).get("since")

    # Filter deprecation rules
    for dep_rule in deprecation_rules:
        dep_rule_ref = ref_from_rule(dep_rule)

        # No matching removal rule - keep the deprecation
        if dep_rule_ref not in removal_by_ref:
            cleaned_rules.append(dep_rule)
            continue

        dep_since = dep_rule.get("metadata", {}).get("since")
        rem_since = removal_since_by_ref[dep_rule_ref]

        # Same-version exception: deprecated and removed in the same version
        # means the symbol was reorganised (moved/renamed) but is still callable
        if dep_since and rem_since and dep_since == rem_since:
            cleaned_rules.append(dep_rule)
        else:
            removed_pairs.append((dep_rule.get("id"), removal_by_ref[dep_rule_ref]))

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

    latest_refs = set(ref_earliest_since_map(latest_deprecations))
    for deprecation_rule in deprecation_rules:
        deprecation_rule_ref = ref_from_rule(deprecation_rule)
        if deprecation_rule_ref in latest_refs:
            kept_rules.append(deprecation_rule)
        else:
            removed_ids.append(deprecation_rule.get("id"))

    return kept_rules, removed_ids


def _clean_superseded_settings(
    settings_removal_rules: list[dict],
) -> tuple[list[dict], list[tuple[str, str]]]:
    """Remove settings removal rules covered by a more general ancestor rule.

    When a parent path (e.g. ``serial``) is covered by a rule, all descendant
    rules (e.g. ``serial.capabilities.autoreport_pos``) are redundant. This
    happens when a fine-grained rule was generated for an earlier OctoPrint
    version and a coarser rule is later generated for a subsequent version.

    Args:
        settings_removal_rules (list[dict]): List of settings removal rule dicts.

    Returns:
        tuple[list[dict], list[tuple[str, str]]]: A
        ``(cleaned_rules, removed_pairs)`` tuple where ``cleaned_rules`` is
        the filtered list and ``removed_pairs`` is a list of
        ``(child_path, covering_ancestor_path)`` pairs.

    Examples:
        >>> cleaned_rules, removed_pairs = _clean_superseded_settings(rules)
        >>> removed_pairs
        [('serial.capabilities.autoreport_pos', 'serial')]
    """
    settings_paths = [tuple(ref_from_rule(rule).split(".")) for rule in settings_removal_rules]
    covered_settings_paths = set(settings_paths)

    cleaned_rules, removed_pairs = [], []
    for settings_path, rule in zip(settings_paths, settings_removal_rules):
        covering_ancestor = next(
            (settings_path[:i] for i in range(1, len(settings_path)) if settings_path[:i] in covered_settings_paths),
            None,
        )
        if covering_ancestor is None:
            cleaned_rules.append(rule)
        else:
            removed_pairs.append((".".join(settings_path), ".".join(covering_ancestor)))

    return cleaned_rules, removed_pairs


class PythonNormalizationProcessor(Processor):
    title = "Python rules normalization"

    def run(self, state: PipelineState) -> list[str]:
        output_lines = []

        dep_rules = state.rules[RuleFile.python_deprecation]
        rem_rules = state.rules[RuleFile.python_removal]

        # Clean deprecations from superseded rules
        cleaned_dep, removed_deps_pairs = _clean_superseded_deprecations(dep_rules, rem_rules)
        if removed_deps_pairs:
            output_lines.append(
                f"  Deprecation -> Removal ({len(removed_deps_pairs)} deprecated APIs removed in later versions):"
            )
            for dep_id, rem_id in removed_deps_pairs:
                output_lines.append(f"    {dep_id} -> {rem_id}")
        else:
            output_lines.append("  No superseded deprecations found")

        # Clean deprecations from stale rules
        cleaned_dep, stale_ids = _clean_stale_deprecations(
            cleaned_dep,
            state.python_analysis_results[state.versions[-1]].deprecations,
        )
        if stale_ids:
            output_lines.append(
                f"  Stale deprecations ({len(stale_ids)} rules no longer deprecated in {state.versions[-1]}):"
            )
            for stale_id in stale_ids:
                output_lines.append(f"    {stale_id}")
        else:
            output_lines.append("  No stale deprecations found")

        # Assign cleaned deprecations
        state.rules[RuleFile.python_deprecation] = cleaned_dep

        # Clean settings from superseded rules
        settings_rules = state.rules[RuleFile.python_settings_removal]
        cleaned_settings, superseded_settings_pairs = _clean_superseded_settings(settings_rules)
        if superseded_settings_pairs:
            output_lines.append(
                f"  Superseded settings ({len(superseded_settings_pairs)} rules covered by a parent rule):"
            )
            for child_path, ancestor_path in superseded_settings_pairs:
                output_lines.append(f"    {child_path} -> {ancestor_path}")
        else:
            output_lines.append("  No superseded settings found")

        # Assign cleaned settings
        state.rules[RuleFile.python_settings_removal] = cleaned_settings

        return output_lines
