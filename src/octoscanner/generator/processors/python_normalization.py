"""Post-generation normalization of Semgrep rules.

The following cleanup passes are applied in order:

1. **Superseded deprecations**: remove deprecation rules for symbols that
   were later fully removed (a removal rule replaces the deprecation).
2. **Stale deprecations**: remove deprecation rules for symbols that exist
   in the latest OctoPrint version but are no longer marked as deprecated.
   This handles cases where deprecations were reverted in a later version.
3. **Superseded signature changes**: remove signature change rules for
   callables that were later fully removed (a removal rule already covers
   any call to them).
4. **Stale signature changes**: remove signature change rules whose removed
   keyword parameter is present again in the latest OctoPrint version.
   This handles cases where a parameter was removed and later reintroduced.
5. **Promoted settings deprecations**: when the compat overlay that kept a
   deprecated settings path reachable disappears in a later OctoPrint
   version, promote the deprecation rule to a removal rule.
6. **Superseded settings**: remove settings removal rules whose path is
   covered by a more general ancestor rule (e.g. ``serial.capabilities.foo``
   is redundant if ``serial`` is already covered).
"""

from __future__ import annotations

import griffe

from ..models import Deprecation, PipelineState, RuleFile
from ..rules import next_rule_id, ref_earliest_since_map, ref_from_rule
from .base import Processor
from .python_settings import is_covered_by_compat, make_rule


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


def _clean_superseded_signature_changes(
    signature_change_rules: list[dict],
    removal_rules: list[dict],
) -> tuple[list[dict], list[tuple[str, str]]]:
    """Remove signature change rules superseded by a corresponding removal rule.

    When a callable whose signature changed is later fully removed, the removal
    rule already covers any call to it, so the signature change rule becomes
    redundant.

    Args:
        signature_change_rules (list[dict]): List of signature change rule dicts.
        removal_rules (list[dict]): List of removal rule dicts.

    Returns:
        tuple[list[dict], list[tuple[str, str]]]: A
        ``(cleaned_rules, removed_pairs)`` tuple where ``cleaned_rules`` is the
        filtered list of signature change rules and ``removed_pairs`` is a list
        of ``(sig_rule_id, superseding_rem_rule_id)`` for each removed pair.
    """
    cleaned_rules, removed_pairs = [], []

    removal_by_ref = {ref_from_rule(rem): rem.get("id") for rem in removal_rules}

    for sig_rule in signature_change_rules:
        sig_rule_ref = ref_from_rule(sig_rule)
        if sig_rule_ref in removal_by_ref:
            removed_pairs.append((sig_rule.get("id"), removal_by_ref[sig_rule_ref]))
        else:
            cleaned_rules.append(sig_rule)

    return cleaned_rules, removed_pairs


def _clean_stale_signature_changes(
    signature_change_rules: list[dict],
    latest_module: griffe.Module,
) -> tuple[list[dict], list[str]]:
    """Remove signature change rules whose removed parameter is back in the latest
    OctoPrint version.

    Rules without ``_removed_param`` metadata, or whose callable cannot be
    resolved in ``latest_module``, are kept unchanged.

    Args:
        signature_change_rules (list[dict]): List of signature change rule dicts.
        latest_module (griffe.Module): Griffe module for the latest OctoPrint version.

    Returns:
        tuple[list[dict], list[str]]: A ``(kept_rules, removed_ids)`` tuple
        where ``kept_rules`` is the filtered list and ``removed_ids`` the IDs
        of the rules dropped as stale.
    """
    kept_rules, removed_ids = [], []

    root_parts = latest_module.path.split(".")

    for sig_rule in signature_change_rules:
        removed_param = sig_rule.get("metadata", {}).get("_removed_param")
        if not removed_param:
            kept_rules.append(sig_rule)
            continue

        # Strip the module root prefix from the rule's FQN to get the path
        # relative to ``latest_module``
        ref_parts = ref_from_rule(sig_rule).split(".")
        if ref_parts[: len(root_parts)] == root_parts:
            ref_parts = ref_parts[len(root_parts) :]

        # Walk the griffe module tree following the relative path
        obj = latest_module
        try:
            for part in ref_parts:
                obj = obj.members[part]
        except (KeyError, AttributeError, griffe.AliasResolutionError):
            kept_rules.append(sig_rule)
            continue

        parameters = getattr(obj, "parameters", None)
        if parameters is None:
            kept_rules.append(sig_rule)
            continue

        current_param_names = {p.name for p in parameters if getattr(p, "name", None)}
        if removed_param in current_param_names:
            removed_ids.append(sig_rule.get("id"))
        else:
            kept_rules.append(sig_rule)

    return kept_rules, removed_ids


def _promote_stale_settings_deprecations(
    settings_deprecation_rules: list[dict],
    settings_removal_rules: list[dict],
    latest_compat_settings_paths: dict[tuple[str, ...], str],
    latest_version: str,
) -> tuple[list[dict], list[dict], list[tuple[str, str]]]:
    """Promote settings deprecations whose compat layer is gone in the latest version.

    For each settings deprecation rule whose path is no longer covered by the
    compat overlay in ``latest_version``:

    - The deprecation rule is dropped.
    - The corresponding ``set``-only removal rule for the same path (if any) is
      dropped too.
    - A new full-coverage removal rule is appended to the removal list.

    Args:
        settings_deprecation_rules (list[dict]): Current settings deprecation rules.
        settings_removal_rules (list[dict]): Current settings removal rules.
        latest_compat_settings_paths (dict[tuple[str, ...], str]): Compat overlay
            mapping for the latest analyzed OctoPrint version.
        latest_version (str): The latest analyzed OctoPrint version (used as the
            ``since`` of the promoted removal rule).

    Returns:
        tuple[list[dict], list[dict], list[tuple[str, str]]]: A
        ``(remaining_dep_rules, updated_removal_rules, promoted_pairs)`` tuple.
        ``promoted_pairs`` lists ``(path, new_removal_rule_id)`` for each
        promoted entry.
    """
    remaining_dep_rules = []
    promoted_pairs = []
    refs_to_promote = set()

    for dep_rule in settings_deprecation_rules:
        ref = ref_from_rule(dep_rule)
        path = tuple(ref.split("."))
        if is_covered_by_compat(path, latest_compat_settings_paths):
            remaining_dep_rules.append(dep_rule)
        else:
            refs_to_promote.add(ref)

    # Drop the existing set-only removal rules for the promoted paths
    updated_removal_rules = [r for r in settings_removal_rules if ref_from_rule(r) not in refs_to_promote]

    # Append fresh full-coverage removal rules
    removal_file = RuleFile.python_settings_removal
    next_id = next_rule_id(settings_removal_rules, removal_file.value.id_prefix)
    for ref in sorted(refs_to_promote):
        path = tuple(ref.split("."))
        rule_id = f"{removal_file.value.id_prefix}-{next_id:04d}"
        rule = make_rule(
            removed_path=path,
            since=latest_version,
            rule_id=rule_id,
            methods_kind="all",
            target_file=removal_file,
        )
        if rule is None:
            continue
        updated_removal_rules.append(rule)
        promoted_pairs.append((ref, rule_id))
        next_id += 1

    return remaining_dep_rules, updated_removal_rules, promoted_pairs


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
        def emit_section(output_lines: list[str], header: str, items: list[str]) -> None:
            """Append a header line followed by indented items (or "None" if empty)."""
            output_lines.append(f"  {header}")
            if items:
                output_lines.extend(f"    {item}" for item in items)
            else:
                output_lines.append("    None")

        output_lines = []

        latest_version = state.versions[-1]
        latest_results = state.python_analysis_results[latest_version]

        deprecation_rules = state.rules[RuleFile.python_deprecation]
        removal_rules = state.rules[RuleFile.python_removal]
        signature_change_rules = state.rules[RuleFile.python_signature_change]
        settings_removal_rules = state.rules[RuleFile.python_settings_removal]
        settings_deprecation_rules = state.rules[RuleFile.python_settings_deprecation]

        # ---------------------------------------------------------------
        # Clean deprecation rules
        # ---------------------------------------------------------------

        # Deprecations superseded by removals
        cleaned_dep, superseded_dep_pairs = _clean_superseded_deprecations(deprecation_rules, removal_rules)
        emit_section(
            output_lines,
            f"Deprecations superseded by removals ({len(superseded_dep_pairs)} deprecated APIs removed in later versions):",
            [f"{dep_id} -> {rem_id}" for dep_id, rem_id in superseded_dep_pairs],
        )

        # Stale deprecations (no longer deprecated in the latest version)
        cleaned_dep, stale_dep_ids = _clean_stale_deprecations(cleaned_dep, latest_results.deprecations)
        emit_section(
            output_lines,
            f"Stale deprecations ({len(stale_dep_ids)} rules no longer deprecated in {latest_version}):",
            list(stale_dep_ids),
        )

        state.rules[RuleFile.python_deprecation] = cleaned_dep

        # ---------------------------------------------------------------
        # Clean signature change rules
        # ---------------------------------------------------------------

        # Signature changes superseded by removals
        cleaned_sig, superseded_sig_pairs = _clean_superseded_signature_changes(signature_change_rules, removal_rules)
        emit_section(
            output_lines,
            f"Signature changes superseded by removals ({len(superseded_sig_pairs)} signatures whose callable was later removed):",
            [f"{sig_id} -> {rem_id}" for sig_id, rem_id in superseded_sig_pairs],
        )

        # Stale signature changes (removed params are back in the latest version)
        cleaned_sig, stale_sig_ids = _clean_stale_signature_changes(cleaned_sig, latest_results.griffe_module)
        emit_section(
            output_lines,
            f"Stale signature changes ({len(stale_sig_ids)} rules whose removed params are back in {latest_version}):",
            list(stale_sig_ids),
        )

        state.rules[RuleFile.python_signature_change] = cleaned_sig

        # ---------------------------------------------------------------
        # Clean settings rules
        # ---------------------------------------------------------------

        # Promote settings deprecations whose compat layer is gone in the latest version
        cleaned_settings_deps, settings_removal_rules, promoted_pairs = _promote_stale_settings_deprecations(
            settings_deprecation_rules,
            settings_removal_rules,
            latest_results.compat_settings_paths,
            latest_version,
        )
        emit_section(
            output_lines,
            f"Promoted settings deprecations ({len(promoted_pairs)} paths whose compat layer was dropped in {latest_version}):",
            [f"{path} -> {rule_id}" for path, rule_id in promoted_pairs],
        )

        state.rules[RuleFile.python_settings_deprecation] = cleaned_settings_deps

        # Settings superseded by a parent path
        cleaned_settings, superseded_settings_pairs = _clean_superseded_settings(settings_removal_rules)
        emit_section(
            output_lines,
            f"Superseded settings ({len(superseded_settings_pairs)} rules covered by a parent rule):",
            [f"{child} -> {ancestor}" for child, ancestor in superseded_settings_pairs],
        )

        state.rules[RuleFile.python_settings_removal] = cleaned_settings

        # ---------------------------------------------------------------
        # Return
        # ---------------------------------------------------------------

        return output_lines
