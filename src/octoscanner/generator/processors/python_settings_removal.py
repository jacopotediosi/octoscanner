"""Generate Semgrep rules for removed OctoPrint settings paths.

Detects settings paths that have been removed between OctoPrint versions and
generates Semgrep rules to catch plugin code accessing them.

Plugins access global OctoPrint settings via the PluginSettings wrapper, e.g.
(complete list in `_GLOBAL_SETTINGS_METHODS`):
- `self._settings.global_get(["serial", "autoconnect"])`
- `self._settings.global_get_boolean(["feature", "autoUppercaseBlacklist"])`
"""

from __future__ import annotations

from ..models import PipelineState, RuleFile
from ..rules import build_rule, next_rule_id, pattern_sig_from_rule
from .base import Processor, format_summary

_GLOBAL_SETTINGS_METHODS = [
    "global_get",
    "global_get_boolean",
    "global_get_float",
    "global_get_int",
    "global_set",
    "global_set_boolean",
    "global_set_float",
    "global_set_int",
]
"""PluginSettings global_* methods for accessing OctoPrint settings."""


def _find_removed_settings_paths(
    old_paths: set[tuple[str, ...]],
    new_paths: set[tuple[str, ...]],
) -> set[tuple[str, ...]]:
    """Find settings paths removed between two OctoPrint versions, collapsed to
    their highest fully-removed ancestor prefix.

    For example, if ``serial.capabilities.autoreport_pos``,
    ``serial.capabilities.autoreport_temp``, etc. are all removed and NO path
    starting with ``serial`` survives in ``new_paths``, emit just ``serial``
    instead of each individual leaf.

    Args:
        old_paths (set[tuple[str, ...]]): All settings paths in the old version.
        new_paths (set[tuple[str, ...]]): All settings paths in the new version.

    Returns:
        set[tuple[str, ...]]: Set of removed paths to emit rules for.
    """

    def has_comparable_in_new(path: tuple[str, ...]) -> bool:
        """True if any new_paths path is a prefix of, equal to, or extends *path*."""
        return any(np[: len(path)] == path or path[: len(np)] == np for np in new_paths)

    def is_fully_removed(prefix: tuple[str, ...]) -> bool:
        """True if no path in new_paths starts with *prefix*."""
        return not any(p[: len(prefix)] == prefix for p in new_paths)

    result = set()

    for path in old_paths - new_paths:
        # Skip paths that still exist in some form in the new schema
        # (widened to a nested object, or narrowed into a generic container).
        if has_comparable_in_new(path):
            continue

        # Shorten to the highest ancestor prefix that is fully removed.
        # If none qualifies, keep the full path.
        shortened = path
        for i in range(1, len(path)):
            prefix = path[:i]
            if is_fully_removed(prefix):
                shortened = prefix
                break
        result.add(shortened)

    return result


def _make_rule(removed_path: tuple[str, ...], since: str, rule_id: str) -> dict | None:
    """Create a Semgrep rule for a settings removal.

    Args:
        removed_path (tuple[str, ...]): The removed settings path.
        since (str): OctoPrint version where the removal occurred.
        rule_id (str): Unique rule ID (e.g. ``"STG-0001"``).

    Returns:
        dict | None: Semgrep rule dict, or ``None`` if the settings path is
        in the ignored refs list.
    """
    removed_path_str = ".".join(removed_path)

    # Semgrep list pattern matching the path with trailing "..." to match any depth
    list_pattern = "[" + ", ".join(f'"{seg}"' for seg in removed_path) + ", ...]"

    # Generate patterns for PluginSettings global_* methods.
    # Setter methods have a value argument.
    patterns = [
        {"pattern": f"$X.{m}({list_pattern}, ...)"}
        if m.startswith("global_set")
        else {"pattern": f"$X.{m}({list_pattern})"}
        for m in _GLOBAL_SETTINGS_METHODS
    ]

    return build_rule(
        rule_id=rule_id,
        ref=removed_path_str,
        message=f"The `{removed_path_str}` settings path has been removed in OctoPrint {since}.",
        patterns=patterns,
        metadata={
            "type": "removal",
            "since": since,
            "suggestion": f"Remove usage of settings paths under `{removed_path_str}`.",
        },
        severity="CRITICAL",
    )


def _generate_rules(
    removed_paths: set[tuple[str, ...]],
    since: str,
    existing_rules: list[dict],
) -> tuple[list[dict], int]:
    """Generate Semgrep rules for settings removals, deduplicating against existing rules.

    Args:
        removed_paths (set[tuple[str, ...]]): Removed settings paths to process.
        since (str): OctoPrint version where the removals occurred.
        existing_rules (list[dict]): Already existing rules (to avoid duplicates).

    Returns:
        tuple[list[dict], int]: A ``(new_rules, skipped_count)`` tuple where
        ``new_rules`` is the list of freshly-generated rule dicts and
        ``skipped_count`` is the number of paths whose pattern already had a
        matching rule.
    """
    new_rules = []
    skipped = 0

    existing_patterns = {pattern_sig_from_rule(r) for r in existing_rules}
    next_id = next_rule_id(existing_rules, "STG")

    for path in sorted(removed_paths):
        rule = _make_rule(path, since, f"STG-{next_id:04d}")

        if rule is None:
            continue

        pattern_sig = pattern_sig_from_rule(rule)
        if pattern_sig in existing_patterns:
            skipped += 1
            continue

        existing_patterns.add(pattern_sig)
        new_rules.append(rule)
        next_id += 1

    return new_rules, skipped


class PythonSettingsRemovalProcessor(Processor):
    title = "Generating python settings removal rules"

    def run(self, state: PipelineState) -> list[str]:
        output_lines = []

        settings_removal_rules = state.rules[RuleFile.python_settings_removal]

        total_new = 0
        for v_old, v_new in zip(state.versions, state.versions[1:]):
            old_settings_paths = state.python_analysis_results[v_old].settings_paths
            new_settings_paths = state.python_analysis_results[v_new].settings_paths

            removed_settings_paths = _find_removed_settings_paths(old_settings_paths, new_settings_paths)

            if not removed_settings_paths:
                output_lines.append(f"  {v_old} -> {v_new}: no settings removals")
                continue

            new_rules, already = _generate_rules(
                removed_paths=removed_settings_paths, since=v_new, existing_rules=settings_removal_rules
            )

            if new_rules:
                settings_removal_rules.extend(new_rules)
                total_new += len(new_rules)

            output_lines.append(format_summary(f"{v_old} -> {v_new}", len(new_rules), already, "no settings removals"))

        output_lines.append("  ---")
        output_lines.append(f"  Total: {total_new} new, {len(settings_removal_rules)} total")

        return output_lines
