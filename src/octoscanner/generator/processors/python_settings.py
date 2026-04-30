"""Generate Semgrep rules for removed/deprecated OctoPrint settings paths.

Detects settings paths that have been removed between OctoPrint versions and
generates Semgrep rules to catch plugin code accessing them.

Plugins access global OctoPrint settings through several entry points, all
covered below:

- ``PluginSettings`` wrapper with ``global_*`` methods, e.g.
  ``self._settings.global_get(["foo", "bar"])``.
- ``PluginSettings.settings`` attribute exposing the underlying ``Settings``
  instance, e.g. ``self._settings.settings.get(["foo", "bar"])``.
- ``octoprint.settings.settings()`` factory returning the global ``Settings``
  singleton, e.g. ``settings().getBoolean(["foo", "bar"])``.

When a removed path is still covered by a deprecated compatibility overlay,
reads keep working (with a deprecation warning) but writes are silently
dropped. In that case the processor emits two rules instead of one:

- A ``deprecation`` rule on the path's read methods.
- A ``removal`` rule on the path's write methods.
"""

from __future__ import annotations

from ..models import PipelineState, RuleFile
from ..rules import build_rule, next_rule_id, pattern_sig_from_rule
from .base import Processor, format_summary

_PLUGIN_SETTINGS_GLOBAL_GET_METHODS = [
    "global_get",
    "global_get_boolean",
    "global_get_float",
    "global_get_int",
    "global_has",
]
_PLUGIN_SETTINGS_GLOBAL_SET_METHODS = [
    "global_remove",
    "global_set",
    "global_set_boolean",
    "global_set_float",
    "global_set_int",
]
_PLUGIN_SETTINGS_GLOBAL_METHODS = _PLUGIN_SETTINGS_GLOBAL_GET_METHODS + _PLUGIN_SETTINGS_GLOBAL_SET_METHODS

_PLUGIN_SETTINGS_RECEIVERS = [
    "$SELF._settings",
]
# Not official OctoPrint receivers, but common plugin rebinding patterns
# (e.g. self.settings = self._settings).
_EXTRA_PLUGIN_SETTINGS_RECEIVERS = [
    "$SELF.settings",
    "$SELF.get_settings()",
    "$SELF._plugin._settings",
]
_PLUGIN_SETTINGS_RECEIVERS += _EXTRA_PLUGIN_SETTINGS_RECEIVERS

_SETTINGS_GET_METHODS = [
    "get",
    "getBoolean",
    "getFloat",
    "getInt",
    "get_boolean",
    "get_float",
    "get_int",
    "has",
]
_SETTINGS_SET_METHODS = [
    "remove",
    "set",
    "setBoolean",
    "setFloat",
    "setInt",
    "set_boolean",
    "set_float",
    "set_int",
]
_SETTINGS_METHODS = _SETTINGS_GET_METHODS + _SETTINGS_SET_METHODS

_SETTINGS_RECEIVERS = [
    "$SELF._settings.settings",
    "$SETTINGS.settings()",
    "settings()",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def is_covered_by_compat(
    path: tuple[str, ...],
    compat_settings_paths: dict[tuple[str, ...], str],
) -> bool:
    """Return whether ``path`` (or one of its descendants) is covered by a
    compat overlay.

    Args:
        path (tuple[str, ...]): The settings path to check.
        compat_settings_paths (dict[tuple[str, ...], str]): Mapping from covered
        settings path to its deprecation message.

    Returns:
        bool: ``True`` if ``path`` or one of its descendants is covered by a
        compat overlay, ``False`` otherwise.

    Examples:
        Exact match:

        >>> is_covered_by_compat(("webcam", "stream"), {("webcam", "stream"): "msg"})
        True

        Wildcard prefix match:

        >>> is_covered_by_compat(("serial", "foo", "bar"), {("serial", "*"): "msg"})
        True

        Descendant coverage (a longer covered path lives under ``path``):

        >>> is_covered_by_compat(("webcam",), {("webcam", "stream"): "msg"})
        True
    """
    # Exact match
    if path in compat_settings_paths:
        return True
    # Wildcard prefix match
    for i in range(1, len(path) + 1):
        if path[:i] + ("*",) in compat_settings_paths:
            return True
    # Descendant coverage
    return any(len(p) > len(path) and p[: len(path)] == path for p in compat_settings_paths)


# ---------------------------------------------------------------------------
# Find removed settings paths
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# Rule generation
# ---------------------------------------------------------------------------


def _compat_message_for(
    path: tuple[str, ...],
    compat_settings_paths: dict[tuple[str, ...], str],
) -> str | None:
    """Return the compat overlay message covering ``path`` (if any).

    Args:
        path (tuple[str, ...]): The settings path to check.
        compat_settings_paths (dict[tuple[str, ...], str]): Mapping from
        covered settings path to its deprecation message.

    Returns:
        str | None: The compat overlay's deprecation message, or ``None`` if
        the path is not covered.
    """
    # Exact match
    if path in compat_settings_paths:
        return compat_settings_paths[path]
    # Wildcard prefix match
    for i in range(1, len(path) + 1):
        prefix_wildcard = path[:i] + ("*",)
        if prefix_wildcard in compat_settings_paths:
            return compat_settings_paths[prefix_wildcard]
    # Descendant coverage
    descendants = sorted(p for p in compat_settings_paths if len(p) > len(path) and p[: len(path)] == path)
    if descendants:
        return compat_settings_paths[descendants[0]]
    return None


def make_rule(
    removed_path: tuple[str, ...],
    since: str,
    rule_id: str,
    methods_kind: str,
    target_file: RuleFile,
    compat_message: str | None = None,
) -> dict | None:
    """Create a Semgrep rule for a settings removal or deprecation.

    Args:
        removed_path (tuple[str, ...]): The settings path being targeted.
        since (str): OctoPrint version where the change occurred.
        rule_id (str): Unique rule ID (e.g. ``"STG-REM-0001"`` or ``"STG-DEP-0001"``).
        methods_kind (str): One of ``"all"``, ``"get"``, ``"set"``. Selects
            which subset of accessor methods the rule's pattern matches.
        target_file (RuleFile): The rule file the rule will be written to.
        compat_message (str | None): For deprecation rules, the human-readable
            deprecation message extracted from the compat overlay.

    Returns:
        dict | None: Semgrep rule dict, or ``None`` if the settings path is
        in the ignored refs list.
    """
    removed_path_str = ".".join(removed_path)
    list_pattern = "[" + ", ".join(f'"{seg}"' for seg in removed_path) + ", ...]"

    if methods_kind == "all":
        plugin_methods = _PLUGIN_SETTINGS_GLOBAL_METHODS
        settings_methods = _SETTINGS_METHODS
    elif methods_kind == "get":
        plugin_methods = _PLUGIN_SETTINGS_GLOBAL_GET_METHODS
        settings_methods = _SETTINGS_GET_METHODS
    elif methods_kind == "set":
        plugin_methods = _PLUGIN_SETTINGS_GLOBAL_SET_METHODS
        settings_methods = _SETTINGS_SET_METHODS
    else:
        raise ValueError(f"Unknown methods_kind: {methods_kind!r}")

    pattern_body = {
        "pattern-either": [
            {
                "patterns": [
                    {
                        "pattern-either": [
                            {"pattern": f"{r}.$METHOD({list_pattern}, ...)"} for r in _PLUGIN_SETTINGS_RECEIVERS
                        ]
                    },
                    {
                        "metavariable-regex": {
                            "metavariable": "$METHOD",
                            "regex": f"^({'|'.join(plugin_methods)})$",
                        }
                    },
                ]
            },
            {
                "patterns": [
                    {"pattern-either": [{"pattern": f"{r}.$METHOD({list_pattern}, ...)"} for r in _SETTINGS_RECEIVERS]},
                    {
                        "metavariable-regex": {
                            "metavariable": "$METHOD",
                            "regex": f"^({'|'.join(settings_methods)})$",
                        }
                    },
                ]
            },
        ]
    }

    if target_file is RuleFile.python_settings_removal:
        if methods_kind == "set":
            message = (
                f"Writes to the `{removed_path_str}` settings path are silently dropped "
                f"by the OctoPrint {since} compatibility overlay. The path was removed in OctoPrint {since}."
            )
        else:
            message = f"The `{removed_path_str}` settings path has been removed in OctoPrint {since}."
        suggestion = f"Remove usage of settings paths under `{removed_path_str}`."
    elif target_file is RuleFile.python_settings_deprecation:
        message = (
            f"The `{removed_path_str}` settings path is deprecated since OctoPrint {since} "
            f"and only kept reachable via a compatibility overlay. {compat_message or ''}".strip()
        )
        suggestion = f"Migrate away from `{removed_path_str}`. {compat_message or ''}".strip()
    else:
        raise ValueError(f"Unsupported target_file: {target_file!r}")

    return build_rule(
        rule_id=rule_id,
        ref=removed_path_str,
        message=message,
        pattern_body=pattern_body,
        metadata={
            "type": target_file.value.rules_type,
            "since": since,
            "suggestion": suggestion,
        },
        severity=target_file.value.severity,
    )


def _generate_rules(
    removed_paths: set[tuple[str, ...]],
    since: str,
    compat_settings_paths: dict[tuple[str, ...], str],
    existing_removal_rules: list[dict],
    existing_deprecation_rules: list[dict],
) -> tuple[list[dict], list[dict], int]:
    """Generate Semgrep rules for settings removals and deprecations.

    For each removed path:
    - If covered by a compat overlay in the new version, emits a deprecation
      rule on the `get` methods plus a removal rule on the `set` methods.
    - Otherwise, emits a single removal rule covering all methods.

    Args:
        removed_paths (set[tuple[str, ...]]): Removed settings paths to process.
        since (str): OctoPrint version where the removals occurred.
        compat_settings_paths (dict[tuple[str, ...], str]): Compat overlay
            mapping from covered settings path to its deprecation message for
            the new version.
        existing_removal_rules (list[dict]): Already existing settings removal
            rules.
        existing_deprecation_rules (list[dict]): Already existing settings
            deprecation rules.

    Returns:
        tuple[list[dict], list[dict], int]: A
        ``(new_removal_rules, new_deprecation_rules, skipped_count)`` tuple.
        ``skipped_count`` counts paths whose pattern already had a matching
        rule (in either bucket).
    """
    new_removal_rules = []
    new_deprecation_rules = []
    skipped_count = 0

    removal_file = RuleFile.python_settings_removal
    deprecation_file = RuleFile.python_settings_deprecation

    existing_removal_patterns = {pattern_sig_from_rule(r) for r in existing_removal_rules}
    existing_deprecation_patterns = {pattern_sig_from_rule(r) for r in existing_deprecation_rules}
    next_removal_id = next_rule_id(existing_removal_rules, removal_file.value.id_prefix)
    next_deprecation_id = next_rule_id(existing_deprecation_rules, deprecation_file.value.id_prefix)

    for path in sorted(removed_paths):
        compat_message = _compat_message_for(path, compat_settings_paths)

        if compat_message is None:
            rule_variants = [("all", removal_file)]
        else:
            rule_variants = [("get", deprecation_file), ("set", removal_file)]

        for methods_kind, target_file in rule_variants:
            if target_file is removal_file:
                rule_id = f"{removal_file.value.id_prefix}-{next_removal_id:04d}"
            else:
                rule_id = f"{deprecation_file.value.id_prefix}-{next_deprecation_id:04d}"

            rule = make_rule(
                removed_path=path,
                since=since,
                rule_id=rule_id,
                methods_kind=methods_kind,
                target_file=target_file,
                compat_message=compat_message,
            )
            if rule is None:
                continue

            sig = pattern_sig_from_rule(rule)
            target_existing = (
                existing_removal_patterns if target_file is removal_file else existing_deprecation_patterns
            )
            if sig in target_existing:
                skipped_count += 1
                continue
            target_existing.add(sig)

            if target_file is removal_file:
                new_removal_rules.append(rule)
                next_removal_id += 1
            else:
                new_deprecation_rules.append(rule)
                next_deprecation_id += 1

    return new_removal_rules, new_deprecation_rules, skipped_count


class PythonSettingsRemovalProcessor(Processor):
    title = "Generating python settings removal and deprecation rules"

    def run(self, state: PipelineState) -> list[str]:
        output_lines = []

        settings_removal_rules = state.rules[RuleFile.python_settings_removal]
        settings_deprecation_rules = state.rules[RuleFile.python_settings_deprecation]

        total_new_removals = 0
        total_new_deprecations = 0
        for v_old, v_new in zip(state.versions, state.versions[1:]):
            old_settings_paths = state.python_analysis_results[v_old].settings_paths
            new_settings_paths = state.python_analysis_results[v_new].settings_paths
            new_compat_settings_paths = state.python_analysis_results[v_new].compat_settings_paths

            removed_settings_paths = _find_removed_settings_paths(old_settings_paths, new_settings_paths)

            if not removed_settings_paths:
                output_lines.append(f"  {v_old} -> {v_new}: no settings removals/deprecations")
                continue

            new_removals, new_deprecations, already = _generate_rules(
                removed_paths=removed_settings_paths,
                since=v_new,
                compat_settings_paths=new_compat_settings_paths,
                existing_removal_rules=settings_removal_rules,
                existing_deprecation_rules=settings_deprecation_rules,
            )

            if new_removals:
                settings_removal_rules.extend(new_removals)
                total_new_removals += len(new_removals)
            if new_deprecations:
                settings_deprecation_rules.extend(new_deprecations)
                total_new_deprecations += len(new_deprecations)

            output_lines.append(
                format_summary(
                    f"{v_old} -> {v_new}",
                    len(new_removals) + len(new_deprecations),
                    already,
                    "no settings removals/deprecations",
                )
                + f" (removals: {len(new_removals)}, deprecations: {len(new_deprecations)})"
            )

        output_lines.append("  ---")
        output_lines.append(
            f"  Total: {total_new_removals} new removals ({len(settings_removal_rules)} total), "
            f"{total_new_deprecations} new deprecations ({len(settings_deprecation_rules)} total)"
        )

        return output_lines
