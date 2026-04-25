"""Generate Semgrep rules for Python callables whose signatures lost keyword parameters.

Uses ``griffe.find_breaking_changes`` to detect ``PARAMETER_REMOVED`` breakages
between consecutive OctoPrint versions and emits one Semgrep rule per
removed keyword parameter.
"""

from __future__ import annotations

import griffe

from ..models import PipelineState, RuleFile, SignatureChange
from ..python_receivers import format_plugin_self_hint, get_receivers_map
from ..rules import (
    build_fqn,
    build_rule,
    next_rule_id,
    pattern_sig_from_rule,
)
from .base import Processor, format_summary

# ---------------------------------------------------------------------------
# Find signature changes
# ---------------------------------------------------------------------------


def _find_signature_changes(v_new: str, old_mod: griffe.Module, new_mod: griffe.Module) -> list[SignatureChange]:
    """Detect keyword parameters removed from callables between OctoPrint versions.

    Emits one :class:`SignatureChange` per removed keyword parameter.

    Args:
        v_new (str): The newer OctoPrint version string.
        old_mod (griffe.Module): Griffe module for the older OctoPrint version.
        new_mod (griffe.Module): Griffe module for the newer OctoPrint version.

    Returns:
        list[SignatureChange]: One ``SignatureChange`` entry per removed keyword
        parameter.
    """
    changes = []

    for breakage in griffe.find_breaking_changes(old_mod, new_mod):
        if breakage.kind != griffe.BreakageKind.PARAMETER_REMOVED:
            continue

        # Consider only parameters that callers can pass by name
        # (otherwise we cannot generate Semgrep rules for them).
        removed_param = getattr(breakage.old_value, "name", None)
        if not removed_param or getattr(breakage.old_value, "kind", None) not in (
            griffe.ParameterKind.positional_or_keyword,
            griffe.ParameterKind.keyword_only,
        ):
            continue

        callable_obj = breakage.obj

        try:
            parent = callable_obj.parent
            class_name = parent.name if parent and parent.is_class else None
        except griffe.AliasResolutionError:
            class_name = None

        changes.append(
            SignatureChange(
                name=callable_obj.name,
                since=v_new,
                class_name=class_name,
                module_path=callable_obj.module.path,
                removed_param=removed_param,
            )
        )

    return changes


# ---------------------------------------------------------------------------
# Rule generation
# ---------------------------------------------------------------------------


def _generate_patterns(change: SignatureChange, receivers_map: dict[str, list[str]]) -> list[dict]:
    """Build Semgrep kwarg-match patterns for a signature change.

    Args:
        change (SignatureChange): The signature change to convert into patterns.
        receivers_map (dict[str, list[str]]): Class -> receiver-variables mapping.

    Returns:
        list[dict]: A list of Semgrep ``{"pattern": ...}`` dicts, possibly empty
        when no reliable pattern can be produced.
    """
    patterns = []

    def _add(call_prefix: str) -> None:
        patterns.append({"pattern": f"{call_prefix}(..., {change.removed_param}=$V, ...)"})

    if change.class_name and change.name == "__init__":
        # Constructor: emit the class instantiation form ``Receiver(..., kw=$V, ...)``
        # for every receiver, since each can be the call target of an instantiation.
        receivers = receivers_map.get(change.class_name, [change.class_name])
        for receiver in receivers:
            _add(receiver)
    elif change.class_name:
        # Method on a known class: enumerate every receiver variant
        receivers = receivers_map.get(change.class_name, [])
        for receiver in receivers:
            if receiver.startswith("_"):
                _add(f"$X.{receiver}.{change.name}")
            else:
                _add(f"{receiver}.{change.name}")
    else:
        # Module-level function: ``module.func(..., kw=$V, ...)``.
        _add(f"{change.module_path}.{change.name}")

    return patterns


def _make_rule(
    change: SignatureChange,
    rule_id: str,
    receivers_map: dict[str, list[str]],
) -> dict | None:
    """Create a Semgrep signature-change rule.

    Args:
        change (SignatureChange): The signature change to convert into a rule.
        rule_id (str): Unique rule identifier (e.g. ``"SIG-0001"``).
        receivers_map (dict[str, list[str]]): Class -> receiver-variables mapping.

    Returns:
        dict | None: A Semgrep rule dict, or ``None`` if no valid patterns
        can be built.

    Examples:
        >>> change = SignatureChange(
        ...     name="add_file",
        ...     since="1.11.0",
        ...     class_name="FileManager",
        ...     module_path="octoprint.filemanager",
        ...     removed_param="links",
        ... )
        >>> rule = _make_rule(change, rule_id="SIG-0001", receivers_map={"FileManager": ["FileManager", "_file_manager"]})
        >>> rule
        {'id': 'SIG-0001',
         'message': '`octoprint.filemanager.FileManager.add_file` '
                    '(commonly accessed by plugins as '
                    '`self._file_manager.add_file`) no longer accepts '
                    'the keyword argument `links`.',
         'languages': ['python'],
         'severity': 'HIGH',
         'pattern-either': [{'pattern': 'FileManager.add_file(..., links=$V, ...)'},
                            {'pattern': '$X._file_manager.add_file(..., links=$V, ...)'}],
         'metadata': {'type': 'removal',
                      'since': '1.11.0',
                      'suggestion': 'Update the call to '
                                    '`octoprint.filemanager.FileManager.add_file` '
                                    '(commonly accessed by plugins as '
                                    '`self._file_manager.add_file`) to match '
                                    'its new signature.',
                      '_removed_param': 'links',
                      '_ref': 'octoprint.filemanager.FileManager.add_file'}}
    """
    patterns = _generate_patterns(change, receivers_map)
    if not patterns:
        return None

    # For ``__init__`` the user-facing target is the class itself (callers write
    # ``ClassName(...)``, not ``ClassName.__init__(...)``)
    if change.class_name and change.name == "__init__":
        target = build_fqn(change.class_name, None, change.module_path)
        message = f"`{target}` constructor no longer accepts the keyword argument `{change.removed_param}`."
        suggestion = f"Update the call to `{target}(...)` to match its new signature."
    else:
        target = build_fqn(change.name, change.class_name, change.module_path)
        self_hint = format_plugin_self_hint(change.class_name, change.name)
        self_hint = f" {self_hint}" if self_hint else ""
        message = f"`{target}`{self_hint} no longer accepts the keyword argument `{change.removed_param}`."
        suggestion = f"Update the call to `{target}`{self_hint} to match its new signature."

    pattern_body = patterns[0] if len(patterns) == 1 else {"pattern-either": patterns}

    return build_rule(
        rule_id=rule_id,
        ref=target,
        message=message,
        pattern_body=pattern_body,
        metadata={
            "type": "removal",
            "since": change.since,
            "suggestion": suggestion,
            "_removed_param": change.removed_param,
        },
        severity="HIGH",
    )


def _generate_rules(
    changes: list[SignatureChange],
    existing_rules: list[dict],
    class_hierarchy: dict[str, list[str]],
) -> tuple[list[dict], int]:
    """Generate new signature-change rules, deduplicating against existing rules.

    Args:
        changes (list[SignatureChange]): Signature changes to generate rules for.
        existing_rules (list[dict]): Already-generated signature-change rules
            to deduplicate against.
        class_hierarchy (dict[str, list[str]]): Class -> base-names mapping
            for receiver inheritance.

    Returns:
        tuple[list[dict], int]: A ``(new_rules, skipped_count)`` tuple where
            ``new_rules`` is the list of freshly-generated rule dicts and
            ``skipped_count`` is the number of changes that already had a
            matching rule.

    Examples:
        >>> changes = [
        ...     SignatureChange(
        ...         name="add_file", since="1.11.0",
        ...         class_name="FileManager",
        ...         module_path="octoprint.filemanager",
        ...         removed_param="links",
        ...     ),
        ... ]
        >>> new_rules, skipped = _generate_rules(changes=changes, existing_rules=[], class_hierarchy={})
        >>> len(new_rules)
        1
    """
    new_rules = []
    skipped = 0

    existing_patterns = {pattern_sig_from_rule(r) for r in existing_rules}

    receivers_map = get_receivers_map(class_hierarchy)
    next_id = next_rule_id(existing_rules, "SIG")
    generated_patterns = set()

    sorted_changes = sorted(changes, key=lambda c: (build_fqn(c.name, c.class_name, c.module_path), c.removed_param))

    for change in sorted_changes:
        rule = _make_rule(change, f"SIG-{next_id:04d}", receivers_map)

        if rule is None:
            continue

        pattern_sig = pattern_sig_from_rule(rule)
        if pattern_sig in generated_patterns:
            continue

        if pattern_sig in existing_patterns:
            skipped += 1
            continue

        generated_patterns.add(pattern_sig)
        new_rules.append(rule)
        next_id += 1

    return new_rules, skipped


class PythonSignatureChangeProcessor(Processor):
    title = "Generating python signature change rules"

    def run(self, state: PipelineState) -> list[str]:
        output_lines = []

        signature_change_rules = state.rules[RuleFile.python_signature_change]

        total_new = 0
        for v_old, v_new in zip(state.versions, state.versions[1:]):
            changes = _find_signature_changes(
                v_new,
                state.python_analysis_results[v_old].griffe_module,
                state.python_analysis_results[v_new].griffe_module,
            )

            if not changes:
                output_lines.append(f"  {v_old} -> {v_new}: no signature changes")
                continue

            new_rules, already = _generate_rules(
                changes=changes,
                existing_rules=signature_change_rules,
                class_hierarchy=state.python_analysis_results[v_new].class_hierarchy,
            )
            if new_rules:
                signature_change_rules.extend(new_rules)
                total_new += len(new_rules)

            output_lines.append(format_summary(f"{v_old} -> {v_new}", len(new_rules), already, "no signature changes"))

        output_lines.append("  ---")
        output_lines.append(f"  Total: {total_new} new, {len(signature_change_rules)} total")

        return output_lines
