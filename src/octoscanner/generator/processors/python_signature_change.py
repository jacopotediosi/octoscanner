"""Generate Semgrep rules for Python callables whose signature broke between versions.

Two breakages are detected between consecutive OctoPrint versions:

- Detects dropped keyword parameters via ``_find_removed_parameters``, which
  keeps the ``PARAMETER_REMOVED`` breakages reported by
  ``griffe.find_breaking_changes``.
- Detects properties that stopped returning a callable shim via
  ``_find_removed_call_forms``, which diffs the shims found during analysis:
  the property's own signature is unchanged, yet the ``member()`` call form
  stops working while ``member`` keeps working.

One Semgrep rule is emitted per breakage.
"""

from __future__ import annotations

import griffe

from ..models import PipelineState, RuleFile, SignatureChange, SignatureChangeKind
from ..python_receivers import format_plugin_self_hint, get_receivers_map
from ..python_utils import ancestry_depth, filter_subclass_duplicates
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


def _find_removed_parameters(v_new: str, old_mod: griffe.Module, new_mod: griffe.Module) -> list[SignatureChange]:
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
                kind=SignatureChangeKind.PARAMETER_REMOVED,
                since=v_new,
                class_name=class_name,
                module_path=callable_obj.module.path,
                removed_param=removed_param,
            )
        )

    return changes


def _find_removed_call_forms(
    v_new: str,
    old_shims: set[tuple[str, str, str]],
    new_shims: set[tuple[str, str, str]],
) -> list[SignatureChange]:
    """Detect properties that stopped being callable between OctoPrint versions.

    Emits one :class:`SignatureChange` per property whose callable shim is gone.

    Args:
        v_new (str): The newer OctoPrint version string.
        old_shims (set[tuple[str, str, str]]): Shim-backed properties of the
            older version, as ``(module_path, class_name, name)`` triples.
        new_shims (set[tuple[str, str, str]]): Shim-backed properties of the
            newer version, in the same form.

    Returns:
        list[SignatureChange]: One ``SignatureChange`` entry per dropped shim.
    """
    return [
        SignatureChange(
            name=name,
            kind=SignatureChangeKind.CALL_FORM_REMOVED,
            since=v_new,
            class_name=class_name,
            module_path=module_path,
        )
        for module_path, class_name, name in old_shims - new_shims
    ]


# ---------------------------------------------------------------------------
# Rule generation
# ---------------------------------------------------------------------------


def _generate_patterns(change: SignatureChange, receivers_map: dict[str, list[str]]) -> list[dict]:
    """Build Semgrep call-match patterns for a signature change.

    Args:
        change (SignatureChange): The signature change to convert into patterns.
        receivers_map (dict[str, list[str]]): Class -> receiver-variables mapping.

    Returns:
        list[dict]: A list of Semgrep ``{"pattern": ...}`` dicts, possibly empty
        when no reliable pattern can be produced.
    """
    patterns = []

    call_args = f"..., {change.removed_param}=$V, ..." if change.removed_param else ""

    def _add(call_prefix: str) -> None:
        patterns.append({"pattern": f"{call_prefix}({call_args})"})

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
        ...     kind=SignatureChangeKind.PARAMETER_REMOVED,
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
         'metadata': {'type': 'breaking',
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
        if change.kind == SignatureChangeKind.CALL_FORM_REMOVED:
            message = (
                f"`{target}`{self_hint} is no longer callable: it now returns a plain value, "
                f"so `{change.name}()` raises `TypeError`."
            )
            suggestion = f"Read `{change.name}` as an attribute instead of calling `{change.name}()`."
        else:
            message = f"`{target}`{self_hint} no longer accepts the keyword argument `{change.removed_param}`."
            suggestion = f"Update the call to `{target}`{self_hint} to match its new signature."

    pattern_body = patterns[0] if len(patterns) == 1 else {"pattern-either": patterns}

    metadata = {
        "type": RuleFile.python_signature_change.value.rules_type,
        "since": change.since,
        "suggestion": suggestion,
    }
    if change.removed_param:
        metadata["_removed_param"] = change.removed_param

    return build_rule(
        rule_id=rule_id,
        ref=target,
        message=message,
        pattern_body=pattern_body,
        metadata=metadata,
        severity=RuleFile.python_signature_change.value.severity,
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
        ...         name="add_file",
        ...         kind=SignatureChangeKind.PARAMETER_REMOVED,
        ...         since="1.11.0",
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
    next_id = next_rule_id(existing_rules, RuleFile.python_signature_change.value.id_prefix)
    generated_patterns = set()

    # Filter out duplicate changes affecting the same member on both
    # a base class and its subclass, keeping only the base class change.
    filtered_changes = filter_subclass_duplicates(changes, class_hierarchy)

    # Sort changes so base classes come before subclasses. When multiple
    # changes produce the same Semgrep pattern, the first one wins the dedup.
    # Preferring base classes yields better messages.
    sorted_changes = sorted(
        filtered_changes,
        key=lambda c: (
            # Fewer ancestors = base class, preferred in dedup for clearer messages
            ancestry_depth(c.class_name, class_hierarchy) if c.class_name else 0,
            build_fqn(c.name, c.class_name, c.module_path),
            c.removed_param or "",
        ),
    )

    for change in sorted_changes:
        rule = _make_rule(change, f"{RuleFile.python_signature_change.value.id_prefix}-{next_id:04d}", receivers_map)

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
            old_results = state.python_analysis_results[v_old]
            new_results = state.python_analysis_results[v_new]

            changes = _find_removed_parameters(v_new, old_results.griffe_module, new_results.griffe_module)
            changes += _find_removed_call_forms(
                v_new, old_results.callable_property_shims, new_results.callable_property_shims
            )

            if not changes:
                output_lines.append(f"  {v_old} -> {v_new}: no signature changes")
                continue

            new_rules, already = _generate_rules(
                changes=changes,
                existing_rules=signature_change_rules,
                class_hierarchy=new_results.class_hierarchy,
            )
            if new_rules:
                signature_change_rules.extend(new_rules)
                total_new += len(new_rules)

            output_lines.append(format_summary(f"{v_old} -> {v_new}", len(new_rules), already, "no signature changes"))

        output_lines.append("  ---")
        output_lines.append(f"  Total: {total_new} new, {len(signature_change_rules)} total")

        return output_lines
