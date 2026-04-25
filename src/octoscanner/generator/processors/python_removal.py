"""Generate Semgrep rules for removed Python OctoPrint APIs.

- Detects removals via ``_find_removals``, extending the breaking changes
  found by ``griffe.find_breaking_changes`` with a custom tree-walking that
  also detects private member removals and includes OctoPrint-specific tuning.
- Converts the detected ``Removal`` objects into Semgrep rules.
"""

from __future__ import annotations

import griffe

from ..models import PipelineState, Removal, RuleFile, SymbolKind
from ..python_receivers import format_plugin_self_hint, get_receivers_map
from ..python_utils import ancestry_depth, griffe_mod_path, griffe_to_symbolkind, is_subclass_of
from ..rules import (
    build_fqn,
    build_python_symbol_rule,
    next_rule_id,
    pattern_sig_from_rule,
    ref_earliest_since_map,
)
from .base import Processor, format_summary

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _filter_subclass_duplicates(
    removals: list[Removal],
    hierarchy: dict[str, list[str]],
) -> list[Removal]:
    """Filter removals where the same member is removed from both base and subclass.

    If a member is removed from class A and class B, and B is a subclass of A,
    keep only the removal for A (the base).

    Args:
        removals (list[Removal]): List of removals to filter.
        hierarchy (dict[str, list[str]]): Class -> base-names mapping.

    Returns:
        list[Removal]: Filtered list with subclass duplicates removed.

    Examples:
        >>> hierarchy = {"ApiUser": ["User"]}
        >>> removals = [
        ...     Removal(name="is_anonymous", kind=SymbolKind.ATTRIBUTE, since="2.0.0", class_name="User", module_path="octoprint.access.users"),
        ...     Removal(name="is_anonymous", kind=SymbolKind.ATTRIBUTE, since="2.0.0", class_name="ApiUser", module_path="octoprint.access.users"),
        ... ]
        >>> filtered = _filter_subclass_duplicates(removals, hierarchy)
        >>> filtered
        [Removal(name='is_anonymous', kind=<SymbolKind.ATTRIBUTE: 'attribute'>, since='2.0.0', class_name='User', module_path='octoprint.access.users')]
    """
    result = []

    # Group removals by (module_path, name, kind)
    removal_groups = {}
    for rem in removals:
        key = (rem.module_path, rem.name, rem.kind)
        removal_groups.setdefault(key, []).append(rem)

    # Process removal groups
    for removal_group in removal_groups.values():
        # Single removal - no filtering needed
        if len(removal_group) == 1:
            result.append(removal_group[0])
            continue

        # Find "covered" classes: those that inherit from another in the set
        covered = set()
        class_names = {r.class_name for r in removal_group if r.class_name}
        for class_name in class_names:
            for other in class_names:
                if class_name != other and is_subclass_of(class_name, other, hierarchy):
                    covered.add(class_name)
                    break

        # Keep only removals for base classes (not covered by another)
        for rem in removal_group:
            if rem.class_name not in covered:
                result.append(rem)

    return result


# ---------------------------------------------------------------------------
# Find removals
# ---------------------------------------------------------------------------


def _griffe_breaking_changes(v_old: str, old_mod: griffe.Module, v_new: str, new_mod: griffe.Module) -> list[Removal]:
    """Find removals between two OctoPrint versions using ``griffe.find_breaking_changes``.

    Args:
        v_old (str): The older OctoPrint version string.
        old_mod (griffe.Module): Griffe module for the older OctoPrint version.
        v_new (str): The newer OctoPrint version string.
        new_mod (griffe.Module): Griffe module for the newer OctoPrint version.

    Returns:
        list[Removal]: List of ``Removal`` objects from Griffe's breaking
        changes analysis.
    """
    removals = []

    for breakage in griffe.find_breaking_changes(old_mod, new_mod):
        if breakage.kind != griffe.BreakageKind.OBJECT_REMOVED:
            continue

        # Get the removed object and its kind
        removed = breakage.old_value
        kind = griffe_to_symbolkind(removed)
        if not kind:
            continue

        # Check if the parent is a class
        try:
            parent_is_class = removed.parent and removed.parent.is_class
        except (griffe.AliasResolutionError, Exception):
            parent_is_class = False

        # Skip nested classes - they can't be imported directly
        if kind == SymbolKind.CLASS and parent_is_class:
            continue

        # Skip __init__: the class is still instantiable via the inherited constructor
        if removed.name == "__init__":
            continue

        # Add to removals
        removals.append(
            Removal(
                name=removed.path if removed.is_module else removed.name,
                kind=kind,
                since=v_new,
                class_name=removed.parent.name if parent_is_class else None,
                module_path=griffe_mod_path(removed),
            )
        )

    return removals


def _custom_octoprint_breaking_changes(
    v_old: str, old_mod: griffe.Module, v_new: str, new_mod: griffe.Module
) -> list[Removal]:
    """Find removals between two OctoPrint versions with custom tree-walking.

    Walks Griffe's ``.members`` trees recursively.
    Compared to ``griffe.find_breaking_changes``, this applies the following
    OctoPrint-specific behaviors:

    - Includes private members (e.g. ``PrinterInterface._comm``) that plugins may use.
    - Detects relocated classes (e.g. ``octoprint.access.User`` -> ``octoprint.access.users.User``)
      and diffs old members against them.
    - Resolves alias targets (e.g. ``PrinterInterface = PrinterMixin``).
    - Cascades module removals, emitting rules for all nested members.
    - Skips alias members (re-exports) to avoid noise.
    - Checks ``inherited_members`` to avoid detecting a false removal when a method
      moves to a base class.

    Args:
        v_old (str): The older OctoPrint version string.
        old_mod (griffe.Module): Griffe module for the older OctoPrint version.
        v_new (str): The newer OctoPrint version string.
        new_mod (griffe.Module): Griffe module for the newer OctoPrint version.

    Returns:
        list[Removal]: List of ``Removal`` objects.

    Examples:
        >>> old = griffe.load("octoprint", search_paths=[Path("octoprint_src/1.10.0/src")])
        >>> new = griffe.load("octoprint", search_paths=[Path("octoprint_src/1.11.0/src")])
        >>> removals = _custom_octoprint_breaking_changes("1.10.0", old, "1.11.0", new)
    """

    def _build_class_index(root: griffe.Object) -> dict[str, griffe.Object]:
        """Build a name -> class mapping by walking the module tree.

        Args:
            root (griffe.Object): The root module to index.

        Returns:
            dict[str, griffe.Object]: Mapping from class name to class object.
                Only the first occurrence of each class name is stored.

        Examples:
            >>> index = _build_class_index(new_mod)
            >>> index["User"].is_class
            True
        """
        index = {}

        def walk(obj: griffe.Object) -> None:
            for member in obj.members.values():
                try:
                    if member.is_class:
                        if member.name not in index:
                            index[member.name] = member
                    if member.is_module and not member.is_alias:
                        walk(member)
                except (griffe.AliasResolutionError, Exception):
                    continue

        walk(root)
        return index

    def _resolve_alias_target(attr: griffe.Object) -> griffe.Object | None:
        """Resolve an attribute that aliases a class to its target class.

        When a class in OctoPrint is replaced by an attribute assignment (e.g.
        ``PrinterInterface = PrinterMixin``), this finds the actual class
        being referenced.

        Args:
            attr (griffe.Object): The attribute to check.

        Returns:
            griffe.Object | None: The target class if ``attr`` is an alias
            to a class, otherwise ``None``.

        Example:
            >>> # Given: PrinterInterface = PrinterMixin
            >>> attr = new_mod["printer"].members["PrinterInterface"]
            >>> target = _resolve_alias_target(attr)
            >>> target.name
            'PrinterMixin'
        """
        # If attr is not an attribute that aliases a class, return None
        if not attr.is_attribute or not hasattr(attr, "value") or attr.value is None:
            return None

        # Get the name of the aliased class
        attr_value_str = str(attr.value).strip()
        if not attr_value_str or not attr_value_str.isidentifier():
            return None

        # Look for the target class among siblings in the same module
        parent = attr.parent
        if parent:
            sibling = parent.members.get(attr_value_str)
            if sibling is not None:
                try:
                    if sibling.is_class:
                        return sibling
                except (griffe.AliasResolutionError, Exception):
                    pass

        # Aliased class not found - return None
        return None

    def _diff(
        old: griffe.Object,
        new: griffe.Object | None,
        new_class_index: dict[str, griffe.Object],
    ) -> list[Removal]:
        """Recursively compare old and new module trees, returning found removals.

        Walks through all members of ``old`` and checks if they exist in ``new``.
        Missing members are recorded as removals. For classes and modules,
        recursion continues to find nested removals.

        Args:
            old (griffe.Object): The object from the older OctoPrint version.
            new (griffe.Object | None): The corresponding object in the newer
                OctoPrint version, or ``None`` if the object was removed.
            new_class_index (dict[str, griffe.Object]): Pre-built index of classes
                in the new module.

        Returns:
            list[Removal]: List of detected removals.

        Example:
            >>> removals = _diff(old_mod, new_mod, new_class_index)
            >>> len(removals) > 0
            True
        """
        removals = []

        for old_member in old.members.values():
            # Skip if the old member is an alias
            if old_member.is_alias:
                continue

            # Get the old member kind
            old_member_kind = griffe_to_symbolkind(old_member)
            if not old_member_kind:
                continue

            # Search the new member corresponding to the old member
            new_member = None
            if new:
                new_member = new.members.get(old_member.name)
                # For classes, also check inherited members (e.g. method moved to base class)
                if new_member is None and new.is_class:
                    try:
                        new_member = new.inherited_members.get(old_member.name)
                    except (griffe.AliasResolutionError, Exception):
                        pass

            # Member has been removed
            if new_member is None:
                # Check if the parent member was a class
                parent_is_class = old_member.parent and old_member.parent.is_class

                # Skip nested classes (e.g. BaseModel.Config) - they can't be imported
                # directly and are usually internal implementation details
                if old_member.is_class and parent_is_class:
                    continue

                # Skip __init__: the class is still instantiable via the inherited constructor
                if old_member.name == "__init__":
                    continue

                # Add member to removals
                removals.append(
                    Removal(
                        name=old_member.path if old_member.is_module else old_member.name,
                        kind=old_member_kind,
                        since=v_new,
                        class_name=old_member.parent.name if parent_is_class else None,
                        module_path=griffe_mod_path(old_member),
                    )
                )

                # If the removed member was a class, check if it was relocated elsewhere
                # and diff the class members against the new location
                if old_member.is_class:
                    relocated = new_class_index.get(old_member.name)
                    removals.extend(_diff(old_member, relocated, new_class_index))

                # If the removed member was a module, descend recursively
                # to mark all its children as removed too
                elif old_member.is_module:
                    removals.extend(_diff(old_member, None, new_class_index))

            # Member was a class and its type changed - it might be aliased
            elif old_member.is_class and not new_member.is_class:
                # Check if the new member is an alias to another class (e.g. PrinterInterface = PrinterMixin)
                alias_target = _resolve_alias_target(new_member)
                if alias_target is None:
                    # Not an alias to another class - actually removed
                    removals.append(
                        Removal(
                            name=old_member.name,
                            kind=SymbolKind.CLASS,
                            since=v_new,
                            class_name=None,
                            module_path=griffe_mod_path(old_member),
                        )
                    )
                else:
                    # It's an alias - class name still usable, check internal differences
                    removals.extend(_diff(old_member, alias_target, new_class_index))

            # Member still exists - recurse to search for deeper differences
            elif old_member.is_module or old_member.is_class:
                removals.extend(_diff(old_member, new_member, new_class_index))

        return removals

    new_mod_class_index = _build_class_index(new_mod)
    return _diff(old_mod, new_mod, new_mod_class_index)


def _find_removals(v_old: str, old_mod: griffe.Module, v_new: str, new_mod: griffe.Module) -> list[Removal]:
    """Find all removals by merging ``_griffe_breaking_changes``and
    ``_custom_octoprint_breaking_changes`` results.

    Combines our custom diffing with Griffe's breaking changes.

    Args:
        v_old (str): The older OctoPrint version string.
        old_mod (griffe.Module): Griffe module for the older OctoPrint version.
        v_new (str): The newer OctoPrint version string.
        new_mod (griffe.Module): Griffe module for the newer OctoPrint version.

    Returns:
        list[Removal]: Deduplicated list of ``Removal`` objects from both sources.

    Examples:
        >>> removals = _find_removals("1.10.0", old_mod, "1.11.0", new_mod)
        >>> removals[0]
        Removal(name='get_user', kind=<SymbolKind.FUNCTION: 'function'>, ...)
    """
    # Get removals
    custom_removals = _custom_octoprint_breaking_changes(v_old, old_mod, v_new, new_mod)
    griffe_removals = _griffe_breaking_changes(v_old, old_mod, v_new, new_mod)

    # Merge and deduplicate
    merged = list(custom_removals)
    seen = {(r.module_path, r.class_name, r.name, r.kind) for r in custom_removals}
    for removal in griffe_removals:
        key = (removal.module_path, removal.class_name, removal.name, removal.kind)
        if key not in seen:
            seen.add(key)
            merged.append(removal)

    # Return
    return merged


# ---------------------------------------------------------------------------
# Rule generation
# ---------------------------------------------------------------------------


def _make_rule(
    rem: Removal,
    rule_id: str,
    receivers_map: dict[str, list[str]],
    was_deprecated: bool,
    dep_since: str | None,
) -> dict | None:
    """Create a Semgrep removal rule.

    Args:
        rem (Removal): The removal to convert into a rule.
        rule_id (str): Unique rule identifier (e.g. ``"REM-0001"``).
        receivers_map (dict[str, list[str]]): Class -> receiver-variables
            mapping.
        was_deprecated (bool): Whether the symbol was previously deprecated.
        dep_since (str | None): OctoPrint version when the symbol was first deprecated.

    Returns:
        dict | None: A Semgrep rule dict, or ``None`` if the removal
        cannot produce a valid pattern.

    Examples:
        >>> rem = Removal(
        ...     name="getApiKey",
        ...     kind=SymbolKind.FUNCTION,
        ...     since="1.8.0",
        ...     class_name="User",
        ...     module_path="octoprint.access",
        ... )
        >>> rule = _make_rule(rem, rule_id="REM-0001", receivers_map={"User": ["User", "_user", "user"]}, was_deprecated=False, dep_since=None)
        >>> rule
        {'id': 'REM-0001',
         'message': '`octoprint.access.User.getApiKey` has been removed.',
         'languages': ['python'],
         'severity': 'CRITICAL',
         'pattern-either': [{'pattern': 'User.getApiKey'},
                            {'pattern': '$X._user.getApiKey'},
                            {'pattern': 'user.getApiKey'}],
         'metadata': {'type': 'removal',
                      'since': '1.8.0',
                      'suggestion': 'Remove usage of `octoprint.access.User.getApiKey`.',
                      '_ref': 'User.getApiKey'}}
    """
    # Pick the message parts based on the symbol kind.
    if rem.kind == SymbolKind.MODULE:
        target, label, suggestion_verb = rem.name, "Module ", "Remove imports of"
    elif rem.kind == SymbolKind.CLASS:
        target, label, suggestion_verb = (
            build_fqn(rem.name, class_name=None, module_path=rem.module_path),
            "Class ",
            "Remove usage of",
        )
    else:
        target, label, suggestion_verb = build_fqn(rem.name, rem.class_name, rem.module_path), "", "Remove usage of"

    # Build the plugin-side "self" hint (e.g. "self._printer.fake_ack") when the
    # enclosing class is a well-known OctoPrint class injected into plugins.
    self_hint = format_plugin_self_hint(rem.class_name, rem.name)
    self_hint = f" {self_hint}" if self_hint else ""

    # Build the subject (shared message prefix) and the suggestion string.
    subject = f"{label}`{target}`{self_hint}"
    suggestion = f"{suggestion_verb} `{target}`{self_hint}."

    # Build the message, enriching it with the "was deprecated" context when applicable.
    if was_deprecated:
        message = (
            f"{subject} was deprecated since {dep_since} and has been removed."
            if dep_since
            else f"{subject} was previously deprecated and has been removed."
        )
    else:
        message = f"{subject} has been removed."

    return build_python_symbol_rule(
        rule_id,
        rem.name,
        rem.kind,
        rem.class_name,
        rem.module_path,
        receivers_map,
        message,
        metadata={"type": "removal", "since": rem.since, "suggestion": suggestion},
        severity="CRITICAL",
    )


def _generate_rules(
    removals: list[Removal],
    existing_removal_rules: list[dict],
    class_hierarchy: dict[str, list[str]],
    deprecated_refs_since_map: dict[str, str | None],
) -> tuple[list[dict], int]:
    """Generate new removal rules, deduplicating against existing rules.

    Args:
        removals (list[Removal]): List of ``Removal`` objects to generate rules for.
        existing_removal_rules (list[dict]): Already-generated removal rules
            to deduplicate against.
        class_hierarchy (dict[str, list[str]]): Class -> base-names
            mapping for receiver inheritance.
        deprecated_refs_since_map (dict[str, str | None]):
            Ref -> ``since`` mapping for existing deprecation rules.
            Used to enrich removal messages with "deprecated since X" context.

    Returns:
        tuple[list[dict], int]: A ``(new_rules, skipped_count)`` tuple where
            ``new_rules`` is the list of freshly-generated rule dicts and
            ``skipped_count`` is the number of removals that already had a
            matching rule.

    Examples:
        >>> removals = [
        ...     Removal(name="getApiKey", kind=SymbolKind.FUNCTION, since="1.11.0", class_name="User", module_path="octoprint.access"),
        ... ]
        >>> existing_rem = []
        >>> hierarchy = {"ApiUser": ["User"]}
        >>> dep_refs = {"octoprint.access.User.getApiKey": "1.9.0"}
        >>> new_rules, skipped = _generate_rules(
        ...     removals, existing_rem,
        ...     hierarchy, deprecated_refs_since_map=dep_refs,
        ... )
        >>> len(new_rules)
        1
    """
    new_rules = []
    skipped = 0

    existing_patterns = {pattern_sig_from_rule(r) for r in existing_removal_rules}

    receivers_map = get_receivers_map(class_hierarchy)
    next_id = next_rule_id(existing_removal_rules, "REM")
    generated_patterns = set()

    removed_classes = {r.name for r in removals if r.kind == SymbolKind.CLASS}

    # Filter out duplicate removals where the same member is removed from both
    # a base class and its subclass (e.g. User.is_anonymous and ApiUser.is_anonymous),
    # keeping only the base class removal.
    filtered_removals = _filter_subclass_duplicates(removals, class_hierarchy)

    # Sort removals so base classes come before subclasses. When multiple
    # removals produce the same Semgrep pattern (e.g. User.is_admin and
    # AnonymousUser.is_admin both match current_user.is_admin), the first
    # one wins the dedup. Preferring base classes yields better messages.
    sorted_removals = sorted(
        filtered_removals,
        key=lambda r: (
            # Fewer ancestors = base class, preferred in dedup for clearer messages
            ancestry_depth(r.class_name, class_hierarchy) if r.class_name else 0,
            r.module_path,
            r.class_name or "",
            r.name,
        ),
    )

    for rem in sorted_removals:
        # Skip members of removed classes that have no useful receivers:
        # the class import rule already catches the import, and using just
        # the bare class name pattern would risk false positives.
        if rem.class_name and rem.kind not in {SymbolKind.CLASS, SymbolKind.MODULE}:
            receivers = receivers_map.get(rem.class_name)
            if not receivers and rem.class_name in removed_classes:
                continue

        ref = build_fqn(rem.name, rem.class_name, rem.module_path)
        was_deprecated = ref in deprecated_refs_since_map
        dep_since = deprecated_refs_since_map.get(ref) if was_deprecated else None
        rule = _make_rule(rem, f"REM-{next_id:04d}", receivers_map, was_deprecated, dep_since)

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


class PythonRemovalProcessor(Processor):
    title = "Generating python removal rules"

    def run(self, state: PipelineState) -> list[str]:
        output_lines = []

        rem_rules = state.rules[RuleFile.python_removal]

        total_new = 0
        for v_old, v_new in zip(state.versions, state.versions[1:]):
            removals = _find_removals(
                v_old,
                state.python_analysis_results[v_old].griffe_module,
                v_new,
                state.python_analysis_results[v_new].griffe_module,
            )
            if not removals:
                output_lines.append(f"  {v_old} -> {v_new}: no removals")
                continue

            new_rules, already = _generate_rules(
                removals=removals,
                existing_removal_rules=rem_rules,
                class_hierarchy=state.python_analysis_results[v_new].class_hierarchy,
                deprecated_refs_since_map=ref_earliest_since_map(state.python_analysis_results[v_old].deprecations),
            )
            if new_rules:
                rem_rules.extend(new_rules)
                total_new += len(new_rules)
            output_lines.append(format_summary(f"{v_old} -> {v_new}", len(new_rules), already, "no removals"))

        output_lines.append("  ---")
        output_lines.append(f"  Total: {total_new} new, {len(rem_rules)} total")

        return output_lines
