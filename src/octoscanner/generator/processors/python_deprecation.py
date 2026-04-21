"""Generate Semgrep rules for deprecated Python OctoPrint APIs.

- Generates new Semgrep rules from ``Deprecation`` objects (from Python analysis).
- Parses deprecation messages to extract replacement suggestions for each rule.
"""

from __future__ import annotations

import re

from ..models import Deprecation, PipelineState, RuleFile
from ..python_receivers import get_receivers_map
from ..rules import (
    build_fqn,
    build_python_symbol_rule,
    next_rule_id,
    pattern_sig_from_rule,
)
from .base import Processor, format_summary

# ---------------------------------------------------------------------------
# Message helpers
# ---------------------------------------------------------------------------


_SUGGESTION_RE = re.compile(
    r"(?:renamed to|replaced by|in favor of|please use|use)\s+(?:the\s+|a\s+|an\s+)?[`'\"\u0060]?(\w[\w.()]*)[`'\"\u0060]?",
    re.IGNORECASE,
)
"""Suggestion regex. Matches phrases like "renamed to X", "use Y instead", "replaced by Z"."""


def _create_suggestion(
    message: str,
    name: str,
    class_name: str | None = None,
    module_path: str | None = None,
) -> str:
    """Extract a replacement suggestion from a deprecation message.

    Looks for phrases like "renamed to X", "use Y instead" and reformats
    them as ``"Use X instead."``. Falls back to ``"Remove usage of X"``.

    Args:
        message (str): Deprecation message text from the source code.
        name (str): Symbol name (e.g. ``"getApiKey"``).
        class_name (str | None): Enclosing class name, or ``None``.
        module_path (str | None): Module path (e.g. ``"octoprint.access"``).

    Returns:
        str: A suggestion string like ``"Use `octoprint.access.User.apikey` instead."`` or
        ``"Remove usage of `octoprint.access.UserManager.getApiKey`."``.

    Examples:
        >>> _create_suggestion(message="Renamed to apikey", name="getApiKey", class_name="User", module_path="octoprint.access")
        'Use `octoprint.access.User.apikey` instead.'
        >>> _create_suggestion(message="use flask.request.remote_addr", name="get_remote_address", class_name=None, module_path="octoprint.server")
        'Use `flask.request.remote_addr` instead.'
        >>> _create_suggestion(message="No longer needed", name="old_func", class_name=None, module_path="octoprint.util")
        'Remove usage of `octoprint.util.old_func`.'
        >>> _create_suggestion(message="Moved elsewhere", name="octoprint.util.comm", class_name=None, module_path="octoprint.util")
        'Remove usage of `octoprint.util.comm`.'
    """
    # Try to extract replacement from message
    suggestion_match = _SUGGESTION_RE.search(message)
    if suggestion_match:
        replacement = suggestion_match.group(1).rstrip(".")
        # Only qualify simple names or names starting with class_name
        # External refs like "flask.request.remote_addr" should not be prefixed
        if "." not in replacement:
            replacement = build_fqn(replacement, class_name, module_path)
        elif class_name and replacement.startswith(f"{class_name}."):
            replacement = f"{module_path}.{replacement}" if module_path else replacement
        return f"Use `{replacement}` instead."

    # Fallback: suggest removing usage
    # If name already contains dots (e.g. module imports), it's already qualified
    full_name = name if "." in name else build_fqn(name, class_name, module_path)
    return f"Remove usage of `{full_name}`."


# ---------------------------------------------------------------------------
# Rule generation
# ---------------------------------------------------------------------------


def _make_rule(dep: Deprecation, rule_id: str, receivers_map: dict[str, list[str]]) -> dict | None:
    """Create a Semgrep deprecation rule.

    Args:
        dep (Deprecation): The deprecation to convert into a rule.
        rule_id (str): Unique rule identifier (e.g. ``"DEP-0001"``).
        receivers_map (dict[str, list[str]]): Class -> receiver-variables
            mapping.

    Returns:
        dict | None: A Semgrep rule dict, or ``None`` if the deprecation
        cannot produce a valid pattern.

    Examples:
        >>> dep = Deprecation(
        ...     name="getApiKey",
        ...     kind=SymbolKind.FUNCTION,
        ...     message="Use apikey",
        ...     since="1.8.0",
        ...     class_name="User",
        ...     module_path="octoprint.access",
        ...     line_number=42,
        ... )
        >>> rule = _make_rule(dep, rule_id="DEP-0001", receivers_map={"User": ["User", "_user", "user"]})
        >>> rule
        {'id': 'DEP-0001',
         'message': 'Use `octoprint.access.User.apikey`.',
         'languages': ['python'],
         'severity': 'MEDIUM',
         'pattern-either': [{'pattern': 'User.getApiKey'},
                            {'pattern': '$X._user.getApiKey'},
                            {'pattern': 'user.getApiKey'}],
         'metadata': {'type': 'deprecation',
                      'since': '1.8.0',
                      'suggestion': 'Use `octoprint.access.User.apikey` instead.',
                      '_ref': 'User.getApiKey'}}
    """
    # Qualify symbol name with fully qualified name (e.g. "use foo instead" -> "use `module.Class.foo` instead") in message
    message = dep.message
    if not message.startswith(f"`{dep.module_path}."):
        qualified = f"`{build_fqn(dep.name, dep.class_name, dep.module_path)}`"

        # Try backtick-quoted name first: `foo` -> `module.Class.foo`
        message = message.replace(f"`{dep.name}`", qualified, 1)

        # Fallback: bare name -> `module.Class.foo` (if message doesn't start with backtick)
        if not message.startswith("`"):
            message = message.replace(dep.name, qualified, 1)

    return build_python_symbol_rule(
        rule_id,
        dep.name,
        dep.kind,
        dep.class_name,
        dep.module_path,
        receivers_map,
        message,
        metadata={
            "type": "deprecation",
            "since": dep.since,
            "suggestion": _create_suggestion(dep.message, dep.name, dep.class_name, dep.module_path),
        },
        severity="MEDIUM",
    )


def _generate_rules(
    deprecations: list[Deprecation],
    existing_deprecations_rules: list[dict],
    class_hierarchy: dict[str, list[str]],
    existing_removal_rules: list[dict] | None = None,
) -> tuple[list[dict], int]:
    """Generate new deprecation rules, skipping duplicates.

    Deduplicates against both existing deprecation rules AND existing removal
    rules, so a symbol that already has a removal rule won't get a deprecation
    rule.

    Args:
        deprecations (list[Deprecation]): List of ``Deprecation``
            objects from one OctoPrint version.
        existing_deprecations_rules (list[dict]): Already-generated deprecation
            rules to deduplicate against.
        class_hierarchy (dict[str, list[str]]): Class -> base-names
            mapping for receiver inheritance.
        existing_removal_rules (list[dict] | None): Removal rules to
            deduplicate against (a symbol with a removal rule won't get a
            deprecation rule).

    Returns:
        tuple[list[dict], int]: A ``(new_rules, skipped_count)`` tuple where
        ``new_rules`` is the list of freshly-generated rule dicts and
        ``skipped_count`` is the number of deprecations that already had a
        matching rule.

    Examples:
        >>> new_rules, skipped = _generate_rules(
        ...     deprecations, existing_dep, class_hierarchy,
        ... )
        >>> len(new_rules)
        5
    """
    new_rules = []
    skipped = 0

    existing_patterns = {pattern_sig_from_rule(r) for r in existing_deprecations_rules}
    existing_patterns |= {pattern_sig_from_rule(r) for r in existing_removal_rules or []}

    receivers_map = get_receivers_map(class_hierarchy)
    next_id = next_rule_id(existing_deprecations_rules, "DEP")
    generated_patterns = set()

    for dep in deprecations:
        rule = _make_rule(dep, f"DEP-{next_id:04d}", receivers_map)
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


class PythonDeprecationProcessor(Processor):
    title = "Generating python deprecation rules"

    def run(self, state: PipelineState) -> list[str]:
        output_lines = []

        dep_rules = state.rules[RuleFile.python_deprecation]
        rem_rules = state.rules[RuleFile.python_removal]

        total_new = 0
        for version in state.versions:
            analysis = state.python_analysis_results[version]

            if not analysis.deprecations:
                output_lines.append(f"  {version}: no deprecations found")
                continue

            new_rules, already = _generate_rules(
                deprecations=analysis.deprecations,
                existing_deprecations_rules=dep_rules,
                class_hierarchy=analysis.class_hierarchy,
                existing_removal_rules=rem_rules,
            )
            if new_rules:
                dep_rules.extend(new_rules)
                total_new += len(new_rules)
            output_lines.append(format_summary(version, len(new_rules), already, "no deprecations found"))

        output_lines.append("  ---")
        output_lines.append(f"  Total: {total_new} new, {len(dep_rules)} total")

        return output_lines
