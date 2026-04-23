"""Rule utilities"""

from __future__ import annotations

import fnmatch
import functools
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import TypeVar

import yaml
from packaging.version import Version

from .. import RULES_DIR
from .models import Deprecation, Removal, RuleFile, SymbolKind

DeprecationOrRemovalType = TypeVar("T", Deprecation, Removal)


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------


def _clean_message(message: str) -> str:
    """Clean a message: strip whitespace, ensure trailing punctuation.

    Args:
        message (str): Raw message.

    Returns:
        str: Cleaned message.

    Examples:
        >>> _clean_message("  Deprecated since 1.5.0  ")
        'Deprecated since 1.5.0.'
        >>> _clean_message("Use foo instead!")
        'Use foo instead!'
    """
    msg = message.strip()
    if msg and not msg.endswith((".", "!", "?")):
        msg += "."
    return msg


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Rule refs
# ---------------------------------------------------------------------------


def build_fqn(name: str, class_name: str | None, module_path: str | None) -> str:
    """Build a fully qualified name from components.

    Args:
        name (str): Symbol name.
        class_name (str | None): Enclosing class name, or ``None``.
        module_path (str | None): Module path, or ``None``.

    Returns:
        str: Fully qualified name like ``"octoprint.access.User.getApiKey"``.

    Examples:
        >>> build_fqn(name="getApiKey", class_name="User", module_path="octoprint.access")
        'octoprint.access.User.getApiKey'
        >>> build_fqn(name="some_func", class_name=None, module_path="octoprint.util")
        'octoprint.util.some_func'
        >>> build_fqn(name="method", class_name="Class", module_path=None)
        'Class.method'
    """
    if class_name:
        if module_path:
            return f"{module_path}.{class_name}.{name}"
        return f"{class_name}.{name}"
    if module_path:
        return f"{module_path}.{name}"
    return name


def ref_from_rule(rule: dict) -> str:
    """Get the ref stored in a rule's metadata.

    Args:
        rule (dict): A Semgrep rule dict with ``metadata._ref``.

    Returns:
        str: The ref (FQN for Python symbols, dotted path for settings, etc.).

    Examples:
        >>> rule = {"metadata": {"_ref": "User.getApiKey"}}
        >>> ref_from_rule(rule)
        'User.getApiKey'
    """
    return rule["metadata"]["_ref"]


def pattern_sig_from_rule(rule: dict) -> str:
    """Create a hashable signature from a rule's Semgrep pattern structure.

    Two rules with identical pattern structures will have the same signature.

    Args:
        rule (dict): A Semgrep rule dict.

    Returns:
        str: A stable string representation of the rule's pattern structure.

    Examples:
        >>> pattern_sig_from_rule({"pattern": "Foo.bar(...)"})
        '{"pattern": "Foo.bar(...)"}'
        >>> a = pattern_sig_from_rule(
        ...     {"pattern-either": [{"pattern": "A.x"}, {"pattern": "B.x"}]}
        ... )
        >>> b = pattern_sig_from_rule(
        ...     {"pattern-either": [{"pattern": "B.x"}, {"pattern": "A.x"}]}
        ... )
        >>> a == b
        True
    """

    def _canonicalize(node: object) -> object:
        if isinstance(node, dict):
            return {k: _canonicalize(v) for k, v in node.items()}
        if isinstance(node, list):
            canonical_items = [_canonicalize(item) for item in node]
            return sorted(canonical_items, key=lambda x: json.dumps(x, sort_keys=True))
        return node

    keys = (
        "pattern",
        "pattern-either",
        "patterns",
        "mode",
        "pattern-sources",
        "pattern-sinks",
        "pattern-propagators",
        "pattern-sanitizers",
    )
    block = {k: rule[k] for k in keys if k in rule}
    return json.dumps(_canonicalize(block), sort_keys=True)


def ref_earliest_since_map(items: Iterable[DeprecationOrRemovalType]) -> dict[str, str | None]:
    """Build a map of ref -> earliest ``since`` version.

    Keeps the earliest ``since`` when the same symbol is deprecated or removed
    multiple times across OctoPrint versions.

    Args:
        items (Iterable[DeprecationOrRemovalType]): Iterable of Removal or Deprecation items
            (typically merged from multiple OctoPrint versions).

    Returns:
        dict[str, str | None]: Dict mapping refs (FQNs) to the earliest
        ``since`` version string, or ``None`` if no version is known.

    Examples:
        >>> deps = [
        ...     Deprecation("foo", SymbolKind.FUNCTION, "msg", "1.8.0", "Cls", "mod", 1),
        ...     Deprecation("foo", SymbolKind.FUNCTION, "msg", "1.6.0", "Cls", "mod", 1),
        ... ]
        >>> refs = ref_earliest_since_map(deps)
        >>> refs["mod.Cls.foo"]
        '1.6.0'
    """
    refs = {}
    for item in items:
        ref = build_fqn(item.name, item.class_name, item.module_path)
        existing = refs.get(ref)
        if existing is None:
            refs[ref] = item.since
        elif item.since is not None and Version(item.since) < Version(existing):
            refs[ref] = item.since
    return refs


# ---------------------------------------------------------------------------
# Ignored refs
# ---------------------------------------------------------------------------


@functools.cache
def _load_ignored_refs() -> dict[str, list[str]]:
    """Load ignored refs from the configuration file `ignored_refs.yaml`.

    Returns:
        dict[str, list[str]]: Mapping of rule type to list of ref patterns.
    """
    patterns_file = Path(__file__).parent / "ignored_refs.yaml"

    if not patterns_file.exists():
        return {}

    with open(patterns_file) as f:
        return yaml.safe_load(f) or {}


def is_ignored_ref(ref: str, rule_type: str) -> bool:
    """Check if a ref matches any ignored pattern for the given rule type.

    Supports wildcards:
      - ``*`` matches any single path component
      - ``**`` matches any number of path components

    Args:
        ref (str): The ref to check (FQN, dotted settings path, etc.).
        rule_type (str): The rule type to check against (e.g. ``"removal"``).

    Returns:
        bool: True if the ref matches any ignored pattern.
    """
    patterns = _load_ignored_refs().get(rule_type, [])

    for pattern in patterns:
        # Convert ** to placeholder, * to single-component match, then ** to multi-component
        glob_pattern = pattern.replace("**", "\x00").replace("*", "[^.]*").replace("\x00", "*")
        if fnmatch.fnmatch(ref, glob_pattern):
            return True

    return False


# ---------------------------------------------------------------------------
# Semgrep pattern helpers
# ---------------------------------------------------------------------------


def python_symbol_pattern_body(
    name: str,
    kind: SymbolKind,
    class_name: str | None = None,
    module_path: str | None = None,
    receivers: list[str] | None = None,
) -> dict | None:
    """Generate a Semgrep pattern body for a Python symbol.

    Uses two modes, picked per-symbol:

    - **Taint mode** (for class members with a ``class_name``): enables
      intra-file inter-procedural flow tracking (via
      ``opengrep --taint-intrafile``), catching plugins that rebind injected
      attributes in ``__init__`` (``self.printer = self._printer``) and use
      them in other methods. Sources are the receivers (injected attributes
      like ``$X._printer``, bare receivers). Sink is ``$SINK.<name>``.
    - **Pattern mode** (for everything else: MODULE imports, CLASS imports,
      module-level symbols): Opengrep's taint engine does not propagate taint
      through ``from X import Y`` to later uses of ``Y``, so taint sources
      that equal sinks produce no findings. Pattern mode with symbol
      resolution catches both the import line and all qualified/unqualified
      uses of the symbol.

    Args:
        name (str): Symbol name or dotted module path for MODULE kind.
        kind (SymbolKind): Symbol kind.
        class_name (str | None): Enclosing class name (for class members).
        module_path (str | None): Module path (e.g. ``"octoprint.access"``).
        receivers (list[str] | None): Receiver variable names for class
            members. Falls back to ``[class_name]`` if not provided.

    Returns:
        dict | None: A Semgrep pattern body, or ``None`` if invalid. For
        class members: ``{"mode": "taint", "pattern-sources": [...],
        "pattern-sinks": [...]}``. For imports/module-level:
        ``{"pattern": ...}`` or ``{"pattern-either": [...]}``.

    Examples:
        >>> python_symbol_pattern_body("octoprint.server.api", SymbolKind.MODULE)
        {'pattern-either': [{'pattern': 'import octoprint.server.api'}, {'pattern': 'from octoprint.server import api'}, {'pattern': 'from octoprint.server.api import $X'}]}
        >>> python_symbol_pattern_body("start", SymbolKind.FUNCTION, class_name="Printer", receivers=["_printer", "printer"])
        {'mode': 'taint', 'pattern-sources': [{'pattern': '$X._printer'}, {'pattern': 'printer'}], 'pattern-sinks': [{'pattern': '$SINK.start'}]}
    """
    # MODULE: pattern mode
    if kind == SymbolKind.MODULE:
        patterns = [{"pattern": f"import {name}"}]
        if "." in name:
            parent, leaf = name.rsplit(".", 1)
            patterns.append({"pattern": f"from {parent} import {leaf}"})
        patterns.append({"pattern": f"from {name} import $X"})
        return patterns[0] if len(patterns) == 1 else {"pattern-either": patterns}

    # CLASS import: pattern mode
    if kind == SymbolKind.CLASS:
        if not module_path:
            return None
        patterns = [
            {"pattern": f"from {module_path} import {name}"},
            {"pattern": f"{module_path}.{name}"},
        ]
        return {"pattern-either": patterns}

    # Class member: taint mode (real taint flow)
    if class_name:
        rcvs = receivers or [class_name]
        sources = []
        for r in rcvs:
            if r.startswith("_"):
                # Injected attribute form: $X._printer
                sources.append({"pattern": f"$X.{r}"})
            else:
                # Bare receiver or class name: printer, PrinterInterface
                sources.append({"pattern": r})
        # Sink matches both bare ref (`.name`) and calls (`.name(...)`)
        sinks = [{"pattern": f"$SINK.{name}"}]
        return {
            "mode": "taint",
            "pattern-sources": sources,
            "pattern-sinks": sinks,
        }

    # Module-level symbol: pattern mode
    if module_path:
        patterns = [
            {"pattern": f"{module_path}.{name}"},
            {"pattern": f"from {module_path} import {name}"},
        ]
        return {"pattern-either": patterns}

    return None


# ---------------------------------------------------------------------------
# Rule builders
# ---------------------------------------------------------------------------


def build_rule(
    rule_id: str,
    ref: str,
    message: str,
    pattern_body: dict,
    metadata: dict,
    severity: str,
) -> dict | None:
    """Assemble a complete Semgrep rule dict.

    Returns ``None`` if ``ref`` matches an entry in ``ignored_refs.yaml``
    for the rule type declared in ``metadata["type"]``.

    The ``ref`` argument is stored under ``metadata._ref`` and used as
    the unique identity of the rule (FQN for Python symbols, dotted path for
    settings paths, etc.).

    Args:
        rule_id (str): Unique rule identifier (e.g. ``"DEP-0001"``).
        ref (str): Ref identifying what the rule targets. Stored under
            ``metadata._ref``.
        message (str): Human-readable message for the Semgrep finding.
        pattern_body (dict): Pre-built Semgrep pattern block, e.g.
            ``{"pattern": "..."}``, ``{"pattern-either": [...]}``,
            ``{"patterns": [...]}``.
        metadata (dict): Dict of metadata fields.
        severity (str): Semgrep severity.

    Returns:
        dict | None: A complete Semgrep rule dict, or ``None`` if the ref
        is in the ignored refs list for the given rule type.

    Examples:
        >>> build_rule(
        ...     rule_id="DEP-0001",
        ...     ref="octoprint.util.foo",
        ...     message="Deprecated API.",
        ...     pattern_body={"pattern": "octoprint.util.foo"},
        ...     metadata={"type": "deprecation", "since": "1.8.0"},
        ...     severity="MEDIUM",
        ... )
        {'id': 'DEP-0001',
         'message': 'Deprecated API.',
         'languages': ['python'],
         'severity': 'MEDIUM',
         'pattern': 'octoprint.util.foo',
         'metadata': {'type': 'deprecation',
                      'since': '1.8.0',
                      '_ref': 'octoprint.util.foo'}}
        >>> build_rule(
        ...     rule_id="REM-0007",
        ...     ref="octoprint.access.User.getApiKey",
        ...     message="Removed in 2.0.0.",
        ...     pattern_body={"pattern-either": [
        ...         {"pattern": "User.getApiKey"},
        ...         {"pattern": "$X._user.getApiKey"},
        ...     ]},
        ...     metadata={"type": "removal", "since": "2.0.0"},
        ...     severity="CRITICAL",
        ... )
        {'id': 'REM-0007',
         'message': 'Removed in 2.0.0.',
         'languages': ['python'],
         'severity': 'CRITICAL',
         'pattern-either': [{'pattern': 'User.getApiKey'},
                            {'pattern': '$X._user.getApiKey'}],
         'metadata': {'type': 'removal',
                      'since': '2.0.0',
                      '_ref': 'octoprint.access.User.getApiKey'}}
    """
    rule_type = metadata.get("type")
    if rule_type is not None and is_ignored_ref(ref, rule_type):
        return None

    metadata = metadata.copy()
    metadata["_ref"] = ref
    if "suggestion" in metadata:
        metadata["suggestion"] = _clean_message(metadata["suggestion"])

    return {
        "id": rule_id,
        "message": _clean_message(message),
        "languages": ["python"],
        "severity": severity,
        **pattern_body,
        "metadata": metadata,
    }


def build_python_symbol_rule(
    rule_id: str,
    name: str,
    kind: SymbolKind,
    class_name: str | None,
    module_path: str,
    receivers_map: dict[str, list[str]],
    message: str,
    metadata: dict,
    severity: str,
) -> dict | None:
    """Build a Semgrep rule for a Python symbol.

    Returns ``None`` if the symbol cannot produce a valid pattern or if
    its ref is in the ignored refs list.

    Args:
        rule_id (str): Unique rule identifier (e.g. ``"DEP-0001"``).
        name (str): Symbol name (e.g. ``"getApiKey"``) or dotted module path
            for module-level symbols.
        kind (SymbolKind): Symbol kind - see :class:`.SymbolKind`.
        class_name (str | None): Enclosing class name, or ``None``.
        module_path (str): Dotted module path (e.g.
            ``"octoprint.access.users"``).
        receivers_map (dict[str, list[str]]): Class -> receiver-variables
            mapping from ``get_receivers_map``.
        message (str): Human-readable message for the Semgrep finding.
        metadata (dict): Dict of metadata fields (``type``, ``since``, etc.).
        severity (str): Semgrep severity.

    Returns:
        dict | None: A Semgrep rule dict, or ``None`` if no valid pattern
        can be built or the ref is in the ignored refs list.

    Examples:
        >>> receivers = get_receivers_map({"UserManager": []})
        >>> rule = build_python_symbol_rule(
        ...     rule_id="DEP-0001",
        ...     name="getApiKey",
        ...     kind=SymbolKind.FUNCTION,
        ...     class_name="UserManager",
        ...     module_path="octoprint.access.users",
        ...     receivers_map=receivers,
        ...     message="Deprecated.",
        ...     metadata={"type": "deprecation", "since": "1.8.0"},
        ...     severity="MEDIUM",
        ... )
        >>> rule
        {'id': 'DEP-0001',
         'message': 'Deprecated.',
         'languages': ['python'],
         'severity': 'MEDIUM',
         'mode': 'taint',
         'pattern-sources': [{'pattern': 'UserManager'},
                             {'pattern': '$X._user_manager'},
                             {'pattern': 'userManager'}],
         'pattern-sinks': [{'pattern': '$SINK.getApiKey'}],
         'metadata': {'type': 'deprecation',
                      'since': '1.8.0',
                      '_ref': 'octoprint.access.users.UserManager.getApiKey'}}
    """
    patterns_body = python_symbol_pattern_body(name, kind, class_name, module_path, receivers_map.get(class_name))
    if patterns_body is None:
        return None

    return build_rule(
        rule_id=rule_id,
        ref=build_fqn(name, class_name, module_path),
        message=message,
        pattern_body=patterns_body,
        metadata=metadata,
        severity=severity,
    )


def next_rule_id(existing_rules: list[dict], prefix: str) -> int:
    """Return the next numeric ID for rules with the given prefix.

    Args:
        existing_rules (list[dict]): Existing rules to scan for the highest ID.
        prefix (str): Rule ID prefix (e.g. ``"DEP"``, ``"REM"``).

    Returns:
        int: The next available numeric ID.
    """
    pattern = re.compile(rf"^{re.escape(prefix)}[-_](\d+)$", re.IGNORECASE)
    ids = [int(m.group(1)) for r in existing_rules for m in [pattern.match(r.get("id", ""))] if m]
    return max(ids, default=0) + 1


# ---------------------------------------------------------------------------
# Rules I/O
# ---------------------------------------------------------------------------


class _NoAliasDumper(yaml.SafeDumper):
    """Disable PyYAML anchor/alias (``&id001``/``*id001``) for readability."""

    def ignore_aliases(self, data: object) -> bool:
        return True


def load_rule_file(rule_file: RuleFile) -> list[dict]:
    """Load a Semgrep rules file from the rules directory.

    Args:
        rule_file (RuleFile): The rule file to load.

    Returns:
        list[dict]: List of rule dicts, or empty list if file doesn't exist.

    Examples:
        >>> load_rule_file(RuleFile.python_deprecation)
        [{'id': 'DEP-0001', 'message': '...', ...}, ...]
    """
    path = RULES_DIR / rule_file.value
    if not path.is_file():
        return []

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "rules" not in data:
        return []

    return data["rules"]


def write_semgrep_file(rule_file: RuleFile, rules: list[dict]) -> None:
    """Write Semgrep rules to a file in the appropriate `RULES_DIR` subdirectory.

    Args:
        rule_file (RuleFile): The rule file to write.
        rules (list[dict]): List of rule dicts to write.
    """
    path = RULES_DIR / rule_file.value
    path.parent.mkdir(parents=True, exist_ok=True)
    header = f"OctoPrint {rule_file.rules_type} rules"
    text = yaml.dump(
        {"rules": rules}, Dumper=_NoAliasDumper, default_flow_style=False, sort_keys=False, allow_unicode=True
    )
    path.write_text(f"# {header}\n\n{text}", encoding="utf-8")
