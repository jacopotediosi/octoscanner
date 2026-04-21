"""Python-specific helpers shared between Python analyzer and processors."""

from __future__ import annotations

import griffe

from .models import SymbolKind

# ---------------------------------------------------------------------------
# Class hierarchy helpers
# ---------------------------------------------------------------------------


def ancestry_depth(cls: str, hierarchy: dict[str, list[str]], seen: set[str] | None = None) -> int:
    """Count how many ancestors a class has in the hierarchy.

    Args:
        cls (str): Class name to look up.
        hierarchy (dict[str, list[str]]): Class -> base-names mapping.
        seen (set[str] | None): Classes already visited (cycle guard).

    Returns:
        int: Number of ancestors in the hierarchy. ``0`` for base classes or
        classes not in the hierarchy.

    Examples:
        >>> hierarchy = {"AnonymousUser": ["User"], "SessionUser": ["User"]}
        >>> ancestry_depth("User", hierarchy)
        0
        >>> ancestry_depth("AnonymousUser", hierarchy)
        1
    """
    # Initialize cycle guard on first call
    if seen is None:
        seen = set()

    # Cycle detected - treat as base class
    if cls in seen:
        return 0
    seen.add(cls)

    # No parents in hierarchy - this is a base class (depth 0)
    bases = hierarchy.get(cls, [])
    if not bases:
        return 0

    # Depth = 1 (for this level) + max depth among parents
    return 1 + max(ancestry_depth(b, hierarchy, set(seen)) for b in bases)


def is_subclass_of(cls: str, base: str, hierarchy: dict[str, list[str]], seen: set[str] | None = None) -> bool:
    """Check if ``cls`` is a subclass of ``base`` using the hierarchy.

    Args:
        cls (str): Class name to check.
        base (str): Potential base class name.
        hierarchy (dict[str, list[str]]): Class -> base-names mapping.
        seen (set[str] | None): Classes already visited (cycle guard).

    Returns:
        bool: ``True`` if ``cls`` inherits from ``base``.

    Examples:
        >>> hierarchy = {"ApiUser": ["User"], "AnonymousUser": ["User"]}
        >>> is_subclass_of("ApiUser", "User", hierarchy)
        True
        >>> is_subclass_of("User", "ApiUser", hierarchy)
        False
    """
    # Initialize cycle guard on first call
    if seen is None:
        seen = set()

    # Cycle detected - not a subclass
    if cls in seen:
        return False
    seen.add(cls)

    # Check direct inheritance
    bases = hierarchy.get(cls, [])
    if base in bases:
        return True

    # Check transitive inheritance through ancestors
    return any(is_subclass_of(b, base, hierarchy, set(seen)) for b in bases)


# ---------------------------------------------------------------------------
# Griffe helpers
# ---------------------------------------------------------------------------


def griffe_to_symbolkind(member: griffe.Object) -> SymbolKind | None:
    """Map a Griffe object to a :class:`.SymbolKind`.

    Args:
        member (griffe.Object): A Griffe object.

    Returns:
        SymbolKind | None: The symbol kind, or ``None`` if the kind is unknown
        or cannot be determined.

    Examples:
        >>> api = griffe.load("octoprint", search_paths=[Path("octoprint_src/1.10.0/src")])
        >>> griffe_to_symbolkind(api["octoprint.printer.PrinterInterface"])
        <SymbolKind.CLASS: 'class'>
        >>> griffe_to_symbolkind(api["octoprint.access.users.UserManager.apikey"])
        <SymbolKind.ATTRIBUTE: 'attribute'>
        >>> griffe_to_symbolkind(api["octoprint.access.users.UserManager.check_password"])
        <SymbolKind.FUNCTION: 'function'>
    """
    try:
        if member.is_class:
            return SymbolKind.CLASS
        if member.is_function:
            return SymbolKind.FUNCTION
        if member.is_attribute:
            return SymbolKind.ATTRIBUTE
        if member.is_module:
            return SymbolKind.MODULE
    except griffe.AliasResolutionError:
        pass
    return None


def griffe_mod_path(member: griffe.Object) -> str:
    """Return the dotted module path for a Griffe object.

    Args:
        member (griffe.Object): A Griffe object.

    Returns:
        str: Dotted module path (e.g. ``"octoprint.printer"``). For modules,
        returns ``member.path`` directly. For other objects, returns the
        owning module's path.

    Examples:
        >>> api = griffe.load("octoprint", search_paths=[Path("octoprint_src/1.10.0/src")])
        >>> griffe_mod_path(api["octoprint.access.users.UserManager.apikey"])
        'octoprint.access.users'
        >>> griffe_mod_path(api["octoprint.printer"])
        'octoprint.printer'
    """
    if member.is_module:
        return member.path
    return member.module.path if member.module else ""
