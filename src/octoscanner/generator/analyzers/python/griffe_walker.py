"""Griffe tree walker: populates deprecations and class hierarchy from a loaded module."""

from __future__ import annotations

import griffe

from ...models import Deprecation
from ...python_utils import griffe_mod_path, griffe_to_symbolkind


def walk_griffe(
    member: griffe.Object,
    deprecations: list[Deprecation],
    class_hierarchy: dict[str, list[str]],
) -> None:
    """Populate ``deprecations`` and ``class_hierarchy`` from Griffe's tree.

    Detects ``@deprecated`` / ``@variable_deprecated`` decorators and collects
    class inheritance (class name -> list of base names).

    Args:
        member (griffe.Object): Root Griffe object to walk (typically a
            ``griffe.Module``).
        deprecations (list[Deprecation]): List to populate with detected
            ``Deprecation`` objects to (modified in place).
        class_hierarchy (dict[str, list[str]]): Dict to populate with
            class -> base-names mappings (modified in place).

    Examples:
        >>> deprecations, hierarchy = [], {}
        >>> walk_griffe(griffe_module, deprecations, hierarchy)
        >>> len(deprecations)
        12
        >>> hierarchy["AnonymousUser"]
        ['AnonymousUserMixin', 'User']
    """
    if member.is_alias:
        return

    # Populate class_hierarchy
    if member.is_class:
        # Griffe stores bases as dotted paths (e.g. "flask.views.View").
        # We extract just the class name for simpler hierarchy matching.
        class_hierarchy[member.name] = [str(base).split(".")[-1] for base in member.bases]

    # Populate deprecations
    if hasattr(member, "decorators") and member.decorators:
        kind = griffe_to_symbolkind(member)
        class_name = member.parent.name if member.parent and member.parent.is_class else None
        mod_path = griffe_mod_path(member)

        for dec in member.decorators:
            path = dec.callable_path
            if path and (
                path.endswith(".deprecated")
                or path.endswith(".variable_deprecated")
                or path in ("deprecated", "variable_deprecated")
            ):
                message, since = "", None
                try:
                    if isinstance(dec.value, griffe.ExprCall):
                        for arg in dec.value.arguments:
                            if hasattr(arg, "name") and arg.name == "message":
                                message = str(arg.value).strip("'\"")
                            elif hasattr(arg, "name") and arg.name == "since":
                                since = str(arg.value).strip("'\"")
                            elif not hasattr(arg, "name") and not message:
                                message = str(arg).strip("'\"")
                except Exception:
                    pass
                deprecations.append(
                    Deprecation(
                        member.name,
                        kind,
                        str(message) if message else "",
                        str(since) if since else None,
                        class_name,
                        mod_path,
                        member.lineno or 0,
                    )
                )

    # Recursive walking
    if member.is_module or member.is_class:
        for sub in member.members.values():
            walk_griffe(sub, deprecations, class_hierarchy)
