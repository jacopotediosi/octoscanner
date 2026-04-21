"""Extract settings paths from an OctoPrint source tree.

OctoPrint's settings schema has changed format over time (dict literal in
1.4.0-1.8.0, Pydantic ``Config`` class in 1.9.0+), so this module tries
multiple strategies until one matches.
"""

from __future__ import annotations

import ast

import griffe


def _extract_dict_literal(griffe_module: griffe.Module) -> set[tuple[str, ...]] | None:
    """Extract settings from a ``default_settings = {...}`` dict literal.

    Used for OctoPrint 1.4.0-1.8.0, which defines settings as a module-level
    dict literal in ``octoprint/settings.py``.

    Args:
        griffe_module (griffe.Module): The root griffe module (``octoprint``).

    Returns:
        set[tuple[str, ...]] | None: Set of leaf settings paths as tuples, or
        ``None`` if the module does not expose this layout.

    Examples:
        >>> griffe_module = griffe.load("octoprint", search_paths=[Path("octoprint_src/1.8.0/src")])
        >>> settings_paths = _extract_dict_literal(griffe_module)
        >>> ("serial", "port") in settings_paths
        True
    """
    settings = griffe_module.members.get("settings")
    if settings is None:
        return None

    default_settings = settings.members.get("default_settings")
    if (
        default_settings is None
        or not default_settings.is_attribute
        or not isinstance(default_settings.value, griffe.ExprDict)
    ):
        return None

    def walk(expr: griffe.ExprDict, path: tuple[str, ...]) -> set[tuple[str, ...]]:
        paths = set()
        for key, value in zip(expr.keys, expr.values):
            # Keys come as string representations like "'serial'"; parse them
            # back to the actual string value.
            key_str = ast.literal_eval(key)
            sub_path = path + (key_str,)
            if isinstance(value, griffe.ExprDict):
                # Recurse into nested dicts, emitting only leaf keys. An
                # empty dict ({}) is treated as a leaf itself: the key still
                # exists in the schema and plugins can still access it.
                nested = walk(value, sub_path)
                if nested:
                    paths.update(nested)
                    continue
            paths.add(sub_path)
        return paths

    return walk(default_settings.value, ())


def _extract_pydantic_config(griffe_module: griffe.Module) -> set[tuple[str, ...]] | None:
    """Extract settings from the Pydantic ``Config`` class.

    Used for OctoPrint 1.9.0+, which defines settings as Pydantic model classes
    in ``octoprint/schema/config/``.

    Args:
        griffe_module (griffe.Module): The root griffe module (``octoprint``).

    Returns:
        set[tuple[str, ...]] | None: Set of leaf settings paths as tuples, or
        ``None`` if the module does not expose this layout.

    Examples:
        >>> griffe_module = griffe.load("octoprint", search_paths=[Path("octoprint_src/1.11.7/src")])
        >>> settings_paths = _extract_pydantic_config(griffe_module)
        >>> ("serial", "port") in settings_paths
        True
    """

    def is_pydantic_model(obj: object) -> bool:
        """True if ``obj`` is a griffe Class inheriting from ``BaseModel``."""
        return (
            obj is not None
            and getattr(obj, "is_class", False)
            and any(rb.name == "BaseModel" for rb in getattr(obj, "resolved_bases", []))
        )

    def resolve_nested_class(annotation: object) -> griffe.Class | None:
        """Resolve a bare-name annotation to its Pydantic model class.

        Returns the class only if the annotation resolves to a Pydantic model.
        """
        if not isinstance(annotation, griffe.ExprName):
            return None
        try:
            resolved = annotation.resolved
        except (griffe.NameResolutionError, AttributeError):
            return None
        return resolved if is_pydantic_model(resolved) else None

    def field_alias(value: object) -> str | None:
        """Return the ``alias=...`` keyword of a Pydantic ``Field(...)`` call.

        OctoPrint uses ``Field(..., alias="_name")`` to expose settings keys
        that start with an underscore (which is not a valid Python attribute
        for Pydantic's strict mode). The alias is what plugins actually see.
        """
        if not isinstance(value, griffe.ExprCall):
            return None
        func = value.function
        if not (isinstance(func, griffe.ExprName) and func.name == "Field"):
            return None
        for arg in value.arguments:
            if isinstance(arg, griffe.ExprKeyword) and arg.name == "alias":
                # Only accept string literals; skip aliases built from
                # constants/expressions, which we cannot statically resolve.
                if not isinstance(arg.value, str):
                    return None
                try:
                    return ast.literal_eval(arg.value)
                except (SyntaxError, ValueError):
                    return None
        return None

    def walk(cls: griffe.Class, path: tuple[str, ...]) -> set[tuple[str, ...]]:
        paths = set()
        for name, member in cls.members.items():
            if not member.is_attribute:
                continue

            # Prefer the Pydantic Field alias over the Python attribute name.
            key = field_alias(member.value) or name
            sub_path = path + (key,)

            # If the annotation points to another Pydantic model, recurse
            # into it emitting only leaf attributes.
            nested_cls = resolve_nested_class(member.annotation)
            if nested_cls is not None:
                nested = walk(nested_cls, sub_path)
                if nested:
                    paths.update(nested)
                    continue

            paths.add(sub_path)
        return paths

    schema = griffe_module.members.get("schema")
    if schema is None:
        return None

    config_mod = schema.members.get("config")
    if config_mod is None:
        return None

    config_class = config_mod.members.get("Config")
    if not is_pydantic_model(config_class):
        return None

    return walk(config_class, ())


def extract_settings_paths(griffe_module: griffe.Module) -> set[tuple[str, ...]]:
    """Extract all leaf settings paths from an OctoPrint Griffe module.

    Args:
        griffe_module (griffe.Module): The root griffe module (``octoprint``).

    Returns:
        set[tuple[str, ...]]: Set of settings paths as tuples,
        e.g. ``{("serial", "port"), ...}``.

    Raises:
        ValueError: If no known strategy can handle this module format. This
            signals that OctoPrint has introduced a new schema format that needs
            a new extraction strategy.

    Examples:
        >>> griffe_module = griffe.load("octoprint", search_paths=[Path("octoprint_src/2.0.0/src")])
        >>> paths = extract_settings_paths(griffe_module)
        >>> ("serial",) in paths  # Removed in 2.0.0
        False
        >>> ("printerConnection",) in paths  # Added in 2.0.0
        True
    """
    # Strategies tried in order; the most recent schema format comes first.
    strategies = (_extract_pydantic_config, _extract_dict_literal)

    for strategy in strategies:
        settings_paths = strategy(griffe_module)
        if settings_paths is not None:
            return settings_paths

    raise ValueError(
        "No suitable settings extraction strategy matched the module. OctoPrint "
        "may have introduced a new schema format that requires a new strategy."
    )
