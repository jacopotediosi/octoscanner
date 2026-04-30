"""Extract settings paths and compatibility overlays coverage from an OctoPrint source tree."""

from __future__ import annotations

import ast
from pathlib import Path

import griffe

# ---------------------------------------------------------------------------
# Settings paths extraction
# ---------------------------------------------------------------------------


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
    # OctoPrint's settings schema has changed format over time (dict literal in
    # 1.4.0-1.8.0, Pydantic ``Config`` class in 1.9.0+), so this function tries
    # multiple strategies until one matches.

    # Strategies tried in order; the most recent schema format comes first.
    strategies = (_extract_settings_from_pydantic_config, _extract_settings_from_dict_literal)

    for strategy in strategies:
        settings_paths = strategy(griffe_module)
        if settings_paths is not None:
            return settings_paths

    raise ValueError(
        "No suitable settings extraction strategy matched the module. OctoPrint "
        "may have introduced a new schema format that requires a new strategy."
    )


def _extract_settings_from_dict_literal(griffe_module: griffe.Module) -> set[tuple[str, ...]] | None:
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
        >>> settings_paths = _extract_settings_from_dict_literal(griffe_module)
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


def _extract_settings_from_pydantic_config(griffe_module: griffe.Module) -> set[tuple[str, ...]] | None:
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
        >>> settings_paths = _extract_settings_from_pydantic_config(griffe_module)
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


# ---------------------------------------------------------------------------
# Compatibility overlays extraction
# ---------------------------------------------------------------------------


def extract_compat_settings_paths(source_dir: Path) -> dict[tuple[str, ...], str]:
    """Extract settings paths covered by a deprecated compatibility overlay.

    Args:
        source_dir (Path): OctoPrint source directory.

    Returns:
        dict[tuple[str, ...], str]: Mapping from covered settings path to its
        deprecation message. Paths whose last segment is ``"*"`` are wildcard
        prefixes (any descendant is considered covered).

    Raises:
        ValueError: If a compat overlay cannot be resolved. This signals
            that OctoPrint has changed the shape of its compatibility
            overlays and the extractor needs an update.

    Examples:
        >>> compat = extract_compat_settings_paths(Path("octoprint_src/2.0.0"))
        >>> ("serial", "port") in compat
        True
    """
    init_file = source_dir / "src" / "octoprint" / "__init__.py"
    if not init_file.is_file():
        raise ValueError(f"OctoPrint __init__.py not found at {init_file}")

    tree = ast.parse(init_file.read_text(encoding="utf-8"))

    result = {}

    for func in ast.walk(tree):
        if not isinstance(func, ast.FunctionDef):
            continue

        for call in ast.walk(func):
            if not isinstance(call, ast.Call):
                continue

            if not (isinstance(call.func, ast.Attribute) and call.func.attr == "add_overlay"):
                continue
            if not call.args:
                continue

            deprecated_kw = next((kw for kw in call.keywords if kw.arg == "deprecated"), None)
            if deprecated_kw is None:
                continue
            if not (isinstance(deprecated_kw.value, ast.Constant) and isinstance(deprecated_kw.value.value, str)):
                raise ValueError(
                    f"Compat overlay at {init_file}:{call.lineno} has a non-literal `deprecated` argument. "
                    "Manual intervention required."
                )
            deprecated_msg = deprecated_kw.value.value

            covered = _walk_compat_overlay_dict(call.args[0], (), func, source_dir)
            normalized_msg = " ".join(deprecated_msg.split())
            result.update(dict.fromkeys(covered, normalized_msg))

    return result


def _walk_compat_overlay_dict(
    node: ast.expr,
    path: tuple[str, ...],
    func: ast.FunctionDef,
    source_dir: Path,
) -> set[tuple[str, ...]]:
    """Walk a compat overlay AST expression, returning the set of compat-covered paths.

    Args:
        node (ast.expr): The overlay expression to walk.
        path (tuple[str, ...]): The path prefix accumulated so far.
        func (ast.FunctionDef): The enclosing function.
        source_dir (Path): OctoPrint source directory.

    Returns:
        set[tuple[str, ...]]: Set of covered paths. Paths whose last segment
        is ``"*"`` are wildcard prefixes (any descendant is considered covered).

    Raises:
        ValueError: If the compat overlay cannot be resolved.

    Examples:
        >>> tree = ast.parse('def f():\\n    settings.add_overlay({"serial": {"port": None}})')
        >>> func = tree.body[0]
        >>> call = func.body[0].value
        >>> _walk_compat_overlay_dict(call.args[0], (), func, Path("."))
        {('serial', 'port')}
    """
    # Expression is a var, resolve its value (union of all assignments + .update() calls)
    if isinstance(node, ast.Name):
        assigned_values = _collect_var_assignments(func, node.id)
        if not assigned_values:
            raise ValueError(
                f"Compat overlay references undefined variable `{node.id}` for path "
                f"{'.'.join(path) or '<root>'}. Manual intervention required."
            )
        result = set()
        for assigned_value in assigned_values:
            result.update(_walk_compat_overlay_dict(assigned_value, path, func, source_dir))
        return result

    # Expression is a dict
    if isinstance(node, ast.Dict):
        # Empty dict - treat as prefix wildcard
        if not node.keys:
            return {path + ("*",)}

        result = set()
        for key_node, value_node in zip(node.keys, node.values):
            if not isinstance(key_node, ast.Constant) or not isinstance(key_node.value, str):
                raise ValueError(
                    f"Compat overlay has non-string-literal key under "
                    f"{'.'.join(path) or '<root>'}. Manual intervention required."
                )
            sub_path = path + (key_node.value,)

            # Nested dict / variable / known dynamic call -> recurse
            if isinstance(value_node, (ast.Dict, ast.Name)) or (
                isinstance(value_node, ast.Call)
                and isinstance(value_node.func, ast.Attribute)
                and value_node.func.attr in ("dict", "model_dump")
            ):
                result.update(_walk_compat_overlay_dict(value_node, sub_path, func, source_dir))
            else:
                # Leaf value (any other expression) -> the path itself is covered
                result.add(sub_path)
        return result

    # Special-case for the `webcam` key, resolve the WebcamCompatibility fields
    if (
        path == ("webcam",)
        and isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in ("dict", "model_dump")
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "compat"
    ):
        return {path + (field,) for field in _webcam_compatibility_fields(source_dir)}

    raise ValueError(
        f"Compat overlay contains unsupported expression `{ast.dump(node)}` under "
        f"{'.'.join(path) or '<root>'}. Manual intervention required."
    )


def _collect_var_assignments(func: ast.FunctionDef, name: str) -> list[ast.expr]:
    """Collect every value assigned (or merged via ``.update()``) into ``name`` inside ``func``.

    Args:
        func (ast.FunctionDef): The enclosing function to scan.
        name (str): The name of the variable whose values to collect.

    Returns:
        list[ast.expr]: The right-hand-side expressions, in source order.

    Examples:
        >>> tree = ast.parse('def f():\\n    overlay = {"a": 1}\\n    overlay.update({"b": 2})')
        >>> func = tree.body[0]
        >>> [type(e).__name__ for e in _collect_var_assignments(func, "overlay")]
        ['Dict', 'Dict']
    """
    assigned_values = []
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name) and target.id == name:
                assigned_values.append(node.value)
        elif (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "update"
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == name
            and node.value.args
        ):
            assigned_values.append(node.value.args[0])
    return assigned_values


def _webcam_compatibility_fields(source_dir: Path) -> list[str]:
    """Return the field names of the ``WebcamCompatibility`` Pydantic model.

    Args:
        source_dir (Path): OctoPrint source directory.

    Returns:
        list[str]: The annotated field names of the ``WebcamCompatibility``
        class, in source order.

    Raises:
        ValueError: If the schema file or the class cannot be found, or the
            class has no annotated fields.

    Examples:
        >>> fields = _webcam_compatibility_fields(Path("octoprint_src/1.11.7"))
        >>> "stream" in fields
        True
    """
    schema_file = source_dir / "src" / "octoprint" / "schema" / "webcam" / "__init__.py"
    if not schema_file.is_file():
        raise ValueError(
            f"Expected `WebcamCompatibility` at {schema_file} but file is missing. Manual intervention required."
        )

    tree = ast.parse(schema_file.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "WebcamCompatibility":
            fields = [
                stmt.target.id
                for stmt in node.body
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name)
            ]
            if not fields:
                raise ValueError(
                    f"`WebcamCompatibility` in {schema_file} has no annotated fields. Manual intervention required."
                )
            return fields

    raise ValueError(f"`WebcamCompatibility` class not found in {schema_file}. Manual intervention required.")
