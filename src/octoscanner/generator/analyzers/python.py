"""Python analyzer.

Extracts deprecations and class hierarchy from OctoPrint sources.

Architecture (Griffe + AST)
---------------------------
This module relies on a hybrid static analysis approach, leveraging Griffe to
build the semantic graph and Python's built-in AST to detect imperative code
patterns.

**Why Griffe?**
We rely heavily on Griffe's semantic module tree rather than raw AST parsing to:
- Construct precise Fully Qualified Names (FQN) across complex directory structures.
- Resolve cross-file imports, re-exports, and aliases automatically.
- Traverse the Method Resolution Order (MRO) via ``inherited_members``.
- Detect decorator-based ``@deprecated`` / ``@variable_deprecated`` via Griffe's
  static decorator model (``_walk_griffe``).

**Why AST?**
An AST visitor (``_DeprecationASTVisitor``) run as a Griffe extension catches
additional imperative deprecation patterns specific to OctoPrint - none of which
Griffe's built-in decorator analysis or ``griffe-warnings-deprecated`` can see (they
only handle PEP 702's ``@warnings.deprecated``).
"""

from __future__ import annotations

import ast
import warnings
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import griffe

from ..models import Deprecation, SymbolKind
from .base import Analyzer

if TYPE_CHECKING:
    from ..models import PipelineState


@dataclass
class PythonAnalysisResult:
    """Result of analyzing one OctoPrint source code.

    Attributes:
        deprecations (list[Deprecation]): All detected deprecations.
        class_hierarchy (dict[str, list[str]]): Class name -> list of base
            class names.
        griffe_module (griffe.Module): The loaded Griffe module tree.
    """

    deprecations: list[Deprecation]
    class_hierarchy: dict[str, list[str]]
    griffe_module: griffe.Module


# ---------------------------------------------------------------------------
# AST visitor - imperative deprecation detection
# ---------------------------------------------------------------------------


class _DeprecationASTVisitor(ast.NodeVisitor):
    """AST visitor for OctoPrint-specific deprecation patterns invisible to Griffe.

    Griffe (and ``griffe-warnings-deprecated``) only handles PEP 702's
    ``@warnings.deprecated``. OctoPrint uses custom decorators from
    ``octoprint.util``. This visitor detects the following imperative
    patterns:

    1. ``@deprecated("msg", since="...")`` stacked on ``@property``.
    2. Module-level ``warnings.warn("...", DeprecationWarning)``.
    3. ``self.deprecated_access_methods = {"oldName": "new_name"}`` -
       dict-based dynamic method aliasing in ``__init__``.
    4. ``name = deprecated("msg", since="...")(func)`` or
       ``name = variable_deprecated("msg", since="...")(value)`` -
       curried decorator wrapping a callable or value.

    Attributes:
        module_path (str): Dotted module path analyzed.
        deprecations (list[Deprecation]): Accumulated list of detected
            ``Deprecation`` objects.

    Examples:
        >>> tree = ast.parse(open("octoprint/printer/__init__.py").read())
        >>> visitor = _DeprecationASTVisitor("octoprint.printer")
        >>> visitor.visit(tree)
        >>> len(visitor.deprecations)
        5
    """

    def __init__(self, module_path: str):
        self.module_path = module_path
        self.deprecations: list[Deprecation] = []
        self._current_class: str | None = None
        self._in_function: bool = False

    @staticmethod
    def _parse_deprecated_call(dec: ast.expr) -> tuple[str, str | None]:
        """Extract ``(message, since)`` from a ``@deprecated(...)`` or
        ``@variable_deprecated(...)`` AST call.

        Args:
            dec (ast.expr): An AST expression node, typically a decorator.

        Returns:
            tuple[str, str | None]: A ``(message, since)`` tuple.  ``message`` is
            the deprecation text (empty string if not found); ``since`` is the
            OctoPrint version where the symbol was deprecated, or ``None``.

        Examples:
            >>> src = "@deprecated('Use bar', since='1.8.0')\\ndef foo(): ..."
            >>> node = ast.parse(src).body[0].decorator_list[0]
            >>> _parse_deprecated_call(node)
            ('Use bar', '1.8.0')
        """
        if not isinstance(dec, ast.Call):
            return ("", None)

        func_name = ast.unparse(dec.func).split(".")[-1]
        if func_name not in ("deprecated", "variable_deprecated"):
            return ("", None)

        message = ""
        since = None

        # Positional: @deprecated("msg", ...)
        first_arg = dec.args[0] if dec.args else None
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            message = first_arg.value

        # Keyword: @deprecated(message="msg", since="1.8.0")
        for kw in dec.keywords:
            if isinstance(kw.value, ast.Constant):
                if kw.arg == "message":
                    message = kw.value.value
                elif kw.arg == "since":
                    since = kw.value.value

        return (message, since)

    def _visit_class(self, node: ast.ClassDef) -> None:
        prev = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = prev

    visit_ClassDef = _visit_class

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        prev_in = self._in_function
        self._in_function = True
        self._check_deprecated_property(node)
        self.generic_visit(node)
        self._in_function = prev_in

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def _check_deprecated_property(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Detect ``@deprecated(...)`` stacked on ``@property`` (or setter/deleter).

        If ``node`` is a property with a ``@deprecated(...)`` decorator, appends
        a :class:`Deprecation` to ``self.deprecations``.

        This is needed because Griffe only recognizes PEP 702's
        ``@warnings.deprecated``, not OctoPrint's custom ``@deprecated``. When stacked
        on ``@property``, the deprecation is invisible to Griffe's static analysis::

            @property
            @deprecated("Use bar instead", since="1.8.0")
            def foo(self): ...

        Args:
            node (ast.FunctionDef | ast.AsyncFunctionDef): Function or method AST
            node to inspect.
        """
        is_property = any(
            ast.unparse(d) in ("property", "property.setter", "property.deleter")
            or (isinstance(d, ast.Attribute) and d.attr in ("setter", "deleter"))
            for d in node.decorator_list
        )
        if not is_property:
            return

        for dec in node.decorator_list:
            msg, since = self._parse_deprecated_call(dec)
            if msg:
                self.deprecations.append(
                    Deprecation(
                        node.name, SymbolKind.ATTRIBUTE, msg, since, self._current_class, self.module_path, node.lineno
                    )
                )

    def visit_Expr(self, node: ast.Expr) -> None:
        # Module-level warnings.warn("...", DeprecationWarning)
        if self._current_class is None and not self._in_function:
            if (
                isinstance(node.value, ast.Call)
                and ast.unparse(node.value.func) in ("warn", "warnings.warn")
                and len(node.value.args) >= 2
                and ast.unparse(node.value.args[1]) == "DeprecationWarning"
            ):
                msg = node.value.args[0]
                if isinstance(msg, ast.Constant) and isinstance(msg.value, str):
                    self.deprecations.append(
                        Deprecation(
                            self.module_path, SymbolKind.MODULE, msg.value, None, None, self.module_path, node.lineno
                        )
                    )

    def visit_Assign(self, node: ast.Assign) -> None:
        if len(node.targets) != 1:
            return
        target = node.targets[0]

        # OctoPrint's dynamic method aliasing: in ``__init__``, classes set
        # ``self.deprecated_access_methods = {"oldName": "new_name", ...}``.
        # The base class ``__getattr__`` intercepts calls to ``oldName`` and
        # redirects them to ``new_name`` with a deprecation warning. Griffe
        # cannot detect this pattern since it's purely runtime behavior.
        if ast.unparse(target) == "self.deprecated_access_methods":
            pairs = []
            if isinstance(node.value, ast.Dict):
                # {"oldName": "new_name", ...}
                for k, v in zip(node.value.keys, node.value.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        repl = v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else None
                        pairs.append((k.value, repl, k.lineno))
            elif isinstance(node.value, ast.Call) and ast.unparse(node.value.func) == "dict":
                # dict(oldName="new_name", ...)
                for kw in node.value.keywords:
                    if kw.arg and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                        pairs.append((kw.arg, kw.value.value, kw.value.lineno))
            for old_name, repl, lineno in pairs:
                msg = f"{old_name} has been renamed to {repl}" if repl else f"{old_name} is deprecated"
                self.deprecations.append(
                    Deprecation(
                        old_name,
                        SymbolKind.FUNCTION,
                        msg,
                        None,
                        self._current_class,
                        self.module_path,
                        lineno,
                    )
                )

        # OctoPrint's curried decorator pattern:
        # ``name = deprecated("msg", since="...")(func)`` or
        # ``name = variable_deprecated("msg", since="...")(val)``.
        # The outer call applies the wrapper, the inner call configures it.
        elif isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Call):
            msg, since = self._parse_deprecated_call(node.value.func)
            if msg:
                name_id = (
                    target.id
                    if isinstance(target, ast.Name)
                    else (target.attr if isinstance(target, ast.Attribute) else "")
                )
                if name_id:
                    self.deprecations.append(
                        Deprecation(
                            name_id,
                            SymbolKind.FUNCTION,
                            msg,
                            since,
                            self._current_class,
                            self.module_path,
                            node.lineno,
                        )
                    )


# ---------------------------------------------------------------------------
# Griffe extensions
# ---------------------------------------------------------------------------


class _GriffeDeprecationExtension(griffe.Extension):
    """Griffe extension that detects OctoPrint imperative deprecation patterns during
    module loading.

    Attributes:
        deprecations (list[Deprecation]): Accumulated ``Deprecation``
            objects from all parsed modules.

    Examples:
        >>> ext = _GriffeDeprecationExtension()
        >>> api = griffe.load("octoprint", extensions=griffe.Extensions(ext))
        >>> len(ext.deprecations)
        45
    """

    def __init__(self) -> None:
        self.deprecations: list[Deprecation] = []

    def on_module_members(self, *, node: ast.Module, agent: griffe.Visitor, **kwargs) -> None:
        visitor = _DeprecationASTVisitor(agent.current.path)
        visitor.visit(node)
        self.deprecations.extend(visitor.deprecations)


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


# ---------------------------------------------------------------------------
# Hierarchy helpers
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
# Griffe tree walking
# ---------------------------------------------------------------------------


def _walk_griffe(
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
        deprecations (list[Deprecation]): List to append detected
            ``Deprecation`` objects to (modified in place).
        class_hierarchy (dict[str, list[str]]): Dict to populate with
            class -> base-names mappings (modified in place).

    Examples:
        >>> deprecations, hierarchy = [], {}
        >>> _walk_griffe(griffe_module, deprecations, hierarchy)
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
            _walk_griffe(sub, deprecations, class_hierarchy)


# ---------------------------------------------------------------------------
# Python analysis entry point
# ---------------------------------------------------------------------------


def python_analyze(source_dir: Path, version: str) -> PythonAnalysisResult:
    """Perform Python analysis on an OctoPrint source directory.

    Args:
        source_dir (Path): Path to the OctoPrint source directory (must
            contain ``src/octoprint/``).
        version (str): OctoPrint version string (e.g. ``"1.10.0"``).

    Returns:
        PythonAnalysisResult: A ``PythonAnalysisResult`` with results of the analysis.

    Raises:
        ValueError: If ``source_dir / src / octoprint`` does not exist.

    Examples:
        >>> result = python_analyze(Path("octoprint_src/1.10.0"), "1.10.0")
        >>> len(result.deprecations)
        45
        >>> result.class_hierarchy["AnonymousUser"]
        ['AnonymousUserMixin', 'User']
    """
    if not (source_dir / "src" / "octoprint").is_dir():
        raise ValueError(f"OctoPrint source not found at {source_dir / 'src' / 'octoprint'}")

    ext = _GriffeDeprecationExtension()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        api = griffe.load("octoprint", search_paths=[source_dir / "src"], extensions=griffe.Extensions(ext))

    deprecations = []
    class_hierarchy = {}

    _walk_griffe(api, deprecations, class_hierarchy)
    deprecations.extend(ext.deprecations)
    deprecations.sort(key=lambda d: (d.module_path, d.line_number))

    # Apply fallback since for deprecations without an explicit version
    for dep in deprecations:
        if dep.since is None:
            dep.since = version

    return PythonAnalysisResult(deprecations=deprecations, class_hierarchy=class_hierarchy, griffe_module=api)


class PythonAnalyzer(Analyzer):
    title = "Analyzing OctoPrint python sources"

    def run(self, state: PipelineState, source_dirs: dict[str, Path]) -> list[str]:
        """Run Python analysis on OctoPrint source directories.

        Populates ``state.python_analysis_results`` with analysis results
        for each version.

        Args:
            state (PipelineState): Pipeline state to populate.
            source_dirs (dict[str, Path]): Version -> source directory mapping.

        Returns:
            list[str]: Log lines describing analysis results.
        """
        output_lines = []

        versions = list(source_dirs.keys())
        paths = list(source_dirs.values())

        with ProcessPoolExecutor() as executor:
            results = list(executor.map(python_analyze, paths, versions))

        state.python_analysis_results = dict(zip(versions, results))

        for version, result in state.python_analysis_results.items():
            dep_count = len(result.deprecations)
            class_count = len(result.class_hierarchy)
            output_lines.append(f"  {version}: {class_count} classes, {dep_count} deprecations")

        return output_lines
