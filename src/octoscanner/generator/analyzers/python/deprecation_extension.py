"""Griffe extension that detects OctoPrint-specific deprecation patterns.

Griffe (and ``griffe-warnings-deprecated``) only handles PEP 702's
``@warnings.deprecated``, missing the custom decorators from ``octoprint.util``
and several imperative patterns used throughout OctoPrint. This extension
plugs into Griffe's loading phase to catch those patterns as well.
"""

from __future__ import annotations

import ast

import griffe

from ...models import Deprecation, SymbolKind


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


class GriffeDeprecationExtension(griffe.Extension):
    """Griffe extension that detects OctoPrint specific deprecation patterns during
    module loading.

    Attributes:
        deprecations (list[Deprecation]): Accumulated ``Deprecation``
            objects from all parsed modules.

    Examples:
        >>> ext = GriffeDeprecationExtension()
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
