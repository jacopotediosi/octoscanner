"""Griffe extension that detects properties backed by a callable shim.

A callable shim is an object that a property returns in place of a plain value.
Besides behaving like that value, it also implements ``__call__``, so both the
attribute and the call form are valid::

    @property
    def member(self):
        return SomeShim("member", lambda: value)

    obj.member    # the value
    obj.member()  # the same value, through the shim

Dropping the shim breaks every caller using the call form, but Griffe's
signature analysis cannot see it: the property's own signature is unchanged,
and the member may still exist, possibly inherited from a base class. This
extension records which properties are shim-backed in a source tree, so that
two OctoPrint versions can be diffed to find the shims that disappeared.
"""

from __future__ import annotations

import ast

import griffe


def _resolve_candidates(
    candidates: set[tuple[str, str, str, str]],
    root_module: griffe.Module,
) -> set[tuple[str, str, str]]:
    """Keep the candidate properties whose returned object is callable.

    Each candidate's constructor is looked up among the members of the module
    declaring the property, and kept only if it resolves to a class defining or
    inheriting ``__call__``.

    Args:
        candidates (set[tuple[str, str, str, str]]): Candidates as
            ``(module_path, class_name, name, constructor)`` tuples.
        root_module (griffe.Module): Root of the loaded Griffe module tree.

    Returns:
        set[tuple[str, str, str]]: The confirmed shim-backed properties, as
        ``(module_path, class_name, name)`` triples.
    """
    shims = set()

    root_prefix = f"{root_module.path}."
    for module_path, class_name, name, constructor in candidates:
        if module_path != root_module.path and not module_path.startswith(root_prefix):
            continue

        relative_path = module_path[len(root_prefix) :]
        try:
            module = root_module[relative_path] if relative_path else root_module
            returned = module.members[constructor.rsplit(".", 1)[-1]]
            if returned.is_class and "__call__" in returned.all_members:
                shims.add((module_path, class_name, name))
        except (KeyError, AttributeError, griffe.GriffeError):
            continue

    return shims


class _CallableShimASTVisitor(ast.NodeVisitor):
    """AST visitor collecting the properties of a module that return a new object.

    Whether the returned object is a callable shim depends on the class being
    instantiated, which cannot be resolved while walking the AST, so the
    properties are collected as mere candidates.

    Attributes:
        module_path (str): Dotted path of the module being visited.
        candidates (list[tuple[str, str, str, str]]): Accumulated
            ``(module_path, class_name, name, constructor)`` tuples.

    Examples:
        >>> src = "class C:\\n    @property\\n    def foo(self): return Shim('foo')"
        >>> visitor = _CallableShimASTVisitor("pkg.mod")
        >>> visitor.visit(ast.parse(src))
        >>> visitor.candidates
        [('pkg.mod', 'C', 'foo', 'Shim')]
    """

    def __init__(self, module_path: str):
        self.module_path = module_path
        self.candidates: list[tuple[str, str, str, str]] = []
        self._current_class: str | None = None
        self._current_property: str | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev_class, prev_property = self._current_class, self._current_property
        self._current_class, self._current_property = node.name, None
        self.generic_visit(node)
        self._current_class, self._current_property = prev_class, prev_property

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        prev_property = self._current_property
        is_property = any(ast.unparse(dec) == "property" for dec in node.decorator_list)
        self._current_property = node.name if is_property and self._current_class else None
        self.generic_visit(node)
        self._current_property = prev_property

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Return(self, node: ast.Return) -> None:
        if self._current_property and isinstance(node.value, ast.Call):
            constructor = ast.unparse(node.value.func)
            self.candidates.append((self.module_path, self._current_class, self._current_property, constructor))


class GriffeCallableShimExtension(griffe.Extension):
    """Griffe extension that records shim-backed properties during module loading.

    Candidates are gathered from the AST as each module is parsed, then
    confirmed once the package is fully loaded, since deciding whether a
    candidate is a shim requires resolving the class it returns.

    Attributes:
        shims (set[tuple[str, str, str]]): Confirmed shim-backed properties, as
            ``(module_path, class_name, name)`` triples. Only populated once
            loading has finished.

    Examples:
        >>> ext = GriffeCallableShimExtension()
        >>> api = griffe.load("pkg", extensions=griffe.Extensions(ext))
        >>> sorted(ext.shims)
        [('pkg.mod', 'C', 'foo')]
    """

    def __init__(self) -> None:
        self.shims: set[tuple[str, str, str]] = set()
        self._candidates: set[tuple[str, str, str, str]] = set()

    def on_module_members(self, *, node: ast.Module, agent: griffe.Visitor, **kwargs) -> None:
        visitor = _CallableShimASTVisitor(agent.current.path)
        visitor.visit(node)
        self._candidates.update(visitor.candidates)

    def on_package(self, *, pkg: griffe.Module, **kwargs) -> None:
        self.shims.update(_resolve_candidates(self._candidates, pkg))
