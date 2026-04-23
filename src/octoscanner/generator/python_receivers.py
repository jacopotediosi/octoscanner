"""Map OctoPrint classes to the variable names plugins may use to access them.

When generating a Semgrep rule for a method like ``PrinterInterface.getApiKey``,
Semgrep needs to match every way a plugin might reference it. Since
Semgrep has no type inference, it cannot know that ``self._printer`` is
a ``PrinterInterface`` - we must list the variable names explicitly so
the rule builder can emit patterns like::

    self._printer.getApiKey    # injected attribute
    printer.getApiKey          # common local name
    PrinterInterface.getApiKey # direct class reference

This module builds that mapping. For each OctoPrint class it collects
variable names from three sources:

1. ``_CLASS_TO_MIXIN_ATTR`` - maps each class to the ``self._xxx``
   attribute that ``PluginMixin.__init__`` injects
   (e.g. ``PrinterInterface`` -> ``_printer``).
2. ``_EXTRA_RECEIVERS`` - additional variable names plugins commonly use
   beyond the injected attribute (e.g. ``settings()`` for ``Settings``).
3. ``class_hierarchy`` - inheritance links, so a subclass inherits the
   receiver names of its parent.
"""

from __future__ import annotations

_CLASS_TO_MIXIN_ATTR = {
    "PrinterInterface": "_printer",
    "PrinterMixin": "_printer",
    "PrinterProfileManager": "_printer_profile_manager",
    "FileManager": "_file_manager",
    "SlicingManager": "_slicing_manager",
    "EventManager": "_event_bus",
    "PluginManager": "_plugin_manager",
    "LifecycleManager": "_plugin_lifecycle_manager",
    "UserManager": "_user_manager",
    "ConnectivityChecker": "_connectivity_checker",
    "AnalysisQueue": "_analysis_queue",
    "SessionManager": "_app_session_manager",
    "PluginSettings": "_settings",
    "PluginInfo": "_plugin_info",
    "GroupManager": "_group_manager",
    "PreemptiveCache": "_preemptive_cache",
    "EnvironmentDetector": "_environment_detector",
    "SystemCommandManager": "_system_commands",
}
"""Maps each OctoPrint class to the ``self._xxx`` attribute that
``PluginMixin.__init__`` injects into plugins. For example, every plugin
receives ``self._printer`` as a ``PrinterInterface`` instance. Multiple
classes may share the same variable (e.g. ``PrinterInterface`` and
``PrinterMixin`` both map to ``_printer``)."""


_EXTRA_RECEIVERS = {
    "User": ["current_user", "user"],
    "SessionUser": ["current_user", "user"],
    "AnonymousUser": ["current_user"],
    "ApiUser": ["current_user"],
    "UserManager": ["userManager"],
    "GroupManager": ["groupManager"],
    "PluginManager": ["pluginManager", "plugin_manager()"],
    "PrinterProfileManager": ["printerProfileManager"],
    "PrinterInterface": ["printer"],
    "PluginInfo": ["plugin_info", "plugin"],
    "Settings": ["settings()"],
}
"""Additional variable names plugins commonly use beyond the injected
``self._xxx`` attributes - function parameters, local variables, and
OctoPrint's own public APIs. For example, ``settings()`` is a function call
that returns a ``Settings`` instance, so Semgrep can match
``settings().get(...)`` as a literal pattern."""


def get_receivers_map(
    class_hierarchy: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Map each OctoPrint class to every variable name a plugin might use for it.

    Since Semgrep has no type inference, a rule for a method like
    ``PrinterInterface.getApiKey`` must list every way an OctoPrint plugin can
    reference that object (e.g. ``self._printer``, ``printer``, ``PrinterInterface``).

    This function collects those names from ``_CLASS_TO_MIXIN_ATTR`` and
    ``_EXTRA_RECEIVERS``, then propagates them through ``class_hierarchy``
    so that subclasses not listed in the mappings inherit the receivers of
    their parent.

    Args:
        class_hierarchy (dict[str, list[str]]): Maps each class to its
            base classes. Classes not in ``_CLASS_TO_MIXIN_ATTR`` that inherit
            from a mapped class will get the same receiver names.

    Returns:
        dict[str, list[str]]: Class name -> list of variable names that
        Semgrep patterns should enumerate for that class.

    Examples:
        >>> hierarchy = {"Printer": ["PrinterInterface"]}
        >>> receivers = get_receivers_map(hierarchy)
        >>> receivers["Printer"]
        ['PrinterInterface', 'PrinterMixin', '_printer', 'printer']
    """
    # Group classes that share the same injected attribute
    # (e.g. _printer -> [PrinterInterface, PrinterMixin]).
    attr_to_classes = {}
    for cls, attr in _CLASS_TO_MIXIN_ATTR.items():
        attr_to_classes.setdefault(attr, []).append(cls)

    # Seed the map: each class gets [co-mapped classes..., attr].
    receivers_map = {}
    for cls, attr in _CLASS_TO_MIXIN_ATTR.items():
        receivers_map[cls] = attr_to_classes[attr] + [attr]

    def _inherit_from_bases(cls: str, seen: set[str] | None = None) -> list[str] | None:
        """Find the first ancestor with known receivers and assign them to ``cls``.

        Walks ``class_hierarchy`` upward recursively until it finds a class already
        in ``receivers_map``, then assigns the same receiver list to ``cls``.
        Uses ``seen`` to guard against cycles.

        We walk the hierarchy manually instead of using Griffe's mro()
        because Griffe can only resolve bases whose source is loaded -
        OctoPrint classes that inherit from third-party packages
        (e.g. Flask, Tornado) have empty MROs, which affects ~50% of
        the codebase.

        Args:
            cls: Class name to look up.
            seen: Classes already visited in this call chain (cycle guard).

        Returns:
            The receiver list if an ancestor was found, ``None`` otherwise.

        Examples:
            >>> _inherit_from_bases("Printer")  # Printer -> PrinterInterface
            ['PrinterInterface', 'PrinterMixin', '_printer']
        """
        if cls in receivers_map:
            return receivers_map[cls]
        if seen is None:
            seen = set()
        if cls in seen:
            return None
        seen.add(cls)
        for base in class_hierarchy.get(cls, []):
            inherited = _inherit_from_bases(base, seen)
            if inherited is not None:
                receivers_map[cls] = inherited
                return inherited
        return None

    for cls in class_hierarchy:
        if cls not in receivers_map:
            _inherit_from_bases(cls)

    # Append extra aliases from _EXTRA_RECEIVERS. Because co-mapped classes
    # share the same list (e.g. PrinterMixin's entry contains
    # "PrinterInterface"), we scan all entries so the aliases for
    # PrinterInterface (like "printer") also reach PrinterMixin's entry.
    for cls, aliases in _EXTRA_RECEIVERS.items():
        if cls in receivers_map:
            for entry in receivers_map.values():
                if cls in entry:
                    entry.extend(a for a in aliases if a not in entry)
        else:
            receivers_map[cls] = list(aliases)

    return receivers_map
