from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, StrEnum

import griffe


class SymbolKind(StrEnum):
    """Symbol kinds detected by Python analysis.

    Matches Griffe's ``Kind`` enum.
    """

    ATTRIBUTE = "attribute"
    CLASS = "class"
    FUNCTION = "function"
    MODULE = "module"


@dataclass(frozen=True)
class RuleFileSpec:
    """Metadata describing a Semgrep rule file.

    Attributes:
        path (str): Relative path under ``RULES_DIR``
            (e.g. ``"deprecation/python_deprecation.yaml"``).
        title (str): Human-readable header title written as the first comment
            line of the generated YAML file.
        rules_type (str): Rules type (e.g. ``"deprecation"``, ``"removal"``).
        id_prefix (str): Rule ID prefix used when generating new rules
            (e.g. ``"DEP"``, ``"STG-REM"``).
        severity (str): Default Semgrep severity for rules in this file
            (e.g. ``"MEDIUM"``, ``"HIGH"``, ``"CRITICAL"``).

    Examples:
        >>> spec = RuleFileSpec(
        ...     path="deprecation/python_deprecation.yaml",
        ...     title="OctoPrint Python deprecations",
        ...     rules_type="deprecation",
        ...     id_prefix="DEP",
        ...     severity="MEDIUM",
        ... )
    """

    path: str
    title: str
    rules_type: str
    id_prefix: str
    severity: str


class RuleFile(Enum):
    """Rule file registry.

    Each member's value is a :class:`RuleFileSpec` carrying the file's
    relative path, rule ID prefix and default severity.

    Examples:
        >>> RuleFile.python_deprecation.value.path
        'deprecation/python_deprecation.yaml'
        >>> RuleFile.python_deprecation.value.id_prefix
        'DEP'
        >>> RuleFile.python_deprecation.value.severity
        'MEDIUM'
    """

    python_deprecation = RuleFileSpec(
        path="deprecation/python_deprecation.yaml",
        title="OctoPrint Python deprecation rules",
        rules_type="deprecation",
        id_prefix="DEP",
        severity="MEDIUM",
    )
    python_removal = RuleFileSpec(
        path="removal/python_removal.yaml",
        title="OctoPrint Python removal rules",
        rules_type="removal",
        id_prefix="REM",
        severity="CRITICAL",
    )
    python_signature_change = RuleFileSpec(
        path="removal/python_signature_change.yaml",
        title="OctoPrint Python signature change rules",
        rules_type="removal",
        id_prefix="SIG",
        severity="HIGH",
    )
    python_settings_deprecation = RuleFileSpec(
        path="deprecation/python_settings_deprecation.yaml",
        title="OctoPrint Python settings deprecation rules",
        rules_type="deprecation",
        id_prefix="STG-DEP",
        severity="MEDIUM",
    )
    python_settings_removal = RuleFileSpec(
        path="removal/python_settings_removal.yaml",
        title="OctoPrint Python settings removal rules",
        rules_type="removal",
        id_prefix="STG-REM",
        severity="CRITICAL",
    )


@dataclass
class PythonAnalysisResult:
    """Python analysis result for a single OctoPrint version.

    Attributes:
        deprecations (list[Deprecation]): All detected deprecations.
        class_hierarchy (dict[str, list[str]]): Class name -> list of base
            class names.
        griffe_module (griffe.Module): The loaded Griffe module tree.
        settings_paths (set[tuple[str, ...]]): All leaf settings paths extracted
            from the configuration schema, e.g. ``{("serial", "port"), ...}``.
        compat_settings_paths (dict[tuple[str, ...], str]): Settings paths covered
            by a deprecated compatibility overlay. Maps the path (or wildcard prefix
            ending in ``"*"``) to the deprecation message declared on the overlay.
    """

    deprecations: list[Deprecation]
    class_hierarchy: dict[str, list[str]]
    griffe_module: griffe.Module
    settings_paths: set[tuple[str, ...]]
    compat_settings_paths: dict[tuple[str, ...], str]


@dataclass
class PipelineState:
    """Shared mutable state passed through analyzers and processors.

    Attributes:
        versions (list[str]): Ordered OctoPrint version strings analyzed.
        python_analysis_results (dict[str, PythonAnalysisResult]): Per-OctoPrint-version
            Python analysis results. Populated by PythonAnalyzer.
        rules (dict[RuleFile, list[dict]]): Rule file -> list of rule dicts.
    """

    versions: list[str]
    python_analysis_results: dict[str, PythonAnalysisResult]
    rules: dict[RuleFile, list[dict]]


@dataclass
class Deprecation:
    """A deprecation detected in OctoPrint source code.

    Attributes:
        name (str): Symbol name (e.g. ``"getApiKey"``) or dotted module path
            for module-level deprecations.
        kind (SymbolKind): Symbol kind - see :class:`SymbolKind` for values.
        message (str): Human-readable deprecation message from the source code.
        since (str | None): OctoPrint version that introduced the deprecation
            (e.g. ``"1.8.0"``), or ``None`` if unknown.
        class_name (str | None): Enclosing class name, or ``None`` for
            module-level symbols.
        module_path (str): Dotted module path (e.g. ``"octoprint.printer"``).
        line_number (int): Source line number where the deprecation was detected.

    Examples:
        >>> dep = Deprecation(
        ...     name="getApiKey", kind=SymbolKind.FUNCTION,
        ...     message="Replaced by apikey.", since="1.8.0",
        ...     class_name="UserManager", module_path="octoprint.access.users",
        ...     line_number=42,
        ... )
    """

    name: str
    kind: SymbolKind
    message: str
    since: str | None
    class_name: str | None
    module_path: str
    line_number: int


@dataclass(frozen=True)
class Removal:
    """A symbol removed between two OctoPrint versions.

    Attributes:
        name (str): Symbol name (e.g. ``"oldMethod"``) or dotted module path
            for module-level removals.
        kind (SymbolKind): Symbol kind - see :class:`SymbolKind` for values.
        since (str): OctoPrint version where the symbol was removed (e.g. ``"1.8.0"``).
        class_name (str | None): Enclosing class name, or ``None`` for
            top-level symbols.
        module_path (str): Dotted module path (e.g. ``"octoprint.server"``).

    Examples:
        >>> rem = Removal("oldMethod", SymbolKind.FUNCTION, "1.8.0", "PrinterInterface", "octoprint.printer")
    """

    name: str
    kind: SymbolKind
    since: str
    class_name: str | None
    module_path: str


@dataclass(frozen=True)
class SignatureChange:
    """A function/method whose signature lost a keyword parameter.

    Attributes:
        name (str): Callable name (e.g. ``"add_file"``).
        since (str): OctoPrint version where the parameter was removed (e.g. ``"1.8.0"``).
        class_name (str | None): Enclosing class name, or ``None`` for
            module-level functions.
        module_path (str): Dotted module path (e.g. ``"octoprint.filemanager"``).
        removed_param (str): Name of the removed keyword parameter.

    Examples:
        >>> sc = SignatureChange(
        ...     name="add_file",
        ...     since="1.10.0",
        ...     class_name="FileManager",
        ...     module_path="octoprint.filemanager",
        ...     removed_param="destination",
        ... )
    """

    name: str
    since: str
    class_name: str | None
    module_path: str
    removed_param: str
