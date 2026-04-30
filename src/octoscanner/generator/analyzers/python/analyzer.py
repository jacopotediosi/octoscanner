from __future__ import annotations

import warnings
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING

import griffe

from ...models import PythonAnalysisResult
from ..base import Analyzer
from .deprecation_extension import GriffeDeprecationExtension
from .griffe_walker import walk_griffe
from .settings_extractor import extract_compat_settings_paths, extract_settings_paths

if TYPE_CHECKING:
    from ...models import PipelineState


def _python_analyze(source_dir: Path, version: str) -> PythonAnalysisResult:
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
        >>> result = _python_analyze(Path("octoprint_src/1.10.0"), "1.10.0")
        >>> len(result.deprecations)
        45
        >>> result.class_hierarchy["AnonymousUser"]
        ['AnonymousUserMixin', 'User']
    """
    if not (source_dir / "src" / "octoprint").is_dir():
        raise ValueError(f"OctoPrint source not found at {source_dir / 'src' / 'octoprint'}")

    deprecations = []
    class_hierarchy = {}

    griffe_deprecation_extension = GriffeDeprecationExtension()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        griffe_module = griffe.load(
            "octoprint", search_paths=[source_dir / "src"], extensions=griffe.Extensions(griffe_deprecation_extension)
        )

    # Populate deprecations and class_hierarchy
    walk_griffe(griffe_module, deprecations, class_hierarchy)
    deprecations.extend(griffe_deprecation_extension.deprecations)
    deprecations.sort(key=lambda d: (d.module_path, d.line_number))

    # Apply "since" fallback for deprecations without an explicit version
    for dep in deprecations:
        if dep.since is None:
            dep.since = version

    # Populate settings paths
    settings_paths = extract_settings_paths(griffe_module)
    compat_settings_paths = extract_compat_settings_paths(source_dir)

    return PythonAnalysisResult(
        deprecations=deprecations,
        class_hierarchy=class_hierarchy,
        griffe_module=griffe_module,
        settings_paths=settings_paths,
        compat_settings_paths=compat_settings_paths,
    )


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
            results = list(executor.map(_python_analyze, paths, versions))

        state.python_analysis_results = dict(zip(versions, results))

        for version, result in state.python_analysis_results.items():
            dep_count = len(result.deprecations)
            class_count = len(result.class_hierarchy)
            settings_paths_count = len(result.settings_paths)
            compat_count = len(result.compat_settings_paths)
            output_lines.append(
                f"  {version}: {class_count} classes, {dep_count} deprecations, "
                f"{settings_paths_count} settings paths, {compat_count} compat settings paths"
            )

        return output_lines
