"""Generator pipeline orchestration.

Architecture
------------
The generator is a modular pipeline driven by :func:`generate`. It works
in two phases:

1. **Analysis** - Each OctoPrint version is loaded and analyzed by
   analyzers (``analyzers/`` sub-package), which e.g. extract information
   like class hierarchies and deprecation markers from the source code.

2. **Processing** - The analysis results are fed through a sequence of
   processors (``processors/`` sub-package), executed sequentially over a
   shared :class:`~models.PipelineState`. Each processor reads the analysis
   data and current rule sets, and mutates the rules in place.
"""

from __future__ import annotations

from datetime import datetime, timezone

from packaging.version import Version

from .. import OCTOPRINT_ALL_VERSION_BRANCHES, OCTOPRINT_SRC_DIR, RULES_DIR, get_version
from ..models import RuleFileMetadata
from .analyzers import ANALYZERS
from .models import PipelineState, RuleFile
from .processors import PROCESSORS
from .rules import load_rule_file, read_rule_file_metadata, write_rule_file


def _annotate_octoprint_versions_with_branches(versions: list[str]) -> list[str]:
    """Return ``versions`` with branch annotations applied.

    Examples:
        >>> _annotate_octoprint_versions_with_branches(["1.11.7", "2.0.0"])
        ['1.11.7', '2.0.0 (dev branch)']
    """
    return [
        f"{v} ({OCTOPRINT_ALL_VERSION_BRANCHES[v]} branch)" if v in OCTOPRINT_ALL_VERSION_BRANCHES else v
        for v in versions
    ]


def _build_metadata(
    rule_file: RuleFile,
    octoscanner_version: str,
    generated_at: str,
    octoprint_versions: list[str],
    replace_existing: bool,
) -> RuleFileMetadata:
    """Build :class:`RuleFileMetadata` for ``rule_file``.

    Args:
        rule_file: Rule file the metadata is being built for.
        octoscanner_version: OctoScanner version string to record.
        generated_at: Timestamp string to record.
        octoprint_versions: OctoPrint versions to record, with branch
            annotations already applied.
        replace_existing: If ``True``, ignore any existing on-disk metadata;
            otherwise merge the OctoPrint versions already recorded in the
            file with the new ones.

    Returns:
        RuleFileMetadata: Metadata to embed in the rule file.

    Examples:
        >>> _build_metadata(
        ...     RuleFile.python_deprecation,
        ...     octoscanner_version="0.1.0",
        ...     generated_at="2026-04-30T12:00:00+00:00",
        ...     octoprint_versions=["1.4.0", "2.0.0 (next branch)"],
        ...     replace_existing=True,
        ... )
        RuleFileMetadata(octoscanner_version='0.1.0',
                         generated_at='2026-04-30T12:00:00+00:00',
                         octoprint_versions=['1.4.0', '2.0.0 (next branch)'])
    """
    existing_versions = []
    if not replace_existing:
        existing = read_rule_file_metadata(RULES_DIR / rule_file.value.path)
        if existing:
            existing_versions = list(existing.octoprint_versions)

    # Dedup by bare version (without considering branch annotations).
    # Entry from new wins on collision so updated branch annotations are preserved.
    by_bare = {}
    for entry in existing_versions:
        by_bare.setdefault(entry.split(" ", 1)[0], entry)
    for entry in octoprint_versions:
        by_bare[entry.split(" ", 1)[0]] = entry
    merged_versions = sorted(by_bare.values(), key=lambda e: Version(e.split(" ", 1)[0]))

    return RuleFileMetadata(
        octoscanner_version=octoscanner_version,
        generated_at=generated_at,
        octoprint_versions=merged_versions,
    )


def generate(
    versions: list[str],
    force: bool = False,
    save: bool = False,
) -> None:
    """Analyze the given OctoPrint versions and generate Semgrep rules into :data:`~octoscanner.RULES_DIR`.

    Args:
        versions (list[str]): Ordered list of OctoPrint version strings to
            analyze (e.g. ``["1.4.0", "1.5.0", ..., "2.0.0"]``).
        force (bool): Clear all existing rules before generating. Implies
            ``save=True``.
        save (bool): Write the resulting rules to disk.

    Raises:
        FileNotFoundError: If any version's source directory is missing.

    Examples:
        Progress is printed to stdout and rules are written to :data:`~octoscanner.RULES_DIR`:

            >>> generate(["1.4.0", "1.5.0", "1.6.0"], force=True)
            === Generating deprecation rules ===
            ...
    """
    save = save or force

    octoscanner_version = get_version()
    generation_datetime = datetime.now(timezone.utc).isoformat(timespec="seconds")
    octoprint_versions_with_branches = _annotate_octoprint_versions_with_branches(versions)

    source_dirs = {}
    for version in versions:
        version_dir = OCTOPRINT_SRC_DIR / version
        if not version_dir.is_dir():
            raise FileNotFoundError(f"Source not found: {version_dir}")
        source_dirs[version] = version_dir

    rules = {rule_file: load_rule_file(rule_file) for rule_file in RuleFile}

    if force:
        for rule_file, rule_list in rules.items():
            rule_list.clear()
            metadata = _build_metadata(
                rule_file=rule_file,
                octoscanner_version=octoscanner_version,
                generated_at=generation_datetime,
                octoprint_versions=octoprint_versions_with_branches,
                replace_existing=force,
            )
            write_rule_file(rule_file, [], metadata)
        print("Cleared existing rules.")
        print()

    original_rules = {f: list(r) for f, r in rules.items()}

    pipeline_state = PipelineState(versions=versions, python_analysis_results={}, rules=rules)

    for analyzer in ANALYZERS:
        print(f"=== {analyzer.title} ===")
        log_lines = analyzer.run(pipeline_state, source_dirs)
        for log_line in log_lines:
            print(log_line)
        print()

    for processor in PROCESSORS:
        print(f"=== {processor.title} ===")
        log_lines = processor.run(pipeline_state)
        for log_line in log_lines:
            print(log_line)
        print()

    if pipeline_state.rules == original_rules:
        print("Nothing to update.")
        print("Current rules:")
        for rule_file, rule_list in pipeline_state.rules.items():
            print(f"  {rule_file.value.path} ({len(rule_list)} rules)")
        return

    if save:
        print("Saved:")
        for rule_file, rule_list in pipeline_state.rules.items():
            metadata = _build_metadata(
                rule_file=rule_file,
                octoscanner_version=octoscanner_version,
                generated_at=generation_datetime,
                octoprint_versions=octoprint_versions_with_branches,
                replace_existing=force,
            )
            write_rule_file(rule_file, rule_list, metadata)
            print(f"  {rule_file.value.path} ({len(rule_list)} rules)")
    else:
        print("Generated:")
        for rule_file, rule_list in pipeline_state.rules.items():
            print(f"  {rule_file.value.path} ({len(rule_list)} rules)")
        print("Use --save to write to disk.")
