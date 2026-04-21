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

from .. import DOWNLOAD_DIR
from .analyzers import ANALYZERS
from .models import PipelineState, RuleFile
from .processors import PROCESSORS
from .rules import load_rule_file, write_semgrep_file


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

    source_dirs = {}
    for version in versions:
        version_dir = DOWNLOAD_DIR / version
        if not version_dir.is_dir():
            raise FileNotFoundError(f"Source not found: {version_dir}")
        source_dirs[version] = version_dir

    rules = {rule_file: load_rule_file(rule_file) for rule_file in RuleFile}

    if force:
        for rule_file, rule_list in rules.items():
            rule_list.clear()
            write_semgrep_file(rule_file, [])
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
            print(f"  {rule_file.value} ({len(rule_list)} rules)")
        return

    if save:
        print("Saved:")
        for rule_file, rule_list in pipeline_state.rules.items():
            write_semgrep_file(rule_file, rule_list)
            print(f"  {rule_file.value} ({len(rule_list)} rules)")
    else:
        print("Generated:")
        for rule_file, rule_list in pipeline_state.rules.items():
            print(f"  {rule_file.value} ({len(rule_list)} rules)")
        print("Use --save to write to disk.")
