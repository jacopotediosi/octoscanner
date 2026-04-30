from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TextIO

import yaml
from rich.console import Console, Group
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text

from .. import RULES_DIR, get_version
from ..models import Finding, RuleFileMetadata, ScanResult

FINDING_SECTIONS = (
    # (header title, ScanResult attr, style keys)
    ("Removal", "removal", ("error", "header")),
    ("Security", "security", ("error", "header")),
    ("Deprecation", "deprecation", ("warning", "header")),
    ("Packaging", "packaging", ("warning", "header")),
)

SINCE_LABELS = {
    "removal": "Removed in",
    "deprecation": "Deprecated since",
}

BACKTICK_RE = re.compile(r"```(.*?)```|`([^`]+)`", re.DOTALL)


# ---------------------------------------------------------------------------
# Styling
# ---------------------------------------------------------------------------


def _get_style(*style_keys: str) -> Style:
    """Return a Rich Style combining one or more predefined style keys.

    Args:
        *style_keys (str): One or more style key names to combine.
            Available keys:
            - ``header``
            - ``rule_id``
            - ``file_path``
            - ``code_snippet``
            - ``inline_code``
            - ``error``
            - ``warning``

    Returns:
        Style: A combined ``Style`` instance.

    Examples:
        >>> _get_style("header")           # bold
        >>> _get_style("header", "error")  # bold red
    """
    styles = {
        "header": "bold",
        "rule_id": "bold",
        "file_path": "cyan",
        "code_snippet": "grey62",
        "inline_code": "cyan",
        "error": "red",
        "warning": "yellow",
    }
    return Style.combine([Style.parse(styles[k]) for k in style_keys])


def _style_code_fragments(text: str) -> Text:
    """Parse backtick-delimited fragments and apply code styles.

    Converts markdown-style backtick code (inline \\`code\\` and fenced \\`\\`\\`blocks\\`\\`\\`)
    into Rich Text with appropriate styling.

    Args:
        text (str): Plain text possibly containing backtick-delimited code fragments.

    Returns:
        Text: A ``Text`` instance with styled code fragments.

    Examples:
        >>> _style_code_fragments("Use `foo()` here")
        >>> _style_code_fragments("Example:\n```python\nprint('hi')\n```")
    """
    result = Text()
    last = 0
    for m in BACKTICK_RE.finditer(text):
        if m.start() > last:
            result.append(text[last : m.start()])
        is_block = m.group(1) is not None
        code = m.group(1) if is_block else m.group(2)
        if is_block:
            code = re.sub(r"^\w*\n", "", code).strip("\n")
        result.append(code, style=_get_style("code_snippet" if is_block else "inline_code"))
        last = m.end()
    if last < len(text):
        result.append(text[last:])
    return result


# ---------------------------------------------------------------------------
# Scan results formatters
# ---------------------------------------------------------------------------


def _collect_rule_files_metadata(rule_paths: list[Path]) -> list[tuple[str, RuleFileMetadata | None]]:
    """Read generation metadata from rule YAML files.

    Args:
        rule_paths (list[Path]): Rule YAML files, or directories that
            contain them (searched recursively).

    Returns:
        list[tuple[str, RuleFileMetadata | None]]: One ``(path, metadata)``
        pair per rule file found, sorted by path. ``metadata`` is ``None``
        when the file has no readable metadata.
    """
    results = []

    yaml_files = set()
    for path in rule_paths:
        if path.is_file() and path.suffix == ".yaml":
            yaml_files.add(path.resolve())
        elif path.is_dir():
            yaml_files.update(p.resolve() for p in path.rglob("*.yaml"))

    rules_root = RULES_DIR.resolve()
    for yaml_path in sorted(yaml_files):
        relative_path = str(yaml_path.relative_to(rules_root))

        try:
            data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            results.append((relative_path, None))
            continue

        block = data.get("_octoscanner") if isinstance(data, dict) else None
        if not isinstance(block, dict):
            results.append((relative_path, None))
            continue

        results.append(
            (
                relative_path,
                RuleFileMetadata(
                    octoscanner_version=block.get("octoscanner_version"),
                    generated_at=block.get("generated_at"),
                    octoprint_versions=list(block.get("octoprint_versions") or []),
                ),
            )
        )

    return results


def format_scan_results_text(
    scan_results: list[tuple[Path, ScanResult]],
    args: argparse.Namespace,
    rule_files: list[Path],
    out: TextIO = sys.stdout,
) -> None:
    """Renders scan results as nested panels with colored output,
    including per-plugin findings and aggregated rule statistics.

    Args:
        scan_results (list[tuple[Path, ScanResult]]): List of (plugin_path, scan_result) tuples to format.
        args (argparse.Namespace): Parsed CLI arguments.
        rule_files (list[Path]): Rule YAML files or directories used by the
            scan.
        out (TextIO): Output stream to write to.

    Returns:
        None: Output is written directly to ``out``.

    Examples:
        >>> format_scan_results_text(results, args, rule_files)
        >>> format_scan_results_text(results, args, rule_files, out=sys.stderr)
    """

    def format_finding(finding: Finding, since_label: str | None = None) -> list[Text | str]:
        """Return formatted lines for a single finding.

        Generates a list of styled text lines including rule ID, message,
        since label, file location, code snippet, and suggestion.

        Args:
            finding (Finding): The finding to format.
            since_label (str | None): Optional since label (e.g., "Deprecated since").

        Returns:
            list[Text | str]: List of ``Text`` or plain strings representing the finding.

        Examples:
            >>> lines = format_finding(finding, since_label="Removed in")
        """
        lines = []

        lines.append(Text(finding.rule.id, style=_get_style("rule_id")))
        lines.append(_style_code_fragments(finding.rule.message.strip()))
        if since_label and finding.rule.since:
            lines.append(f"{since_label}: {finding.rule.since}")
        lines.append(Text("File: ").append(f"{finding.file_path}:{finding.line_number}", style=_get_style("file_path")))
        if finding.code_snippet:
            lines.append(Text(finding.code_snippet, style=_get_style("code_snippet")))
        if finding.rule.suggestion:
            lines.append(_style_code_fragments(f"Suggestion: {finding.rule.suggestion.strip()}"))

        return lines

    def format_generated_at(value: str | None) -> str:
        """Render an ISO-8601 timestamp as ``YYYY-MM-DD HH:MM:SS UTC``.

        Returns ``"-"`` for ``None``/empty input and falls back to the raw
        string if parsing fails.
        """
        if not value:
            return "-"
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return value
        if dt.tzinfo is not None:
            dt = dt.astimezone(timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    def build_rule_files_panel(rule_files: list[Path]) -> Panel:
        """Build a panel listing rule files with their generation metadata.

        Args:
            rule_files (list[Path]): Rule YAML files or directories used by
                the scan.

        Returns:
            Panel: A ``Panel`` containing the table.
        """
        rule_files_metadata = _collect_rule_files_metadata(rule_files)

        table = Table(box=None, show_header=True, padding=(0, 2, 0, 0))
        table.add_column("Rule file")
        table.add_column("Generated by")
        table.add_column("Generated at")
        table.add_column("For OctoPrint versions")
        for path, meta in rule_files_metadata:
            if meta is None:
                table.add_row(Text(path, style=_get_style("file_path")), "-", "-", "-")
                continue
            table.add_row(
                Text(path, style=_get_style("file_path")),
                meta.octoscanner_version or "-",
                format_generated_at(meta.generated_at),
                ", ".join(meta.octoprint_versions) if meta.octoprint_versions else "-",
            )

        return Panel(
            table,
            title=Text(f"Loaded rule files ({len(rule_files_metadata)})", style=_get_style("header")),
        )

    def build_plugin_panel(plugin_path: Path, scan_result: ScanResult) -> Panel | None:
        """Build a panel for a single plugin's findings.

        Creates a nested panel structure with a summary panel at the top,
        followed by section panels for each finding section
        (see ``FINDING_SECTIONS``).

        Args:
            plugin_path (Path): Path to the plugin directory.
            scan_result (ScanResult): Scan result containing findings for this plugin.

        Returns:
            Panel | None: A ``Panel`` containing the plugin's findings, or ``None`` if no issues.

        Examples:
            >>> panel = build_plugin_panel(Path("/home/user/myplugin"), scan_result)
        """
        if not scan_result.has_issues:
            return None

        plugin_subpanels = []
        summary_panel_parts = []
        finding_section_panels = []

        for title, scan_result_attr, style_keys in FINDING_SECTIONS:
            findings = getattr(scan_result, scan_result_attr)
            if findings:
                since_label = SINCE_LABELS.get(scan_result_attr)

                finding_lines = []
                for i, finding in enumerate(findings):
                    if i > 0:
                        finding_lines.append("")
                    finding_lines.extend(format_finding(finding, since_label=since_label))

                finding_section_panel = Panel(
                    Group(*finding_lines),
                    title=Text(f"{title} ({len(findings)} findings)", style=_get_style(*style_keys)),
                )
                finding_section_panels.append(finding_section_panel)

                summary_panel_parts.append(f"{len(findings)} {title.lower()}")

        summary_panel = Panel(
            ", ".join(summary_panel_parts),
            title=Text(f"Summary ({len(scan_result.findings)} total findings)", style=_get_style("header")),
        )
        plugin_subpanels.append(summary_panel)
        plugin_subpanels.extend(finding_section_panels)

        return Panel(
            Group(*plugin_subpanels),
            title=Text("Plugin ", style=_get_style("header")).append(str(plugin_path), style=_get_style("file_path")),
        )

    def build_plugins_without_issues_panel(plugin_paths: list[Path]) -> Panel:
        """Build a panel listing plugin paths without issues.

        Args:
            plugin_paths (list[Path]): List of plugin paths without issues.

        Returns:
            Panel | None: A ``Panel`` listing the plugin paths, or ``None`` if empty.
        """
        if not plugin_paths:
            return None

        content = Text()
        for i, plugin_path in enumerate(plugin_paths):
            if i > 0:
                content.append("\n")
            content.append(str(plugin_path), style=_get_style("file_path"))

        return Panel(
            content,
            title=Text(f"Plugins without issues ({len(plugin_paths)})", style=_get_style("header")),
        )

    def build_rule_stats_panel(scan_results: list[tuple[Path, ScanResult]]) -> Panel | None:
        """Build a panel with aggregated rule statistics.

        Aggregates rule match counts across all plugins and displays them
        in a tabular format sorted by frequency.

        Args:
            scan_results (list[tuple[Path, ScanResult]]): List of (plugin_path, scan_result) tuples.

        Returns:
            Panel | None: A ``Panel`` containing the rule statistics table, or ``None`` if no matches.

        Examples:
            >>> stats = build_rule_stats_panel(scan_results)
        """
        rule_counter = Counter()
        plugins_by_rule = {}
        rule_info = {}
        plugins_with_matches = 0

        for plugin_path, scan_result in scan_results:
            if scan_result.findings:
                plugins_with_matches += 1
            for finding in scan_result.findings:
                rule_counter[finding.rule.id] += 1
                plugins_by_rule.setdefault(finding.rule.id, set()).add(plugin_path)
                rule_info[finding.rule.id] = finding.rule.message.strip().split("\n")[0]

        if not rule_counter:
            return None

        total_rules = len(rule_counter)
        total_matches = sum(rule_counter.values())
        total_plugins = len(scan_results)

        table = Table(box=None, show_header=True, padding=(0, 2, 0, 0))
        table.add_column("Total\nmatches", justify="right")
        table.add_column("Plugins\nmatched", justify="right")
        table.add_column("Rule ID")
        table.add_column("Message")
        for rule_id, count in rule_counter.most_common():
            table.add_row(
                str(count),
                str(len(plugins_by_rule[rule_id])),
                rule_id,
                _style_code_fragments(rule_info[rule_id]),
            )

        return Panel(
            table,
            title=Text(
                f"Rule Statistics ({total_rules} rules matched {total_matches} times on {plugins_with_matches}/{total_plugins} plugins)",
                style=_get_style("header"),
            ),
        )

    color = not args.no_color and out.isatty()
    console = Console(file=out, no_color=not color, highlight=False)

    plugin_panels = []
    footer_panels = []

    plugins_without_issues_paths = []

    rule_files_panel = build_rule_files_panel(rule_files)

    for plugin_path, scan_result in scan_results:
        plugin_panel = build_plugin_panel(plugin_path, scan_result)
        if plugin_panel:
            plugin_panels.append(plugin_panel)
        else:
            plugins_without_issues_paths.append(plugin_path)

    plugins_without_issues_panel = build_plugins_without_issues_panel(plugins_without_issues_paths)
    if plugins_without_issues_panel:
        footer_panels.append(plugins_without_issues_panel)

    rule_stats_panel = build_rule_stats_panel(scan_results)
    if rule_stats_panel:
        footer_panels.append(rule_stats_panel)

    all_panels = [rule_files_panel, *plugin_panels, *footer_panels]

    spaced_panels = [""]
    for plugin_panel in all_panels:
        spaced_panels.append(plugin_panel)
        spaced_panels.append("")

    outer_panel = Panel(
        Group(*spaced_panels),
        title=Text(f"OctoScanner {get_version()}", style=_get_style("header")),
    )
    console.print()
    console.print(outer_panel)


def format_scan_results_json(
    scan_results: list[tuple[Path, ScanResult]],
    args: argparse.Namespace,
    rule_files: list[Path],
    out: TextIO = sys.stdout,
) -> None:
    """Format scan results as JSON.

    Outputs a JSON object containing per-plugin findings and aggregated rule statistics.

    Args:
        scan_results (list[tuple[Path, ScanResult]]): List of (plugin_path, scan_result) tuples to format.
        args (argparse.Namespace): Parsed CLI arguments.
        rule_files (list[Path]): Rule YAML files or directories used by the
            scan.
        out (TextIO): Output stream to write to.

    Returns:
        None: JSON is written directly to ``out``.

    Examples:
        >>> format_scan_results_json(results, args, rule_files)
        >>> format_scan_results_json(results, args, rule_files, out=open("out.json", "w"))
    """
    rule_counter = Counter()
    plugins_by_rule = {}
    rule_info = {}

    plugins_data = []
    for plugin_path, scan_result in scan_results:
        for finding in scan_result.findings:
            rule_counter[finding.rule.id] += 1
            plugins_by_rule.setdefault(finding.rule.id, set()).add(plugin_path)
            rule_info[finding.rule.id] = finding.rule.message

        plugins_data.append(
            {
                "plugin_path": str(plugin_path),
                "summary": {
                    scan_result_attr: len(getattr(scan_result, scan_result_attr))
                    for _, scan_result_attr, _ in FINDING_SECTIONS
                },
                **{
                    scan_result_attr: [asdict(f) for f in getattr(scan_result, scan_result_attr)]
                    for _, scan_result_attr, _ in FINDING_SECTIONS
                },
            }
        )

    rule_stats = [
        {
            "rule_id": rule_id,
            "total_matches": count,
            "plugins_matched": len(plugins_by_rule[rule_id]),
            "message": rule_info[rule_id],
        }
        for rule_id, count in rule_counter.most_common()
    ]

    data = {
        "octoscanner_version": get_version(),
        "rule_files": [
            {"path": path, **(asdict(meta) if meta is not None else {})}
            for path, meta in _collect_rule_files_metadata(rule_files)
        ],
        "plugins": plugins_data,
        "rule_statistics": rule_stats,
    }

    json.dump(
        data,
        out,
        indent=2,
        default=lambda obj: obj.value if isinstance(obj, Enum) else str(obj),
    )
    out.write("\n")
