from __future__ import annotations

import json
import linecache
import subprocess
import sys
from pathlib import Path

from packaging.version import Version

from . import PLUGINS_SRC_DIR
from .models import Finding, Rule, RuleType, ScanResult

SNIPPET_CONTEXT_LINES = 1
"""Lines of context around matched lines in code snippets."""


def scan(
    plugin_paths: list[Path],
    rule_files: list[Path],
    extra_args: list[str] | None = None,
    use_opengrep: bool = False,
) -> list[tuple[Path, ScanResult]]:
    """Scan plugin directories by running Semgrep/Opengrep once and mapping results."""
    semgrep_results = _run_semgrep(plugin_paths, rule_files, extra_args, use_opengrep)

    # Pre-compute plugin_paths_set
    plugin_paths_set = {plugin_path.resolve(): plugin_path for plugin_path in plugin_paths}

    findings_by_plugin_path = {plugin_path: [] for plugin_path in plugin_paths}
    for semgrep_result in semgrep_results:
        semgrep_result_abs_path = Path(semgrep_result.get("path", "")).resolve()
        # Find which plugin this finding belongs to
        # Walk up parents to find matching plugin path
        plugin_path = _find_plugin_path_by_file_path(semgrep_result_abs_path, plugin_paths_set)
        if plugin_path is None:
            continue
        finding = _semgrep_json_to_finding(semgrep_result, plugin_path)
        if finding is not None:
            findings_by_plugin_path[plugin_path].append(finding)

    scan_results = []
    for plugin_path in plugin_paths:
        findings = sorted(findings_by_plugin_path[plugin_path], key=lambda f: f.rule.id)
        scan_results.append((plugin_path, ScanResult(findings)))

    return scan_results


# ---------------------------------------------------------------------------
# Semgrep execution
# ---------------------------------------------------------------------------


def _run_semgrep(
    targets: list[Path],
    rule_files: list[Path],
    extra_args: list[str] | None = None,
    use_opengrep: bool = False,
) -> list[dict]:
    """Run semgrep/opengrep with the given rule files and return the JSON results list."""
    tool_name = "Opengrep" if use_opengrep else "Semgrep"

    configs = [arg for rf in rule_files for arg in ("--config", str(rf))]
    targets_str = [str(target) for target in targets]

    extra_args = list(extra_args or [])

    # Bypass octoscanner's own .gitignore when scanning PLUGINS_SRC_DIR
    plugins_src_root = PLUGINS_SRC_DIR.resolve()
    if any(plugins_src_root in target.resolve().parents or target.resolve() == plugins_src_root for target in targets):
        if "--no-git-ignore" not in extra_args:
            extra_args.append("--no-git-ignore")

    if use_opengrep:
        cmd = [
            "opengrep",
            "scan",
            *configs,
            "--json",
            "--no-rewrite-rule-ids",
            "--quiet",
            *extra_args,
            *targets_str,
        ]
    else:
        cmd = [
            "semgrep",
            "scan",
            *configs,
            "--json",
            "--metrics=off",
            "--no-rewrite-rule-ids",
            "--quiet",
            *extra_args,
            *targets_str,
        ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode not in (0, 1):
        print(result.stderr, file=sys.stderr)
        return []
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"{tool_name} returned invalid JSON", file=sys.stderr)
        return []
    return data.get("results", [])


# ---------------------------------------------------------------------------
# Result parsing
# ---------------------------------------------------------------------------


def _find_plugin_path_by_file_path(file_path: Path, plugin_paths_set: dict[Path, Path]) -> Path | None:
    """Find the plugin path that contains the given file path."""
    current = file_path.parent
    while current != current.parent:  # Stop at root
        if current in plugin_paths_set:
            return plugin_paths_set[current]
        current = current.parent
    return None


def _semgrep_json_to_finding(
    semgrep_result: dict,
    plugin_path: Path,
) -> Finding | None:
    """Convert a single Semgrep JSON result into a Finding object."""
    rule = _parse_rule(semgrep_result)
    if rule is None:
        return None

    abs_path = semgrep_result.get("path", "")
    try:
        rel_path = str(Path(abs_path).relative_to(plugin_path))
    except ValueError:
        rel_path = abs_path

    start = semgrep_result.get("start", {})
    end = semgrep_result.get("end", {})
    line = start.get("line", 0)
    end_line = end.get("line")
    snippet = _build_snippet(abs_path, line, end_line)

    return Finding(
        rule=rule,
        file_path=rel_path,
        line_number=line,
        end_line_number=end_line,
        code_snippet=snippet,
    )


def _parse_rule(item: dict) -> Rule | None:
    """Build a Rule from a single Semgrep JSON result item."""
    extra = item.get("extra", {})
    meta = extra.get("metadata", {})
    if "type" not in meta:
        return None

    try:
        rule_type = RuleType(meta["type"])
    except ValueError:
        return None

    check_id = item.get("check_id", "")
    rule_id = check_id.rsplit(".", 1)[-1]
    since = Version(str(meta["since"])) if "since" in meta else None

    return Rule(
        id=rule_id,
        type=rule_type,
        message=extra.get("message", ""),
        severity=extra.get("severity", "MEDIUM"),
        suggestion=meta.get("suggestion"),
        since=since,
    )


# ---------------------------------------------------------------------------
# Snippet generation
# ---------------------------------------------------------------------------


def _build_snippet(abs_path: str, start_line: int, end_line: int | None) -> str:
    """Build a numbered code snippet from the source file."""
    if start_line < 1:
        return ""

    first = max(start_line - SNIPPET_CONTEXT_LINES, 1)
    last = start_line + SNIPPET_CONTEXT_LINES
    result = []
    for lineno in range(first, last + 1):
        content = linecache.getline(abs_path, lineno)
        if not content:
            break
        marker = ">" if lineno == start_line else " "
        result.append(f"  {marker} {lineno:>4} | {content.rstrip()}")
    return "\n".join(result)
