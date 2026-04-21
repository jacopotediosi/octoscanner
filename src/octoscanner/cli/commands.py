from __future__ import annotations

import argparse
import sys
from pathlib import Path

from packaging.version import Version

from .. import (
    DOWNLOAD_DIR,
    OCTOPRINT_ALL_VERSION_BRANCHES,
    OCTOPRINT_ALL_VERSION_TAGS,
    RULES_DIR,
)
from ..downloader import download_octoprint_source
from ..generator import generate
from ..scanner import scan
from .formatter import format_scan_results_json, format_scan_results_text

# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------


def cmd_download_octoprint(args: argparse.Namespace) -> None:
    refs = []
    if args.download_type == "all":
        refs += [(tag, tag, "tag") for tag in OCTOPRINT_ALL_VERSION_TAGS]
        refs += [(branch, name, "branch") for name, branch in OCTOPRINT_ALL_VERSION_BRANCHES.items()]
    elif args.download_type == "tag":
        refs.append((args.tag, args.tag, "tag"))
    elif args.download_type == "branch":
        refs.append((args.branch, args.name, "branch"))

    for ref, name, kind in refs:
        try:
            download_octoprint_source(ref, name=name, kind=kind, force=args.force)
        except FileExistsError:
            print(f"{name}: already downloaded")


def cmd_generate(args: argparse.Namespace) -> None:
    if args.versions == ["all"]:
        if not DOWNLOAD_DIR.is_dir():
            raise FileNotFoundError(f"Download directory {DOWNLOAD_DIR} does not exist. Use 'download' command first.")
        dirs = sorted(
            (d for d in DOWNLOAD_DIR.iterdir() if d.is_dir()),
            key=lambda p: Version(p.name),
        )
        if not dirs:
            raise FileNotFoundError(f"No version directories found in {DOWNLOAD_DIR}. Use 'download' command first.")
        versions = [d.name for d in dirs]
    else:
        versions = args.versions

    generate(versions, force=args.force, save=args.save)


def cmd_scan(args: argparse.Namespace) -> None:
    plugin_paths = [p.resolve() for p in args.plugin_paths]
    for plugin_path in plugin_paths:
        if not plugin_path.is_dir():
            raise FileNotFoundError(f"{plugin_path} is not a directory")

    rule_files = _resolve_rule_types(args.rule_type)

    extra_args = []
    for pattern in args.exclude:
        extra_args += ["--exclude", pattern]
    if args.no_git_ignore:
        extra_args.append("--no-git-ignore")
    for rule_id in args.exclude_rule:
        extra_args += ["--exclude-rule", rule_id]

    results = scan(
        plugin_paths=plugin_paths,
        rule_files=rule_files,
        extra_args=extra_args,
        use_opengrep=args.use_opengrep,
    )

    if args.format == "json":
        format_scan_results_json(results, args)
    else:
        format_scan_results_text(results, args)

    if any(result.has_issues for _, result in results):
        sys.exit(1)


# ---------------------------------------------------------------------------
# Args parsing helpers
# ---------------------------------------------------------------------------


def _resolve_rule_types(rule_types: list[str] | None) -> list[Path]:
    """Resolve rule type names to YAML file paths inside `RULES_DIR`.

    Args:
        rule_types: List of rule types (e.g. ``["deprecation", "removal"]``),
            or ``None`` to load all rules.

    Returns:
        List of resolved paths to YAML rule files.

    Raises:
        FileNotFoundError: If ``RULES_DIR`` doesn't exist.
        ValueError: If a rule type doesn't correspond to a valid subfolder.
    """
    if not RULES_DIR.is_dir():
        raise FileNotFoundError(f"Rules directory not found: {RULES_DIR}")
    if not rule_types:
        return sorted(RULES_DIR.glob("**/*.yaml"))

    rule_paths = []

    for rule_type in rule_types:
        rule_type_subdir = RULES_DIR / rule_type
        if not rule_type_subdir.is_dir():
            available = [d.name for d in RULES_DIR.iterdir() if d.is_dir()]
            raise ValueError(f"Unknown rule type: {rule_type}. Available: {', '.join(sorted(available))}.")
        rule_paths.extend(sorted(rule_type_subdir.glob("*.yaml")))

    return rule_paths
