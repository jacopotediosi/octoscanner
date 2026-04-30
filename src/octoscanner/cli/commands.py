from __future__ import annotations

import argparse
import sys
from pathlib import Path

from packaging.version import Version

from .. import (
    OCTOPRINT_ALL_VERSION_BRANCHES,
    OCTOPRINT_ALL_VERSION_TAGS,
    OCTOPRINT_SRC_DIR,
    RULES_DIR,
)
from ..downloader import download_octoprint, download_plugins
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
            download_octoprint(ref=ref, kind=kind, name=name, force=args.force)
        except FileExistsError:
            print(f"{name}: already downloaded")


def cmd_download_plugins(args: argparse.Namespace) -> None:
    download_plugins(
        identifiers=args.identifiers,
        subfolder=args.subfolder,
        max_workers=args.workers,
        force=args.force,
    )


def cmd_generate(args: argparse.Namespace) -> None:
    if args.versions == ["all"]:
        if not OCTOPRINT_SRC_DIR.is_dir():
            raise FileNotFoundError(
                f"Download directory {OCTOPRINT_SRC_DIR} does not exist. Use 'download' command first."
            )
        dirs = sorted(
            (d for d in OCTOPRINT_SRC_DIR.iterdir() if d.is_dir()),
            key=lambda p: Version(p.name),
        )
        if not dirs:
            raise FileNotFoundError(
                f"No version directories found in {OCTOPRINT_SRC_DIR}. Use 'download' command first."
            )
        versions = [d.name for d in dirs]
    else:
        versions = args.versions

    generate(versions, force=args.force, save=args.save)


def cmd_scan(args: argparse.Namespace) -> None:
    plugin_paths = [p.resolve() for p in args.plugin_paths]
    for plugin_path in plugin_paths:
        if not plugin_path.is_dir():
            raise FileNotFoundError(f"{plugin_path} is not a directory")

    rule_files = _resolve_rules(args.rules)

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
        format_scan_results_json(results, args, rule_files)
    else:
        format_scan_results_text(results, args, rule_files)

    if any(result.has_issues for _, result in results):
        sys.exit(1)


# ---------------------------------------------------------------------------
# Args parsing helpers
# ---------------------------------------------------------------------------


def _resolve_rules(rules: list[str] | None) -> list[Path]:
    """Resolve rule selectors to YAML file or directory paths inside `RULES_DIR`.

    Each selector can be either a subdirectory name (e.g. ``"removal"``) or a
    relative path to a subdirectory or YAML file under `RULES_DIR` (e.g.
    ``"removal/python_removal.yaml"``).

    Args:
        rules: List of rule selectors, or ``None`` to load all rules.

    Returns:
        List of resolved paths (files or directories) under `RULES_DIR`.

    Raises:
        FileNotFoundError: If ``RULES_DIR`` doesn't exist.
        ValueError: If a selector doesn't resolve to a valid subfolder or file.

    Examples:
        >>> _resolve_rules(None)  # all rules
        [Path('rules')]

        >>> _resolve_rules(["removal"])  # rules/removal/ directory
        [Path('rules/removal')]

        >>> _resolve_rules(["removal/python_removal.yaml"])  # single file
        [Path('rules/removal/python_removal.yaml')]

        >>> _resolve_rules(["removal", "deprecation/python_deprecation.yaml"])  # mixed
        [Path('rules/removal'), Path('rules/deprecation/python_deprecation.yaml')]
    """
    if not RULES_DIR.is_dir():
        raise FileNotFoundError(f"Rules directory not found: {RULES_DIR}")
    if not rules:
        return [RULES_DIR]

    rule_paths = []

    for selector in rules:
        target = (RULES_DIR / selector).resolve()
        rules_root = RULES_DIR.resolve()
        if rules_root not in target.parents and target != rules_root:
            raise ValueError(f"Rule selector must stay within {RULES_DIR}: {selector}")

        if target.is_dir() or (target.is_file() and target.suffix == ".yaml"):
            rule_paths.append(target)
        else:
            available_dirs = sorted(d.name for d in RULES_DIR.iterdir() if d.is_dir())
            raise ValueError(
                f"Unknown rule selector: {selector}. "
                f"Expected a subdirectory or YAML file under {RULES_DIR} "
                f"(available subdirectories: {', '.join(available_dirs)})."
            )

    return rule_paths
