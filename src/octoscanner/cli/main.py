from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .commands import cmd_download_octoprint, cmd_generate, cmd_scan


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="octoscanner",
        description="Scan OctoPrint plugins for compatibility issues",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- download sub-command ---
    download_parser = sub.add_parser(
        "download",
        help="Download OctoPrint sources or plugins",
    )
    download_what = download_parser.add_subparsers(dest="download_what", required=True)

    download_octoprint = download_what.add_parser("octoprint", help="Download OctoPrint sources")
    download_octoprint.set_defaults(func=cmd_download_octoprint)
    download_octoprint_type = download_octoprint.add_subparsers(dest="download_type", required=True)

    download_octoprint_tag = download_octoprint_type.add_parser("tag", help="Download a release tag")
    download_octoprint_tag.add_argument("tag", help="Tag name (e.g. 1.11.7)")
    download_octoprint_tag.add_argument(
        "--force", action="store_true", help="Re-download even if the folder already exists"
    )

    download_octoprint_branch = download_octoprint_type.add_parser("branch", help="Download a branch")
    download_octoprint_branch.add_argument("branch", help="Branch name (e.g. dev)")
    download_octoprint_branch.add_argument("name", help="Folder name under octoprint_src/ (e.g. 2.0.0)")
    download_octoprint_branch.add_argument(
        "--force", action="store_true", help="Re-download even if the folder already exists"
    )

    download_octoprint_all = download_octoprint_type.add_parser(
        "all", help="Download a set of relevant OctoPrint versions"
    )
    download_octoprint_all.add_argument(
        "--force", action="store_true", help="Re-download even if folders already exist"
    )

    # --- generate sub-command ---
    generate_parser = sub.add_parser(
        "generate",
        help="Generate rules from OctoPrint downloaded sources",
    )
    generate_parser.set_defaults(func=cmd_generate)
    generate_parser.add_argument(
        "versions",
        nargs="+",
        help="OctoPrint versions to analyze (e.g. 1.11.7 2.0.0), or 'all' for every downloaded version",
    )
    generate_parser.add_argument(
        "--save",
        action="store_true",
        help="Save rules to YAML files (default: dry-run to stdout)",
    )
    generate_parser.add_argument(
        "--force",
        action="store_true",
        help="Regenerate all rules from scratch (implies --save)",
    )

    # --- scan sub-command ---
    scan_parser = sub.add_parser("scan", help="Scan a plugin directory")
    scan_parser.set_defaults(func=cmd_scan)
    scan_parser.add_argument("plugin_paths", nargs="+", type=Path, help="Path(s) to the plugin folder(s)")
    scan_parser.add_argument(
        "--rule-type",
        "-r",
        action="append",
        default=None,
        metavar="TYPE",
        help="Scan only for these rule types (e.g. -r deprecation -r removal)",
    )
    scan_parser.add_argument(
        "--format",
        "-f",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text)",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="Skip files matching this pattern (e.g. --exclude '*.pyc' --exclude 'tests/')",
    )
    scan_parser.add_argument(
        "--no-git-ignore",
        action="store_true",
        help="Don't skip files ignored by .gitignore",
    )
    scan_parser.add_argument(
        "--exclude-rule",
        action="append",
        default=[],
        metavar="RULE_ID",
        help="Skip this rule ID (e.g. --exclude-rule DEP-0001 --exclude-rule REM-0001)",
    )
    scan_parser.add_argument(
        "--use-opengrep",
        action="store_true",
        help="Use opengrep instead of semgrep (must be installed separately)",
    )

    args = parser.parse_args(argv)

    try:
        args.func(args)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
