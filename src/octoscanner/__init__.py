from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path

# OctoPrint versions
OCTOPRINT_NEXT_BRANCH = "next"
OCTOPRINT_NEXT_VERSION = "2.0.0"
OCTOPRINT_DEV_BRANCH = "dev"
OCTOPRINT_DEV_VERSION = "2.1.0"
OCTOPRINT_ALL_VERSION_TAGS = [
    "1.4.0",
    "1.5.0",
    "1.6.0",
    "1.7.0",
    "1.8.0",
    "1.9.0",
    "1.10.0",
    "1.11.0",
    "1.11.7",
]
OCTOPRINT_ALL_VERSION_BRANCHES = {
    OCTOPRINT_NEXT_VERSION: OCTOPRINT_NEXT_BRANCH,
    OCTOPRINT_DEV_VERSION: OCTOPRINT_DEV_BRANCH,
}

# Plugins repository
PLUGINS_REPO_URL = "https://plugins.octoprint.org/plugins.json"

# Paths
OCTOPRINT_SRC_DIR = Path("octoprint_src")
PLUGINS_SRC_DIR = Path("plugins_src")
RULES_DIR = Path("rules")


def get_version() -> str:
    """Return the installed octoscanner package version, or ``"0.0.0"`` if unavailable."""
    try:
        return _pkg_version("octoscanner")
    except PackageNotFoundError:
        return "0.0.0"
