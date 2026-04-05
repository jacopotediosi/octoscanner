from pathlib import Path

# OctoPrint versions
OCTOPRINT_DEV_BRANCH = "dev"
OCTOPRINT_DEV_VERSION = "2.0.0"
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
OCTOPRINT_ALL_VERSION_BRANCHES = {OCTOPRINT_DEV_VERSION: OCTOPRINT_DEV_BRANCH}

# Paths
DOWNLOAD_DIR = Path("octoprint_src")
RULES_DIR = Path("rules")
