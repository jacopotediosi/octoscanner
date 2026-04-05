from __future__ import annotations

import shutil
import tempfile
import urllib.request
from pathlib import Path

from . import DOWNLOAD_DIR

OCTOPRINT_ZIP_URLS = {
    "tag": "https://github.com/OctoPrint/OctoPrint/archive/refs/tags/{}.zip",
    "branch": "https://github.com/OctoPrint/OctoPrint/archive/refs/heads/{}.zip",
}


def _fetch(ref: str, kind: str, dest: Path) -> None:
    """Download a zip for *ref* of the given *kind* ('tag' or 'branch')."""
    try:
        urllib.request.urlretrieve(OCTOPRINT_ZIP_URLS[kind].format(ref), dest)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise ValueError(f"{kind} '{ref}' not found on GitHub.") from None
        raise


def download_octoprint_source(ref: str, name: str, *, kind: str = "tag", force: bool = False) -> Path:
    """Download and extract OctoPrint source for *ref* (tag or branch)."""
    if Path(name).name != name or name in {".", ".."}:
        raise ValueError(f"Invalid name: {name}")

    dest = DOWNLOAD_DIR / name
    if dest.exists():
        if not force:
            raise FileExistsError(f"Destination already exists: {dest}")
        shutil.rmtree(dest)

    DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        archive, extract = tmp / "src.zip", tmp / "ext"

        print(f"Downloading OctoPrint {ref}...")
        _fetch(ref, kind, archive)

        print("Extracting...")
        shutil.unpack_archive(archive, extract)

        # GitHub zips contain a single top-level directory
        top_dirs = list(extract.iterdir())
        if len(top_dirs) != 1 or not top_dirs[0].is_dir():
            raise RuntimeError("Unexpected archive structure")

        shutil.move(top_dirs[0], dest)

    print(f"OctoPrint {ref} saved to {dest}")
    return dest
