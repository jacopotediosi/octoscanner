from __future__ import annotations

import json
import shutil
import tempfile
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from . import OCTOPRINT_SRC_DIR, PLUGINS_REPO_URL, PLUGINS_SRC_DIR


def download_octoprint(ref: str, kind: str, name: str, force: bool = False) -> None:
    """Download and extract an OctoPrint source archive from GitHub.

    The archive is fetched from the official OctoPrint GitHub repository,
    unpacked, and moved under ``OCTOPRINT_SRC_DIR/<name>/``.

    Args:
        ref: The git reference to download (tag or branch name,
            e.g. ``"1.11.7"`` for a tag or ``"dev"`` for a branch).
        kind: Either ``"tag"`` or ``"branch"``, selecting which GitHub
            archive URL template to use.
        name: Subfolder of ``OCTOPRINT_SRC_DIR``, will be created if it
            doesn't already exist.
        force: If ``True``, overwrite the existing destination.
            If ``False`` and the destination already exists, raise
            `FileExistsError`.
    """
    # Validate name
    if Path(name).name != name or name in {".", ".."}:
        raise ValueError(f"Invalid name: {name}")

    # Create OCTOPRINT_SRC_DIR if doesn't exist
    OCTOPRINT_SRC_DIR.mkdir(parents=True, exist_ok=True)

    # Check destination existence
    dest = OCTOPRINT_SRC_DIR / name
    if dest.exists():
        if not force:
            raise FileExistsError(f"Destination already exists: {dest}")
        shutil.rmtree(dest)

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Temp paths
        tmp_dir = Path(tmp_dir)
        tmp_archive_filename = tmp_dir / "octoprint_src.zip"
        tmp_extract_dir = tmp_dir / "octoprint_src_extracted"

        # Download archive
        print(f"Downloading OctoPrint {ref}...")
        try:
            octoprint_zip_urls = {
                "tag": "https://github.com/OctoPrint/OctoPrint/archive/refs/tags/{}.zip",
                "branch": "https://github.com/OctoPrint/OctoPrint/archive/refs/heads/{}.zip",
            }
            zip_url = octoprint_zip_urls[kind].format(ref)
            urllib.request.urlretrieve(zip_url, tmp_archive_filename)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                raise ValueError(f"{kind} '{ref}' not found on GitHub.")
            raise

        # Extract archive
        print("Extracting...")
        shutil.unpack_archive(tmp_archive_filename, tmp_extract_dir)

        # Check extracted archive structure
        top_dirs = list(tmp_extract_dir.iterdir())
        if len(top_dirs) != 1 or not top_dirs[0].is_dir():
            raise RuntimeError("Unexpected archive structure")

        # Move extracted folder to dest
        shutil.move(top_dirs[0], dest)

    # Print result
    print(f"OctoPrint {ref} saved to {dest}")


def download_plugins(
    identifiers: list[str],
    subfolder: str | None = None,
    max_workers: int = 8,
    force: bool = False,
) -> None:
    """Download and extract one or more OctoPrint plugins from the official
    OctoPrint plugins repository.

    Args:
        identifiers: Plugin ids from ``plugins.octoprint.org``. The single
            value ``["all"]`` selects every plugin in the index.
        subfolder: Optional subfolder name under ``PLUGINS_SRC_DIR`` in which
            to store the extracted plugins. Each plugin lands in
            ``PLUGINS_SRC_DIR/[subfolder/]<id>/``.
        max_workers: Maximum number of parallel download workers.
        force: If ``True``, re-download and overwrite existing destinations.
    """

    def download_plugin(entry: dict, tmp_dir: Path, target_root: Path, force: bool) -> None:
        # Validate plugin id
        plugin_id = entry["id"]
        if Path(plugin_id).name != plugin_id or plugin_id in {".", ".."}:
            raise ValueError(f"Invalid plugin id: {plugin_id}")

        # Check destination existence
        dest = target_root / plugin_id
        if dest.exists():
            if not force:
                raise FileExistsError(f"Destination already exists: {dest}")
            shutil.rmtree(dest)

        # Determine archive url and extension
        archive_url = entry["archive"]
        archive_url_path = Path(urllib.parse.urlparse(archive_url).path.lower())
        archive_ext = ".tar.gz" if archive_url_path.name.endswith(".tar.gz") else archive_url_path.suffix

        # Single-file plugin: just download it to dest/<plugin_id>.py
        if archive_ext == ".py":
            dest.mkdir(parents=True)
            urllib.request.urlretrieve(archive_url, dest / f"{plugin_id}.py")

        # Plugin is a supported archive
        elif archive_ext in (".zip", ".tar.gz", ".tgz", ".tar", ".whl"):
            # Create temp paths
            tmp_archive_filename = tmp_dir / f"{plugin_id}{archive_ext}"
            tmp_extract_dir = tmp_dir / f"{plugin_id}_extracted"

            # Download and extract the archive
            urllib.request.urlretrieve(archive_url, tmp_archive_filename)
            shutil.unpack_archive(
                tmp_archive_filename,
                tmp_extract_dir,
                format="zip" if archive_ext == ".whl" else None,
            )

            # GitHub archive zips have a single top-level directory; some plugin
            # archives may already extract their sources at top level
            top_dirs = list(tmp_extract_dir.iterdir())
            payload = top_dirs[0] if len(top_dirs) == 1 and top_dirs[0].is_dir() else tmp_extract_dir

            # Move extracted folder to dest
            shutil.move(payload, dest)

        # Plugin extension is unsupported
        else:
            raise ValueError(f"Unsupported archive format: {archive_ext}")

    # Validate subfolder name
    if subfolder is not None and (Path(subfolder).name != subfolder or subfolder in {".", ".."}):
        raise ValueError(f"Invalid subfolder name: {subfolder}")

    # Create target root
    target_root = PLUGINS_SRC_DIR / subfolder if subfolder else PLUGINS_SRC_DIR
    target_root.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir = Path(tmp_dir)

        # Download and parse plugins index
        index_path = tmp_dir / "plugins.json"
        print(f"Downloading plugins index from {PLUGINS_REPO_URL}...")
        urllib.request.urlretrieve(PLUGINS_REPO_URL, index_path)
        with index_path.open("r", encoding="utf-8") as index_file:
            index = json.load(index_file)

        # Resolve requested identifiers against the index
        by_id = {entry["id"]: entry for entry in index if "id" in entry and "archive" in entry}
        if identifiers == ["all"]:
            entries = list(by_id.values())
        else:
            missing = [ident for ident in identifiers if ident not in by_id]
            if missing:
                raise ValueError(f"Unknown plugin identifier(s): {', '.join(sorted(missing))}")
            entries = [by_id[ident] for ident in identifiers]
        print(f"Resolved {len(entries)} plugin(s) to download to {target_root}")
        print()

        # Download plugins in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(download_plugin, entry, tmp_dir, target_root, force): entry["id"] for entry in entries
            }
            total = len(entries)
            done_count = 0
            skipped_count = 0
            failed_count = 0
            for i, future in enumerate(as_completed(futures), start=1):
                plugin_id = futures[future]
                try:
                    future.result()
                    done_count += 1
                    print(f"[{i}/{total}] {plugin_id}: done")
                except FileExistsError:
                    skipped_count += 1
                    print(f"[{i}/{total}] {plugin_id}: already downloaded")
                except Exception as exc:
                    failed_count += 1
                    print(f"[{i}/{total}] {plugin_id}: failed - {exc}")

    # Print summary
    print()
    print(f"Summary ({total} total): {done_count} downloaded, {skipped_count} already present, {failed_count} failed.")
