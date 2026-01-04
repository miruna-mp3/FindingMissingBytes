import hashlib
import json
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .validator import CentralDirectoryEntry


def extract_and_hash_members(
    src_path: Path,
    entries: List[CentralDirectoryEntry],
    sidecar_dir: Path,
    logger,
) -> int:
    sidecar_dir.mkdir(parents=True, exist_ok=True)

    members_hashed = 0

    with zipfile.ZipFile(src_path, "r") as zf:
        for entry in entries:
            if entry.filename.endswith("/"):
                logger.debug(f"Skipping directory: {entry.filename}")
                continue

            member_path = entry.filename.replace("\\", "/").lstrip("/")

            try:
                with zf.open(entry.filename) as member_file:
                    content = member_file.read()
            except Exception as e:
                logger.warning(f"Failed to extract {entry.filename}: {e}")
                continue

            sha256_hash = hashlib.sha256(content).hexdigest().lower()

            sidecar_path = sidecar_dir / (member_path + ".sha256")
            sidecar_path.parent.mkdir(parents=True, exist_ok=True)

            with open(sidecar_path, "w") as f:
                f.write(sha256_hash)

            logger.info(f"Hashed: {member_path} -> {sha256_hash[:16]}...")
            members_hashed += 1

    return members_hashed


def truncate_archive(
    src_path: Path,
    remove_bytes: int,
    truncated_zip_path: Path,
    logger,
) -> None:
    with open(src_path, "rb") as f:
        original_data = f.read()

    truncated_data = original_data[:-remove_bytes]

    temp_path = truncated_zip_path.with_suffix(".tmp")
    with open(temp_path, "wb") as f:
        f.write(truncated_data)

    temp_path.rename(truncated_zip_path)

    logger.info(f"Created truncated archive: {truncated_zip_path}")
    logger.info(f"Original size: {len(original_data)} bytes")
    logger.info(f"Truncated size: {len(truncated_data)} bytes")


def write_metadata_json(
    source_archive: str,
    truncated_archive: str,
    removed_bytes: int,
    members_hashed: int,
    json_path: Path,
    logger,
) -> None:
    metadata = {
        "source_archive": source_archive,
        "truncated_archive": truncated_archive,
        "removed_bytes": removed_bytes,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "hash_alg": "sha256",
        "members_hashed": members_hashed,
    }

    temp_path = json_path.with_suffix(".tmp")
    with open(temp_path, "w") as f:
        json.dump(metadata, f, indent=2)

    temp_path.rename(json_path)

    logger.info(f"Created metadata: {json_path}")
