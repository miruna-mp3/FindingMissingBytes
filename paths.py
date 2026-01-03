import os
from pathlib import Path

ARCHIVES_DIR = Path("./archives")
LOGS_DIR = Path("./logs")


class PathSecurityError(Exception):
    pass


class PathNotFoundError(Exception):
    pass


def ensure_directories():
    ARCHIVES_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)


def is_path_safe(path: Path, base: Path) -> bool:
    try:
        resolved = path.resolve()
        base_resolved = base.resolve()
        return resolved.is_relative_to(base_resolved)
    except (ValueError, RuntimeError):
        return False


def resolve_archive_path(filename: str) -> Path:
    if os.path.sep in filename or "/" in filename or "\\" in filename:
        raise PathSecurityError(f"Archive name must be a filename, not a path: {filename}")

    if ".." in filename:
        raise PathSecurityError(f"Path escapes workspace: {filename}")

    path = ARCHIVES_DIR / filename

    if not is_path_safe(path, ARCHIVES_DIR):
        raise PathSecurityError(f"Path escapes workspace: {filename}")

    if not path.exists():
        raise PathNotFoundError(f"Archive not found: {path}")

    return path


def resolve_archive_path_for_write(filename: str) -> Path:
    if os.path.sep in filename or "/" in filename or "\\" in filename:
        raise PathSecurityError(f"Archive name must be a filename, not a path: {filename}")

    if ".." in filename:
        raise PathSecurityError(f"Path escapes workspace: {filename}")

    path = ARCHIVES_DIR / filename

    if not is_path_safe(path, ARCHIVES_DIR):
        raise PathSecurityError(f"Path escapes workspace: {filename}")

    return path


def get_archive_basename(filename: str) -> str:
    if filename.lower().endswith(".zip"):
        return filename[:-4]
    return filename


def resolve_hash_path(archive_basename: str, member_path: str) -> Path:
    member_path = member_path.replace("\\", "/")

    if ".." in member_path:
        raise PathSecurityError(f"Path escapes workspace: {member_path}")

    member_path = member_path.lstrip("/")

    path = ARCHIVES_DIR / archive_basename / (member_path + ".sha256")

    if not is_path_safe(path, ARCHIVES_DIR):
        raise PathSecurityError(f"Path escapes workspace: {member_path}")

    return path


def resolve_output_path(archive_basename: str, member_path: str) -> Path:
    member_path = member_path.replace("\\", "/")

    if ".." in member_path:
        raise PathSecurityError(f"Path escapes workspace: {member_path}")

    member_path = member_path.lstrip("/")

    path = ARCHIVES_DIR / f"{archive_basename}_recovered" / member_path

    if not is_path_safe(path, ARCHIVES_DIR):
        raise PathSecurityError(f"Path escapes workspace: {member_path}")

    return path


def resolve_metadata_path(archive_basename: str) -> Path:
    path = ARCHIVES_DIR / f"{archive_basename}.json"

    if not is_path_safe(path, ARCHIVES_DIR):
        raise PathSecurityError(f"Path escapes workspace: {archive_basename}")

    return path
