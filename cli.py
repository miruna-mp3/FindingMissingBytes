import argparse
import os
import sys

from .paths import (
    PathSecurityError,
    PathNotFoundError,
    ensure_directories,
    resolve_archive_path,
    resolve_hash_path,
    get_archive_basename,
    resolve_truncated_paths,
)
from .validator import (
    ZipValidationError,
    UnsupportedZipError,
    validate_zip_file,
    validate_member_exists,
    read_expected_hash,
)
from .logging_setup import setup_logging, get_logger
from .truncate import truncate_archive, extract_and_hash_members, write_metadata_json


def cmd_truncate(args):
    logger = setup_logging("truncate", [args.archive, "--remove", str(args.remove)])

    try:
        archive_path = resolve_archive_path(args.archive)
        logger.info(f"Archive path: {archive_path}")
    except PathSecurityError as e:
        logger.error(str(e))
        return 1
    except PathNotFoundError as e:
        logger.error(str(e))
        return 1

    try:
        zip_info = validate_zip_file(archive_path)
        logger.info(f"ZIP validated: {zip_info.total_entries} entries, {zip_info.file_size} bytes")
    except ZipValidationError as e:
        logger.error(str(e))
        return 1
    except UnsupportedZipError as e:
        logger.error(str(e))
        return 1

    if args.remove <= 0:
        logger.error("--remove must be a positive integer")
        return 1

    if args.remove >= zip_info.file_size:
        logger.error(f"Cannot remove {args.remove} bytes from {zip_info.file_size} byte archive")
        return 1

    logger.info(f"Truncation validated: will remove {args.remove} bytes")

    archive_basename = get_archive_basename(args.archive)

    try:
        paths = resolve_truncated_paths(archive_basename)
    except PathSecurityError as e:
        logger.error(str(e))
        return 1

    logger.info(f"Output truncated ZIP: {paths['truncated_zip']}")
    logger.info(f"Output metadata JSON: {paths['truncated_json']}")
    logger.info(f"Output sidecar dir: {paths['sidecar_dir']}")

    members_hashed = extract_and_hash_members(
        archive_path,
        zip_info.entries,
        paths["sidecar_dir"],
        logger,
    )

    truncate_archive(
        archive_path,
        args.remove,
        paths["truncated_zip"],
        logger,
    )

    write_metadata_json(
        source_archive=args.archive,
        truncated_archive=f"{paths['truncated_basename']}.zip",
        removed_bytes=args.remove,
        members_hashed=members_hashed,
        json_path=paths["truncated_json"],
        logger=logger,
    )

    logger.info(f"Truncation complete: {members_hashed} members hashed")

    return 0


def cmd_recover(args):
    arg_list = [
        args.archive,
        args.member,
        "--max-missing",
        str(args.max_missing),
        "--jobs",
        str(args.jobs),
    ]
    logger = setup_logging("recover", arg_list)

    try:
        archive_path = resolve_archive_path(args.archive)
        logger.info(f"Archive path: {archive_path}")
    except PathSecurityError as e:
        logger.error(str(e))
        return 1
    except PathNotFoundError as e:
        logger.error(str(e))
        return 1

    try:
        zip_info = validate_zip_file(archive_path)
        logger.info(f"ZIP validated: {zip_info.total_entries} entries, {zip_info.file_size} bytes")
    except ZipValidationError as e:
        logger.error(str(e))
        return 1
    except UnsupportedZipError as e:
        logger.error(str(e))
        return 1

    try:
        member_entry = validate_member_exists(zip_info, args.member)
        logger.info(f"Member found: {member_entry.filename}")
        logger.info(f"  Compression: {'deflate' if member_entry.compression_method == 8 else 'stored'}")
        logger.info(f"  Compressed size: {member_entry.compressed_size}")
        logger.info(f"  Uncompressed size: {member_entry.uncompressed_size}")
    except ZipValidationError as e:
        logger.error(str(e))
        return 1

    archive_basename = get_archive_basename(args.archive)
    try:
        hash_path = resolve_hash_path(archive_basename, args.member)
        logger.info(f"Hash file path: {hash_path}")
    except PathSecurityError as e:
        logger.error(str(e))
        return 1

    try:
        expected_hash = read_expected_hash(hash_path)
        logger.info(f"Expected SHA-256: {expected_hash}")
    except ZipValidationError as e:
        logger.error(str(e))
        return 1

    if args.max_missing < 1 or args.max_missing > 21:
        logger.error("--max-missing must be between 1 and 21")
        return 1

    if args.jobs < 1:
        logger.error("--jobs must be at least 1")
        return 1

    logger.info(f"Max missing bytes: {args.max_missing}")
    logger.info(f"Worker jobs: {args.jobs}")
    logger.info("Phase 1 complete: recovery logic will be implemented in Phase 3+")

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="findmissingbytes",
        description="Reconstruct a file from a truncated ZIP archive using expected hash validation",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    truncate_parser = subparsers.add_parser(
        "truncate",
        help="Create a truncated archive for testing",
    )
    truncate_parser.add_argument(
        "archive",
        help="Archive filename (must be in ./archives/)",
    )
    truncate_parser.add_argument(
        "--remove",
        type=int,
        required=True,
        help="Number of bytes to remove from the end",
    )

    recover_parser = subparsers.add_parser(
        "recover",
        help="Recover a member from a (possibly truncated) archive",
    )
    recover_parser.add_argument(
        "archive",
        help="Archive filename (must be in ./archives/)",
    )
    recover_parser.add_argument(
        "member",
        help="Path of the member to recover within the archive",
    )
    recover_parser.add_argument(
        "--max-missing",
        type=int,
        default=21,
        help="Maximum number of missing bytes to try (default: 21, max: 21)",
    )
    recover_parser.add_argument(
        "--jobs",
        type=int,
        default=os.cpu_count() or 1,
        help=f"Number of parallel workers (default: {os.cpu_count() or 1})",
    )

    args = parser.parse_args()

    ensure_directories()

    if args.command == "truncate":
        sys.exit(cmd_truncate(args))
    elif args.command == "recover":
        sys.exit(cmd_recover(args))


if __name__ == "__main__":
    main()
