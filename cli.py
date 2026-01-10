import argparse
import os
import sys
import time

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
from .recover import recover_member
from .paths import resolve_output_path
from . import console


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
    start_time = time.time()

    try:
        archive_path = resolve_archive_path(args.archive)
        logger.info(f"Archive: {archive_path}")
    except PathSecurityError as e:
        logger.error(str(e))
        print(f"Error: {e}")
        return 1
    except PathNotFoundError as e:
        logger.error(str(e))
        print(f"Error: {e}")
        return 1

    archive_basename = get_archive_basename(args.archive)

    if args.hash:
        expected_hash = args.hash.lower().strip()
        if len(expected_hash) != 64 or not all(c in "0123456789abcdef" for c in expected_hash):
            logger.error("Invalid SHA-256 hash format")
            print("Error: Invalid SHA-256 hash format (expected 64 hex characters)")
            return 1
        logger.info(f"Expected SHA-256 (from CLI): {expected_hash}")
    else:
        try:
            hash_path = resolve_hash_path(archive_basename, args.member)
        except PathSecurityError as e:
            logger.error(str(e))
            print(f"Error: {e}")
            return 1

        try:
            expected_hash = read_expected_hash(hash_path)
            logger.info(f"Expected SHA-256 (from sidecar): {expected_hash}")
        except ZipValidationError as e:
            logger.error(str(e))
            print(f"Error: {e}")
            return 1

    if args.max_missing < 1 or args.max_missing > 21:
        logger.error("--max-missing must be between 1 and 21")
        print("Error: --max-missing must be between 1 and 21")
        return 1

    if args.jobs < 1:
        logger.error("--jobs must be at least 1")
        print("Error: --jobs must be at least 1")
        return 1

    try:
        output_path = resolve_output_path(archive_basename, args.member)
    except PathSecurityError as e:
        logger.error(str(e))
        print(f"Error: {e}")
        return 1

    console.print_search_start(
        archive=args.archive,
        member=args.member,
        expected_hash=expected_hash,
        max_missing=args.max_missing,
        num_jobs=args.jobs,
    )

    result = recover_member(
        truncated_path=archive_path,
        target_member=args.member,
        expected_hash=expected_hash,
        max_missing=args.max_missing,
        num_jobs=args.jobs,
        logger=logger,
    )

    elapsed = time.time() - start_time

    logger.info(f"Candidates tested: {result.candidates_tested}")
    logger.info(f"CD rejects: {result.cd_rejects}")
    logger.info(f"LFH rejects: {result.lfh_rejects}")
    logger.info(f"Decompress rejects: {result.decompress_rejects}")
    logger.info(f"CRC rejects: {result.crc_rejects}")
    logger.info(f"Hash rejects: {result.hash_rejects}")

    stats = {
        "candidates_tested": result.candidates_tested,
        "cd_rejects": result.cd_rejects,
        "lfh_rejects": result.lfh_rejects,
        "decompress_rejects": result.decompress_rejects,
        "crc_rejects": result.crc_rejects,
        "hash_rejects": result.hash_rejects,
    }

    if not result.success:
        logger.error(f"Recovery failed: {result.message}")
        console.print_failure(result.message, elapsed, stats)
        return 1

    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_suffix(".tmp")

    with open(temp_path, "wb") as f:
        f.write(result.recovered_data)

    temp_path.rename(output_path)

    logger.info(f"Recovered: {output_path}")
    logger.info(f"SHA-256: {result.sha256_hash}")
    logger.info(f"N={result.n_value} bytes were missing")

    console.print_success(
        output_path=str(output_path),
        sha256=result.sha256_hash,
        n_value=result.n_value,
        elapsed=elapsed,
        stats=stats,
    )

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="findmissingbytes",
        description="Reconstruct a file from a truncated ZIP archive using expected hash validation",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    truncate_parser = subparsers.add_parser(
        "truncate",
        help="Create a truncated archive for testing.",
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
        help="Recover a member from a truncated archive",
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
        "hash",
        nargs="?",
        default=None,
        help="Expected SHA-256 hash (optional, defaults to reading from sidecar file)",
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
