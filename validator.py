import struct
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


PK_SIGNATURE = b"PK"
EOCD_SIGNATURE = b"PK\x05\x06"
ZIP64_EOCD_LOCATOR_SIGNATURE = b"PK\x06\x07"
CENTRAL_DIR_SIGNATURE = b"PK\x01\x02"
LOCAL_FILE_HEADER_SIGNATURE = b"PK\x03\x04"

EOCD_SIZE = 22
ZIP64_EOCD_LOCATOR_SIZE = 20

COMPRESSION_STORED = 0
COMPRESSION_DEFLATE = 8
SUPPORTED_COMPRESSION_METHODS = {COMPRESSION_STORED, COMPRESSION_DEFLATE}

ENCRYPTION_FLAG_BIT = 0x0001


class ZipValidationError(Exception):
    pass


class UnsupportedZipError(ZipValidationError):
    pass


@dataclass
class CentralDirectoryEntry:
    filename: str
    compression_method: int
    compressed_size: int
    uncompressed_size: int
    local_header_offset: int
    crc32: int
    general_purpose_flag: int


@dataclass
class ZipInfo:
    path: Path
    file_size: int
    eocd_offset: int
    cd_offset: int
    cd_size: int
    total_entries: int
    entries: list


def validate_zip_file(path: Path) -> ZipInfo:
    if not path.exists():
        raise ZipValidationError(f"File not found: {path}")

    if not path.is_file():
        raise ZipValidationError(f"Not a file: {path}")

    file_size = path.stat().st_size

    if file_size < EOCD_SIZE:
        raise ZipValidationError(f"File too small to be a valid ZIP: {path}")

    with open(path, "rb") as f:
        magic = f.read(2)
        if magic != PK_SIGNATURE:
            raise ZipValidationError(f"Not a valid ZIP file: missing PK signature at start")

        eocd_offset = file_size - EOCD_SIZE
        f.seek(eocd_offset)
        eocd_sig = f.read(4)

        if eocd_sig != EOCD_SIGNATURE:
            raise ZipValidationError(
                f"EOCD signature not found at expected offset {eocd_offset}. "
                f"Archive may have a comment (unsupported) or be corrupted."
            )

        eocd_data = eocd_sig + f.read(EOCD_SIZE - 4)
        (
            sig,
            disk_number,
            disk_with_cd,
            entries_on_disk,
            total_entries,
            cd_size,
            cd_offset,
            comment_length,
        ) = struct.unpack("<4sHHHHIIH", eocd_data)

        if disk_number != 0 or disk_with_cd != 0:
            raise UnsupportedZipError("Unsupported: multi-disk archive")

        if comment_length != 0:
            raise UnsupportedZipError("Unsupported: archive has a comment")

        if total_entries == 0xFFFF or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF:
            raise UnsupportedZipError("Unsupported: ZIP64 archive (sentinel values in EOCD)")

        if file_size >= EOCD_SIZE + ZIP64_EOCD_LOCATOR_SIZE:
            zip64_locator_offset = eocd_offset - ZIP64_EOCD_LOCATOR_SIZE
            f.seek(zip64_locator_offset)
            zip64_locator_sig = f.read(4)
            if zip64_locator_sig == ZIP64_EOCD_LOCATOR_SIGNATURE:
                raise UnsupportedZipError("Unsupported: ZIP64 archive")

        if cd_offset + cd_size != eocd_offset:
            raise ZipValidationError(
                f"Central directory does not end at EOCD. "
                f"cd_offset={cd_offset}, cd_size={cd_size}, eocd_offset={eocd_offset}"
            )

        entries = parse_central_directory(f, cd_offset, cd_size, total_entries)

        return ZipInfo(
            path=path,
            file_size=file_size,
            eocd_offset=eocd_offset,
            cd_offset=cd_offset,
            cd_size=cd_size,
            total_entries=total_entries,
            entries=entries,
        )


def parse_central_directory(f, cd_offset: int, cd_size: int, expected_entries: int) -> list:
    f.seek(cd_offset)
    cd_data = f.read(cd_size)

    entries = []
    offset = 0

    for _ in range(expected_entries):
        if offset + 46 > len(cd_data):
            raise ZipValidationError("Central directory truncated")

        sig = cd_data[offset : offset + 4]
        if sig != CENTRAL_DIR_SIGNATURE:
            raise ZipValidationError(
                f"Invalid central directory entry signature at offset {cd_offset + offset}"
            )

        (
            version_made,
            version_needed,
            general_purpose_flag,
            compression_method,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            filename_length,
            extra_length,
            comment_length,
            disk_start,
            internal_attr,
            external_attr,
            local_header_offset,
        ) = struct.unpack("<4xHHHHHHIIIHHHHHII", cd_data[offset : offset + 46])

        if compression_method not in SUPPORTED_COMPRESSION_METHODS:
            raise UnsupportedZipError(
                f"Unsupported: compression method {compression_method} "
                f"(only stored/deflate supported)"
            )

        if general_purpose_flag & ENCRYPTION_FLAG_BIT:
            raise UnsupportedZipError("Unsupported: encrypted archive")

        if disk_start != 0:
            raise UnsupportedZipError("Unsupported: multi-disk archive")

        filename_start = offset + 46
        filename_end = filename_start + filename_length
        if filename_end > len(cd_data):
            raise ZipValidationError("Central directory truncated (filename)")

        filename_bytes = cd_data[filename_start:filename_end]
        try:
            filename = filename_bytes.decode("utf-8")
        except UnicodeDecodeError:
            filename = filename_bytes.decode("cp437")

        filename = filename.replace("\\", "/")

        entry = CentralDirectoryEntry(
            filename=filename,
            compression_method=compression_method,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            local_header_offset=local_header_offset,
            crc32=crc32,
            general_purpose_flag=general_purpose_flag,
        )
        entries.append(entry)

        offset = filename_end + extra_length + comment_length

    return entries


def validate_member_exists(zip_info: ZipInfo, member_path: str) -> CentralDirectoryEntry:
    member_path = member_path.replace("\\", "/").lstrip("/")

    for entry in zip_info.entries:
        entry_name = entry.filename.lstrip("/")
        if entry_name == member_path:
            return entry

    raise ZipValidationError(f"Member not found in archive: {member_path}")


def get_member_info(zip_info: ZipInfo, member_path: str) -> CentralDirectoryEntry:
    return validate_member_exists(zip_info, member_path)


def read_expected_hash(hash_path: Path) -> str:
    if not hash_path.exists():
        raise ZipValidationError(f"Hash file not found: {hash_path}")

    content = hash_path.read_text().strip()

    content = content.split()[0] if content else ""

    if len(content) != 64:
        raise ZipValidationError(
            f"Invalid hash: expected 64 hex characters, got {len(content)}"
        )

    try:
        int(content, 16)
    except ValueError:
        raise ZipValidationError(f"Invalid hash: not a valid hexadecimal string")

    return content.lower()
