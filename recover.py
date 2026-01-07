import hashlib
import os
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed
import time

EOCD_SIGNATURE = b"PK\x05\x06"
CD_SIGNATURE = b"PK\x01\x02"
LFH_SIGNATURE = b"PK\x03\x04"

EOCD_SIZE = 22
CD_ENTRY_MIN_SIZE = 46
LFH_MIN_SIZE = 30


@dataclass
class CandidateResult:
    n_value: int
    eocd_start: int
    cd_offset: int
    cd_size: int
    total_entries: int
    disk_num: int
    target_info: dict


@dataclass
class GenerationResult:
    success: bool
    candidates: List[CandidateResult]
    truncated_data: bytes
    message: str = ""
    candidates_tested: int = 0
    cd_rejects: int = 0


@dataclass
class RecoveryResult:
    success: bool
    n_value: Optional[int] = None
    recovered_data: Optional[bytes] = None
    sha256_hash: Optional[str] = None
    message: str = ""
    candidates_tested: int = 0
    cd_rejects: int = 0
    lfh_rejects: int = 0
    decompress_rejects: int = 0
    crc_rejects: int = 0
    hash_rejects: int = 0


def get_disk_number(file_path: Path) -> int:
    try:
        resolved = file_path.resolve()
        drive = os.path.splitdrive(str(resolved))[0]
        if not drive:
            return 0
        drive_letter = drive[0].upper()
        return ord(drive_letter) - ord('A')
    except Exception:
        return 0


def find_valid_n_values(truncated_data: bytes, max_missing: int) -> List[Tuple[int, int]]:
    truncated_size = len(truncated_data)
    valid = []

    for n in range(1, min(max_missing + 1, 19)):
        candidate_size = truncated_size + n
        eocd_start = candidate_size - EOCD_SIZE

        if eocd_start < 0 or eocd_start + 4 > truncated_size:
            continue

        if truncated_data[eocd_start:eocd_start + 4] == EOCD_SIGNATURE:
            valid.append((n, eocd_start))

    return valid


def generate_offset_ranges(eocd_start: int, num_workers: int) -> List[Tuple[int, int]]:
    max_offset = eocd_start - CD_ENTRY_MIN_SIZE
    if max_offset < 0:
        return []

    total_offsets = max_offset + 1
    ranges = []

    for i in range(num_workers):
        start = (i * total_offsets) // num_workers
        end = ((i + 1) * total_offsets) // num_workers
        if start < end:
            ranges.append((start, end))

    return ranges


def parse_and_validate_cd(
    data: bytes,
    cd_offset: int,
    cd_size: int,
    expected_entries: int,
    target_member: str,
) -> Optional[dict]:

    if cd_offset < 0 or cd_size <= 0:
        return None

    if cd_offset + cd_size > len(data):
        return None

    cd_data = data[cd_offset:cd_offset + cd_size]
    entries = []
    offset = 0
    target_info = None
    target_normalized = target_member.replace("\\", "/").lstrip("/")

    while offset + CD_ENTRY_MIN_SIZE <= len(cd_data) and len(entries) < expected_entries:
        if cd_data[offset:offset + 4] != CD_SIGNATURE:
            break

        try:
            (
                version_made,
                version_needed,
                flags,
                compression,
                mod_time,
                mod_date,
                crc32,
                compressed_size,
                uncompressed_size,
                filename_len,
                extra_len,
                comment_len,
                disk_start,
                internal_attr,
                external_attr,
                local_header_offset,
            ) = struct.unpack("<4xHHHHHHIIIHHHHHII", cd_data[offset:offset + CD_ENTRY_MIN_SIZE])
        except struct.error:
            return None

        if disk_start != 0:
            return None

        filename_start = offset + CD_ENTRY_MIN_SIZE
        filename_end = filename_start + filename_len

        if filename_end > len(cd_data):
            return None

        try:
            filename = cd_data[filename_start:filename_end].decode("utf-8")
        except UnicodeDecodeError:
            try:
                filename = cd_data[filename_start:filename_end].decode("cp437")
            except:
                return None

        filename_normalized = filename.replace("\\", "/").lstrip("/")

        entry = {
            "filename": filename,
            "compression": compression,
            "crc32": crc32,
            "compressed_size": compressed_size,
            "uncompressed_size": uncompressed_size,
            "local_header_offset": local_header_offset,
            "flags": flags,
        }
        entries.append(entry)

        if filename_normalized == target_normalized:
            target_info = entry

        offset = filename_end + extra_len + comment_len

    if len(entries) != expected_entries:
        return None

    if target_info is None:
        return None

    return target_info


def worker_process_range(args: Tuple) -> Tuple[List[dict], dict]:
    (
        truncated_data,
        n_value,
        eocd_start,
        offset_start,
        offset_end,
        disk_num,
        target_member,
    ) = args

    stats = {
        "candidates_tested": 0,
        "cd_rejects": 0,
    }

    valid_candidates = []

    for cd_offset in range(offset_start, offset_end):
        cd_size = eocd_start - cd_offset

        if cd_size < CD_ENTRY_MIN_SIZE:
            continue

        max_entries = cd_size // CD_ENTRY_MIN_SIZE

        for total_entries in range(1, max_entries + 1):
            stats["candidates_tested"] += 1

            target_info = parse_and_validate_cd(
                truncated_data, cd_offset, cd_size, total_entries, target_member
            )

            if target_info is None:
                stats["cd_rejects"] += 1
                continue

            valid_candidates.append({
                "n_value": n_value,
                "eocd_start": eocd_start,
                "cd_offset": cd_offset,
                "cd_size": cd_size,
                "total_entries": total_entries,
                "disk_num": disk_num,
                "target_info": target_info,
            })

    return (valid_candidates, stats)


def generate_candidates(
    truncated_path: Path,
    target_member: str,
    max_missing: int,
    num_jobs: int,
    logger,
) -> GenerationResult:

    start_time = time.time()

    with open(truncated_path, "rb") as f:
        truncated_data = f.read()

    truncated_size = len(truncated_data)
    logger.info(f"Truncated archive: {truncated_size} bytes")

    disk_num = get_disk_number(truncated_path)
    logger.info(f"Disk number: {disk_num}")

    valid_n_values = find_valid_n_values(truncated_data, max_missing)

    if not valid_n_values:
        return GenerationResult(
            success=False,
            candidates=[],
            truncated_data=truncated_data,
            message="No valid N values found",
        )

    logger.info(f"Valid N values: {[n for n, _ in valid_n_values]}")

    total_stats = {
        "candidates_tested": 0,
        "cd_rejects": 0,
    }

    all_valid_candidates = []

    for n, eocd_start in valid_n_values:
        ranges = generate_offset_ranges(eocd_start, num_jobs)
        ranges = [r for r in ranges if r[0] < r[1]]

        if not ranges:
            continue

        logger.info(f"N={n}: {len(ranges)} workers, cd_offset range [0, {eocd_start - CD_ENTRY_MIN_SIZE}]")

        work_items = [
            (truncated_data, n, eocd_start, start, end, disk_num, target_member)
            for start, end in ranges
        ]

        if len(work_items) == 1:
            candidates, stats = worker_process_range(work_items[0])
            all_valid_candidates.extend(candidates)
            for key in stats:
                total_stats[key] += stats[key]
        else:
            with ProcessPoolExecutor(max_workers=len(work_items)) as executor:
                futures = [executor.submit(worker_process_range, item) for item in work_items]

                for future in as_completed(futures):
                    try:
                        candidates, stats = future.result()
                        all_valid_candidates.extend(candidates)
                        for key in stats:
                            total_stats[key] += stats[key]
                    except Exception as e:
                        logger.debug(f"Worker exception: {e}")

    elapsed = time.time() - start_time
    logger.info(f"Candidate generation: {len(all_valid_candidates)} valid / {total_stats['candidates_tested']} tested in {elapsed:.3f}s")

    return GenerationResult(
        success=len(all_valid_candidates) > 0,
        candidates=[
            CandidateResult(
                n_value=c["n_value"],
                eocd_start=c["eocd_start"],
                cd_offset=c["cd_offset"],
                cd_size=c["cd_size"],
                total_entries=c["total_entries"],
                disk_num=c["disk_num"],
                target_info=c["target_info"],
            )
            for c in all_valid_candidates
        ],
        truncated_data=truncated_data,
        message=f"{len(all_valid_candidates)} valid candidates",
        **total_stats,
    )


def build_eocd(cd_offset: int, cd_size: int, total_entries: int, disk_num: int) -> bytes:
    return struct.pack(
        "<4sHHHHIIH",
        EOCD_SIGNATURE,
        disk_num,
        disk_num,
        total_entries,
        total_entries,
        cd_size,
        cd_offset,
        0,
    )


def try_extraction(
    candidate_data: bytes,
    target_info: dict,
    expected_hash: str,
) -> Tuple[bool, Optional[bytes], str, dict]:
    stats = {
        "lfh_rejects": 0,
        "decompress_rejects": 0,
        "crc_rejects": 0,
        "hash_rejects": 0,
    }

    lfh_offset = target_info["local_header_offset"]

    if lfh_offset + LFH_MIN_SIZE > len(candidate_data):
        stats["lfh_rejects"] = 1
        return (False, None, "", stats)

    if candidate_data[lfh_offset:lfh_offset + 4] != LFH_SIGNATURE:
        stats["lfh_rejects"] = 1
        return (False, None, "", stats)

    try:
        (
            version_needed,
            flags,
            compression,
            mod_time,
            mod_date,
            crc32,
            compressed_size,
            uncompressed_size,
            filename_len,
            extra_len,
        ) = struct.unpack("<4xHHHHHIIIHH", candidate_data[lfh_offset:lfh_offset + LFH_MIN_SIZE])
    except struct.error:
        stats["lfh_rejects"] = 1
        return (False, None, "", stats)

    data_offset = lfh_offset + LFH_MIN_SIZE + filename_len + extra_len
    cd_compressed_size = target_info["compressed_size"]
    cd_uncompressed_size = target_info["uncompressed_size"]
    cd_crc32 = target_info["crc32"]
    cd_compression = target_info["compression"]

    if data_offset + cd_compressed_size > len(candidate_data):
        stats["lfh_rejects"] = 1
        return (False, None, "", stats)

    compressed_data = candidate_data[data_offset:data_offset + cd_compressed_size]

    if cd_compression == 0:
        decompressed_data = compressed_data
    elif cd_compression == 8:
        try:
            decompressed_data = zlib.decompress(compressed_data, -zlib.MAX_WBITS)
        except zlib.error:
            stats["decompress_rejects"] = 1
            return (False, None, "", stats)
    else:
        stats["decompress_rejects"] = 1
        return (False, None, "", stats)

    if len(decompressed_data) != cd_uncompressed_size:
        stats["decompress_rejects"] = 1
        return (False, None, "", stats)

    computed_crc = zlib.crc32(decompressed_data) & 0xFFFFFFFF
    if computed_crc != cd_crc32:
        stats["crc_rejects"] = 1
        return (False, None, "", stats)

    hasher = hashlib.sha256()
    hasher.update(decompressed_data)
    computed_hash = hasher.hexdigest().lower()

    if computed_hash != expected_hash.lower():
        stats["hash_rejects"] = 1
        return (False, None, "", stats)

    return (True, decompressed_data, computed_hash, stats)


def extraction_worker(args: Tuple) -> Tuple[bool, dict]:
    (
        truncated_data,
        n_value,
        eocd_start,
        cd_offset,
        cd_size,
        total_entries,
        disk_num,
        target_info,
        expected_hash,
    ) = args

    eocd = build_eocd(cd_offset, cd_size, total_entries, disk_num)
    candidate_data = truncated_data[:eocd_start] + eocd

    success, data, hash_val, stats = try_extraction(
        candidate_data, target_info, expected_hash
    )

    if success:
        return (True, {
            "data": data,
            "hash": hash_val,
            "n_value": n_value,
            "cd_offset": cd_offset,
            "total_entries": total_entries,
            "stats": stats,
        })

    return (False, {"stats": stats})


def recover_member(
    truncated_path: Path,
    target_member: str,
    expected_hash: str,
    max_missing: int,
    num_jobs: int,
    logger,
) -> RecoveryResult:
    start_time = time.time()

    gen_result = generate_candidates(
        truncated_path, target_member, max_missing, num_jobs, logger
    )

    total_stats = {
        "candidates_tested": gen_result.candidates_tested,
        "cd_rejects": gen_result.cd_rejects,
        "lfh_rejects": 0,
        "decompress_rejects": 0,
        "crc_rejects": 0,
        "hash_rejects": 0,
    }

    if not gen_result.success:
        return RecoveryResult(
            success=False,
            message=gen_result.message,
            **total_stats,
        )

    logger.info(f"Testing {len(gen_result.candidates)} candidates in parallel")

    work_items = [
        (
            gen_result.truncated_data,
            c.n_value,
            c.eocd_start,
            c.cd_offset,
            c.cd_size,
            c.total_entries,
            c.disk_num,
            c.target_info,
            expected_hash,
        )
        for c in gen_result.candidates
    ]

    if len(work_items) == 1:
        success, result = extraction_worker(work_items[0])
        stats = result["stats"]
        total_stats["lfh_rejects"] += stats["lfh_rejects"]
        total_stats["decompress_rejects"] += stats["decompress_rejects"]
        total_stats["crc_rejects"] += stats["crc_rejects"]
        total_stats["hash_rejects"] += stats["hash_rejects"]

        if success:
            elapsed = time.time() - start_time
            logger.info(f"Recovery successful: N={result['n_value']}, "
                       f"cd_offset={result['cd_offset']}, entries={result['total_entries']} "
                       f"in {elapsed:.3f}s")
            return RecoveryResult(
                success=True,
                n_value=result["n_value"],
                recovered_data=result["data"],
                sha256_hash=result["hash"],
                message="Recovery successful",
                **total_stats,
            )
    else:
        with ProcessPoolExecutor(max_workers=num_jobs) as executor:
            futures = {executor.submit(extraction_worker, item): item for item in work_items}

            for future in as_completed(futures):
                try:
                    success, result = future.result()
                except Exception:
                    continue

                stats = result["stats"]
                total_stats["lfh_rejects"] += stats["lfh_rejects"]
                total_stats["decompress_rejects"] += stats["decompress_rejects"]
                total_stats["crc_rejects"] += stats["crc_rejects"]
                total_stats["hash_rejects"] += stats["hash_rejects"]

                if success:
                    executor.shutdown(wait=False, cancel_futures=True)

                    elapsed = time.time() - start_time
                    logger.info(f"Recovery successful: N={result['n_value']}, "
                               f"cd_offset={result['cd_offset']}, entries={result['total_entries']} "
                               f"in {elapsed:.3f}s")
                    return RecoveryResult(
                        success=True,
                        n_value=result["n_value"],
                        recovered_data=result["data"],
                        sha256_hash=result["hash"],
                        message="Recovery successful",
                        **total_stats,
                    )

    elapsed = time.time() - start_time
    return RecoveryResult(
        success=False,
        message=f"No valid match after {len(gen_result.candidates)} extractions in {elapsed:.3f}s",
        **total_stats,
    )
