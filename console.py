import sys
import time
from typing import Optional
from dataclasses import dataclass


SPINNERS = ["[    ]", "[=   ]", "[==  ]", "[=== ]", "[ ===]", "[  ==]", "[   =]", "[    ]"]
BOX_TL = "+"
BOX_TR = "+"
BOX_BL = "+"
BOX_BR = "+"
BOX_H = "-"
BOX_V = "|"


@dataclass
class ConsoleState:
    total_candidates: int = 0
    tested: int = 0
    cd_rejects: int = 0
    lfh_rejects: int = 0
    decompress_rejects: int = 0
    crc_rejects: int = 0
    hash_rejects: int = 0
    current_n: int = 0
    num_workers: int = 0
    start_time: float = 0.0
    phase: str = "init"


def clear_lines(n: int):
    for _ in range(n):
        sys.stdout.write("\033[A\033[K")


def print_box(lines: list[str], width: int = 60):
    print(f"{BOX_TL}{BOX_H * width}{BOX_TR}")
    for line in lines:
        padded = line.ljust(width - 2)[:width - 2]
        print(f"{BOX_V} {padded} {BOX_V}")
    print(f"{BOX_BL}{BOX_H * width}{BOX_BR}")


def format_time(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = seconds % 60
    return f"{minutes}m {secs:.1f}s"


def print_header():
    print()
    print("  FindMissingBytes - ZIP Recovery Tool")
    print("  " + "=" * 38)
    print()


def print_search_start(archive: str, member: str, expected_hash: str, max_missing: int, num_jobs: int):
    print_header()
    lines = [
        f"Archive: {archive}",
        f"Member:  {member}",
        f"Hash:    {expected_hash[:16]}...{expected_hash[-8:]}",
        f"Max N:   {max_missing} bytes",
        f"Workers: {num_jobs}",
    ]
    print_box(lines)
    print()


def print_candidates_found(n_values: list[int], total_candidates: int):
    print(f"  Valid N values: {n_values}")
    print(f"  Candidates to test: {total_candidates}")
    print()


def print_extraction_progress(state: ConsoleState, spinner_idx: int):
    elapsed = time.time() - state.start_time
    spinner = SPINNERS[spinner_idx % len(SPINNERS)]

    rate = state.tested / elapsed if elapsed > 0 else 0

    lines = [
        f"Phase: Extraction {spinner}",
        f"",
        f"N = {state.current_n} missing bytes",
        f"Workers active: {state.num_workers}",
        f"",
        f"Tested:     {state.tested:>8} / {state.total_candidates}",
        f"CD reject:  {state.cd_rejects:>8}",
        f"LFH reject: {state.lfh_rejects:>8}",
        f"CRC reject: {state.crc_rejects:>8}",
        f"Hash reject:{state.hash_rejects:>8}",
        f"",
        f"Rate: {rate:.0f} candidates/sec",
        f"Time: {format_time(elapsed)}",
    ]
    print_box(lines)


def print_generation_progress(n_value: int, num_workers: int, offset_range: tuple[int, int]):
    print(f"  N={n_value}: Scanning cd_offset [{offset_range[0]:,} - {offset_range[1]:,}] with {num_workers} workers...")


def print_workers_cancelled(num_cancelled: int):
    print()
    print(f"  >> Match found! Terminating {num_cancelled} remaining workers...")
    print(f"  >> Workers terminated cleanly.")
    print()


def print_success(output_path: str, sha256: str, n_value: int, elapsed: float, stats: dict):
    print()
    lines = [
        "RECOVERY SUCCESSFUL",
        "",
        f"Output:   {output_path}",
        f"SHA-256:  {sha256}",
        f"Missing:  {n_value} bytes",
        f"Time:     {format_time(elapsed)}",
    ]
    print_box(lines, width=70)
    print()
    print("  Search Summary:")
    print(f"    Candidates tested:   {stats.get('candidates_tested', 0):>10}")
    print(f"    CD rejects:          {stats.get('cd_rejects', 0):>10}")
    print(f"    LFH rejects:         {stats.get('lfh_rejects', 0):>10}")
    print(f"    Decompress rejects:  {stats.get('decompress_rejects', 0):>10}")
    print(f"    CRC rejects:         {stats.get('crc_rejects', 0):>10}")
    print(f"    Hash rejects:        {stats.get('hash_rejects', 0):>10}")
    print()


def print_failure(message: str, elapsed: float, stats: dict):
    print()
    lines = [
        "RECOVERY FAILED",
        "",
        f"Reason: {message}",
        f"Time:   {format_time(elapsed)}",
    ]
    print_box(lines, width=70)
    print()
    print("  Search Summary:")
    print(f"    Candidates tested:   {stats.get('candidates_tested', 0):>10}")
    print(f"    CD rejects:          {stats.get('cd_rejects', 0):>10}")
    print(f"    LFH rejects:         {stats.get('lfh_rejects', 0):>10}")
    print(f"    Decompress rejects:  {stats.get('decompress_rejects', 0):>10}")
    print(f"    CRC rejects:         {stats.get('crc_rejects', 0):>10}")
    print(f"    Hash rejects:        {stats.get('hash_rejects', 0):>10}")
    print()
