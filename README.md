# FindMissingBytes

Reconstruct files from truncated ZIP archives using SHA-256 hash validation.

## Overview

When a ZIP archive is truncated (missing bytes from the end), the End of Central Directory (EOCD) record becomes corrupted. This tool brute-forces the missing EOCD fields to reconstruct and extract files, validating against a known SHA-256 hash.

## Installation

```bash
pip install -e .
```

## Usage

### Truncate (for testing)

Create a truncated archive to test recovery:

```bash
python -m findmissingbytes truncate myarchive.zip --remove 10
```

This creates:
- `archives/myarchive_truncated.zip` - The truncated archive
- `archives/myarchive_truncated.json` - Metadata about the truncation
- `archives/myarchive_truncated/` - SHA-256 hash files for each member

### Recover

Recover a file from a truncated archive:

```bash
# Hash read from archives/<basename>/<member>.sha256
python -m findmissingbytes recover myarchive_truncated.zip path/to/file.txt

# Hash provided directly
python -m findmissingbytes recover myarchive_truncated.zip path/to/file.txt e36b3b7f53bfe...

# With options
python -m findmissingbytes recover myarchive_truncated.zip path/to/file.txt --jobs 16
```

Arguments:
- `archive` - Truncated archive filename (in ./archives/)
- `member` - Path of the member to recover
- `hash` - (optional) SHA-256 hash. If omitted, reads from `archives/<basename>/<member>.sha256`

Options:
- `--max-missing N` - Maximum missing bytes to try (default: 21, max: 21)
- `--jobs N` - Number of parallel workers (default: CPU count)

Output is written to `output/<archive>_recovered/<member_path>`.

## Directory Structure

```
./archives/       # Input archives and truncation artifacts
./output/         # Recovered files
./logs/           # Log files
```


## Assumptions

The following assumptions are made about truncated archives:

1. **comment_length = 0** - The EOCD has no trailing comment. This is the only assumption about unknown fields.

2. **Single-disk archive** - The disk number fields match the actual disk where the file resides (derived from drive letter on Windows).

3. **EOCD signature intact** - At least 4 bytes of the EOCD signature must be present in the truncated file to locate the EOCD position.

4. **N <= 18 bytes missing** - The maximum missing tail is 18 bytes (EOCD size 22 minus 4-byte signature).

5. **Target member exists** - The file to recover must be listed in the Central Directory.

6. **Compression method 0 or 8** - Only stored (0) and deflate (8) compression are supported.

## Console Output

The tool displays:
- Archive info and valid N values
- Worker progress during candidate generation
- Extraction progress with candidate count
- Worker termination message on match
- Summary statistics (tested, rejects by stage)
- Output file path and hash
