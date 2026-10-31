![Banner](banner.png)

# dso-file-name-anonymizer
Renames files in a directory based on a keyed hash (HMAC, HMAC-SHA256 with the default algorithm), providing a one-way anonymization of file names to prevent information leakage based on naming conventions. The key holder can verify a candidate name against its anonymized form; anyone without the key cannot, so a candidate list does not recover the original names. - Focused on Tools for sanitizing and obfuscating sensitive data within text files and structured data formats

## Install
`git clone https://github.com/ShadowStrikeHQ/dso-file-name-anonymizer`

## Usage
`python main.py DIRECTORY --key YOUR_SECRET`

A key is required. Supply it with `--key` or set the `DSO_FILE_NAME_ANONYMIZER_KEY` environment variable. With no key supplied, the tool exits with code 1 and renames nothing, because unkeyed hashed names can be matched against a candidate list by anyone.

## Parameters
- `-h`: Show help message and exit
- `directory`: The directory containing the files to anonymize.
- `--algorithm`: The hashing algorithm to use for the keyed HMAC (default: sha256, giving HMAC-SHA256).
- `--prefix`: The prefix to add to the anonymized file names (default: anonymized_).
- `--key`: Secret key for the keyed hash. Falls back to the `DSO_FILE_NAME_ANONYMIZER_KEY` environment variable. Required.
- `--dry-run`: Perform a dry run without actually renaming any files.
- `--log-file`: Specify a log file path. If not set, it will print to console.

## Behavior
- File extensions are kept, and file contents are never changed. Only names change.
- If a rename would land on a name that already exists, that rename is refused and counted as skipped. An existing file is never overwritten.
- Names that are already in anonymized form (the prefix followed by a hex digest of the right length) are detected and skipped, so running the tool a second time on its own output does not hash its own hashes and the mapping back to the original names survives for the key holder.
- Every run ends by printing counts of renamed, failed, and skipped files.
- The run exits with code 1 when any rename fails, when any rename is refused because its target name already exists, or when the directory holds nothing to rename.

## License
Copyright (c) ShadowStrikeHQ
