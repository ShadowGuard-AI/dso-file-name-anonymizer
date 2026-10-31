import os
import hashlib
import hmac
import re
import argparse
import logging
import sys
import chardet  # Import chardet
from typing import List
from typing import Optional


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def setup_argparse() -> argparse.ArgumentParser:
    """
    Sets up the argument parser for the command-line interface.

    Returns:
        argparse.ArgumentParser: The configured argument parser.
    """
    parser = argparse.ArgumentParser(
        description="Anonymizes file names in a directory using a keyed hash (HMAC) under an operator secret."
    )
    parser.add_argument(
        "directory",
        type=str,
        help="The directory containing the files to anonymize."
    )
    parser.add_argument(
        "--algorithm",
        type=str,
        default="sha256",
        choices=["md5", "sha1", "sha256", "sha512"],
        help="The hashing algorithm to use (default: sha256)."
    )
    parser.add_argument(
        "--prefix",
        type=str,
        default="anonymized_",
        help="The prefix to add to the anonymized file names (default: anonymized_)."
    )
    parser.add_argument(
        "--key",
        type=str,
        default=None,
        help="Secret key for the keyed hash. If not set, the DSO_FILE_NAME_ANONYMIZER_KEY environment variable is used. A key is required."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Perform a dry run without actually renaming any files."
    )
    parser.add_argument(
        "--log-file",
        type=str,
        help="Specify a log file path. If not set, it will print to console.",
        default=None
    )
    return parser


def is_valid_directory(directory: str) -> bool:
    """
    Validates if the given path is a valid and existing directory.

    Args:
        directory (str): The path to the directory.

    Returns:
        bool: True if the path is a valid directory, False otherwise.
    """
    if not isinstance(directory, str):
        logging.error(f"Directory must be a string, but got {type(directory)}")
        return False
    if not os.path.isdir(directory):
        logging.error(f"Directory '{directory}' does not exist or is not a directory.")
        return False
    return True


def is_already_anonymized(file_name: str, algorithm: str, prefix: str) -> bool:
    """
    Checks whether a file name already has this tool's anonymized shape:
    the prefix followed by a hex digest of the length the chosen
    algorithm produces, plus the kept extension.
    """
    stem, _extension = os.path.splitext(file_name)
    if not stem.startswith(prefix):
        return False
    digest_hex = stem[len(prefix):]
    digest_length = hashlib.new(algorithm).digest_size * 2
    return re.fullmatch(r"[0-9a-f]{%d}" % digest_length, digest_hex) is not None


def anonymize_file_name(file_name: str, algorithm: str, prefix: str, key: str) -> str:
    """
    Anonymizes a file name using a keyed hash (HMAC) under an operator
    secret. With the default algorithm this is HMAC-SHA256.

    Args:
        file_name (str): The name of the file to anonymize.
        algorithm (str): The hashing algorithm to use.
        prefix (str): The prefix to add to the anonymized file name.
        key (str): The operator secret the hash is keyed with.

    Returns:
        str: The anonymized file name.
    """
    try:
        # Hash the file name with a keyed HMAC so that only the key
        # holder can check a candidate name against its anonymized form.
        hashed_name = hmac.new(
            key.encode('utf-8'), file_name.encode('utf-8'), getattr(hashlib, algorithm)
        ).hexdigest()

        # Get the file extension
        file_extension = os.path.splitext(file_name)[1]

        # Construct the anonymized file name
        anonymized_name = f"{prefix}{hashed_name}{file_extension}"
        return anonymized_name
    except Exception as e:
        logging.error(f"Error anonymizing file name '{file_name}': {e}")
        return None


def process_directory(directory: str, algorithm: str, prefix: str, dry_run: bool, key: str) -> int:
    """
    Processes all files in the specified directory, anonymizing their names.

    Args:
        directory (str): The directory containing the files to anonymize.
        algorithm (str): The hashing algorithm to use.
        prefix (str): The prefix to add to the anonymized file names.
        dry_run (bool): Whether to perform a dry run without renaming files.
        key (str): The operator secret the hash is keyed with.

    Returns:
        int: Exit code. 1 when any rename fails, when a rename is refused
        because its target name already exists, or when the directory
        holds nothing to rename; 0 otherwise.
    """
    renamed = 0
    failed = 0
    skipped = 0
    collisions = 0
    try:
        if not is_valid_directory(directory):
            return 1

        file_names = [
            name for name in os.listdir(directory)
            if os.path.isfile(os.path.join(directory, name))
        ]

        if not file_names:
            logging.error(f"Directory '{directory}' holds nothing to rename.")
            logging.info(f"Done. Renamed: {renamed}, Failed: {failed}, Skipped: {skipped}")
            return 1

        for file_name in file_names:
            file_path = os.path.join(directory, file_name)

            if is_already_anonymized(file_name, algorithm, prefix):
                skipped += 1
                logging.info(f"Skipping '{file_name}': already in anonymized form.")
                continue

            anonymized_name = anonymize_file_name(file_name, algorithm, prefix, key)

            if not anonymized_name:
                failed += 1
                continue

            anonymized_path = os.path.join(directory, anonymized_name)

            if os.path.exists(anonymized_path):
                skipped += 1
                collisions += 1
                logging.error(
                    f"Refusing to rename '{file_name}' to '{anonymized_name}': "
                    "the target name already exists and will not be overwritten."
                )
                continue

            if dry_run:
                renamed += 1
                logging.info(f"[Dry Run] Renaming '{file_name}' to '{anonymized_name}'")
            else:
                try:
                    os.rename(file_path, anonymized_path)
                    renamed += 1
                    logging.info(f"Renamed '{file_name}' to '{anonymized_name}'")
                except OSError as e:
                    failed += 1
                    logging.error(f"Error renaming '{file_name}' to '{anonymized_name}': {e}")
                except Exception as e:
                    failed += 1
                    logging.error(f"Unexpected error renaming '{file_name}' to '{anonymized_name}': {e}")
    except Exception as e:
        logging.error(f"Error processing directory '{directory}': {e}")
        failed += 1

    logging.info(f"Done. Renamed: {renamed}, Failed: {failed}, Skipped: {skipped}")
    if failed > 0 or collisions > 0 or renamed == 0:
        return 1
    return 0


def main() -> int:
    """
    Main function to execute the file name anonymization tool.

    Returns:
        int: Exit code (0 for success, 1 for failure).
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Configure logging to file, if specified.
    if args.log_file:
        file_handler = logging.FileHandler(args.log_file)
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(file_handler)

    if not is_valid_directory(args.directory):
        return 1

    key = args.key or os.environ.get("DSO_FILE_NAME_ANONYMIZER_KEY")
    if not key:
        logging.error(
            "A key is required: supply --key or set the "
            "DSO_FILE_NAME_ANONYMIZER_KEY environment variable. "
            "Without a key the anonymized names would be reversible "
            "by anyone with a candidate list, so nothing was renamed."
        )
        return 1

    return process_directory(args.directory, args.algorithm, args.prefix, args.dry_run, key)


if __name__ == "__main__":
    sys.exit(main())


# Usage Examples:
# 1. Anonymize files in a directory using the default settings.
#    A key is required, either as an option or as an environment variable:
#    python main.py /path/to/directory --key YOUR_SECRET
#    DSO_FILE_NAME_ANONYMIZER_KEY=YOUR_SECRET python main.py /path/to/directory
#
# 2. Anonymize files using SHA-1 hashing and a custom prefix:
#    python main.py /path/to/directory --algorithm sha1 --prefix custom_ --key YOUR_SECRET
#
# 3. Perform a dry run without renaming files:
#    python main.py /path/to/directory --dry-run --key YOUR_SECRET
#
# 4. Specify a log file:
#    python main.py /path/to/directory --log-file anonymizer.log --key YOUR_SECRET