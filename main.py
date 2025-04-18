import os
import hashlib
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
        description="Anonymizes file names in a directory using a consistent hashing algorithm."
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


def anonymize_file_name(file_name: str, algorithm: str, prefix: str) -> str:
    """
    Anonymizes a file name using the specified hashing algorithm.

    Args:
        file_name (str): The name of the file to anonymize.
        algorithm (str): The hashing algorithm to use.
        prefix (str): The prefix to add to the anonymized file name.

    Returns:
        str: The anonymized file name.
    """
    try:
        # Hash the file name
        hash_object = hashlib.new(algorithm, file_name.encode('utf-8'))
        hashed_name = hash_object.hexdigest()

        # Get the file extension
        file_extension = os.path.splitext(file_name)[1]

        # Construct the anonymized file name
        anonymized_name = f"{prefix}{hashed_name}{file_extension}"
        return anonymized_name
    except Exception as e:
        logging.error(f"Error anonymizing file name '{file_name}': {e}")
        return None


def process_directory(directory: str, algorithm: str, prefix: str, dry_run: bool) -> None:
    """
    Processes all files in the specified directory, anonymizing their names.

    Args:
        directory (str): The directory containing the files to anonymize.
        algorithm (str): The hashing algorithm to use.
        prefix (str): The prefix to add to the anonymized file names.
        dry_run (bool): Whether to perform a dry run without renaming files.
    """
    try:
        if not is_valid_directory(directory):
            return

        for file_name in os.listdir(directory):
            file_path = os.path.join(directory, file_name)

            if os.path.isfile(file_path):
                anonymized_name = anonymize_file_name(file_name, algorithm, prefix)

                if anonymized_name:
                    anonymized_path = os.path.join(directory, anonymized_name)

                    if dry_run:
                        logging.info(f"[Dry Run] Renaming '{file_name}' to '{anonymized_name}'")
                    else:
                        try:
                            os.rename(file_path, anonymized_path)
                            logging.info(f"Renamed '{file_name}' to '{anonymized_name}'")
                        except OSError as e:
                            logging.error(f"Error renaming '{file_name}' to '{anonymized_name}': {e}")
                        except Exception as e:
                            logging.error(f"Unexpected error renaming '{file_name}' to '{anonymized_name}': {e}")
    except Exception as e:
        logging.error(f"Error processing directory '{directory}': {e}")


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

    process_directory(args.directory, args.algorithm, args.prefix, args.dry_run)
    return 0


if __name__ == "__main__":
    sys.exit(main())


# Usage Examples:
# 1. Anonymize files in a directory using the default settings:
#    python main.py /path/to/directory
#
# 2. Anonymize files using SHA-1 hashing and a custom prefix:
#    python main.py /path/to/directory --algorithm sha1 --prefix custom_
#
# 3. Perform a dry run without renaming files:
#    python main.py /path/to/directory --dry-run
#
# 4. Specify a log file:
#    python main.py /path/to/directory --log-file anonymizer.log