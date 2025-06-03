# cryptoanalyzer/utils/file_utils.py

"""
Utility functions for file operations in CryptoAnalyzer.

Provides helpers for:
  - Reading and writing text files with proper encoding
  - Checking file types (e.g., `.py` files)
  - Ensuring directories exist before writing
  - Walking a directory tree to list files by extension
  - Safely copying or moving files
"""

import os
import shutil
from typing import List


def is_python_file(path: str) -> bool:
    """
    Return True if the given path points to an existing Python file (ends with .py).

    :param path: File path to check
    :return: True if file exists and has a .py extension, False otherwise
    """
    return os.path.isfile(path) and path.lower().endswith(".py")


def read_text_file(path: str, encoding: str = "utf-8") -> str:
    """
    Read and return the entire contents of a text file.

    Raises FileNotFoundError if the file does not exist.

    :param path: Path to the text file
    :param encoding: Encoding to use (default: utf-8)
    :return: File contents as a single string
    """
    with open(path, mode="r", encoding=encoding) as f:
        return f.read()


def write_text_file(path: str, content: str, encoding: str = "utf-8") -> None:
    """
    Write the given content to a text file, creating parent directories if needed.

    :param path: Path to the output text file
    :param content: String content to write
    :param encoding: Encoding to use (default: utf-8)
    """
    directory = os.path.dirname(path)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
    with open(path, mode="w", encoding=encoding) as f:
        f.write(content)


def list_files_with_extension(
    root_dir: str,
    extension: str,
    recursive: bool = True,
    exclude_patterns: List[str] = None
) -> List[str]:
    """
    Return a sorted list of file paths under `root_dir` that end with the given extension.

    :param root_dir: Directory to search
    :param extension: File extension to match (e.g., ".py", ".txt")
    :param recursive: If True, walk subdirectories; if False, only list top-level files
    :param exclude_patterns: List of glob patterns; any path matching one is skipped
    :return: Sorted list of matching file paths
    """
    if exclude_patterns is None:
        exclude_patterns = []

    matches: List[str] = []
    ext = extension.lower()

    if recursive:
        for dirpath, _, filenames in os.walk(root_dir):
            for fname in filenames:
                if fname.lower().endswith(ext):
                    full_path = os.path.join(dirpath, fname)
                    if not _is_excluded(full_path, exclude_patterns):
                        matches.append(full_path)
    else:
        for fname in os.listdir(root_dir):
            full_path = os.path.join(root_dir, fname)
            if os.path.isfile(full_path) and full_path.lower().endswith(ext):
                if not _is_excluded(full_path, exclude_patterns):
                    matches.append(full_path)

    return sorted(matches)


def _is_excluded(path: str, patterns: List[str]) -> bool:
    """
    Helper: return True if `path` matches any of the glob in `patterns`.

    :param path: File or directory path
    :param patterns: List of glob patterns (e.g., ["*/tests/*", "*.md"])
    :return: True if excluded, False otherwise
    """
    from fnmatch import fnmatch
    for pat in patterns:
        if fnmatch(path, pat):
            return True
    return False


def ensure_directory(path: str) -> None:
    """
    Ensure that the directory `path` exists. If it does not, create it (recursively).

    :param path: Directory path to create or verify
    """
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def copy_file(src: str, dst: str, overwrite: bool = False) -> None:
    """
    Copy a file from `src` to `dst`. If parent directories of `dst` do not exist, create them.

    :param src: Source file path
    :param dst: Destination file path
    :param overwrite: If True, overwrite dst if it exists; if False, raise FileExistsError
    """
    if not os.path.isfile(src):
        raise FileNotFoundError(f"Source file not found: {src}")

    dst_dir = os.path.dirname(dst)
    if dst_dir and not os.path.exists(dst_dir):
        os.makedirs(dst_dir, exist_ok=True)

    if os.path.exists(dst) and not overwrite:
        raise FileExistsError(f"Destination file already exists: {dst}")

    shutil.copy2(src, dst)


def move_file(src: str, dst: str, overwrite: bool = False) -> None:
    """
    Move (or rename) a file from `src` to `dst`. Creates parent directories of `dst` if needed.

    :param src: Source file path
    :param dst: Destination file path
    :param overwrite: If True, overwrite dst if it exists; if False, raise FileExistsError
    """
    if not os.path.isfile(src):
        raise FileNotFoundError(f"Source file not found: {src}")

    dst_dir = os.path.dirname(dst)
    if dst_dir and not os.path.exists(dst_dir):
        os.makedirs(dst_dir, exist_ok=True)

    if os.path.exists(dst):
        if overwrite:
            os.remove(dst)
        else:
            raise FileExistsError(f"Destination file already exists: {dst}")

    shutil.move(src, dst)
