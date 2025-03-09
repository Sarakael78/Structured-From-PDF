import os
import re
import tempfile
import logging  # Import logging
from tkinter import messagebox

class FileValidator:
    def __init__(self, allowed_extensions=None):
        self.allowed_extensions = allowed_extensions
        self.allowed_prefixes = [
            os.path.expanduser("~"),
            os.path.abspath(os.getcwd()),
            tempfile.gettempdir(),
        ]
        self.logger = logging.getLogger(__name__)  # Get logger for this module


    def _validate_path(self, path: str, must_exist: bool = True, must_be_file: bool = False, must_be_dir: bool = False) -> bool:
        """Internal path validation logic (combines original validate_path and is_safe_path)."""
        if not path:
            return False

        normalized_path = os.path.normpath(os.path.abspath(path))

        if (
            ".." in normalized_path
            or normalized_path.startswith("/")
            or normalized_path.startswith("\\")
            or ":" in normalized_path  # Prevent Windows drive letters
        ):
            self.logger.warning(f"Path validation failed: Potential directory traversal detected for {path}")
            return False

        path_allowed = any(normalized_path.startswith(prefix) for prefix in self.allowed_prefixes)
        if not path_allowed:
            self.logger.warning(f"Path validation failed: {path} is outside of allowed directories")
            return False

        if must_exist and not os.path.exists(normalized_path):
            return False

        if must_be_file and not os.path.isfile(normalized_path):
            return False

        if must_be_dir and not os.path.isdir(normalized_path):
            return False

        return True

    def is_valid_file_path(self, file_path):
        """
        Checks if a file path is valid, exists, is readable, has allowed extensions,
        is not empty, and handles large files.  Uses messagebox for user feedback.
        """
        if not self._validate_path(file_path, must_exist=True, must_be_file=True):
            messagebox.showerror("Error", f"Invalid file path: {file_path}")  # Generic error
            return False

        if self.allowed_extensions:
            if not file_path.lower().endswith(tuple(self.allowed_extensions)):
                allowed_ext_str = ", ".join(self.allowed_extensions)
                messagebox.showerror("Error", f"Invalid file type.  Must be one of: {allowed_ext_str}")
                return False

        try:
            file_size = os.path.getsize(file_path)
            if file_size == 0:
                messagebox.showwarning("Warning", f"File is empty: {file_path}")
                return False

            if file_size > 10 * 1024 * 1024:  # 10MB
                if not messagebox.askyesno(
                    "Warning",
                    f"File is large ({file_size/1024/1024:.1f} MB). Processing may take longer. Continue?",
                ):
                    return False
        except OSError as e:
            messagebox.showerror("Error", f"Error getting file size: {str(e)}")
            return False

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                f.read(1)  # Try to read one byte
        except PermissionError:
            messagebox.showerror("Error", f"Permission denied: Cannot read {file_path}")
            return False
        except UnicodeDecodeError:
            if self.allowed_extensions and ".pdf" in self.allowed_extensions and file_path.lower().endswith(".pdf"):
                return True
            else:
                messagebox.showwarning("Warning", f"File encoding issues. {file_path} might not be a readable text file.")
                return True  # Treat non-UTF-8, non-PDF files as potentially valid, but warn
        except Exception as e:
            messagebox.showerror("Error", f"Error reading file: {str(e)}")
            return False

        return True # All checks passed


    def is_valid_directory_path(self, dir_path):
        if not self._validate_path(dir_path, must_exist=True, must_be_dir=True):
             messagebox.showerror("Error", f"Invalid directory path: {dir_path}")
             return False

        files = [f for f in os.listdir(dir_path) if os.path.isfile(os.path.join(dir_path, f))]
        if not files:
            messagebox.showwarning("Warning", f"Directory is empty: {dir_path}")
            return False

        if self.allowed_extensions:
            valid_files = [f for f in files if os.path.splitext(f)[1].lower() in self.allowed_extensions]
            if not valid_files:
                allowed_ext_str = ", ".join(self.allowed_extensions)
                messagebox.showwarning("Warning",f"No supported files found in {dir_path}. Supported formats: {allowed_ext_str}")
                return False  # No valid files found

        return True

    def is_valid_input_file(self, file_path):
        return self.is_valid_file_path(file_path)


    def is_valid_output_directory(self, dir_path):
        return self.is_valid_directory_path(dir_path)