# file_handler.py
"""
Module to handle file input/output operations.

This includes reading raw text files and saving JSON data.  It also
now handles reading PDF files.
"""

import json
import logging
import sys
import os
from typing import Union

# Add PyMuPDF for PDF handling
import fitz

# Add to file_handler.py
def read_large_file_in_chunks(file_path: str, chunk_size: int = 1024*1024) -> Generator[str, None, None]:
    """Read a large file in chunks to avoid memory issues."""
    with open(file_path, 'r', encoding='utf-8') as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            yield chunk
        
def read_text_file(file_path: str) -> str:
    """
    Read and return the content of a text file.

    Args:
        file_path (str): Path to the text file.

    Returns:
        str: Contents of the file.

    Exits:
        If the file cannot be read.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
        logging.info("Successfully read file: %s", file_path)
        return content
    except Exception as e:
        logging.error("Error reading file '%s': %s", file_path, e)
        sys.exit(1)

def read_pdf_file(file_path: str) -> str:
    """
    Reads a PDF file and extracts all text content.

    Args:
      file_path: The path to the PDF file.

    Returns:
      A string containing all the text extracted from the PDF.

    Raises:
      FileNotFoundError: If the provided file_path does not exist.
      Exception: For any other errors encountered during PDF processing.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"The file '{file_path}' was not found.")

    try:
        text = ""
        with fitz.open(file_path) as doc:
            for page in doc:
                text += page.get_text()
        return text
    except Exception as e:
        logging.error(f"Error processing PDF file '{file_path}': {e}")
        raise  # Re-raise the exception to be handled by the caller.

def read_file(file_path: str) -> str:
    """
    Reads a file and returns its content as a string.  Handles both
    .txt and .pdf extensions.

    Args:
        file_path: Path to the input file.

    Returns:
        The content of the file as a string.
    """

    _, ext = os.path.splitext(file_path)

    if ext.lower() == ".txt":
        return read_text_file(file_path)
    elif ext.lower() == ".pdf":
        return read_pdf_file(file_path)
    else:
        raise ValueError(f"Unsupported file type: {ext}")


def save_json_file(data: dict, file_path: str) -> None:
    """
    Save a dictionary as JSON to the specified file.

    Args:
        data (dict): Data to write.
        file_path (str): Target file path.

    Exits:
        In case of an error during file writing.
    """
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        logging.info("Successfully saved JSON output to '%s'", file_path)
    except Exception as e:
        logging.error("Error writing JSON to '%s': %s", file_path, e)
        sys.exit(1)
