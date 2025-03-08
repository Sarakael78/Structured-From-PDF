"""
Module to handle loading and validation of configuration files.
"""

import json
import logging
import os
import sys
from typing import Any, Dict


def load_configuration(config_path: str) -> Dict[str, Any]:
    """
    Load and validate the JSON configuration file.

    Args:
        config_path (str): Path to the JSON configuration file.

    Returns:
        Dict[str, Any]: Configuration data as a dictionary.

    Exits:
        If the file is missing, unreadable, or if the JSON is malformed.
    """
    if not os.path.exists(config_path):
        logging.error("Configuration file '%s' does not exist.", config_path)
        sys.exit(1)
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Validate that the configuration has a "fields" key and that it is a list.
        if "fields" not in data or not isinstance(data["fields"], list):
            logging.error("Invalid configuration: Missing 'fields' key or 'fields' is not a list.")
            sys.exit(1)
        return data
    except json.JSONDecodeError as e:
        logging.error("Error decoding JSON configuration file '%s': %s", config_path, e)
        sys.exit(1)
    except Exception as e:
        logging.error("Error reading configuration file '%s': %s", config_path, e)
        sys.exit(1)