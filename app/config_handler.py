import json
import os
from configparser import ConfigParser

def load_configuration(filepath: str) -> dict:
    """Loads configuration from a JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}  # Return an empty dictionary if file not found.
    except json.JSONDecodeError as e:
        raise ValueError(f"Error parsing JSON configuration file: {e}") from None

def save_configuration(filepath: str, config: dict) -> None:
    """Saves configuration to a JSON file."""
    try:
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=4)
    except (IOError, OSError) as e:
        raise IOError(f"Error writing configuration file: {e}") from None

#Optionally define a class to deal with INI files (If you also want INI support)
class INIConfigHandler:
    #methods to load and save INI configs
    pass


