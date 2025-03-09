# response_validator.py
"""
Module to validate and sanitize the AI model's JSON response.

It ensures the response is valid JSON and contains the expected fields as defined in the configuration.
"""

import json
import logging
import sys
from typing import Any, Dict

class ResponseValidationError(Exception):
    """Custom exception for response validation errors."""
    pass
def parse_response(response_text: str) -> Dict[str, Any]:
    """
    Parse the AI response, attempting YAML first, then JSON.

    Args:
        response_text (str): Raw response from the AI model.

    Returns:
        Dict[str, Any]: Parsed structured data.

    Raises:
        ValueError: If parsing fails for both YAML and JSON.
    """
    data = None
    if "```yaml" in response_text and "```" in response_text:
        try:
            start = response_text.find("```yaml") + len("```yaml")
            end = response_text.rfind("```")
            yaml_content = response_text[start:end].strip()
            import yaml
            data = yaml.safe_load(yaml_content)
            logging.info("Successfully parsed YAML response")
            return data
        except Exception as e:
            logging.warning(f"Failed to parse YAML response: {e}")

    # Try JSON parsing if YAML parsing failed or wasn't attempted
    try:
        data = json.loads(response_text)
        logging.info("Successfully parsed JSON response")
        return data
    except json.JSONDecodeError as e:
        logging.error(f"AI response is not valid JSON: {e}")
        raise ValueError("AI response is neither valid YAML nor JSON.") from e

def validate_required_fields(data: Dict[str, Any], instructions: Dict[str, Any]) -> None:
    """
    Verify that all required fields defined in YAML instructions are present.

    Args:
        data (Dict[str, Any]): Parsed structured data.
        instructions (Dict[str, Any]): YAML instructions defining required fields.

    Raises:
        ValueError: If required fields are missing.
    """
    missing_fields = []

    def check_fields(data_section, instruction_section, path=""):
        if isinstance(instruction_section, dict):
            for key, value in instruction_section.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(value, dict):
                    if key not in data_section or not isinstance(data_section[key], dict):
                        missing_fields.append(current_path)
                    else:
                        check_fields(data_section[key], value, current_path)
                elif isinstance(value, list):
                    if key not in data_section or not isinstance(data_section[key], list):
                        missing_fields.append(current_path)
                    else:
                        for idx, item in enumerate(data_section[key]):
                            if isinstance(value[0], dict):
                                check_fields(item, value[0], f"{current_path}[{idx}]")
                else:
                    if key not in data_section:
                        missing_fields.append(current_path)

    check_fields(data, instructions.get('yamlDefinitions', {}))

    if missing_fields:
        raise ResponseValidationError(f"Missing required fields: {', '.join(missing_fields)}")
    
def validate_response(response_text: str, instructions: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate the AI response ensuring it is valid YAML or JSON and contains required fields.

    Args:
        response_text (str): Raw response from the AI model.
        instructions (Dict[str, Any]): YAML instructions defining required fields.

    Returns:
        Dict[str, Any]: The validated and sanitized structured data.

    Raises:
        ValueError: If parsing fails or required fields are missing.
    """
    data = parse_response(response_text)

    # Validate required fields
    try:
        validate_response(data, instructions.get("yamlDefinitions", {}))
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        raise

    logging.info("AI response validated successfully.")
    return data