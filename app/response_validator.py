# response_validator.py
"""
Module to validate and sanitize the AI model's JSON response.

It ensures the response is valid JSON and contains the expected fields as defined in the configuration.
"""

import json
import logging
import sys
from typing import Any, Dict


def validate_response(response_text: str, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate the AI response ensuring it is valid JSON and contains all required fields.

    Args:
        response_text (str): Raw JSON response from the AI model.
        config (Dict[str, Any]): Configuration dictionary with the expected fields.

    Returns:
        Dict[str, Any]: The validated and sanitized structured data.

    Exits:
        If the response is not valid JSON or if required fields are missing.
    """
    try:
        data = json.loads(response_text)
    except json.JSONDecodeError as e:
        logging.error("AI response is not valid JSON: %s\nResponse: %s", e, response_text)
        sys.exit(1)

    # Verify that all required fields are present.
    required_fields = [field["name"] for field in config.get("fields",) if field.get("required")]
    missing = [field for field in required_fields if field not in data]
    if missing:
        logging.error("The AI response is missing required fields: %s", ", ".join(missing))
        sys.exit(1)

    # Additional type checking and coercion.
    for field in config.get("fields",):
        name = field.get("name")
        expected_type = field.get("type", "string")
        if name in data:
            value = data[name]
            if expected_type == "list" and not isinstance(value, list):
                if isinstance(value, str):
                    coerced_list = [item.strip() for item in value.split(",") if item.strip()]
                    logging.warning("Coerced field '%s' from string to list: %s", name, coerced_list)
                    data[name] = coerced_list
                else:
                    logging.error("Field '%s' expects a list but got %s", name, type(value).__name__)
                    sys.exit(1)
            elif expected_type == "date" and not isinstance(value, str):
                logging.error("Field '%s' expects a date string but got %s", name, type(value).__name__)
                sys.exit(1)
    logging.info("AI response validated with keys: %s", list(data.keys()))
    return data