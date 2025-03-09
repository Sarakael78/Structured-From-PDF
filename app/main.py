#!/usr/bin/env python3
"""
Application entry point for the legal data extraction process.

This application extracts structured data from South African legal judgments using a generative AI model.
It performs the following tasks:
  - Loads a JSON configuration file defining the required data fields.
  - Reads a raw legal judgment pdf text file.
  - Dynamically generates a prompt for the AI model.
  - Calls the AI model using Google’s generative AI API.
  - Validates the returned structured JSON response.
  - Saves the result in a user-specified JSON file.
"""

import argparse
import logging
from logging import config
import os
from config_handler import load_configuration
from file_handler import read_file, save_json_file, read_yaml_file
from prompt_generator import generatePromptFromYaml
from ai_model_handler import call_ai_model
from response_validator import validate_response
from utils import setup_logging


def parseArguments() -> argparse.Namespace:
        """Parse and return the command-line arguments.

        Returns:
            argparse.Namespace: Parsed command-line arguments."""
        parser = argparse.ArgumentParser(description="Extract structured legal data using an LLM based on YAML instructions.")
        parser.add_argument("--instructions", required=True, help="Path to the YAML instructions file")
        parser.add_argument("--input", required=True, help="Path to the input file containing the legal judgment (.txt or .pdf)")
        parser.add_argument("--output", default="output.json", help="Path to save the extracted structured data as a JSON file")
        parser.add_argument("--api_key", required=True, help="Your API key for the LLM")
        parser.add_argument("--model", default="gemini-2.0-flash", help="Name of the AI model to use")
        parser.add_argument("--verbose", action="store_true", help="Enable verbose logging for debugging")
        return parser.parse_args()


def main() -> None:
    """
    Main function to orchestrate the legal data extraction.
    """
    args = parseArguments()
    setup_logging(args.verbose)
    logging.info("Starting legal data extraction process...")

    # Load configuration file
    instructions = read_yaml_file(args.instructions)
    logging.debug("Loaded YAML instructions.")

    # Read the raw legal judgment text or PDF
    legalText = read_file(args.input)
    logging.debug(f"Legal judgment text length: {len(legalText)} characters")
    prompt = generatePromptFromYaml(instructions, legalText)
    logging.debug("Generated prompt:\n%s", prompt)

    # Call the AI model
    apiKey = os.environ.get("API_KEY") or args.api_key
    ai_response = call_ai_model(prompt, apiKey, args.model)
    logging.debug("AI model raw response:\n%s", ai_response)

    # Validate and sanitize the AI's response
    structured_data = validate_response(ai_response, config)
    logging.debug("Validated structured data:\n%s", structured_data)

    # Save the extracted data to the specified output file
    save_json_file(structured_data, args.output)
    logging.info("Legal data extraction process completed successfully.")


if __name__ == "__main__":
	try:
		args = parseArguments()
		setup_logging(args.verbose)
		main()
	except Exception as e:
		logging.exception("Unexpected error occurred: %s", e)
		exit(1)