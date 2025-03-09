# batch_processor.py
"""
Module for batch processing multiple legal documents.
"""

import os
import logging
from typing import List, Dict, Any
from pathlib import Path
import json
import csv
import concurrent.futures

from config_handler import load_configuration
from file_handler import read_file, save_json_file
from prompt_generator import generate_prompt
from ai_model_handler import call_ai_model
from response_validator import validate_response
from prompt_generator import generatePromptFromYaml
from file_validator import FileValidator    
from file_handler import read_yaml_file


class BatchProcessor:
    def __init__(self, config_path: str, api_key: str, model_name: str, max_workers: int = 3):
        """
        Initialize the batch processor.

        Args:
            config_path (str): Path to the configuration file.
            api_key (str): API key for the AI model.
            model_name (str): Name of the AI model to use.
            max_workers (int): Maximum number of concurrent workers for processing.
        """
        self.config_path = config_path
        self.api_key = api_key
        self.model_name = model_name
        self.max_workers = max_workers
        self.config = load_configuration(config_path)
        self.results = []
        self.failed = []
        self.progress_callback = None


    def set_progress_callback(self, callback):
        """Set a callback function to report progress"""
        self.progress_callback = callback


    def process_directory(self, input_dir: str, output_dir: str, file_pattern: str = "*.txt|*.pdf") -> Dict[str, Any]:
        """Process all matching files in a directory.
        Args:
            input_dir (str): Directory containing input files.
            output_dir (str): Directory to save output files.
            file_pattern (str): Glob pattern(s) to match input files separated by '|'. Defaults to both .txt and .pdf.

        Returns:
            Dict[str, Any]: Summary of processing results.
        """
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)
        
        # Use file_validator for proper validation
        file_validator = FileValidator([".txt", ".pdf"])
        if not file_validator.is_valid_directory_path(input_dir):
            logging.error(f"Invalid input directory: {input_dir}")
            return {"success": 0, "failed": 0, "total": 0}
            
        # Process files with validation
        input_files = [f for f in Path(input_dir).glob(pattern) 
                    if file_validator.is_valid_file_path(str(f))]
        input_path = Path(input_dir)
        patterns = file_pattern.split("|")
        input_files = []
        for pattern in patterns:
            input_files.extend(list(input_path.glob(pattern)))
        total_files = len(input_files)

        if total_files == 0:
            logging.warning(f"No files matching patterns {file_pattern} found in {input_dir}")
            return {"success": 0, "failed": 0, "total": 0}

        logging.info(f"Found {total_files} files to process")

        # Process files with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.process_file, str(input_file), str(Path(output_dir) / f"{input_file.stem}.json")): input_file.name
                    for input_file in input_files}

            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                file_name = futures[future]
                try:
                    result = future.result()
                    self.results.append({"file": file_name, "result": result})
                except Exception as e:
                    logging.error(f"Error processing {file_name}: {e}")
                    self.failed.append({"file": file_name, "error": str(e)})

                if self.progress_callback:
                    self.progress_callback(i + 1, total_files)

        summary = {
            "success": len(self.results),
            "failed": len(self.failed),
            "total": total_files
        }

        summary_file = Path(output_dir) / "summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=4)

        return summary

    def processFile(self, inputFile: str, outputFile: str, instructionsFile: str) -> Dict[str, Any]:
        """
        Process a single file.

        Args:
            input_file (str): Path to the input file.
            output_file (str): Path to save the output JSON.

        Returns:
            Dict[str, Any]: Processed data.
        """
        logging.info(f"Processing {inputFile}")

        # Use the new read_file function
        legalText = read_file(inputFile)
        instructions = read_yaml_file(instructionsFile)

        # Generate prompt
        prompt = generatePromptFromYaml(instructions, legalText)
        aiResponse = call_ai_model(prompt, self.api_key, self.model_name)
        structuredData = validate_response(aiResponse, instructions)
        save_json_file(structuredData, outputFile)

        # Call AI model
        ai_response = call_ai_model(prompt, self.api_key, self.model_name)

        # Validate response
        structured_data = validate_response(ai_response, self.config)

        # Save output
        save_json_file(structured_data, outputFile)

        logging.info(f"Successfully processed {inputFile} to {outputFile}")
        return structured_data



    def export_results_csv(self, output_file: str) -> None:
        """
        Export all results to a CSV file.

        Args:
            output_file (str): Path to save the CSV file.
        """
        if not self.results:
            logging.warning("No results to export")
            return

        # Get all possible field names from results
        all_fields = set()
        for result in self.results:
            all_fields.update(result["result"].keys())

        # Convert to list and sort
        fields = ["file"] + sorted(all_fields)

        # Write CSV
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()

            for result in self.results:
                row = {"file": result["file"]}
                row.update(result["result"])
                writer.writerow(row)

        logging.info(f"Exported results to {output_file}")