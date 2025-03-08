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
        """
        Process all matching files in a directory.  Now handles both
        .txt and .pdf files.

        Args:
            input_dir (str): Directory containing input files.
            output_dir (str): Directory to save output files.
            file_pattern (str): Glob pattern to match input files.  Defaults to both .txt and .pdf.

        Returns:
            Dict[str, Any]: Summary of processing results.
        """
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Find all matching files
        input_path = Path(input_dir)
        # Separate patterns for .txt and .pdf
        input_files = list(input_path.glob("*.txt")) + list(input_path.glob("*.pdf"))
        total_files = len(input_files)

        if total_files == 0:
            logging.warning(f"No files matching '*.txt' or '*.pdf' found in {input_dir}")
            return {"success": 0, "failed": 0, "total": 0}

        logging.info(f"Found {total_files} files to process")

        # Process files with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.process_file, str(input_file), str(Path(output_dir) / f"{input_file.stem}.json")): input_file.name
                       for input_file in input_files}

            # Process results as they complete
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                file_name = futures[future]
                try:
                    result = future.result()
                    self.results.append({"file": file_name, "result": result})
                except Exception as e:
                    logging.error(f"Error processing {file_name}: {e}")
                    self.failed.append({"file": file_name, "error": str(e)})

                # Report progress if callback is set
                if self.progress_callback:
                    self.progress_callback(i + 1, total_files)

        # Generate summary
        summary = {
            "success": len(self.results),
            "failed": len(self.failed),
            "total": total_files
        }

        # Save summary to output directory
        summary_file = Path(output_dir) / "summary.json"
        with open(summary_file, "w") as f:
            json.dump(summary, f, indent=4)

        return summary


    def process_file(self, input_file: str, output_file: str) -> Dict[str, Any]:
        """
        Process a single file.

        Args:
            input_file (str): Path to the input file.
            output_file (str): Path to save the output JSON.

        Returns:
            Dict[str, Any]: Processed data.
        """
        logging.info(f"Processing {input_file}")

        # Use the new read_file function
        legal_text = read_file(input_file)

        # Generate prompt
        prompt = generate_prompt(self.config, legal_text)

        # Call AI model
        ai_response = call_ai_model(prompt, self.api_key, self.model_name)

        # Validate response
        structured_data = validate_response(ai_response, self.config)

        # Save output
        save_json_file(structured_data, output_file)

        logging.info(f"Successfully processed {input_file} to {output_file}")
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