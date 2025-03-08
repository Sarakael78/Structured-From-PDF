# gui.py
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import json
import os
import csv
import logging
from typing import Dict, Any, Optional
import webbrowser

from config_handler import load_configuration
from file_handler import read_text_file, save_json_file
from prompt_generator import generate_prompt
from ai_model_handler import call_ai_model, get_available_models
from response_validator import validate_response
from utils import setup_logging
from batch_processor import BatchProcessor
import pandas as pd


class LegalDataExtractorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Legal Data Extractor")
        self.geometry("900x700")
        self.configure(padx=20, pady=20)

        # Set application icon
        # self.iconphoto(True, tk.PhotoImage(file="icon.png"))

        self.api_key = tk.StringVar(value="")
        self.config_path = tk.StringVar(value="config.json")  # Default to config.json
        self.input_path = tk.StringVar(value="input.txt")  # Default
        self.output_path = tk.StringVar(value="output.json")  # Default
        self.model_name = tk.StringVar(value="gemini-2.0-flash")
        self.status_text = tk.StringVar(value="Ready")
        self.processing = False
        self.batch_processor = None  # Initialize BatchProcessor instance

        self._create_widgets()
        self._create_menu()

        # Load saved settings if available
        self.load_settings()

    def _create_widgets(self):
        # Create notebook for tabs
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Main tab
        main_frame = ttk.Frame(notebook, padding=10)
        notebook.add(main_frame, text="Extract Data")

        # Config editor tab
        config_editor_frame = ttk.Frame(notebook, padding=10)
        notebook.add(config_editor_frame, text="Configuration Editor")

        # Results viewer tab
        results_frame = ttk.Frame(notebook, padding=10)
        notebook.add(results_frame, text="Results Viewer")

        # Log viewer tab
        log_frame = ttk.Frame(notebook, padding=10)
        notebook.add(log_frame, text="Logs")

        # Build the main extraction tab
        self._build_main_tab(main_frame)
        self._build_config_editor_tab(config_editor_frame)
        self._build_results_viewer_tab(results_frame)
        self._build_log_viewer_tab(log_frame)

    def _build_main_tab(self, parent):
        # File selection section
        file_frame = ttk.LabelFrame(parent, text="File Selection", padding=10)
        file_frame.pack(fill=tk.X, pady=5)

        # Config file
        ttk.Label(file_frame, text="Configuration File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(file_frame, textvariable=self.config_path, width=50).grid(row=0, column=1, pady=5, padx=5)
        ttk.Button(file_frame, text="Browse...", command=self.browse_config).grid(row=0, column=2, pady=5)

        # Input file/directory - Dynamically changes based on batch mode
        self.input_label = ttk.Label(file_frame, text="Input Legal Text:")
        self.input_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        self.input_entry = ttk.Entry(file_frame, textvariable=self.input_path, width=50)
        self.input_entry.grid(row=1, column=1, pady=5, padx=5)
        self.input_browse_button = ttk.Button(file_frame, text="Browse...", command=self.browse_input)
        self.input_browse_button.grid(row=1, column=2, pady=5)


        # Output file/directory - Dynamically changes based on batch mode
        self.output_label = ttk.Label(file_frame, text="Output JSON File:")
        self.output_label.grid(row=2, column=0, sticky=tk.W, pady=5)
        self.output_entry = ttk.Entry(file_frame, textvariable=self.output_path, width=50)
        self.output_entry.grid(row=2, column=1, pady=5, padx=5)
        self.output_browse_button = ttk.Button(file_frame, text="Browse...", command=self.browse_output)
        self.output_browse_button.grid(row=2, column=2, pady=5)

        # API settings section
        api_frame = ttk.LabelFrame(parent, text="API Settings", padding=10)
        api_frame.pack(fill=tk.X, pady=10)

        # API Key
        ttk.Label(api_frame, text="API Key:").grid(row=0, column=0, sticky=tk.W, pady=5)
        api_entry = ttk.Entry(api_frame, textvariable=self.api_key, width=50, show="*")
        api_entry.grid(row=0, column=1, pady=5, padx=5)
        ttk.Button(api_frame, text="Show/Hide",
                   command=lambda: api_entry.configure(show="" if api_entry.cget("show") else "*")
                   ).grid(row=0, column=2)

        # Model selection
        ttk.Label(api_frame, text="AI Model:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.model_combobox = ttk.Combobox(api_frame, textvariable=self.model_name, width=48)
        self.model_combobox.grid(row=1, column=1, pady=5, padx=5)
        ttk.Button(api_frame, text="Refresh", command=self.refresh_models).grid(row=1, column=2)

        # Processing options
        options_frame = ttk.LabelFrame(parent, text="Processing Options", padding=10)
        options_frame.pack(fill=tk.X, pady=10)

        self.verbose_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Verbose logging", variable=self.verbose_var).pack(anchor=tk.W)

        self.batch_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Batch processing mode", variable=self.batch_var,
                        command=self.toggle_batch_mode).pack(anchor=tk.W)

        # Execute section
        exec_frame = ttk.Frame(parent, padding=10)
        exec_frame.pack(fill=tk.X, pady=10)

        self.progress = ttk.Progressbar(exec_frame, orient=tk.HORIZONTAL, length=100, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=10)

        button_frame = ttk.Frame(exec_frame)
        button_frame.pack(fill=tk.X)

        ttk.Button(button_frame, text="Extract Data", command=self.start_extraction, style='Accent.TButton',
                   width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Cancel", command=self.cancel_extraction,
                   width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Fields", command=self.clear_fields,
                   width=20).pack(side=tk.LEFT, padx=5)

        # Status bar
        status_bar = ttk.Label(parent, textvariable=self.status_text, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=5)

    def _build_config_editor_tab(self, parent):
        # Add configuration editor components
        control_frame = ttk.Frame(parent)
        control_frame.pack(side=tk.TOP, fill=tk.X, pady=5)

        ttk.Button(control_frame, text="New Configuration", command=self.new_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Load Configuration", command=self.load_config_to_editor).pack(side=tk.LEFT,padx=5)
        ttk.Button(control_frame, text="Save Configuration", command=self.save_config_from_editor).pack(side=tk.LEFT,padx=5)

        # Fields list frame
        fields_frame = ttk.LabelFrame(parent, text="Configuration Fields", padding=10)
        fields_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Create treeview for fields
        self.fields_tree = ttk.Treeview(fields_frame, columns=("name", "type", "required"), show="headings")
        self.fields_tree.heading("name", text="Field Name")
        self.fields_tree.heading("type", text="Data Type")
        self.fields_tree.heading("required", text="Required")
        self.fields_tree.column("name", width=200)
        self.fields_tree.column("type", width=100)
        self.fields_tree.column("required", width=80)

        # Add scrollbar
        scrollbar = ttk.Scrollbar(fields_frame, orient=tk.VERTICAL, command=self.fields_tree.yview)
        self.fields_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.fields_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Field editor frame
        edit_frame = ttk.LabelFrame(parent, text="Edit Field", padding=10)
        edit_frame.pack(fill=tk.X, pady=10)

        ttk.Label(edit_frame, text="Field Name:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.field_name_var = tk.StringVar()
        ttk.Entry(edit_frame, textvariable=self.field_name_var, width=40).grid(row=0, column=1, pady=5, padx=5)

        ttk.Label(edit_frame, text="Field Type:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.field_type_var = tk.StringVar(value="string")
        field_type_combo = ttk.Combobox(edit_frame, textvariable=self.field_type_var, width=38)
        field_type_combo["values"] = ["string", "list", "date", "number", "boolean"]
        field_type_combo.grid(row=1, column=1, pady=5, padx=5)

        ttk.Label(edit_frame, text="Required:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.field_required_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(edit_frame, variable=self.field_required_var).grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)

        # Buttons for field manipulation
        btn_frame = ttk.Frame(edit_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="Add Field", command=self.add_field).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Update Field", command=self.update_field).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete Field", command=self.delete_field).pack(side=tk.LEFT, padx=5)

        # Connect treeview selection to field editor
        self.fields_tree.bind("<<TreeviewSelect>>", self.on_field_select)

    def _build_results_viewer_tab(self, parent):
        # Results viewer components
        control_frame = ttk.Frame(parent)
        control_frame.pack(side=tk.TOP, fill=tk.X, pady=5)

        ttk.Button(control_frame, text="Load Results", command=self.load_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export as CSV", command=lambda: self.export_results("csv")).pack(side=tk.LEFT,padx=5)
        ttk.Button(control_frame, text="Export as Excel", command=lambda: self.export_results("excel")).pack(side=tk.LEFT, padx=5)

        # Results display
        results_frame = ttk.LabelFrame(parent, text="Extracted Data", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Create Text widget with scrollbar for JSON display
        self.results_text = tk.Text(results_frame, wrap=tk.WORD, width=80, height=20)
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    def _build_log_viewer_tab(self, parent):
        # Log viewer components
        control_frame = ttk.Frame(parent)
        control_frame.pack(side=tk.TOP, fill=tk.X, pady=5)

        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Save Logs", command=self.save_logs).pack(side=tk.LEFT, padx=5)

        # Log display
        log_frame = ttk.Frame(parent)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.log_text = tk.Text(log_frame, wrap=tk.WORD, width=80, height=20, state='disabled')  # Initially disabled
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Redirect logging to this widget
        self.setup_log_redirection()

    def _create_menu(self):
        menubar = tk.Menu(self)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open Configuration", command=self.browse_config)
        file_menu.add_command(label="Open Legal Text", command=self.browse_input)
        file_menu.add_command(label="Save Output As...", command=self.browse_output)
        file_menu.add_separator()
        file_menu.add_command(label="Save Settings", command=self.save_settings)
        file_menu.add_command(label="Load Settings", command=self.load_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Clear All Fields", command=self.clear_fields)
        edit_menu.add_command(label="Set API Key", command=self.set_api_key)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Batch Process", command=self.batch_process)
        tools_menu.add_command(label="Model Settings", command=self.model_settings)
        tools_menu.add_separator()
        tools_menu.add_command(label="Validate Configuration", command=self.validate_config)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    # File and Directory Handling Methods
    def browse_config(self):
        filename = filedialog.askopenfilename(
            title="Select Configuration File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.config_path.set(filename)

    def browse_input(self):
        if self.batch_var.get():  # Batch mode
            dirname = filedialog.askdirectory(title="Select Input Directory")
            if dirname:
                self.input_path.set(dirname)
        else:  # Single file mode
            filename = filedialog.askopenfilename(
                title="Select Legal Text File",
                filetypes=[("Text files", "*.txt"), ("PDF files", "*.pdf"), ("All files", "*.*")]
            )
            if filename:
                self.input_path.set(filename)

    def browse_output(self):
        if self.batch_var.get():  # Batch mode
            dirname = filedialog.askdirectory(title="Select Output Directory")
            if dirname:
                self.output_path.set(dirname)

        else:
            filename = filedialog.asksaveasfilename(
                title="Save Output As",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if filename:
                self.output_path.set(filename)

    # Main Extraction and Batch Processing Logic
    def start_extraction(self):
        # Validate inputs
        if not self.config_path.get() or not self.input_path.get() or not self.output_path.get():
            messagebox.showerror("Error", "Please select all required files/directories.")
            return

        if not self.api_key.get():
            messagebox.showerror("Error", "Please enter an API key.")
            return

        if not self.model_name.get():
            messagebox.showerror("Error", "Please select an AI model.")
            return

        if self.batch_var.get():
            self.batch_process()  # Directly call batch process if in batch mode
        else:
            # Single file extraction (existing logic)
            self.processing = True
            self.progress.start(10)
            self.status_text.set("Processing...")
            threading.Thread(target=self.run_extraction, daemon=True).start()


    def run_extraction(self):
        try:
            # Setup logging
            setup_logging(self.verbose_var.get())

            # Load configuration
            config = load_configuration(self.config_path.get())

            # Read legal text
            legal_text = read_text_file(self.input_path.get())

            # Generate prompt
            prompt = generate_prompt(config, legal_text)

            # Call AI model
            self.update_status("Calling AI model...")
            ai_response = call_ai_model(prompt, self.api_key.get(), self.model_name.get())

            # Validate response
            self.update_status("Validating response...")
            structured_data = validate_response(ai_response, config)

            # Save output
            save_json_file(structured_data, self.output_path.get())

            # Display results
            self.display_results(structured_data)

            self.update_status("Extraction completed successfully!")
            messagebox.showinfo("Success", "Legal data extraction completed successfully!")

        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            messagebox.showerror("Error", f"An error occurred during extraction: {str(e)}")
        finally:
            # Stop progress indicator
            self.after(0, self.progress.stop)
            self.processing = False

    def cancel_extraction(self):
        if self.processing:
            # Implement cancellation logic if possible (e.g., using a threading.Event)
            self.processing = False
            self.progress.stop()
            self.status_text.set("Extraction cancelled")

    def clear_fields(self):
        self.config_path.set("")
        self.input_path.set("")
        self.output_path.set("")

    def refresh_models(self):
        try:
            models = get_available_models(self.api_key.get())
            model_names = []
            for provider, model_list in models.items():
                model_names.extend(model_list)  # Flatten the list
            self.model_combobox["values"] = model_names
            if model_names:
                self.model_name.set(model_names[0])  # Default to the first
            self.update_status("Models refreshed")
        except Exception as e:
            self.update_status(f"Error refreshing models: {e}")

    def toggle_batch_mode(self):
        if self.batch_var.get():
            self.input_label.config(text="Input Directory:")
            self.output_label.config(text="Output Directory:")
            self.input_path.set("")  # Clear previous value
            self.output_path.set("")
            self.input_browse_button.config(command=self.browse_input)  # Update browse button
            self.output_browse_button.config(command=self.browse_output)
        else:
            self.input_label.config(text="Input Legal Text:")
            self.output_label.config(text="Output JSON File:")
            self.input_path.set("input.txt")  # Reset to default
            self.output_path.set("output.json")
            self.input_browse_button.config(command=self.browse_input)
            self.output_browse_button.config(command=self.browse_output)

    def update_status(self, message: str):
        self.status_text.set(message)
        self.update_idletasks()  # Force UI update

    def display_results(self, data: Dict[str, Any]):
        # Clear previous content
        self.results_text.delete("1.0", tk.END)
        # Insert formatted JSON
        self.results_text.insert("1.0", json.dumps(data, indent=4))
        self.results_text.see("1.0")  # Scroll to the top

    def save_settings(self):
        settings = {
            "api_key": self.api_key.get(),
            "config_path": self.config_path.get(),
            "input_path": self.input_path.get(),
            "output_path": self.output_path.get(),
            "model_name": self.model_name.get(),
            "verbose": self.verbose_var.get(),
            "batch_mode": self.batch_var.get()
        }
        try:
            with open("settings.json", "w") as f:
                json.dump(settings, f, indent=4)
            messagebox.showinfo("Settings", "Settings saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")

    def load_settings(self):
        try:
            with open("settings.json", "r") as f:
                settings = json.load(f)
                self.api_key.set(settings.get("api_key", ""))
                self.config_path.set(settings.get("config_path", "config.json"))
                self.input_path.set(settings.get("input_path", "input.txt"))
                self.output_path.set(settings.get("output_path", "output.json"))
                self.model_name.set(settings.get("model_name", "gemini-2.0-flash"))
                self.verbose_var.set(settings.get("verbose", True))
                self.batch_var.set(settings.get("batch_mode", False))
                self.toggle_batch_mode() #update the mode

                # Refresh model list after loading API key
                self.refresh_models()

        except FileNotFoundError:
            # Use default settings if no settings file
            self.refresh_models()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load settings: {e}")
            self.refresh_models()

    def set_api_key(self):
        api_key, ok = tk.simpledialog.askstring("API Key", "Enter your API Key:", show="*", parent=self)
        if ok:
            self.api_key.set(api_key)

    def batch_process(self):
        input_dir = self.input_path.get()
        output_dir = self.output_path.get()
        config_path = self.config_path.get()

        if not input_dir or not output_dir or not config_path:
            messagebox.showerror("Error", "Please select input and output directories, and a configuration file.")
            return
        
        if not os.path.isdir(input_dir):
            messagebox.showerror("Error", "Invalid Input Directory.")

        if not os.path.isdir(output_dir):
            messagebox.showerror("Error", "Invalid Output Directory")
        # Start the batch processing in a separate thread
        threading.Thread(target=self._run_batch_process, args=(input_dir, output_dir, config_path), daemon=True).start()


    def _run_batch_process(self, input_dir, output_dir, config_path):
        try:
            self.processing = True
            self.progress.start(10)
            self.update_status("Starting batch processing...")

            # Create BatchProcessor instance here
            processor = BatchProcessor(config_path, self.api_key.get(), self.model_name.get())
            processor.set_progress_callback(self.update_batch_progress)  # Set callback
            summary = processor.process_directory(input_dir, output_dir)

            self.update_status(f"Batch processing complete: {summary['success']} successful, {summary['failed']} failed.")
            messagebox.showinfo("Batch Processing",
                                f"Batch processing complete!\n\nSuccessful: {summary['success']}\nFailed: {summary['failed']}\nTotal: {summary['total']}")
        except Exception as e:
            self.update_status(f"Batch processing error: {e}")
            messagebox.showerror("Error", f"Batch Processing Error: {e}")
        finally:
            self.progress.stop()
            self.processing = False

    def update_batch_progress(self, current, total):
        """Callback function to update the progress bar during batch processing."""
        progress_percent = (current / total) * 100
        self.progress["mode"] = "determinate"  # Switch to determinate mode
        self.progress["value"] = progress_percent
        self.update_status(f"Batch Processing: {current}/{total} files processed")
        self.update_idletasks()

    def model_settings(self):
        # Implement any model-specific settings adjustments
        pass

    def validate_config(self):
        try:
            config = load_configuration(self.config_path.get())
            messagebox.showinfo("Configuration Validation", "Configuration file is valid!")
        except Exception as e:
            messagebox.showerror("Error", f"Invalid configuration file: {str(e)}")

    def show_documentation(self):
        # Implement displaying documentation (e.g., open a web page)
        webbrowser.open("https://example.com/documentation")  # Replace with your documentation URL
        pass

    def show_about(self):
        # Implement displaying about information
        messagebox.showinfo("About", "Legal Data Extractor\nVersion 1.0\nCreated by [Your Name]")
        pass

    def load_results(self):
        """Loads results from a JSON file and displays them."""
        filename = filedialog.askopenfilename(
            title="Select Results File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.display_results(data)
                self.update_status(f"Loaded results from {filename}")
            except Exception as e:
                self.update_status(f"Error loading results: {e}")
                messagebox.showerror("Error", f"Failed to load results: {e}")

    def export_results(self, file_type: str):
        """Exports the currently loaded results to CSV or Excel."""
        if not self.results_text.get("1.0", tk.END).strip():
            messagebox.showinfo("Export", "No results to export.")
            return

        try:
            data = json.loads(self.results_text.get("1.0", tk.END))
        except json.JSONDecodeError:
            messagebox.showerror("Error", "The displayed results are not valid JSON.  Cannot export.")
            return

        if file_type == "csv":
            filename = filedialog.asksaveasfilename(
                title="Export Results as CSV",
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
            )
            if not filename: return
            self.export_to_csv(data, filename)
        elif file_type == "excel":
            filename = filedialog.asksaveasfilename(
                title="Export Results as Excel",
                defaultextension=".xlsx",
                filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")]
            )
            if not filename: return
            self.export_to_excel(data, filename)
        else:
            messagebox.showerror("Error", f"Unsupported export format: {file_type}")

    def export_to_csv(self, data: Dict, filename: str):
        """Exports JSON data to a CSV file."""
        try:
            if isinstance(data, dict):
                # Handle single result object.
                data = [data]  # Convert to a list of one dictionary.

            if not isinstance(data, list):
                raise ValueError("Invalid data format for CSV export.  Expected list of dictionaries.")

            if not data:
                messagebox.showinfo("Export", "No data to export")
                return

            all_fields = set()
            for item in data:
                all_fields.update(item.keys())
            fields = sorted(all_fields)

            with open(filename, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields)
                writer.writeheader()
                writer.writerows(data)  # Write all rows at once
            self.update_status(f"Exported results to CSV: {filename}")

        except Exception as e:
            self.update_status(f"CSV export error: {e}")
            messagebox.showerror("Error", f"Failed to export to CSV: {e}")

    def export_to_excel(self, data: Dict, filename: str):
        """Exports JSON data to an Excel file."""
        try:

            if isinstance(data, dict):
                data = [data]

            if not isinstance(data, list):
                raise ValueError("Invalid data format for Excel export. Expected list of dictionaries.")

            if not data:
                messagebox.showinfo("Export", "No data to export.")
                return;

            df = pd.DataFrame(data)
            df.to_excel(filename, index=False)
            self.update_status(f"Exported results to Excel: {filename}")


        except Exception as e:
            self.update_status(f"Excel export error: {e}")
            messagebox.showerror("Error", f"Failed to export to Excel: {e}")

    def clear_logs(self):
        """Clears the log text widget."""
        self.log_text.config(state='normal')  # Enable editing
        self.log_text.delete("1.0", tk.END)
        self.log_text.config(state='disabled')  # Disable editing

    def save_logs(self):
        """Saves the log content to a file."""
        filename = filedialog.asksaveasfilename(
            title="Save Logs",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(self.log_text.get("1.0", tk.END))
                self.update_status(f"Logs saved to {filename}")
            except Exception as e:
                self.update_status(f"Error saving logs: {e}")
                messagebox.showerror("Error", f"Failed to save logs: {e}")

    def setup_log_redirection(self):
        """Redirects logging output to the log text widget."""

        class LogHandler(logging.Handler):
            def __init__(self, text_widget):
                super().__init__()
                self.text_widget = text_widget

            def emit(self, record):
                msg = self.format(record)
                self.text_widget.config(state='normal')
                self.text_widget.insert(tk.END, msg + "\n")
                self.text_widget.config(state='disabled')
                self.text_widget.see(tk.END)  # Auto-scroll to the end

        log_handler = LogHandler(self.log_text)
        log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(log_handler)
        logging.getLogger().setLevel(logging.INFO)  # Set the root logger level

    def new_config(self):
        """Clears the current configuration in the editor."""
        self.fields_tree.delete(*self.fields_tree.get_children())
        self.field_name_var.set("")
        self.field_type_var.set("string")
        self.field_required_var.set(True)

    def load_config_to_editor(self):
        """Loads a configuration file into the editor."""
        filename = filedialog.askopenfilename(
            title="Select Configuration File",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                config = load_configuration(filename)
                self.new_config()  # Clear existing fields first
                for field_name, details in config.items():
                    field_type = details.get("type", "string")  # Default to string
                    required = details.get("required", True)  # Default to True
                    self.fields_tree.insert("", "end", values=(field_name, field_type, required))
                self.update_status(f"Loaded config from {filename}")
            except Exception as e:
                self.update_status(f"Error loading config: {e}")
                messagebox.showerror("Error", f"Failed to load config: {e}")


    def save_config_from_editor(self):
        """Saves the current configuration from the editor to a file."""
        filename = filedialog.asksaveasfilename(
            title="Save Configuration As",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                config = {}
                for item in self.fields_tree.get_children():
                    name, field_type, required_str = self.fields_tree.item(item, "values")
                    required = required_str.lower() == "true"
                    config[name] = {"type": field_type, "required": required}
                with open(filename, "w") as f:
                    json.dump(config, f, indent=4)
                self.update_status(f"Saved config to {filename}")
                self.config_path.set(filename)  # Update the config path
            except Exception as e:
                self.update_status(f"Error saving config: {e}")
                messagebox.showerror("Error", f"Failed to save config: {e}")


    def add_field(self):
        """Adds a new field to the configuration."""
        name = self.field_name_var.get().strip()
        field_type = self.field_type_var.get()
        required = self.field_required_var.get()

        if not name:
            messagebox.showerror("Error", "Field name cannot be empty.")
            return

        # Check for duplicate field names
        for item in self.fields_tree.get_children():
            existing_name, _, _ = self.fields_tree.item(item, "values")
            if existing_name == name:
                messagebox.showerror("Error", f"Field '{name}' already exists.")
                return

        self.fields_tree.insert("", "end", values=(name, field_type, required))
        self.clear_field_editor()

    def update_field(self):
        """Updates the selected field in the configuration."""
        selected_item = self.fields_tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a field to update.")
            return
        selected_item = selected_item[0]

        name = self.field_name_var.get().strip()
        field_type = self.field_type_var.get()
        required = self.field_required_var.get()

        if not name:
            messagebox.showerror("Error", "Field name cannot be empty.")
            return

        # Check for duplicate names, excluding the current field
        for item in self.fields_tree.get_children():
            if item != selected_item:
                existing_name, _, _ = self.fields_tree.item(item, "values")
                if existing_name == name:
                    messagebox.showerror("Error", f"Field '{name}' already exists.")
                    return

        self.fields_tree.item(selected_item, values=(name, field_type, required))
        self.clear_field_editor()

    def delete_field(self):
        """Deletes the selected field from the configuration."""
        selected_item = self.fields_tree.selection()
        if not selected_item:
            messagebox.showinfo("Info", "Please select a field to delete.")
            return
        self.fields_tree.delete(selected_item[0])
        self.clear_field_editor()


    def on_field_select(self, event):
        """Handles field selection in the treeview."""
        selected_item = self.fields_tree.selection()
        if selected_item:
            name, field_type, required_str = self.fields_tree.item(selected_item[0], "values")
            required = required_str.lower() == "true"
            self.field_name_var.set(name)
            self.field_type_var.set(field_type)
            self.field_required_var.set(required)


    def clear_field_editor(self):
        """Clears the field editor."""
        self.field_name_var.set("")
        self.field_type_var.set("string")  # Reset to default
        self.field_required_var.set(True)

    # In gui.py, for long operations:
    def process_file_background(self, input_path, output_path):
        """Process a file in a background thread with progress updates."""
        def background_task():
            try:
                # Processing logic here
                # ...
                # Update UI when done
                self.after(0, lambda: self.update_status("Processing complete"))
            except Exception as e:
                # Update UI with error
                self.after(0, lambda: self.show_error(str(e)))
        
        threading.Thread(target=background_task, daemon=True).start()

if __name__ == "__main__":
    app = LegalDataExtractorApp()

    # Add a style for the "Extract" button
    style = ttk.Style()
    style.configure('Accent.TButton', font=('Arial', 12, 'bold'))

    app.mainloop()