# gui.py
import logging  # Add this import
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading
import json
import os
import csv
import logging
import logging.handlers
import base64
import tempfile
from typing import Dict, Any, Optional, List, Callable
import webbrowser
import queue
import time
from configparser import ConfigParser
import hashlib
import google.generativeai
import openai

from config_handler import load_configuration
from file_handler import read_file, save_json_file
from prompt_generator import generate_prompt, chunk_text
from ai_model_handler import call_ai_model, get_available_models
from response_validator import validate_response
from utils import setup_logging, ThreadSafeQueue, SecureStorage, retry_with_backoff

from file_validator import FileValidator


# Try importing batch_processor, but handle case where it doesn't exist
try:
    from batch_processor import BatchProcessor
    BATCH_PROCESSOR_AVAILABLE = True
except ImportError:
    BATCH_PROCESSOR_AVAILABLE = False
    # Create a placeholder BatchProcessor for graceful degradation
    class BatchProcessor:
        def __init__(self, config_path, api_key, model_name):
            self.config_path = config_path
            self.api_key = api_key
            self.model_name = model_name
            self._progress_callback = None  # Initialize the callback to None
            self.cancel_event = threading.Event() # Event for cancellation

        def set_progress_callback(self, callback):
            self._progress_callback = callback

        def process_directory(self, input_dir, output_dir):
            #the real process_directory logic
            if self._progress_callback:
                self._progress_callback(0) #init progress
            logging.info("process_directory is starting")

# Try importing pandas, but handle case where it doesn't exist
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

# Application settings and defaults
APP_NAME = "Legal Data Extractor"
APP_VERSION = "1.0.1"
APP_DEVELOPER = "Your Company"
APP_DEFAULTS = {
    "config_path": "config.json",
    "input_path": "input.txt",
    "output_path": "output.json",
    "model_name": "gemini-2.0-flash",
    "verbose": True,
    "batch_mode": False,
    "docs_url": "https://example.com/documentation"  # Replace with actual URL
}

class AppConfig:
    """Application configuration manager."""
    def __init__(self, config_file="app_config.ini"):
        self.config_file = config_file
        self.config = ConfigParser()
        
        # Set default values
        self.config["General"] = {
            "docs_url": APP_DEFAULTS["docs_url"],
            "log_level": "INFO",
            "max_threads": "4",
            "ui_theme": "default"
        }
        
        # Load existing config if it exists
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
    
    def get(self, section, key, fallback=None):
        """Get a configuration value."""
        return self.config.get(section, key, fallback=fallback)
    
    def set(self, section, key, value):
        """Set a configuration value."""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, str(value))
    
    def save(self):
        """Save the configuration to file."""
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def get_int(self, section, key, fallback=0):
        """Get a configuration value as an integer."""
        try:
            return self.config.getint(section, key, fallback=fallback)
        except ValueError:
            return fallback
    
    def get_bool(self, section, key, fallback=False):
        """Get a configuration value as a boolean."""
        try:
            return self.config.getboolean(section, key, fallback=fallback)
        except ValueError:
            return fallback
        
#Create a global AppConfig instance
app_config = AppConfig() # Initialize the shared config

class LegalDataExtractorApp(tk.Tk):
    def __init__(self, config_file="app_config.ini"):  #pass config_file to init the AppConfig object
        super().__init__()
        self.title(APP_NAME)
        self.geometry("900x700")
        self.configure(padx=20, pady=20)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.app_config = app_config #assign the shared app_config to this class
        self.file_validator = FileValidator(allowed_extensions=[".txt", ".pdf"])
        
        # Initialize task queue for background operations
        self.task_queue = ThreadSafeQueue()
        self.task_queue.start(self.app_config.get_int("General", "max_threads", 4))
        
        # Cancellation event
        self.cancel_event = threading.Event()

        # Set application icon
        # try:
        #     self.iconphoto(True, tk.PhotoImage(file="icon.png"))
        # except Exception as e:
        #     logging.warning(f"Could not load application icon: {e}")

        # Application variables
        self.api_key = tk.StringVar(value="")
        self.config_path = tk.StringVar(value=APP_DEFAULTS["config_path"])
        self.input_path = tk.StringVar(value=APP_DEFAULTS["input_path"])
        self.output_path = tk.StringVar(value=APP_DEFAULTS["output_path"])
        self.model_name = tk.StringVar(value=APP_DEFAULTS["model_name"])
        self.status_text = tk.StringVar(value="Ready")
        self.instructionsPath = tk.StringVar(value="") # Add this line
        self.processing = False
        self.batch_processor = None
        self.verbose_var = tk.BooleanVar(value=APP_DEFAULTS["verbose"]) # Add this line to init the variable.
        self.batch_var = tk.BooleanVar(value=APP_DEFAULTS["batch_mode"]) # Initialize batch_var here.
        
        # Create UI elements
        self._create_widgets()
        self._create_menu()
        self._create_keyboard_shortcuts()

        # Load saved settings if available
        self.load_settings()
        
        # Set up logging
        self._configure_logging()

        self.active_threads = []  # Track active threads

    def browseInstructions(self):
        """Open a file dialog to select the instructions YAML file."""
        filename = self.open_file_dialog("Select Instructions YAML File", [("YAML files", "*.yaml"), ("All files", "*.*")])
        if filename:
            self.instructionsPath.set(filename)   
    
    def search_results(self, event=None, next=False):
        """Searches for text within the results_text widget."""
        search_term = self.search_var.get().strip()
        if not search_term:
            messagebox.showinfo("Search", "Please enter a search term.")
            return

        text_widget = self.results_text
        text_widget.tag_remove('search_highlight', '1.0', tk.END)

        start_pos = text_widget.index(tk.INSERT) if next else '1.0'
        idx = text_widget.search(search_term, start_pos, nocase=True, stopindex=tk.END)

        if not idx:
            messagebox.showinfo("Search", f"'{search_term}' not found.")
            return

        end_idx = f"{idx}+{len(search_term)}c"
        text_widget.tag_add('search_highlight', idx, f"{idx}+{len(search_term)}c")
        text_widget.tag_config('search_highlight', background='yellow')
        text_widget.mark_set(tk.INSERT, f"{idx}+{len(search_term)}c")
        text_widget.see(idx)

        self.update_status(f"Found '{search_term}' at position {idx}")
       
    def _configure_logging(self):
        log_level_str = self.app_config.get("General", "log_level", "INFO").upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        setup_logging(self.verbose_var.get(), log_level)
        self.log_action(f"Logging initialized with level: {log_level_str}")

    def open_file_dialog(self, title, filetypes):
        """Open a file dialog and return the selected file path."""
        filename = filedialog.askopenfilename(title=title, filetypes=filetypes)
        if filename:
            self.log_action(f"Selected file: {filename}")
        return filename

    def save_file_dialog(self, title, defaultextension, filetypes):
        """Open a save file dialog and return the selected file path."""
        filename = filedialog.asksaveasfilename(title=title, defaultextension=defaultextension, filetypes=filetypes)
        if filename:
            self.log_action(f"Selected file: {filename}")
        return filename

    def log_action(self, message: str, level: int = logging.INFO) -> None:
        """Log an action with the specified message and level.
        
        Args:
            message: The message to log.
            level: The logging level (default is logging.INFO).
        """
        logging.log(level, message)

    def on_close(self):
            """Clean up resources before closing the application."""
            if self.processing and messagebox.askyesno("Confirm Exit", "Processing is active. Are you sure you want to exit?"):
                self.cancel_extraction()
                self.update()
                self.after(500)
                self.quit()
            elif not self.processing:
                self.quit()
   
    def _create_widgets(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Main tab
        main_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(main_frame, text="Extract Data")

        # Config editor tab
        config_editor_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(config_editor_frame, text="Configuration Editor")

        # Results viewer tab
        results_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(results_frame, text="Results Viewer")

        # Log viewer tab
        log_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(log_frame, text="Logs")

        # Build the tabs
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
        config_entry = ttk.Entry(file_frame, textvariable=self.config_path, width=50)
        config_entry.grid(row=0, column=1, pady=5, padx=5)
        ttk.Button(file_frame, text="Browse...", command=self.browse_config).grid(row=0, column=2, pady=5)

        # Input file/directory
        self.input_label = ttk.Label(file_frame, text="Input Legal Text:")
        self.input_label.grid(row=1, column=0, sticky=tk.W, pady=5)
        self.input_entry = ttk.Entry(file_frame, textvariable=self.input_path, width=50)
        self.input_entry.grid(row=1, column=1, pady=5, padx=5)
        self.input_browse_button = ttk.Button(file_frame, text="Browse...", command=self.browse_input)
        self.input_browse_button.grid(row=1, column=2, pady=5)

        # Output file/directory
        self.output_label = ttk.Label(file_frame, text="Output JSON File:")
        self.output_label.grid(row=2, column=0, sticky=tk.W, pady=5)
        self.output_entry = ttk.Entry(file_frame, textvariable=self.output_path, width=50)
        self.output_entry.grid(row=2, column=1, pady=5, padx=5)
        self.output_browse_button = ttk.Button(file_frame, text="Browse...", command=self.browse_output)
        self.output_browse_button.grid(row=2, column=2, pady=5)

        # YAML Instructions file (newly added)
        ttk.Label(file_frame, text="Instructions YAML:").grid(row=3, column=0, sticky=tk.W, pady=5)
        instructionsEntry = ttk.Entry(file_frame, textvariable=self.instructionsPath, width=50)
        instructionsEntry.grid(row=3, column=1, pady=5, padx=5)
        ttk.Button(file_frame, text="Browse...", command=self.browseInstructions).grid(row=3, column=2, pady=5)
        self._add_tooltip(instructionsEntry, "Path to the YAML instructions file defining extraction fields")

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
        name_entry = ttk.Entry(edit_frame, textvariable=self.field_name_var, width=40)
        name_entry.grid(row=0, column=1, pady=5, padx=5)
        self._add_tooltip(name_entry, "Name of the field to extract")

        ttk.Label(edit_frame, text="Field Type:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.field_type_var = tk.StringVar(value="string")
        field_type_combo = ttk.Combobox(edit_frame, textvariable=self.field_type_var, width=38)
        field_type_combo["values"] = ["string", "list", "date", "number", "boolean"]
        field_type_combo.grid(row=1, column=1, pady=5, padx=5)
        self._add_tooltip(field_type_combo, "Data type of the extracted field")

        ttk.Label(edit_frame, text="Required:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.field_required_var = tk.BooleanVar(value=True)
        required_check = ttk.Checkbutton(edit_frame, variable=self.field_required_var)
        required_check.grid(row=2, column=1, sticky=tk.W, pady=5, padx=5)
        self._add_tooltip(required_check, "Whether this field must be present in the extraction")

        # Buttons for field manipulation
        btn_frame = ttk.Frame(edit_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=10)

        ttk.Button(btn_frame, text="Add Field", command=self.add_field).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Update Field", command=self.update_field).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete Field", command=self.delete_field).pack(side=tk.LEFT, padx=5)

        # Connect treeview selection to field editor
        self.fields_tree.bind("<<TreeviewSelect>>", self.on_field_select)
    
        # Add context menu to treeview
        self._add_treeview_context_menu()

    def _build_results_viewer_tab(self, parent):
        # Results viewer components
        control_frame = ttk.Frame(parent)
        control_frame.pack(side=tk.TOP, fill=tk.X, pady=5)

        ttk.Button(control_frame, text="Load Results", command=self.load_results).pack(side=tk.LEFT, padx=5)
        self.csv_export_button = ttk.Button(control_frame, text="Export as CSV", 
                                            command=lambda: self.export_results("csv"))
        self.csv_export_button.pack(side=tk.LEFT, padx=5)
        
        self.excel_export_button = ttk.Button(control_frame, text="Export as Excel", 
                                            command=lambda: self.export_results("excel"))
        self.excel_export_button.pack(side=tk.LEFT, padx=5)
        
        # Disable Excel button if pandas not available
        if not PANDAS_AVAILABLE:
            self.excel_export_button.config(state="disabled")
            self._add_tooltip(self.excel_export_button, "Excel export requires pandas module")

        # Results display
        results_frame = ttk.LabelFrame(parent, text="Extracted Data", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # Create Text widget with scrollbar for JSON display
        self.results_text = tk.Text(results_frame, wrap=tk.WORD, width=80, height=20)
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.results_text.yview)
        self.results_text.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add search functionality
        search_frame = ttk.Frame(parent)
        search_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        search_entry.bind("<Return>", self.search_results)
        
        ttk.Button(search_frame, text="Find", command=self.search_results).pack(side=tk.LEFT, padx=5)
        ttk.Button(search_frame, text="Find Next", command=lambda: self.search_results(next=True)).pack(side=tk.LEFT, padx=5)

    def _build_log_viewer_tab(self, parent):
        # Log viewer components
        control_frame = ttk.Frame(parent)
        control_frame.pack(side=tk.TOP, fill=tk.X, pady=5)

        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Save Logs", command=self.save_logs).pack(side=tk.LEFT, padx=5)
        
        # Log level selector
        ttk.Label(control_frame, text="Log Level:").pack(side=tk.LEFT, padx=(20, 5))
        self.log_level_var = tk.StringVar(value="INFO")
        log_level_combo = ttk.Combobox(control_frame, textvariable=self.log_level_var, width=10,
                                        values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        log_level_combo.pack(side=tk.LEFT, padx=5)
        log_level_combo.bind("<<ComboboxSelected>>", self.change_log_level)

        # Log display
        log_frame = ttk.Frame(parent)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        self.log_text = tk.Text(log_frame, wrap=tk.WORD, width=80, height=20, state='disabled')
        scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Add log filter
        filter_frame = ttk.Frame(parent)
        filter_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.log_filter_var = tk.StringVar()
        filter_entry = ttk.Entry(filter_frame, textvariable=self.log_filter_var, width=30)
        filter_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        filter_entry.bind("<Return>", self.filter_logs)
        
        ttk.Button(filter_frame, text="Apply Filter", command=self.filter_logs).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear Filter", command=self.clear_log_filter).pack(side=tk.LEFT, padx=5)

        # Redirect logging to this widget
        self.setup_log_redirection()

    def clear_log_filter(self):
        """Clear the log filter and display all log records."""
        self.log_filter_var.set("")
        self.log_text.config(state='normal')
        self.log_text.delete("1.0", tk.END)
        
        for record in self.log_records:
            self.log_text.insert(tk.END, record + "\n")
        
        self.log_text.config(state='disabled')

    def change_log_level(self, event=None):
        """Change the log level based on the selected value in the combobox."""
        new_log_level = self.log_level_var.get().upper()
        log_level = getattr(logging, new_log_level, logging.INFO)
        logging.getLogger().setLevel(log_level)
        self.log_action(f"Log level changed to: {new_log_level}")
    
    def filter_logs(self, event=None):
        """Filter the log display based on the filter text."""
        filter_text = self.log_filter_var.get().lower()
        self.log_text.config(state='normal')
        self.log_text.delete("1.0", tk.END)
        
        for record in self.log_records:
            if filter_text in record.lower():
                self.log_text.insert(tk.END, record + "\n")
    
        self.log_text.config(state='disabled')

    def _create_menu(self):
        menubar = tk.Menu(self)

        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Open Configuration", command=self.browse_config, accelerator="Ctrl+O")
        file_menu.add_command(label="Open Legal Text", command=self.browse_input, accelerator="Ctrl+I")
        file_menu.add_command(label="Save Output As...", command=self.browse_output, accelerator="Ctrl+S")
        file_menu.add_separator()
        file_menu.add_command(label="Save Settings", command=self.save_settings)
        file_menu.add_command(label="Load Settings", command=self.load_settings)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close, accelerator="Alt+F4")
        menubar.add_cascade(label="File", menu=file_menu)

        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Clear All Fields", command=self.clear_fields)
        edit_menu.add_command(label="Set API Key", command=self.set_api_key, accelerator="Ctrl+K")
        edit_menu.add_separator()
        edit_menu.add_command(label="Preferences", command=self.show_preferences)
        menubar.add_cascade(label="Edit", menu=edit_menu)

        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Batch Process", command=self.batch_process, 
                            state="normal" if BATCH_PROCESSOR_AVAILABLE else "disabled")
        tools_menu.add_command(label="Model Settings", command=self.model_settings)
        tools_menu.add_separator()
        tools_menu.add_command(label="Validate Configuration", command=self.validate_config)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Documentation", command=self.show_documentation, accelerator="F1")
        help_menu.add_command(label="Check for Updates", command=self.check_for_updates)
        help_menu.add_separator()
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def check_for_updates(self):
        """Check for updates to the application."""
        self.update_status("Checking for updates...")
        try:
            # Simulate checking for updates (replace with actual update logic)
            time.sleep(2)  # Simulate network delay
            latest_version = "1.0.2"  # Example latest version
            if APP_VERSION < latest_version:
                messagebox.showinfo("Update Available", f"A new version ({latest_version}) is available.")
            else:
                messagebox.showinfo("No Updates", "You are using the latest version.")
            self.update_status("Update check complete.")
        except Exception as e:
            self.update_status(f"Update check failed: {e}")
            messagebox.showerror("Error", f"Failed to check for updates: {e}")

    def _create_keyboard_shortcuts(self):
        """Create keyboard shortcuts for common operations."""
        self.bind("<Control-o>", lambda event: self.browse_config())
        self.bind("<Control-i>", lambda event: self.browse_input())
        self.bind("<Control-s>", lambda event: self.browse_output())
        self.bind("<Control-k>", lambda event: self.set_api_key())
        self.bind("<F1>", lambda event: self.show_documentation())
        self.bind("<F5>", lambda event: self.start_extraction())
        self.bind("<Escape>", lambda event: self.cancel_extraction())

    def show_preferences(self):
        """Show the preferences dialog."""
        preferences_window = tk.Toplevel(self)
        preferences_window.title("Preferences")
        preferences_window.geometry("400x300")
        preferences_window.grab_set()  # Make the window modal

        ttk.Label(preferences_window, text="Preferences", font=("Arial", 14)).pack(pady=10)

        # Example preference: Log Level
        ttk.Label(preferences_window, text="Log Level:").pack(anchor=tk.W, padx=10, pady=5)
        log_level_var = tk.StringVar(value=self.app_config.get("General", "log_level", "INFO"))
        log_level_combo = ttk.Combobox(preferences_window, textvariable=log_level_var, values=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"])
        log_level_combo.pack(fill=tk.X, padx=10, pady=5)

        # Example preference: Max Threads
        ttk.Label(preferences_window, text="Max Threads:").pack(anchor=tk.W, padx=10, pady=5)
        max_threads_var = tk.IntVar(value=self.app_config.get_int("General", "max_threads", 4))
        max_threads_spinbox = ttk.Spinbox(preferences_window, from_=1, to=16, textvariable=max_threads_var)
        max_threads_spinbox.pack(fill=tk.X, padx=10, pady=5)

        # Save button
        ttk.Button(preferences_window, text="Save", command=lambda: self.save_preferences(log_level_var.get(), max_threads_var.get())).pack(pady=10)

    def save_preferences(self, log_level, max_threads):
        """Save the preferences."""
        self.app_config.set("General", "log_level", log_level)
        self.app_config.set("General", "max_threads", max_threads)
        self.app_config.save()
        self.update_status("Preferences saved successfully")
        messagebox.showinfo("Preferences", "Preferences saved successfully")

    def _add_tooltip(self, widget, text):
        """Add a tooltip to a widget."""
        def enter(event):
            x, y, _, _ = widget.bbox("insert")
            x += widget.winfo_rootx() + 25
            y += widget.winfo_rooty() + 25
            
            # Create a toplevel window
            self.tooltip = tk.Toplevel(widget)
            self.tooltip.wm_overrideredirect(True)
            self.tooltip.wm_geometry(f"+{x}+{y}")
            
            label = ttk.Label(self.tooltip, text=text, justify=tk.LEFT,
                            background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                            font=("tahoma", "8", "normal"))
            label.pack(ipadx=1)
        
        def leave(event):
            if hasattr(self, "tooltip"):
                self.tooltip.destroy()
        
        widget.bind("<Enter>", enter)
        widget.bind("<Leave>", leave)

    def _add_treeview_context_menu(self):
        """Add a context menu to the fields treeview."""
        self.tree_context_menu = tk.Menu(self, tearoff=0)
        self.tree_context_menu.add_command(label="Edit Field", command=self.edit_selected_field)
        self.tree_context_menu.add_command(label="Delete Field", command=self.delete_field)
        self.tree_context_menu.add_separator()
        self.tree_context_menu.add_command(label="Move Up", command=self.move_field_up)
        self.tree_context_menu.add_command(label="Move Down", command=self.move_field_down)
        
        # Bind right-click event to show context menu
        self.fields_tree.bind("<Button-3>", self._show_context_menu)
        
    def _show_context_menu(self, event):
        """Show the context menu on right-click."""
        # Select the item under cursor first
        item = self.fields_tree.identify_row(event.y)
        if item:
            self.fields_tree.selection_set(item)
            # Display context menu
            try:
                self.tree_context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                # Make sure to release the grab
                self.tree_context_menu.grab_release()
                
    def edit_selected_field(self):
        """Open the field for editing in the field editor section."""
        selected_item = self.fields_tree.selection()
        if selected_item:
            self.on_field_select(None)  # Pass None as event to reuse existing method
            
    def move_field_up(self):
        """Move the selected field up in the list."""
        selected = self.fields_tree.selection()
        if not selected:
            return
            
        for item in selected:
            prev = self.fields_tree.prev(item)
            if prev:
                # Get positions
                item_idx = self.fields_tree.index(item)
                prev_idx = self.fields_tree.index(prev)
                
                # Store values
                item_values = self.fields_tree.item(item, "values")
                prev_values = self.fields_tree.item(prev, "values")
                
                # Swap values
                self.fields_tree.item(item, values=prev_values)
                self.fields_tree.item(prev, values=item_values)
                
                # Keep selection on moved item
                self.fields_tree.selection_set(prev)
                self.fields_tree.focus(prev)
                
    def move_field_down(self):
        """Move the selected field down in the list."""
        selected = self.fields_tree.selection()
        if not selected:
            return
            
        # Process items in reverse to prevent issues with multiple selections
        for item in reversed(selected):
            next_item = self.fields_tree.next(item)
            if next_item:
                # Get positions
                item_idx = self.fields_tree.index(item)
                next_idx = self.fields_tree.index(next_item)
                
                # Store values
                item_values = self.fields_tree.item(item, "values")
                next_values = self.fields_tree.item(next_item, "values")
                
                # Swap values
                self.fields_tree.item(item, values=next_values)
                self.fields_tree.item(next_item, values=item_values)
                
                # Keep selection on moved item
                self.fields_tree.selection_set(next_item)
                self.fields_tree.focus(next_item)
                                            
    ## File and Directory Handling Methods
    def browse_config(self):
        """Open a file dialog to select a configuration file."""
        filename = self.open_file_dialog("Select Configuration File", [("JSON files", "*.json"), ("All files", "*.*")])
        if filename:
            self.config_path.set(filename)

    def browse_input(self) -> None:
        """Open a file/directory dialog to select input file(s)."""
        if self.batch_var.get():  # Batch mode
            dirname = filedialog.askdirectory(title="Select Input Directory")
            if dirname:
                self.input_path.set(dirname)
                self.log_action(f"Selected input directory: {dirname}")
                # Validate the directory contains acceptable files
                self._validate_input_directory(dirname)
        else:  # Single file mode
            filename = filedialog.askopenfilename(
                title="Select Legal Text File",
                filetypes=[("Text files", "*.txt"), ("PDF files", "*.pdf"), ("All files", "*.*")]
            )
            if filename:
                self.input_path.set(filename)
                self.log_action(f"Selected input file: {filename}")
                # Validate the file exists and is readable
                self._validate_input_file(filename)

    def _validate_input_file(self, filepath: str) -> bool:
        return self.file_validator.is_valid_file_path(filepath)

    def _validate_input_directory(self, dirpath: str) -> bool:
        return self.file_validator.is_valid_directory_path(dirpath)
        
    def browse_output(self):
        """Open a file/directory dialog to select output location."""
        if self.batch_var.get():  # Batch mode
            dirname = filedialog.askdirectory(title="Select Output Directory")
            if dirname:
                self.output_path.set(dirname)
                self.log_action(f"Selected output directory: {dirname}")
        else:
            filename = self.save_file_dialog("Save Output As", ".json", [("JSON files", "*.json"), ("All files", "*.*")])
            if filename:
                self.output_path.set(filename)

    # Main Extraction and Batch Processing Logic
    def start_extraction(self) -> None:
        """Start the extraction process based on the current mode (single or batch)."""
        # Validate inputs
        if not self.validate_inputs():
            return

        if self.batch_var.get():
            self.batch_process()  # Call batch process if in batch mode
        else:
            # Single file extraction
            self.processing = True
            self.cancel_event.clear()  # Reset cancel flag
            self.progress.start(10)
            self.update_status("Processing...")
            threading.Thread(target=self.run_extraction, daemon=True).start()

    def validate_inputs(self) -> bool:
        """Validate all required inputs before processing.
        
        Returns:
            bool: True if all inputs are valid, False otherwise
        """
        # Check configuration file
        if not self.config_path.get():
            messagebox.showerror("Error", "Please select a configuration file.")
            return False
            
        if not os.path.isfile(self.config_path.get()):
            messagebox.showerror("Error", f"Configuration file does not exist: {self.config_path.get()}")
            return False
            
        # Check input path
        if not self.input_path.get():
            messagebox.showerror("Error", "Please select an input file or directory.")
            return False
            
        if self.batch_var.get():
            if not os.path.isdir(self.input_path.get()):
                messagebox.showerror("Error", f"Input directory does not exist: {self.input_path.get()}")
                return False
        else:
            if not os.path.isfile(self.input_path.get()):
                messagebox.showerror("Error", f"Input file does not exist: {self.input_path.get()}")
                return False
                
        # Check output path
        if not self.output_path.get():
            messagebox.showerror("Error", "Please select an output location.")
            return False
            
        if self.batch_var.get():
            if not os.path.isdir(self.output_path.get()) and not os.access(os.path.dirname(self.output_path.get()), os.W_OK):
                messagebox.showerror("Error", "Cannot write to output directory.")
                return False
        else:
            output_dir = os.path.dirname(self.output_path.get())
            if output_dir and not os.access(output_dir, os.W_OK):
                messagebox.showerror("Error", "Cannot write to output location.")
                return False

        # Check API key
        if not self.api_key.get():
            messagebox.showerror("Error", "Please enter an API key.")
            return False

        # Check model selection
        if not self.model_name.get():
            messagebox.showerror("Error", "Please select an AI model.")
            return False
            
        return True

    def run_extraction(self) -> None:
        """Run the extraction process for a single file."""
        try:
            # Setup logging
            setup_logging(self.verbose_var.get())
            self.log_action("Starting extraction process")

            # Load configuration
            self.update_status("Loading configuration...")
            config = load_configuration(self.config_path.get())
            self.log_action(f"Configuration loaded from {self.config_path.get()}")

            # Read input file
            self.update_status("Reading input file...")
            legal_text = read_file(self.input_path.get())
            self.log_action(f"Read file {self.input_path.get()}")

            # Generate prompt
            self.update_status("Generating AI prompt...")
            prompt = generate_prompt(config, legal_text)
            self.log_action("Prompt generated successfully")

            # Check for cancellation
            if self.cancel_event.is_set():
                self.update_status("Extraction cancelled")
                return

            # Call AI model with retry
            self.update_status("Calling AI model...")
            @retry_with_backoff(max_retries=3, initial_backoff=2, backoff_factor=2)
            def call_ai_with_retry(*args, **kwargs):
                return call_ai_model(*args, **kwargs)

            ai_response = call_ai_with_retry(prompt, self.api_key.get(), self.model_name.get(), temperature=0.7)
            self.log_action("Received response from AI model")


            # Check for cancellation
            if self.cancel_event.is_set():
                self.update_status("Extraction cancelled")
                return

            # Validate response
            self.update_status("Validating response...")
            structured_data = validate_response(ai_response, config)
            self.log_action("Response validated successfully")

            # Save output
            self.update_status("Saving output...")
            save_json_file(structured_data, self.output_path.get())
            self.log_action(f"Output saved to {self.output_path.get()}")

            # Display results
            self.after(0, lambda: self.display_results(structured_data))

            self.update_status("Extraction completed successfully!")
            self.after(0, lambda: messagebox.showinfo("Success", "Legal data extraction completed successfully!"))

        except (google.generativeai.GenerativeAIError, openai.OpenAIError) as e:
            error_msg = f"AI Model Error: {str(e)}"
            self.log_action(error_msg, level=logging.ERROR)
            self.update_status(f"AI Model Error: {str(e)}")
            self.after(0, lambda: messagebox.showerror("AI Model Error", error_msg))
        except json.JSONDecodeError as e:
            error_msg = f"Invalid JSON response from AI model: {str(e)}"
            self.log_action(error_msg, level=logging.ERROR)
            self.update_status(error_msg)
            self.after(0, lambda: messagebox.showerror("JSON Error", error_msg))
        except IOError as e:
            error_msg = f"IO Error: {str(e)}"
            self.log_action(error_msg, level=logging.ERROR)
            self.update_status(error_msg)
            self.after(0, lambda: messagebox.showerror("IO Error", error_msg))
        except Exception as e:
            error_msg = f"An unexpected error occurred: {str(e)}"
            self.log_action(error_msg, level=logging.ERROR)
            self.update_status(f"Error: {str(e)}")
            self.after(0, lambda: messagebox.showerror("Error", error_msg))
        finally:
            # Stop progress indicator
            self.after(0, self.progress.stop)
            self.processing = False

    def cancel_extraction(self) -> None:
        """Cancel the current extraction process."""
        if self.processing:
            self.cancel_event.set()  # Signal threads to stop
            self.update_status("Cancelling operation...")
            self.log_action("User requested cancellation of extraction process")
            
            # If batch processor exists and is running
            if self.batch_processor and hasattr(self.batch_processor, 'cancel'):
                self.batch_processor.cancel()

    def clear_fields(self) -> None:
        """Clear all input fields."""
        if messagebox.askyesno("Confirm", "Clear all fields?"):
            self.config_path.set("")
            self.input_path.set("")
            self.output_path.set("")
            self.log_action("All fields cleared")

    def refresh_models(self) -> None:
        """Refresh the available AI models based on the current API key."""
        if not self.api_key.get():
            messagebox.showinfo("API Key Required", "Please enter an API key to refresh models.")
            return
            
        self.update_status("Refreshing available models...")
        
        def refresh_task():
            try:
                models = get_available_models(self.api_key.get())
                model_names = []
                for provider, model_list in models.items():
                    model_names.extend(model_list)  # Flatten the list
                    
                # Update UI in main thread
                self.after(0, lambda: self._update_models_list(model_names))
                
            except Exception as e:
                error_msg = f"Error refreshing models: {str(e)}"
                self.log_action(error_msg, level=logging.ERROR)
                self.after(0, lambda: messagebox.showerror("Error", error_msg))
                self.after(0, lambda: self.update_status("Failed to refresh models"))
                
        # Run in background thread
        threading.Thread(target=refresh_task, daemon=True).start()
        
    def _update_models_list(self, model_names: List[str]) -> None:
        """Update the model dropdown with available models.
        
        Args:
            model_names: List of model names to display
        """
        self.model_combobox["values"] = model_names
        if model_names:
            # Keep current selection if it's in the list
            if self.model_name.get() in model_names:
                pass
            else:
                self.model_name.set(model_names[0])  # Default to the first
        self.update_status("Models refreshed")

    def toggle_batch_mode(self) -> None:
        """Toggle between single file and batch processing modes."""
        if self.batch_var.get():
            self.input_label.config(text="Input Directory:")
            self.output_label.config(text="Output Directory:")
            self.input_path.set("")  # Clear previous value
            self.output_path.set("")
            self.log_action("Switched to batch processing mode")
        else:
            self.input_label.config(text="Input Legal Text:")
            self.output_label.config(text="Output JSON File:")
            self.input_path.set("input.txt")  # Reset to default
            self.output_path.set("output.json")
            self.log_action("Switched to single file processing mode")

    def update_status(self, message: str) -> None:
        """Update the status bar message.
        
        Args:
            message: The message to display
        """
        # Always use after() to ensure we're updating from the main thread
        self.after(0, lambda: self._update_status_text(message))
        
    def _update_status_text(self, message: str) -> None:
        """Internal method to update status text from main thread.
        
        Args:
            message: The message to display
        """
        self.status_text.set(message)
        self.update_idletasks()  # Force UI update
        self.log_action(message, level=logging.INFO)

    def display_results(self, data: Dict[str, Any]) -> None:
        """Display the extracted data in the results viewer.
        
        Args:
            data: The structured data to display
        """
        # Clear previous content
        self.results_text.delete("1.0", tk.END)
        # Insert formatted JSON
        self.results_text.insert("1.0", json.dumps(data, indent=4))
        self.results_text.see("1.0")  # Scroll to the top

    def save_settings(self) -> None:
        """Save the current application settings to a file."""
        settings = {
            "api_key": SecureStorage.encrypt(self.api_key.get()),
            "config_path": self.config_path.get(),
            "input_path": self.input_path.get(),
            "output_path": self.output_path.get(),
            "model_name": self.model_name.get(),
            "verbose": self.verbose_var.get(),
            "batch_mode": self.batch_var.get()
        }
        
        # Get user settings directory
        settings_dir = self._get_settings_dir()
        settings_file = os.path.join(settings_dir, "settings.json")
        
        try:
            # Ensure directory exists
            os.makedirs(settings_dir, exist_ok=True)
            
            with open(settings_file, "w") as f:
                json.dump(settings, f, indent=4)
            self.log_action("Settings saved successfully")
            messagebox.showinfo("Settings", "Settings saved successfully.")
        except Exception as e:
            error_msg = f"Failed to save settings: {str(e)}"
            self.log_action(error_msg, level=logging.ERROR)
            messagebox.showerror("Error", error_msg)

    def load_settings(self) -> None:
        """Load application settings from a file."""
        settings_file = os.path.join(self._get_settings_dir(), "settings.json")
        try:
            with open(settings_file, "r") as f:
                settings = json.load(f)

                # Decrypt the API key using SecureStorage from utils.py
                try:
                    encrypted_key = settings.get("api_key", "")
                    if encrypted_key:
                        api_key = SecureStorage.decrypt(encrypted_key)
                        self.api_key.set(api_key)
                    else:
                        self.api_key.set("")  # Set to empty string if no key
                except Exception as e:
                    logging.warning(f"Failed to decrypt API key: {e}")
                    messagebox.showwarning("Warning", "Failed to decrypt API key.  Using empty key.")
                    self.api_key.set("")


                # Load other settings with default values if they don't exist.
                self.config_path.set(settings.get("config_path", APP_DEFAULTS["config_path"]))
                self.input_path.set(settings.get("input_path", APP_DEFAULTS["input_path"]))
                self.output_path.set(settings.get("output_path", APP_DEFAULTS["output_path"]))
                self.model_name.set(settings.get("model_name", APP_DEFAULTS["model_name"]))
                self.verbose_var.set(settings.get("verbose", APP_DEFAULTS["verbose"]))
                self.batch_var.set(settings.get("batch_mode", APP_DEFAULTS["batch_mode"]))

                self.toggle_batch_mode()  # Update UI for batch mode
                self.log_action("Settings loaded successfully")
                
                # Only refresh models if API key is available to avoid unnecessary calls
                if self.api_key.get():
                    self.refresh_models()


        except FileNotFoundError:
            logging.info("No settings file found, using defaults.")
            # Only refresh models if an API key is already set (avoid unnecessary calls)
            if self.api_key.get():
                self.refresh_models()
        except json.JSONDecodeError as e:
            logging.error(f"Error decoding settings JSON: {e}")
            messagebox.showerror("Error", f"Corrupted settings file: {e}")
        except Exception as e:
            logging.exception(f"Unexpected error loading settings: {e}")  # Log the full traceback
            messagebox.showerror("Error", f"Failed to load settings: {e}")



    def _get_settings_dir(self) -> str:
        """Get the directory to store settings.
        
        Returns:
            str: Path to the settings directory
        """
        # Use platform-specific location for user settings
        if os.name == 'nt':  # Windows
            app_data = os.getenv('APPDATA')
            if app_data:
                return os.path.join(app_data, "LegalDataExtractor")
        else:  # Unix/Linux/Mac
            home = os.path.expanduser("~")
            if home:
                return os.path.join(home, ".legaldataextractor")
                
        # Fallback to current directory
        return os.path.abspath(".")

    def set_api_key(self) -> None:
        """Prompt user to enter an API key."""
        api_key = simpledialog.askstring("API Key", "Enter your API Key:", show="*", parent=self)
        if api_key is not None:  # User didn't cancel
            self.api_key.set(api_key)
            self.log_action("API key updated")

    def batch_process(self):
        input_dir = self.input_path.get()
        output_dir = self.output_path.get()
        config_path = self.config_path.get()

        if not input_dir or not output_dir or not config_path:
            messagebox.showerror("Error", "Please select input and output directories, and a configuration file.")
            return
        
        if not os.path.isdir(input_dir):
            messagebox.showerror("Error", "Invalid Input Directory.")
            return  # Added return statement
            
        if not os.path.isdir(output_dir):
            messagebox.showerror("Error", "Invalid Output Directory")
            return  # Added return statement
            
        # Start the batch processing in a separate thread
        self.batch_thread = threading.Thread(
            target=self._run_batch_process, 
            args=(input_dir, output_dir, config_path), 
            daemon=True
        )
        self.batch_thread.start()

    def _run_batch_process(self, input_dir: str, output_dir: str, config_path: str) -> None:
        """Run the batch processing of files in a separate thread.
        
        Args:
            input_dir: Directory containing input files
            output_dir: Directory for output files
            config_path: Path to configuration file
        """
        try:
            self.progress.start(10)
            self.update_status("Starting batch processing...")
            self.log_action(f"Starting batch processing from {input_dir} to {output_dir}")

            # Create BatchProcessor instance
            self.batch_processor = BatchProcessor(config_path, self.api_key.get(), self.model_name.get())
            self.batch_processor.set_progress_callback(self.update_batch_progress)
            self.batch_processor.set_cancel_event(self.cancel_event)  # Pass cancel event
            
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)
            
            summary = self.batch_processor.process_directory(input_dir, output_dir)

            if self.cancel_event.is_set():
                self.log_action("Batch processing was cancelled")
                self.update_status(f"Batch processing cancelled: {summary['success']} completed, {summary['failed']} failed, {summary['skipped']} skipped.")
                self.after(0, lambda: messagebox.showinfo("Batch Processing", 
                    f"Batch processing cancelled.\n\nCompleted: {summary['success']}\nFailed: {summary['failed']}\nSkipped: {summary['skipped']}\nTotal: {summary['total']}"))
            else:
                self.log_action(f"Batch processing complete: {summary['success']} successful, {summary['failed']} failed")
                self.update_status(f"Batch processing complete: {summary['success']} successful, {summary['failed']} failed.")
                self.after(0, lambda: messagebox.showinfo("Batch Processing",
                    f"Batch processing complete!\n\nSuccessful: {summary['success']}\nFailed: {summary['failed']}\nTotal: {summary['total']}"))
        except Exception as e:
            error_msg = f"Batch processing error: {str(e)}"
            self.log_action(error_msg, level=logging.ERROR)
            self.update_status(error_msg)
            self.after(0, lambda: messagebox.showerror("Error", error_msg))
        finally:
            self.after(0, self.progress.stop)
            self.processing = False
            self.batch_processor = None

    def update_batch_progress(self, current: int, total: int) -> None:
        """Callback function to update the progress bar during batch processing.
        
        Args:
            current: Current number of processed files
            total: Total number of files to process
        """
        if total <= 0:
            progress_percent = 0
        else:
            progress_percent = (current / total) * 100
            
        # Update UI in main thread
        self.after(0, lambda: self._update_progress_ui(progress_percent, current, total))
        
    def _update_progress_ui(self, progress_percent: float, current: int, total: int) -> None:
        """Update progress UI components from main thread.
        
        Args:
            progress_percent: Percentage of completion
            current: Current number of processed files
            total: Total number of files to process
        """
        self.progress["mode"] = "determinate"  # Switch to determinate mode
        self.progress["value"] = progress_percent
        self.update_status(f"Batch Processing: {current}/{total} files processed")

    def model_settings(self) -> None:
        """Configure model-specific settings."""
        # Create a new dialog window for model settings
        settings_window = tk.Toplevel(self)
        settings_window.title(f"Settings for {self.model_name.get()}")
        settings_window.geometry("400x300")
        settings_window.grab_set()  # Make the window modal
        
        # Add settings based on the selected model
        ttk.Label(settings_window, text=f"Settings for {self.model_name.get()}").pack(pady=10)
        
        # Example settings (customize based on model)
        frame = ttk.Frame(settings_window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Temperature setting
        ttk.Label(frame, text="Temperature:").grid(row=0, column=0, sticky=tk.W, pady=5)
        temp_var = tk.DoubleVar(value=0.7)

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
            def __init__(self, text_widget, root):
                super().__init__()
                self.text_widget = text_widget
                self.root = root  # Store root widget for thread-safe updates

            def emit(self, record):
                msg = self.format(record)
                # Schedule UI update on main thread
                self.root.after(0, self._update_log_widget, msg)
                
            def _update_log_widget(self, msg):
                """Updates the log widget from the main thread"""
                self.text_widget.config(state='normal')
                self.text_widget.insert(tk.END, msg + "\n")
                self.text_widget.config(state='disabled')
                self.text_widget.see(tk.END)  # Auto-scroll to the end

        log_handler = LogHandler(self.log_text, self)
        log_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        logging.getLogger().addHandler(log_handler)
        logging.getLogger().setLevel(logging.INFO) # Set the root logger level

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
        
        thread = threading.Thread(target=background_task, daemon=True)
        self.active_threads.append(thread)
        thread.start()

    def show_error(self, message):
        """Shows an error message in a thread-safe manner."""
        messagebox.showerror("Error", message)
        self.update_status(f"Error: {message}")

if __name__ == "__main__":
    app = LegalDataExtractorApp()

    # Add a style for the "Extract" button
    style = ttk.Style()
    style.configure('Accent.TButton', font=('Arial', 12, 'bold'))

    app.mainloop()