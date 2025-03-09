# config_editor.py
"""
Module for creating and editing extraction configurations.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import json
from config_handler import ConfigHandler
from file_validator import FileValidator

class ConfigEditor:
    def __init__(self, parent, config_handler, apply_callback=None):
        self.parent = parent
        self.config_handler = config_handler
        self.apply_callback = apply_callback
        self.file_validator = FileValidator(['.json'])
        self.selected_field_frame = None  # Keep track of the selected frame

        self.config_window = tk.Toplevel(self.parent)
        self.config_window.title("Configuration Editor")
        self.config_window.geometry("500x400")
        self.config_window.transient(self.parent)
        self.config_window.grab_set()

        self.create_widgets()
        self.config_window.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_widgets(self):
        # --- Input File Path ---
        self.input_file_label = ttk.Label(self.config_window, text="Input File:")
        self.input_file_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.input_file_path = tk.StringVar()
        self.input_file_entry = ttk.Entry(self.config_window, textvariable=self.input_file_path, width=40)
        self.input_file_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        self.input_file_button = ttk.Button(self.config_window, text="Browse", command=self.browse_input_file)
        self.input_file_button.grid(row=0, column=2, padx=5, pady=5)

        # --- Output Directory ---
        self.output_dir_label = ttk.Label(self.config_window, text="Output Directory:")
        self.output_dir_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.output_dir = tk.StringVar()
        self.output_dir_entry = ttk.Entry(self.config_window, textvariable=self.output_dir, width=40)
        self.output_dir_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.output_dir_button = ttk.Button(self.config_window, text="Browse", command=self.browse_output_dir)
        self.output_dir_button.grid(row=1, column=2, padx=5, pady=5)

        # --- Fields Frame ---
        self.fields_frame = ttk.LabelFrame(self.config_window, text="Fields")
        self.fields_frame.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

        self.field_entries = []
        self.add_field_button = ttk.Button(self.fields_frame, text="Add Field", command=self.add_field)
        self.add_field_button.pack(pady=5)

        # --- Move Up/Down Buttons --- (Added back)
        self.move_up_button = ttk.Button(self.fields_frame, text="Move Up", command=self.move_field_up, state=tk.DISABLED)  # Initially disabled
        self.move_up_button.pack(pady=2, side=tk.LEFT, padx=2)

        self.move_down_button = ttk.Button(self.fields_frame, text="Move Down", command=self.move_field_down, state=tk.DISABLED)  # Initially disabled
        self.move_down_button.pack(pady=2, side=tk.LEFT, padx=2)


        # --- Buttons ---
        self.load_button = ttk.Button(self.config_window, text="Load Config", command=self.load_config)
        self.load_button.grid(row=3, column=0, padx=5, pady=5)

        self.save_button = ttk.Button(self.config_window, text="Save Config", command=self.save_config)
        self.save_button.grid(row=3, column=1, padx=5, pady=5)

        self.apply_button = ttk.Button(self.config_window, text="Apply", command=self.apply_config)
        self.apply_button.grid(row=3, column=2, padx=5, pady=5)

        # --- Configure grid weights ---
        self.config_window.columnconfigure(1, weight=1)
        self.config_window.rowconfigure(2, weight=1)
        self.fields_frame.columnconfigure(1, weight=1)

    def browse_input_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("PDF Files", "*.pdf")])
        if file_path:
            self.input_file_path.set(file_path)

    def browse_output_dir(self):
        dir_path = filedialog.askdirectory()
        if dir_path:
            self.output_dir.set(dir_path)
    
    def _highlight_field(self, field_frame):
        """Highlights the selected field and updates button states."""
        # Remove highlight from previously selected field
        if self.selected_field_frame:
            self.selected_field_frame.config(bg="SystemButtonFace")  # Reset to default background

        # Highlight the new selected field
        self.selected_field_frame = field_frame
        if self.selected_field_frame:
           self.selected_field_frame.config(bg="lightblue") # Highlight color

        self._update_move_buttons() # Update button states

    def _update_move_buttons(self):
        """Enables/disables Move Up/Down buttons based on selection."""
        if not self.selected_field_frame:
            self.move_up_button.config(state=tk.DISABLED)
            self.move_down_button.config(state=tk.DISABLED)
            return

        index = self.field_entries.index(self.selected_field_frame)

        if index > 0:
            self.move_up_button.config(state=tk.NORMAL)
        else:
            self.move_up_button.config(state=tk.DISABLED)

        if index < len(self.field_entries) - 1:
            self.move_down_button.config(state=tk.NORMAL)
        else:
            self.move_down_button.config(state=tk.DISABLED)


    def add_field(self, field_name="", field_description=""):
        field_frame = ttk.Frame(self.fields_frame)
        field_frame.pack(fill="x", expand=True, pady=2)

        name_label = ttk.Label(field_frame, text="Name:")
        name_label.pack(side="left", padx=5)
        name_entry = ttk.Entry(field_frame)
        name_entry.insert(0, field_name)
        name_entry.pack(side="left", fill="x", expand=True, padx=5)

        desc_label = ttk.Label(field_frame, text="Description:")
        desc_label.pack(side="left", padx=5)
        desc_entry = ttk.Entry(field_frame)
        desc_entry.insert(0, field_description)
        desc_entry.pack(side="left", fill="x", expand=True, padx=5)

        remove_button = ttk.Button(field_frame, text="Remove", command=lambda: self.remove_field(field_frame))
        remove_button.pack(side="left", padx=5)

        # Add highlight on click
        field_frame.bind("<Button-1>", lambda event, ff=field_frame: self._highlight_field(ff))
        name_entry.bind("<FocusIn>", lambda event, ff=field_frame: self._highlight_field(ff))
        desc_entry.bind("<FocusIn>", lambda event, ff=field_frame: self._highlight_field(ff))

        self.field_entries.append((field_frame, name_entry, desc_entry))
        self._highlight_field(field_frame) # Select the newly added field
        self._update_move_buttons()

    def remove_field(self, field_frame):
        for frame, _, _ in self.field_entries:
            if frame == field_frame:
                self.field_entries.remove((frame, _, _))
                frame.destroy()
                if self.selected_field_frame == field_frame:
                   self.selected_field_frame = None # Clear selection
                self._update_move_buttons()
                break


    def move_field_up(self):
        if not self.selected_field_frame:
            return

        index = self.field_entries.index(self.selected_field_frame)
        if index > 0:
            # Swap in the list
            self.field_entries[index], self.field_entries[index - 1] = self.field_entries[index - 1], self.field_entries[index]
            # Repack to change visual order
            self.field_entries[index][0].pack_forget()
            self.field_entries[index-1][0].pack_forget()

            self.field_entries[index-1][0].pack(fill="x", expand=True, pady=2)
            self.field_entries[index][0].pack(fill="x", expand=True, pady=2)

            self._update_move_buttons()

    def move_field_down(self):
        if not self.selected_field_frame:
            return

        index = self.field_entries.index(self.selected_field_frame)
        if index < len(self.field_entries) - 1:
            # Swap in the list
            self.field_entries[index], self.field_entries[index + 1] = self.field_entries[index + 1], self.field_entries[index]
            # Repack widgets.
            self.field_entries[index][0].pack_forget()
            self.field_entries[index + 1][0].pack_forget()

            self.field_entries[index + 1][0].pack(fill="x", expand=True, pady=2)
            self.field_entries[index][0].pack(fill="x", expand=True, pady=2)

            self._update_move_buttons()

    def load_config(self):
        file_path = filedialog.askopenfilename(filetypes=[("JSON Files", "*.json")])
        if file_path:
            if not self.file_validator.is_valid_file_path(file_path):
                return

            try:
                config = self.config_handler.load_config(file_path)
                self.populate_from_config(config)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load config: {e}")

    def save_config(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if file_path:
            try:
                config = self.get_current_config()
                self.config_handler.save_config(config, file_path)
                messagebox.showinfo("Info", "Configuration saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save config: {e}")

    def apply_config(self):
        if self.apply_callback:
            current_config = self.get_current_config()
            self.apply_callback(current_config)
            self.config_window.destroy()
        else:
            messagebox.showwarning("Warning", "No apply callback defined.")

    def get_current_config(self):
        """Gets the current configuration from the GUI elements."""
        config = {
            "input_file": self.input_file_path.get(),
            "output_dir": self.output_dir.get(),
            "fields": []
        }
        for _, name_entry, desc_entry in self.field_entries:
            field_name = name_entry.get().strip()
            field_desc = desc_entry.get().strip()
            if field_name:
                config["fields"].append({"field_name": field_name, "field_description": field_desc})
        return config

    def populate_from_config(self, config):
        """Populates the GUI elements from a configuration dictionary."""

        # Clear existing fields
        for frame, _, _ in self.field_entries:
            frame.destroy()
        self.field_entries.clear()
        self.selected_field_frame = None # Reset selection

        # Set input file and output directory
        self.input_file_path.set(config.get("input_file", ""))
        self.output_dir.set(config.get("output_dir", ""))

        # Add fields
        for field_data in config.get("fields", []):
            self.add_field(field_data.get("field_name", ""), field_data.get("field_description", ""))

        self._update_move_buttons() #Initialize button states

    def on_close(self):
        """Handles closing of configuration window"""
        self.config_window.destroy()