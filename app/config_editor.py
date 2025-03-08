# config_editor.py
"""
Module for creating and editing extraction configurations.
"""

import json
import os
import logging
from typing import Dict, List, Any
import tkinter as tk
from tkinter import ttk, filedialog, messagebox


class ConfigurationEditor:
    def __init__(self, parent=None):
        """
        Create a configuration editor widget or standalone window.

        Args:
            parent: Parent widget or None for standalone window.
        """
        self.is_standalone = parent is None

        if self.is_standalone:
            self.window = tk.Tk()
            self.window.title("Legal Data Extractor - Configuration Editor")
            self.window.geometry("800x600")
            parent = self.window

        self.parent = parent
        self.config_data = {"fields":[]}
        self.current_file = None

        self._create_widgets()

    def _create_widgets(self):
        """Create UI widgets"""
        # Main frame
        main_frame = ttk.Frame(self.parent, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Toolbar
        toolbar = ttk.Frame(main_frame)
        toolbar.pack(fill=tk.X, pady=5)

        ttk.Button(toolbar, text="New", command=self.new_config).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Open", command=self.open_config).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Save", command=self.save_config).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="Save As", command=self.save_config_as).pack(side=tk.LEFT, padx=2)

        # Split view with fields list on left, edit form on right
        paned = ttk.PanedWindow(main_frame, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, pady=5)

        # Left side: Fields list
        fields_frame = ttk.Frame(paned)
        paned.add(fields_frame, weight=1)

        # Fields label and actions
        fields_header = ttk.Frame(fields_frame)
        fields_header.pack(fill=tk.X)
        ttk.Label(fields_header, text="Fields:").pack(side=tk.LEFT)
        ttk.Button(fields_header, text="+", width=3,
                   command=self.add_new_field).pack(side=tk.RIGHT)

        # Fields treeview with scrollbar
        tree_frame = ttk.Frame(fields_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        self.fields_tree = ttk.Treeview(tree_frame, columns=("name", "type", "required"),
                                        show="headings", selectmode=tk.BROWSE)
        self.fields_tree.heading("name", text="Field Name")
        self.fields_tree.heading("type", text="Type")
        self.fields_tree.heading("required", text="Required")
        self.fields_tree.column("name", width=150)
        self.fields_tree.column("type", width=80)
        self.fields_tree.column("required", width=80)
        self.fields_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Field operations
        field_ops = ttk.Frame(fields_frame)
        field_ops.pack(fill=tk.X)
        ttk.Button(field_ops, text="Move Up", command=self.move_field_up).pack(side=tk.LEFT, padx=2)
        ttk.Button(field_ops, text="Move Down", command=self.move_field_down).pack(side=tk.LEFT, padx=2)
        ttk.Button(field_ops, text="Delete", command=self.delete_field).pack(side=tk.LEFT, padx=2)

        # Right side: Field editor
        edit_frame = ttk.LabelFrame(paned, text="Field Editor")
        paned.add(edit_frame, weight=1)

        # Name
        ttk.Label(edit_frame, text="Field Name:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.name_var = tk.StringVar()
        ttk.Entry(edit_frame, textvariable=self.name_var).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)

        # Type
        ttk.Label(edit_frame, text="Field Type:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.type_var = tk.StringVar(value="string")
        type_combo = ttk.Combobox(edit_frame, textvariable=self.type_var)
        type_combo["values"] = ["string", "list", "date", "number", "boolean", "object"]
        type_combo.grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)

        # Required
        self.required_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(edit_frame, text="Required Field",
                       variable=self.required_var).grid(row=2, column=0, columnspan=2,
                                                      sticky=tk.W, padx=5, pady=5)

        # Description
        ttk.Label(edit_frame, text="Description:").grid(row=3, column=0, sticky=tk.W, padx=5, pady=5)
        self.description_var = tk.StringVar()
        ttk.Entry(edit_frame, textvariable=self.description_var).grid(row=3, column=1, sticky=tk.EW, padx=5, pady=5)

        # Example
        ttk.Label(edit_frame, text="Example:").grid(row=4, column=0, sticky=tk.W, padx=5, pady=5)
        self.example_var = tk.StringVar()
        ttk.Entry(edit_frame, textvariable=self.example_var).grid(row=4, column=1, sticky=tk.EW, padx=5, pady=5)

        # Format (for dates, etc.)
        ttk.Label(edit_frame, text="Format:").grid(row=5, column=0, sticky=tk.W, padx=5, pady=5)
        self.format_var = tk.StringVar()
        ttk.Entry(edit_frame, textvariable=self.format_var).grid(row=5, column=1, sticky=tk.EW, padx=5, pady=5)

        # Update buttons
        btn_frame = ttk.Frame(edit_frame)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=10)
        ttk.Button(btn_frame, text="Apply Changes", command=self.apply_field_changes).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Reset", command=self.reset_field_form).pack(side=tk.LEFT, padx=5)

        # Config metadata frame (bottom)
        meta_frame = ttk.LabelFrame(main_frame, text="Configuration Metadata")
        meta_frame.pack(fill=tk.X, pady=10)

        # Title
        ttk.Label(meta_frame, text="Title:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.title_var = tk.StringVar(value="Legal Data Extraction Configuration")
        ttk.Entry(meta_frame, textvariable=self.title_var).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)

        # Description
        ttk.Label(meta_frame, text="Description:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.config_desc_var = tk.StringVar()
        ttk.Entry(meta_frame, textvariable=self.config_desc_var).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=5)

        # Version
        ttk.Label(meta_frame, text="Version:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=5)
        self.version_var = tk.StringVar(value="1.0")
        ttk.Entry(meta_frame, textvariable=self.version_var).grid(row=2, column=1, sticky=tk.EW, padx=5, pady=5)

        # Status bar
        self.status_var = tk.StringVar(value="New configuration")
        status = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status.pack(side=tk.BOTTOM, fill=tk.X)

        # Configure grid weights
        edit_frame.columnconfigure(1, weight=1)
        meta_frame.columnconfigure(1, weight=1)

        # Bind events
        self.fields_tree.bind("<<TreeviewSelect>>", self.on_field_select)

        # Initialize with empty config
        self.new_config()

    def run(self):
        """Run the standalone editor"""
        if self.is_standalone:
            self.window.mainloop()

    # Configuration operations
    def new_config(self):
        """Create a new configuration"""
        self.config_data = {
            "title": "Legal Data Extraction Configuration",
            "description": "",
            "version": "1.0",
            "fields":[]
        }
        self.current_file = None
        self.refresh_ui()
        self.status_var.set("New configuration created")

    def open_config(self):
        """Open a configuration file"""
        filename = filedialog.askopenfilename(
            title="Open Configuration",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not filename:
            return

        try:
            with open(filename, "r", encoding="utf-8") as f:
                self.config_data = json.load(f)

            # Ensure required structure
            if "fields" not in self.config_data or not isinstance(self.config_data["fields"], list):
                raise ValueError("Invalid configuration format: 'fields' key missing or not a list")

            self.current_file = filename
            self.refresh_ui()
            self.status_var.set(f"Loaded configuration from {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration: {e}")

    def save_config(self):
        """Save the current configuration"""
        if self.current_file:
            self._save_to_file(self.current_file)
        else:
            self.save_config_as()

    def save_config_as(self):
        """Save the configuration to a new file"""
        filename = filedialog.asksaveasfilename(
            title="Save Configuration As",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self._save_to_file(filename)
            self.current_file = filename

    def _save_to_file(self, filename):
        """Save configuration to the specified file"""
        # Update metadata from UI
        self.config_data["title"] = self.title_var.get()
        self.config_data["description"] = self.config_desc_var.get()
        self.config_data["version"] = self.version_var.get()

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.config_data, indent=4, fp=f)
            self.status_var.set(f"Saved configuration to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")

    # Field operations
    def add_new_field(self):
        """Add a new field to the configuration"""
        # Generate a unique field name
        base_name = "new_field"
        counter = 1
        name = base_name
        while any(field["name"] == name for field in self.config_data["fields"]):
            name = f"{base_name}_{counter}"
            counter += 1

        # Create the new field
        new_field = {
            "name": name,
            "type": "string",
            "required": True,
            "description": ""
        }

        self.config_data["fields"].append(new_field)
        self.refresh_fields_list()

        # Select the new field
        for item in self.fields_tree.get_children():
            if self.fields_tree.item(item, "values")[0] == name:
                self.fields_tree.selection_set(item)
                break

        self.status_var.set(f"Added new field '{name}'")

    def delete_field(self):
        """Delete the selected field"""
        selection = self.fields_tree.selection()
        if not selection:
            return

        item = selection[0]
        name = self.fields_tree.item(item, "values")[0]

        # Confirm deletion
        if not messagebox.askyesno("Confirm Delete", f"Delete field '{name}'?"):
            return

        # Remove from config
        self.config_data["fields"] = [
            field for field in self.config_data["fields"]
            if field["name"] != name
        ]

        self.refresh_fields_list()
        self.reset_field_form()
        self.status_var.set(f"Deleted field '{name}'")

    def move_field_up(self):
        """Move the selected field up in the list"""
        selection = self.fields_tree.selection()
        if not selection:
            return

        item = selection[0]
        idx = self.fields_tree.index(item)
        if idx == 0:  # Already at the top
            return

        name = self.fields_tree.item(item, "values")[0]

        # Find the field in the config
        fields = self.config_data["fields"]
        for i, field in enumerate(fields):
            if field["name"] == name:
                # Swap with previous
                fields[i], fields[i - 1] = fields[i - 1], fields[i]
                break

        self.refresh_fields_list()

        # Reselect the moved item
        items = self.fields_tree.get_children()
        self.fields_tree.selection_set(items[idx - 1])

    def move_field_down(self):
        """Move the selected field down in the list"""
        selection = self.fields_tree.selection()
        if not selection:
            return

        item = selection[0]
        idx = self.fields_tree.index(item)
        if idx >= len(self.fields_tree.get_children()) - 1:  # Already at the bottom
            return

        name = self.fields_tree.item(item, "values")[0]

        # Find the field in the config
        fields = self.config_data["fields"]
        for i, field in enumerate(fields):
            if field["name"] == name and i < len(fields) - 1:
                # Swap with next
                fields[i], fields[i + 1] = fields[i + 1], fields[i]
                break

        self.refresh_fields_list()

        # Reselect the moved item
        items = self.fields_tree.get_children()
        self.fields_tree.selection_set(items[idx + 1])

    def on_field_select(self, event=None):
        """Handle selection of a field in the treeview"""
        selection = self.fields_tree.selection()
        if selection:
            item = selection[0]
            values = self.fields_tree.item(item, "values")
            self.load_field_form(values)

    def load_field_form(self, values):
        """Load field data into the editor form"""
        name, type_str, required_str = values
        field_data = next((f for f in self.config_data["fields"] if f["name"] == name), None)
        if field_data:
            self.name_var.set(name)
            self.type_var.set(type_str)
            self.required_var.set(required_str.lower() == "true")
            self.description_var.set(field_data.get("description", ""))
            self.example_var.set(field_data.get("example", ""))
            self.format_var.set(field_data.get("format", ""))

    def apply_field_changes(self):
        """Apply changes from the editor form to the selected field"""
        selection = self.fields_tree.selection()
        if not selection:
            return

        item = selection[0]
        old_name = self.fields_tree.item(item, "values")[0]
        new_name = self.name_var.get()
        new_type = self.type_var.get()
        new_required = self.required_var.get()

        # Validate field name
        if not new_name:
            messagebox.showerror("Error", "Field name cannot be empty")
            return

        # Check for duplicate names (excluding the current field being edited)
        if any(f["name"] == new_name for f in self.config_data["fields"] if f["name"] != old_name):
            messagebox.showerror("Error", f"A field with the name '{new_name}' already exists")
            return

        # Update field in config data
        for field in self.config_data["fields"]:
            if field["name"] == old_name:
                field["name"] = new_name
                field["type"] = new_type
                field["required"] = new_required
                field["description"] = self.description_var.get()
                field["example"] = self.example_var.get()
                field["format"] = self.format_var.get()
                break

        self.refresh_fields_list()
        self.status_var.set(f"Updated field '{new_name}'")

    def reset_field_form(self):
        """Reset the editor form to default values"""
        self.name_var.set("")
        self.type_var.set("string")
        self.required_var.set(True)
        self.description_var.set("")
        self.example_var.set("")
        self.format_var.set("")

    # UI refresh methods
    def refresh_ui(self):
        """Refresh the entire UI with current config data"""
        self.refresh_fields_list()
        self.reset_field_form()
        self.update_metadata_fields()

    def refresh_fields_list(self):
        """Refresh the fields list in the treeview"""
        self.fields_tree.delete(*self.fields_tree.get_children())
        for field in self.config_data["fields"]:
            self.fields_tree.insert("", tk.END, values=(
                field["name"],
                field["type"],
                "True" if field["required"] else "False"
            ))

    def update_metadata_fields(self):
        """Update the metadata fields with values from config_data"""
        self.title_var.set(self.config_data.get("title", ""))
        self.config_desc_var.set(self.config_data.get("description", ""))
        self.version_var.set(self.config_data.get("version", ""))