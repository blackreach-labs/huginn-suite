# app/pages/ui_components/export_controls.py
from PyQt6.QtWidgets import (QWidget, QHBoxLayout, QLabel, QComboBox, 
                             QPushButton, QFileDialog, QMessageBox)
from PyQt6.QtCore import pyqtSignal, Qt
import os
import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime

class ExportControls(QWidget):
    """Reusable export controls component with format selection and export functionality."""
    
    # Signals
    export_requested = pyqtSignal(str, str)  # format, filepath
    export_completed = pyqtSignal(str)  # filepath
    export_failed = pyqtSignal(str)  # error message
    
    def __init__(self, formats=None, parent=None):
        super().__init__(parent)
        self.formats = formats or ["JSON", "CSV", "XML", "HTML", "TXT"]
        self.results_data = {}
        self.scan_type = "scan"
        self.target = "target"
        self.setup_ui()
        self.apply_styles()
    
    def setup_ui(self):
        """Setup the export controls UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)
        layout.setSpacing(10)
        
        # Format selection
        format_label = QLabel("Export:")
        layout.addWidget(format_label)
        
        self.format_combo = QComboBox()
        self.format_combo.addItems(self.formats)
        self.format_combo.setFixedWidth(100)
        layout.addWidget(self.format_combo)
        
        # Export button
        self.export_button = QPushButton("Export")
        self.export_button.setFixedWidth(80)
        self.export_button.setEnabled(False)
        self.export_button.clicked.connect(self.export_results)
        layout.addWidget(self.export_button)
        
        layout.addStretch()
    
    def apply_styles(self):
        """Apply component styles."""
        self.setStyleSheet("""
            QLabel {
                color: #DCDCDC;
                font-weight: bold;
                background: transparent;
            }
            QComboBox {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 4px;
                color: #DCDCDC;
                padding: 5px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #DCDCDC;
            }
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                border: 1px solid #64C8FF;
                border-radius: 4px;
                color: #000000;
                font-weight: bold;
                padding: 5px;
            }
            QPushButton:hover {
                background-color: rgba(120, 220, 255, 180);
            }
            QPushButton:pressed {
                background-color: rgba(80, 180, 255, 200);
            }
            QPushButton:disabled {
                background-color: rgba(60, 60, 60, 100);
                border: 1px solid rgba(100, 100, 100, 100);
                color: #888888;
            }
        """)
    
    def set_results_data(self, data, scan_type="scan", target="target"):
        """Set the results data to export."""
        self.results_data = data
        self.scan_type = scan_type
        self.target = target
        self.export_button.setEnabled(bool(data))
    
    def export_results(self):
        """Export results in selected format."""
        if not self.results_data:
            self.export_failed.emit("No data to export")
            return
        
        format_type = self.format_combo.currentText().lower()
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.scan_type}_{self.target}_{timestamp}.{format_type}"
        
        # Get save location
        filepath, _ = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            filename,
            f"{format_type.upper()} Files (*.{format_type});;All Files (*)"
        )
        
        if not filepath:
            return
        
        try:
            success = self.write_export_file(filepath, format_type)
            if success:
                self.export_completed.emit(filepath)
            else:
                self.export_failed.emit(f"Failed to export in {format_type} format")
        except Exception as e:
            self.export_failed.emit(f"Export error: {str(e)}")
    
    def write_export_file(self, filepath, format_type):
        """Write export file in specified format."""
        try:
            if format_type == "json":
                return self.export_json(filepath)
            elif format_type == "csv":
                return self.export_csv(filepath)
            elif format_type == "xml":
                return self.export_xml(filepath)
            elif format_type == "html":
                return self.export_html(filepath)
            elif format_type == "txt":
                return self.export_txt(filepath)
            else:
                return False
        except Exception:
            return False
    
    def export_json(self, filepath):
        """Export results as JSON."""
        export_data = {
            "scan_type": self.scan_type,
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "results": self.results_data
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
        
        return True
    
    def export_csv(self, filepath):
        """Export results as CSV."""
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(["Scan Type", "Target", "Timestamp"])
            writer.writerow([self.scan_type, self.target, datetime.now().isoformat()])
            writer.writerow([])  # Empty row
            
            # Write results
            if isinstance(self.results_data, dict):
                writer.writerow(["Key", "Value", "Type"])
                for key, value in self.results_data.items():
                    value_type = type(value).__name__
                    if isinstance(value, (list, dict)):
                        value_str = json.dumps(value, default=str)
                    else:
                        value_str = str(value)
                    writer.writerow([key, value_str, value_type])
            else:
                writer.writerow(["Results"])
                writer.writerow([str(self.results_data)])
        
        return True
    
    def export_xml(self, filepath):
        """Export results as XML."""
        root = ET.Element("scan_results")
        
        # Add metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "scan_type").text = self.scan_type
        ET.SubElement(metadata, "target").text = self.target
        ET.SubElement(metadata, "timestamp").text = datetime.now().isoformat()
        
        # Add results
        results_elem = ET.SubElement(root, "results")
        self.dict_to_xml(self.results_data, results_elem)
        
        # Write to file
        tree = ET.ElementTree(root)
        tree.write(filepath, encoding='utf-8', xml_declaration=True)
        
        return True
    
    def dict_to_xml(self, data, parent):
        """Convert dictionary to XML elements."""
        if isinstance(data, dict):
            for key, value in data.items():
                # Sanitize key for XML
                clean_key = str(key).replace(' ', '_').replace('-', '_')
                elem = ET.SubElement(parent, clean_key)
                
                if isinstance(value, (dict, list)):
                    self.dict_to_xml(value, elem)
                else:
                    elem.text = str(value)
        elif isinstance(data, list):
            for i, item in enumerate(data):
                elem = ET.SubElement(parent, f"item_{i}")
                if isinstance(item, (dict, list)):
                    self.dict_to_xml(item, elem)
                else:
                    elem.text = str(item)
        else:
            parent.text = str(data)
    
    def export_html(self, filepath):
        """Export results as HTML."""
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Scan Results - {self.scan_type}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 10px; border-radius: 5px; }}
                .results {{ margin-top: 20px; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .json-data {{ background-color: #f8f8f8; padding: 10px; border-radius: 5px; white-space: pre-wrap; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Scan Results</h1>
                <p><strong>Scan Type:</strong> {self.scan_type}</p>
                <p><strong>Target:</strong> {self.target}</p>
                <p><strong>Timestamp:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            </div>
            
            <div class="results">
                <h2>Results</h2>
                <div class="json-data">
                    {json.dumps(self.results_data, indent=2, default=str)}
                </div>
            </div>
        </body>
        </html>
        """
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return True
    
    def export_txt(self, filepath):
        """Export results as plain text."""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"Scan Results\n")
            f.write(f"============\n\n")
            f.write(f"Scan Type: {self.scan_type}\n")
            f.write(f"Target: {self.target}\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"Results:\n")
            f.write(f"--------\n")
            
            if isinstance(self.results_data, dict):
                for key, value in self.results_data.items():
                    f.write(f"{key}: {value}\n")
            else:
                f.write(str(self.results_data))
        
        return True
    
    def get_selected_format(self):
        """Get the currently selected export format."""
        return self.format_combo.currentText().lower()
    
    def set_enabled(self, enabled):
        """Enable or disable export functionality."""
        self.export_button.setEnabled(enabled and bool(self.results_data))