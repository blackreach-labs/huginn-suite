from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QComboBox, QPushButton
from PyQt6.QtCore import pyqtSignal

class DNSResultsComponent(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_results = {}
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup results UI"""
        layout = QVBoxLayout(self)
        
        # Header with view options
        header_layout = QHBoxLayout()
        
        title = QLabel("DNS Results")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        # View mode selector
        view_label = QLabel("View:")
        header_layout.addWidget(view_label)
        
        self.view_combo = QComboBox()
        self.view_combo.addItems(["Text", "Table", "Tree"])
        self.view_combo.currentTextChanged.connect(self.change_view_mode)
        header_layout.addWidget(self.view_combo)
        
        # Export button
        self.export_button = QPushButton("Export")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        header_layout.addWidget(self.export_button)
        
        layout.addLayout(header_layout)
        
        # Results display
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setPlaceholderText("DNS enumeration results will appear here...")
        layout.addWidget(self.results_text)

    def clear_results(self):
        """Clear results display"""
        self.results_text.clear()
        self.scan_results = {}
        self.export_button.setEnabled(False)

    def append_output(self, text):
        """Append text to results"""
        # Format text for display
        if not text.startswith('<'):
            if '[ERROR]' in text:
                text = f"<p style='color: #FF6B6B;'>{text}</p>"
            elif '[SCAN]' in text:
                text = f"<p style='color: #00FF41;'>{text}</p>"
            elif '[INFO]' in text:
                text = f"<p style='color: #64C8FF;'>{text}</p>"
            else:
                text = f"<p style='color: #DCDCDC;'>{text}</p>"
        
        self.results_text.insertHtml(text)
        
        # Auto-scroll to bottom
        scrollbar = self.results_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_results(self, results):
        """Update results display with structured data"""
        self.scan_results = results
        self.export_button.setEnabled(bool(results))
        
        # Display results based on current view mode
        self.change_view_mode(self.view_combo.currentText())

    def change_view_mode(self, view_mode):
        """Change results view mode"""
        if not self.scan_results:
            return
        
        if view_mode == "Text":
            self.display_text_view()
        elif view_mode == "Table":
            self.display_table_view()
        elif view_mode == "Tree":
            self.display_tree_view()

    def display_text_view(self):
        """Display results in text format"""
        if not self.scan_results:
            return
        
        output = "<h3 style='color: #64C8FF;'>DNS Enumeration Results</h3>"
        
        for record_type, records in self.scan_results.items():
            if records:
                output += f"<h4 style='color: #FFD93D;'>{record_type} Records:</h4>"
                for record in records:
                    output += f"<p style='color: #DCDCDC;'>{record}</p>"
        
        self.results_text.setHtml(output)

    def display_table_view(self):
        """Display results in table format"""
        if not self.scan_results:
            return
        
        output = "<h3 style='color: #64C8FF;'>DNS Enumeration Results</h3>"
        output += "<table border='1' style='border-collapse: collapse; width: 100%;'>"
        output += "<tr style='background-color: rgba(100, 200, 255, 150);'>"
        output += "<th>Type</th><th>Name</th><th>Value</th></tr>"
        
        for record_type, records in self.scan_results.items():
            for record in records:
                parts = record.split(' -> ')
                name = parts[0] if len(parts) > 0 else record
                value = parts[1] if len(parts) > 1 else ''
                
                output += f"<tr style='color: #DCDCDC;'>"
                output += f"<td>{record_type}</td>"
                output += f"<td>{name}</td>"
                output += f"<td>{value}</td>"
                output += "</tr>"
        
        output += "</table>"
        self.results_text.setHtml(output)

    def display_tree_view(self):
        """Display results in tree format"""
        if not self.scan_results:
            return
        
        output = "<h3 style='color: #64C8FF;'>DNS Enumeration Results</h3>"
        
        for record_type, records in self.scan_results.items():
            if records:
                output += f"<p style='color: #FFD93D;'>├── {record_type} Records ({len(records)})</p>"
                for i, record in enumerate(records):
                    prefix = "└──" if i == len(records) - 1 else "├──"
                    output += f"<p style='color: #DCDCDC; margin-left: 20px;'>{prefix} {record}</p>"
        
        self.results_text.setHtml(output)

    def export_results(self):
        """Export DNS results"""
        if not self.scan_results:
            return
        
        from PyQt6.QtWidgets import QFileDialog
        import json
        
        filename, _ = QFileDialog.getSaveFileName(
            self, 
            "Export DNS Results", 
            "dns_results.json", 
            "JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(self.scan_results, f, indent=2)
                elif filename.endswith('.csv'):
                    import csv
                    with open(filename, 'w', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow(['Type', 'Record'])
                        for record_type, records in self.scan_results.items():
                            for record in records:
                                writer.writerow([record_type, record])
                
                self.append_output(f"[EXPORT] Results exported to {filename}")
            except Exception as e:
                self.append_output(f"[ERROR] Export failed: {e}")

    def apply_theme(self):
        """Apply component theme"""
        self.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 100);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 5px;
                color: #DCDCDC;
                font-family: 'Consolas', 'Monaco', monospace;
                padding: 10px;
            }
            QComboBox {
                background-color: rgba(20, 30, 40, 150);
                border: 1px solid rgba(100, 200, 255, 100);
                border-radius: 3px;
                color: #DCDCDC;
                padding: 5px;
            }
            QPushButton {
                background-color: rgba(30, 40, 50, 150);
                border: 2px solid rgba(100, 200, 255, 100);
                border-radius: 8px;
                color: #DCDCDC;
                font-weight: bold;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: rgba(50, 70, 90, 200);
                border: 2px solid #64C8FF;
            }
            QPushButton:disabled {
                background-color: rgba(100, 100, 100, 100);
                color: #666666;
            }
            QLabel {
                color: #64C8FF;
                font-weight: bold;
            }
        """)