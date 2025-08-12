# app/components/cracking/results_management_component.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QFileDialog)
from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QFont
import json
import csv

class ResultsManagementComponent(QWidget):
    def __init__(self):
        super().__init__()
        self.cracked_results = []
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        
        header = QLabel("Results Management")
        header.setFont(QFont("Arial", 12, QFont.Weight.Bold))
        layout.addWidget(header)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(4)
        self.results_table.setHorizontalHeaderLabels(["Hash", "Password", "Type", "Time"])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.results_table.setMaximumHeight(120)
        layout.addWidget(self.results_table)
        
        # Sample data
        self.add_sample_results()
        
        # Export controls
        export_layout = QHBoxLayout()
        self.export_csv_btn = QPushButton("Export CSV")
        self.export_csv_btn.clicked.connect(self.export_csv)
        self.export_json_btn = QPushButton("Export JSON")
        self.export_json_btn.clicked.connect(self.export_json)
        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        
        export_layout.addWidget(self.export_csv_btn)
        export_layout.addWidget(self.export_json_btn)
        export_layout.addWidget(self.clear_btn)
        layout.addLayout(export_layout)
        
        # Statistics
        stats_layout = QHBoxLayout()
        stats_layout.addWidget(QLabel("Total Results:"))
        self.total_results_label = QLabel("0")
        stats_layout.addWidget(self.total_results_label)
        stats_layout.addWidget(QLabel("Success Rate:"))
        self.success_rate_label = QLabel("0%")
        stats_layout.addWidget(self.success_rate_label)
        layout.addLayout(stats_layout)
        
        self.update_statistics()

    def add_sample_results(self):
        sample_results = [
            ("5d41402abc4b2a76b9719d911017c592", "hello", "MD5", "2023-12-01 10:30:15"),
            ("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", "hello", "SHA1", "2023-12-01 10:30:20"),
            ("e3b0c44298fc1c149afbf4c8996fb924", "password123", "SHA256", "2023-12-01 10:31:05")
        ]
        
        for hash_val, password, hash_type, time_cracked in sample_results:
            self.add_result(hash_val, password, hash_type, time_cracked)

    def add_result(self, hash_val, password, hash_type, time_cracked):
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Truncate hash for display
        display_hash = hash_val[:16] + "..." if len(hash_val) > 16 else hash_val
        
        self.results_table.setItem(row, 0, QTableWidgetItem(display_hash))
        self.results_table.setItem(row, 1, QTableWidgetItem(password))
        self.results_table.setItem(row, 2, QTableWidgetItem(hash_type))
        self.results_table.setItem(row, 3, QTableWidgetItem(time_cracked))
        
        # Store full result
        self.cracked_results.append({
            'hash': hash_val,
            'password': password,
            'type': hash_type,
            'time': time_cracked
        })
        
        self.update_statistics()

    def export_csv(self):
        if not self.cracked_results:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "cracked_passwords.csv", "CSV Files (*.csv)")
        if file_path:
            try:
                with open(file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Hash', 'Password', 'Type', 'Time'])
                    for result in self.cracked_results:
                        writer.writerow([result['hash'], result['password'], result['type'], result['time']])
            except Exception as e:
                print(f"Export error: {e}")

    def export_json(self):
        if not self.cracked_results:
            return
        
        file_path, _ = QFileDialog.getSaveFileName(self, "Export JSON", "cracked_passwords.json", "JSON Files (*.json)")
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    json.dump(self.cracked_results, f, indent=2)
            except Exception as e:
                print(f"Export error: {e}")

    def clear_results(self):
        self.results_table.setRowCount(0)
        self.cracked_results.clear()
        self.update_statistics()

    def update_statistics(self):
        total = len(self.cracked_results)
        self.total_results_label.setText(str(total))
        
        # Calculate success rate (assuming some failed attempts)
        if total > 0:
            success_rate = min(100, (total * 100) // (total + 5))  # Simulate some failures
            self.success_rate_label.setText(f"{success_rate}%")
        else:
            self.success_rate_label.setText("0%")