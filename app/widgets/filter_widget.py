# app/widgets/filter_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QLineEdit, QTextEdit, QTableWidget, 
                            QTableWidgetItem, QGroupBox, QComboBox, QSpinBox,
                            QCheckBox, QTabWidget)
from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from app.core.result_filter import result_filter
import json

class FilterWidget(QWidget):
    """Widget for result filtering and search"""
    
    results_filtered = pyqtSignal(list)  # Signal when results are filtered
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_results = []
        self.filtered_results = []
        self.search_timer = QTimer()
        self.search_timer.setSingleShot(True)
        self.search_timer.timeout.connect(self.apply_filters)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Main group
        main_group = QGroupBox("🔍 Result Filtering & Search")
        main_group.setStyleSheet("""
            QGroupBox {
                font-weight: bold;
                color: #64C8FF;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px 0 5px;
            }
        """)
        
        main_layout = QVBoxLayout(main_group)
        
        # Search section
        search_layout = QHBoxLayout()
        search_layout.addWidget(QLabel("Search:"))
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search query...")
        self.search_input.textChanged.connect(self.on_search_changed)
        self.search_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
                font-size: 10pt;
            }
            QLineEdit:focus {
                border: 2px solid #64C8FF;
            }
        """)
        
        self.search_fields_combo = QComboBox()
        self.search_fields_combo.addItem("All Fields")
        self.search_fields_combo.setFixedWidth(120)
        
        self.clear_button = QPushButton("🗑️ Clear")
        self.clear_button.clicked.connect(self.clear_filters)
        
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(QLabel("in"))
        search_layout.addWidget(self.search_fields_combo)
        search_layout.addWidget(self.clear_button)
        
        # Filter controls
        filter_layout = QHBoxLayout()
        
        self.field_combo = QComboBox()
        self.field_combo.setFixedWidth(120)
        
        self.operator_combo = QComboBox()
        self.operator_combo.addItems(["contains", "equals", "starts_with", "ends_with", "regex"])
        self.operator_combo.setFixedWidth(100)
        
        self.value_input = QLineEdit()
        self.value_input.setPlaceholderText("Filter value...")
        self.value_input.setStyleSheet("""
            QLineEdit {
                background-color: rgba(20, 30, 40, 180);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                padding: 4px 8px;
                font-size: 10pt;
            }
        """)
        
        self.add_filter_button = QPushButton("➕ Add Filter")
        self.add_filter_button.clicked.connect(self.add_filter)
        
        button_style = """
            QPushButton {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                border: none;
                border-radius: 4px;
                padding: 6px 12px;
                font-size: 10pt;
            }
            QPushButton:hover {
                background-color: rgba(100, 200, 255, 200);
            }
        """
        
        self.add_filter_button.setStyleSheet(button_style)
        self.clear_button.setStyleSheet(button_style.replace("100, 200, 255", "255, 100, 100"))
        
        filter_layout.addWidget(QLabel("Field:"))
        filter_layout.addWidget(self.field_combo)
        filter_layout.addWidget(QLabel("Operator:"))
        filter_layout.addWidget(self.operator_combo)
        filter_layout.addWidget(QLabel("Value:"))
        filter_layout.addWidget(self.value_input)
        filter_layout.addWidget(self.add_filter_button)
        filter_layout.addStretch()
        
        # Active filters display
        self.active_filters_text = QTextEdit()
        self.active_filters_text.setFixedHeight(60)
        self.active_filters_text.setReadOnly(True)
        self.active_filters_text.setPlaceholderText("Active filters will appear here...")
        self.active_filters_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 9pt;
                padding: 5px;
            }
        """)
        
        # Results tabs
        self.results_tabs = QTabWidget()
        self.results_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #555;
                background-color: rgba(0, 0, 0, 100);
            }
            QTabBar::tab {
                background-color: rgba(50, 50, 50, 150);
                color: #DCDCDC;
                padding: 8px 12px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: rgba(100, 200, 255, 150);
                color: #000;
            }
        """)
        
        # Filtered results table
        self.results_table = QTableWidget()
        self.results_table.setStyleSheet("""
            QTableWidget {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                gridline-color: #555;
            }
            QHeaderView::section {
                background-color: rgba(100, 200, 255, 150);
                color: white;
                padding: 4px;
                border: none;
                font-weight: bold;
            }
        """)
        self.results_tabs.addTab(self.results_table, "📋 Filtered Results")
        
        # Statistics tab
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setStyleSheet("""
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 4px;
                color: #DCDCDC;
                font-size: 10pt;
                padding: 8px;
                font-family: 'Courier New', monospace;
            }
        """)
        self.results_tabs.addTab(self.stats_text, "📊 Statistics")
        
        # Status and controls
        status_layout = QHBoxLayout()
        
        self.status_label = QLabel("No results loaded")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        self.sort_combo = QComboBox()
        self.sort_combo.addItem("No Sorting")
        self.sort_combo.currentTextChanged.connect(self.apply_sorting)
        
        self.sort_desc_cb = QCheckBox("Descending")
        self.sort_desc_cb.toggled.connect(self.apply_sorting)
        self.sort_desc_cb.setStyleSheet("color: #DCDCDC;")
        
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        status_layout.addWidget(QLabel("Sort by:"))
        status_layout.addWidget(self.sort_combo)
        status_layout.addWidget(self.sort_desc_cb)
        
        # Add to main layout
        main_layout.addLayout(search_layout)
        main_layout.addLayout(filter_layout)
        main_layout.addWidget(QLabel("Active Filters:"))
        main_layout.addWidget(self.active_filters_text)
        main_layout.addWidget(self.results_tabs)
        main_layout.addLayout(status_layout)
        
        layout.addWidget(main_group)
        
        # Initialize
        self.active_filters = []
        
    def load_results(self, results: list):
        """Load results for filtering"""
        self.current_results = results if results else []
        self.filtered_results = self.current_results.copy()
        
        # Update field options
        self.update_field_options()
        
        # Display results
        self.display_results()
        
        # Update statistics
        self.update_statistics()
        
        self.status_label.setText(f"Loaded {len(self.current_results)} results")
        self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
    
    def update_field_options(self):
        """Update available fields for filtering"""
        if not self.current_results:
            return
        
        # Get all available fields
        all_fields = set()
        for result in self.current_results[:10]:  # Sample first 10 results
            if isinstance(result, dict):
                all_fields.update(result_filter._get_all_fields(result))
        
        # Update field combo
        current_field = self.field_combo.currentText()
        self.field_combo.clear()
        
        sorted_fields = sorted(list(all_fields))
        self.field_combo.addItems(sorted_fields)
        
        # Update search fields combo
        current_search_field = self.search_fields_combo.currentText()
        self.search_fields_combo.clear()
        self.search_fields_combo.addItem("All Fields")
        self.search_fields_combo.addItems(sorted_fields)
        
        # Update sort combo
        current_sort = self.sort_combo.currentText()
        self.sort_combo.clear()
        self.sort_combo.addItem("No Sorting")
        self.sort_combo.addItems(sorted_fields)
        
        # Restore selections
        field_index = self.field_combo.findText(current_field)
        if field_index >= 0:
            self.field_combo.setCurrentIndex(field_index)
        
        search_index = self.search_fields_combo.findText(current_search_field)
        if search_index >= 0:
            self.search_fields_combo.setCurrentIndex(search_index)
        
        sort_index = self.sort_combo.findText(current_sort)
        if sort_index >= 0:
            self.sort_combo.setCurrentIndex(sort_index)
    
    def on_search_changed(self):
        """Handle search input change with debouncing"""
        self.search_timer.stop()
        self.search_timer.start(300)  # 300ms delay
    
    def add_filter(self):
        """Add new filter criteria"""
        field = self.field_combo.currentText()
        operator = self.operator_combo.currentText()
        value = self.value_input.text().strip()
        
        if not field or not value:
            self.status_label.setText("❌ Please select field and enter value")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        # Create filter
        filter_criteria = {
            'field': field,
            'operator': operator,
            'value': value
        }
        
        self.active_filters.append(filter_criteria)
        self.value_input.clear()
        
        # Update display and apply filters
        self.update_active_filters_display()
        self.apply_filters()
    
    def clear_filters(self):
        """Clear all filters and search"""
        self.active_filters.clear()
        self.search_input.clear()
        self.update_active_filters_display()
        self.filtered_results = self.current_results.copy()
        self.display_results()
        
        self.status_label.setText(f"Showing all {len(self.current_results)} results")
        self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
    
    def apply_filters(self):
        """Apply all active filters and search"""
        if not self.current_results:
            return
        
        results = self.current_results.copy()
        
        # Apply search
        search_query = self.search_input.text().strip()
        if search_query:
            search_fields = None
            if self.search_fields_combo.currentText() != "All Fields":
                search_fields = [self.search_fields_combo.currentText()]
            
            results = result_filter.search_results(results, search_query, search_fields)
        
        # Apply filters
        if self.active_filters:
            results = result_filter.apply_multiple_filters(results, self.active_filters, 'AND')
        
        self.filtered_results = results
        self.display_results()
        self.update_statistics()
        
        # Emit signal
        self.results_filtered.emit(self.filtered_results)
        
        # Update status
        if search_query or self.active_filters:
            self.status_label.setText(f"Filtered to {len(self.filtered_results)} of {len(self.current_results)} results")
            self.status_label.setStyleSheet("color: #64C8FF; font-size: 10pt; padding: 5px;")
        else:
            self.status_label.setText(f"Showing all {len(self.current_results)} results")
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
    
    def apply_sorting(self):
        """Apply sorting to filtered results"""
        sort_field = self.sort_combo.currentText()
        
        if sort_field == "No Sorting" or not self.filtered_results:
            return
        
        descending = self.sort_desc_cb.isChecked()
        self.filtered_results = result_filter.sort_results(self.filtered_results, sort_field, descending)
        self.display_results()
    
    def update_active_filters_display(self):
        """Update active filters display"""
        if not self.active_filters:
            self.active_filters_text.setPlainText("No active filters")
            return
        
        filter_text = []
        for i, f in enumerate(self.active_filters):
            filter_text.append(f"{i+1}. {f['field']} {f['operator']} '{f['value']}'")
        
        self.active_filters_text.setPlainText(" AND ".join(filter_text))
    
    def display_results(self):
        """Display filtered results in table"""
        if not self.filtered_results:
            self.results_table.setRowCount(0)
            self.results_table.setColumnCount(0)
            return
        
        # Get all unique fields from results
        all_fields = set()
        for result in self.filtered_results:
            if isinstance(result, dict):
                all_fields.update(result.keys())
        
        fields = sorted(list(all_fields))
        
        # Setup table
        self.results_table.setRowCount(len(self.filtered_results))
        self.results_table.setColumnCount(len(fields))
        self.results_table.setHorizontalHeaderLabels(fields)
        
        # Populate table
        for row, result in enumerate(self.filtered_results):
            for col, field in enumerate(fields):
                value = result.get(field, '')
                
                # Handle complex values
                if isinstance(value, (dict, list)):
                    display_value = json.dumps(value)[:50] + "..." if len(json.dumps(value)) > 50 else json.dumps(value)
                else:
                    display_value = str(value)
                
                item = QTableWidgetItem(display_value)
                self.results_table.setItem(row, col, item)
        
        self.results_table.resizeColumnsToContents()
    
    def update_statistics(self):
        """Update statistics display"""
        if not self.filtered_results:
            self.stats_text.setPlainText("No results to analyze")
            return
        
        stats = result_filter.create_summary_stats(self.filtered_results)
        
        stats_text = "Result Statistics\n"
        stats_text += "=" * 20 + "\n\n"
        
        stats_text += f"Total Results: {stats.get('total_results', 0)}\n"
        stats_text += f"Available Fields: {len(stats.get('common_fields', []))}\n\n"
        
        # Field statistics
        field_stats = stats.get('field_stats', {})
        if field_stats:
            stats_text += "Field Analysis:\n"
            stats_text += "-" * 15 + "\n"
            
            for field, field_data in list(field_stats.items())[:10]:  # Show first 10 fields
                stats_text += f"{field}:\n"
                stats_text += f"  Count: {field_data.get('count', 0)}\n"
                stats_text += f"  Unique: {field_data.get('unique_count', 0)}\n"
                
                samples = field_data.get('sample_values', [])
                if samples:
                    stats_text += f"  Samples: {', '.join(samples[:3])}\n"
                stats_text += "\n"
        
        self.stats_text.setPlainText(stats_text)