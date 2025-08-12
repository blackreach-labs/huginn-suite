# app/widgets/ml_pattern_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QTextEdit, QTableWidget, QTableWidgetItem, QGroupBox)
from PyQt6.QtCore import pyqtSignal, Qt
from PyQt6.QtGui import QColor
from app.core.ml_pattern_detection import ml_pattern_detection

class MLPatternWidget(QWidget):
    """Widget for machine learning pattern detection and analysis."""
    
    pattern_analyzed = pyqtSignal(str, dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_results = None
        self.setup_ui()
        self.connect_signals()
        
    def setup_ui(self):
        """Setup ML pattern detection widget UI."""
        layout = QVBoxLayout(self)
        
        # Title
        title = QLabel("ML Pattern Detection")
        title.setStyleSheet("font-size: 14pt; font-weight: bold; color: #64C8FF;")
        layout.addWidget(title)
        
        # Analysis controls
        controls_group = QGroupBox("Pattern Analysis")
        controls_layout = QHBoxLayout(controls_group)
        
        self.analyze_button = QPushButton("Analyze Current Results")
        self.analyze_button.clicked.connect(self.analyze_current_results)
        controls_layout.addWidget(self.analyze_button)
        
        self.clear_button = QPushButton("Clear Analysis")
        self.clear_button.clicked.connect(self.clear_analysis)
        controls_layout.addWidget(self.clear_button)
        
        controls_layout.addStretch()
        layout.addWidget(controls_group)
        
        # Patterns table
        patterns_label = QLabel("Detected Patterns:")
        patterns_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(patterns_label)
        
        self.patterns_table = QTableWidget()
        self.patterns_table.setColumnCount(3)
        self.patterns_table.setHorizontalHeaderLabels(["Type", "Pattern", "Confidence"])
        self.patterns_table.setMaximumHeight(150)
        layout.addWidget(self.patterns_table)
        
        # Anomalies table
        anomalies_label = QLabel("Detected Anomalies:")
        anomalies_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(anomalies_label)
        
        self.anomalies_table = QTableWidget()
        self.anomalies_table.setColumnCount(3)
        self.anomalies_table.setHorizontalHeaderLabels(["Type", "Description", "Severity"])
        self.anomalies_table.setMaximumHeight(150)
        layout.addWidget(self.anomalies_table)
        
        # Insights area
        insights_label = QLabel("ML Insights:")
        insights_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(insights_label)
        
        self.insights_output = QTextEdit()
        self.insights_output.setMaximumHeight(120)
        self.insights_output.setPlaceholderText("ML analysis insights will appear here...")
        layout.addWidget(self.insights_output)
        
        layout.addStretch()
        
    def connect_signals(self):
        """Connect ML pattern detection signals."""
        ml_pattern_detection.pattern_detected.connect(self.on_pattern_detected)
        
    def load_results(self, results, scan_type="unknown"):
        """Load scan results for analysis."""
        self.current_results = results
        self.scan_type = scan_type
        self.analyze_button.setEnabled(True)
        
    def analyze_current_results(self):
        """Analyze current scan results for patterns."""
        if not self.current_results:
            self.insights_output.append("No results available for analysis")
            return
            
        self.insights_output.append(f"Analyzing {self.scan_type} results...")
        
        # Perform ML pattern analysis
        analysis = ml_pattern_detection.analyze_scan_results(
            self.current_results, 
            getattr(self, 'scan_type', 'unknown')
        )
        
    def on_pattern_detected(self, scan_type, analysis):
        """Handle pattern detection results."""
        patterns = analysis.get("patterns", [])
        anomalies = analysis.get("anomalies", [])
        insights = analysis.get("insights", [])
        
        # Update patterns table
        self.patterns_table.setRowCount(len(patterns))
        for i, pattern in enumerate(patterns):
            self.patterns_table.setItem(i, 0, QTableWidgetItem(pattern.get("type", "Unknown")))
            self.patterns_table.setItem(i, 1, QTableWidgetItem(pattern.get("pattern", "No description")))
            
            confidence = pattern.get("confidence", 0)
            conf_item = QTableWidgetItem(f"{confidence:.1%}")
            
            # Color code confidence
            if confidence > 0.8:
                conf_item.setBackground(QColor(100, 255, 100, 100))
            elif confidence > 0.6:
                conf_item.setBackground(QColor(255, 255, 100, 100))
            else:
                conf_item.setBackground(QColor(255, 150, 150, 100))
                
            self.patterns_table.setItem(i, 2, conf_item)
        
        # Update anomalies table
        self.anomalies_table.setRowCount(len(anomalies))
        for i, anomaly in enumerate(anomalies):
            self.anomalies_table.setItem(i, 0, QTableWidgetItem(anomaly.get("type", "Unknown")))
            self.anomalies_table.setItem(i, 1, QTableWidgetItem(anomaly.get("description", "No description")))
            
            severity = anomaly.get("severity", "low")
            sev_item = QTableWidgetItem(severity.upper())
            
            # Color code severity
            if severity.lower() == "high":
                sev_item.setBackground(QColor(255, 100, 100, 100))
            elif severity.lower() == "medium":
                sev_item.setBackground(QColor(255, 200, 100, 100))
            else:
                sev_item.setBackground(QColor(200, 200, 200, 100))
                
            self.anomalies_table.setItem(i, 2, sev_item)
        
        # Update insights
        self.insights_output.append(f"Analysis completed for {scan_type}")
        self.insights_output.append(f"Patterns detected: {len(patterns)}")
        self.insights_output.append(f"Anomalies detected: {len(anomalies)}")
        
        for insight in insights:
            self.insights_output.append(f"💡 {insight}")
            
        # Generate additional insights
        additional_insights = ml_pattern_detection.generate_insights(analysis)
        for insight in additional_insights:
            self.insights_output.append(f"🔍 {insight}")
            
        self.insights_output.append("---")
        self.pattern_analyzed.emit(scan_type, analysis)
        
    def clear_analysis(self):
        """Clear all analysis results."""
        self.patterns_table.setRowCount(0)
        self.anomalies_table.setRowCount(0)
        self.insights_output.clear()
        self.insights_output.append("Analysis cleared")