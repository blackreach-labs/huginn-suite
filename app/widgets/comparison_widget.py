# app/widgets/comparison_widget.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QTabWidget
from PyQt6.QtCore import Qt

class ComparisonWidget(QWidget):
    """Widget to display scan result comparisons"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = QLabel("📊 Scan Result Comparison")
        header.setStyleSheet("color: #64C8FF; font-size: 14pt; font-weight: bold;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Summary section
        self.summary_label = QLabel("No comparison data")
        self.summary_label.setStyleSheet("color: #FFAA00; font-size: 12pt; padding: 10px;")
        self.summary_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Tabbed content
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
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
        
        # New findings tab
        self.new_text = QTextEdit()
        self.new_text.setReadOnly(True)
        self.new_text.setStyleSheet(self._get_text_style())
        self.tabs.addTab(self.new_text, "🆕 New Findings")
        
        # Removed findings tab
        self.removed_text = QTextEdit()
        self.removed_text.setReadOnly(True)
        self.removed_text.setStyleSheet(self._get_text_style())
        self.tabs.addTab(self.removed_text, "❌ Removed")
        
        # Summary tab
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet(self._get_text_style())
        self.tabs.addTab(self.details_text, "📋 Summary")
        
        layout.addWidget(header)
        layout.addWidget(self.summary_label)
        layout.addWidget(self.tabs)
        
    def _get_text_style(self):
        return """
            QTextEdit {
                background-color: rgba(0, 0, 0, 150);
                border: 1px solid #555;
                border-radius: 5px;
                color: #DCDCDC;
                font-size: 11pt;
                padding: 8px;
            }
        """
    
    def display_comparison(self, comparison):
        """Display comparison results"""
        if not comparison:
            return
        
        # Update summary
        summary = comparison.get('summary', {})
        changes_detected = comparison.get('changes_detected', False)
        
        if summary.get('status') == 'first_scan':
            self.summary_label.setText("🔍 First scan - no comparison available")
            self.summary_label.setStyleSheet("color: #64C8FF; font-size: 12pt; padding: 10px;")
        elif changes_detected:
            new_count = len(comparison.get('new_findings', []))
            removed_count = len(comparison.get('removed_findings', []))
            self.summary_label.setText(f"⚠️ Changes detected: +{new_count} new, -{removed_count} removed")
            self.summary_label.setStyleSheet("color: #FF6600; font-size: 12pt; padding: 10px;")
        else:
            self.summary_label.setText("✅ No changes since last scan")
            self.summary_label.setStyleSheet("color: #00AA00; font-size: 12pt; padding: 10px;")
        
        # Display new findings
        new_html = "<h3 style='color: #00FF41;'>New Findings</h3>"
        new_findings = comparison.get('new_findings', [])
        
        if new_findings:
            for i, finding in enumerate(new_findings, 1):
                new_html += f"""
                <div style='margin-bottom: 10px; padding: 8px; border-left: 3px solid #00FF41;'>
                    <h4 style='color: #00FF41; margin: 0;'>{i}. {finding.get('type', 'Unknown').replace('_', ' ').title()}</h4>
                    <p><strong>Value:</strong> {finding.get('value', 'N/A')}</p>
                """
                if finding.get('details'):
                    new_html += f"<p><strong>Details:</strong> {str(finding['details'])[:100]}...</p>"
                new_html += "</div>"
        else:
            new_html += "<p style='color: #888;'>No new findings detected.</p>"
        
        self.new_text.setHtml(new_html)
        
        # Display removed findings
        removed_html = "<h3 style='color: #FF4444;'>Removed Findings</h3>"
        removed_findings = comparison.get('removed_findings', [])
        
        if removed_findings:
            for i, finding in enumerate(removed_findings, 1):
                removed_html += f"""
                <div style='margin-bottom: 10px; padding: 8px; border-left: 3px solid #FF4444;'>
                    <h4 style='color: #FF4444; margin: 0;'>{i}. {finding.get('type', 'Unknown').replace('_', ' ').title()}</h4>
                    <p><strong>Value:</strong> {finding.get('value', 'N/A')}</p>
                """
                if finding.get('details'):
                    removed_html += f"<p><strong>Details:</strong> {str(finding['details'])[:100]}...</p>"
                removed_html += "</div>"
        else:
            removed_html += "<p style='color: #888;'>No removed findings detected.</p>"
        
        self.removed_text.setHtml(removed_html)
        
        # Display detailed summary
        details_html = f"""
        <h3 style='color: #64C8FF;'>Comparison Summary</h3>
        <p><strong>Target:</strong> {comparison.get('target', 'Unknown')}</p>
        <p><strong>Scan Type:</strong> {comparison.get('scan_type', 'Unknown').replace('_', ' ').title()}</p>
        <p><strong>Timestamp:</strong> {comparison.get('timestamp', 'Unknown')}</p>
        <p><strong>Changes Detected:</strong> {'Yes' if changes_detected else 'No'}</p>
        
        <h4 style='color: #FFAA00;'>Statistics:</h4>
        <ul>
        """
        
        if 'new_count' in summary:
            details_html += f"<li>New findings: {summary.get('new_count', 0)}</li>"
            details_html += f"<li>Removed findings: {summary.get('removed_count', 0)}</li>"
            details_html += f"<li>Unchanged findings: {summary.get('unchanged_count', 0)}</li>"
            details_html += f"<li>Current total: {summary.get('total_current', 0)}</li>"
            details_html += f"<li>Previous total: {summary.get('total_previous', 0)}</li>"
        else:
            details_html += f"<li>Status: {summary.get('status', 'Unknown')}</li>"
            details_html += f"<li>Message: {summary.get('message', 'No details')}</li>"
        
        details_html += "</ul>"
        
        self.details_text.setHtml(details_html)