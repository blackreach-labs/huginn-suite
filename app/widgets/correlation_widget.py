# app/widgets/correlation_widget.py
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QProgressBar, QTabWidget
from PyQt6.QtCore import Qt

class CorrelationWidget(QWidget):
    """Widget to display vulnerability correlations"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Header
        header = QLabel("🔗 Vulnerability Correlation Analysis")
        header.setStyleSheet("color: #64C8FF; font-size: 14pt; font-weight: bold;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        # Correlation score
        score_layout = QHBoxLayout()
        self.score_label = QLabel("Correlation Risk Score:")
        self.score_label.setStyleSheet("color: #FFAA00; font-weight: bold;")
        
        self.score_bar = QProgressBar()
        self.score_bar.setFixedHeight(20)
        self.score_bar.setRange(0, 100)
        self.score_bar.setValue(0)
        
        score_layout.addWidget(self.score_label)
        score_layout.addWidget(self.score_bar)
        
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
        
        # Attack chains tab
        self.chains_text = QTextEdit()
        self.chains_text.setReadOnly(True)
        self.chains_text.setStyleSheet(self._get_text_style())
        self.tabs.addTab(self.chains_text, "🎯 Attack Chains")
        
        # Risk amplifiers tab
        self.amplifiers_text = QTextEdit()
        self.amplifiers_text.setReadOnly(True)
        self.amplifiers_text.setStyleSheet(self._get_text_style())
        self.tabs.addTab(self.amplifiers_text, "⚡ Risk Amplifiers")
        
        # Security gaps tab
        self.gaps_text = QTextEdit()
        self.gaps_text.setReadOnly(True)
        self.gaps_text.setStyleSheet(self._get_text_style())
        self.tabs.addTab(self.gaps_text, "🔓 Security Gaps")
        
        layout.addWidget(header)
        layout.addLayout(score_layout)
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
    
    def display_correlations(self, correlations):
        """Display correlation analysis results"""
        # Update score
        score = correlations.get('correlation_score', 0)
        self.score_bar.setValue(score)
        self.score_label.setText(f"Correlation Risk Score: {score}/100")
        
        # Set color based on score
        if score > 70:
            color = "#FF4444"
        elif score > 40:
            color = "#FF6600"
        elif score > 20:
            color = "#FFAA00"
        else:
            color = "#00AA00"
            
        self.score_bar.setStyleSheet(f"""
            QProgressBar::chunk {{
                background-color: {color};
            }}
        """)
        
        # Display attack chains
        chains_html = "<h3 style='color: #FF6666;'>Potential Attack Chains</h3>"
        attack_chains = correlations.get('attack_chains', [])
        
        if attack_chains:
            for i, chain in enumerate(attack_chains, 1):
                risk_color = self._get_risk_color(chain.get('risk', 'low'))
                chains_html += f"""
                <div style='margin-bottom: 15px; padding: 10px; border-left: 3px solid {risk_color};'>
                    <h4 style='color: {risk_color}; margin: 0;'>{i}. {chain.get('chain_type', 'Unknown').replace('_', ' ').title()}</h4>
                    <p><strong>Risk:</strong> <span style='color: {risk_color};'>{chain.get('risk', 'Unknown').upper()}</span></p>
                    <p><strong>Description:</strong> {chain.get('description', 'No description')}</p>
                    <p><strong>Impact:</strong> {chain.get('impact', 'Unknown impact')}</p>
                </div>
                """
        else:
            chains_html += "<p style='color: #00AA00;'>No attack chains identified.</p>"
        
        self.chains_text.setHtml(chains_html)
        
        # Display risk amplifiers
        amp_html = "<h3 style='color: #FFAA00;'>Risk Amplifiers</h3>"
        amplifiers = correlations.get('risk_amplifiers', [])
        
        if amplifiers:
            for i, amp in enumerate(amplifiers, 1):
                risk_color = self._get_risk_color(amp.get('risk', 'low'))
                amp_html += f"""
                <div style='margin-bottom: 15px; padding: 10px; border-left: 3px solid {risk_color};'>
                    <h4 style='color: {risk_color}; margin: 0;'>{i}. {amp.get('type', 'Unknown').replace('_', ' ').title()}</h4>
                    <p><strong>Risk:</strong> <span style='color: {risk_color};'>{amp.get('risk', 'Unknown').upper()}</span></p>
                    <p><strong>Count:</strong> {amp.get('count', 'N/A')}</p>
                    <p><strong>Description:</strong> {amp.get('description', 'No description')}</p>
                    <p><strong>Impact:</strong> {amp.get('impact', 'Unknown impact')}</p>
                </div>
                """
        else:
            amp_html += "<p style='color: #00AA00;'>No risk amplifiers identified.</p>"
        
        self.amplifiers_text.setHtml(amp_html)
        
        # Display security gaps
        gaps_html = "<h3 style='color: #64C8FF;'>Security Gaps</h3>"
        gaps = correlations.get('security_gaps', [])
        
        if gaps:
            for i, gap in enumerate(gaps, 1):
                risk_color = self._get_risk_color(gap.get('risk', 'low'))
                gaps_html += f"""
                <div style='margin-bottom: 15px; padding: 10px; border-left: 3px solid {risk_color};'>
                    <h4 style='color: {risk_color}; margin: 0;'>{i}. {gap.get('type', 'Unknown').replace('_', ' ').title()}</h4>
                    <p><strong>Risk:</strong> <span style='color: {risk_color};'>{gap.get('risk', 'Unknown').upper()}</span></p>
                    <p><strong>Description:</strong> {gap.get('description', 'No description')}</p>
                    <p><strong>Recommendation:</strong> {gap.get('recommendation', 'No recommendation')}</p>
                </div>
                """
        else:
            gaps_html += "<p style='color: #00AA00;'>No security gaps identified.</p>"
        
        self.gaps_text.setHtml(gaps_html)
    
    def _get_risk_color(self, risk_level):
        """Get color for risk level"""
        colors = {
            'critical': '#FF0000',
            'high': '#FF6600',
            'medium': '#FFAA00',
            'low': '#00AA00',
            'info': '#64C8FF'
        }
        return colors.get(risk_level.lower(), '#DCDCDC')