# app/widgets/advanced_analytics_widget.py
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *
import json
from datetime import datetime
from ..core.advanced_analytics_engine import create_advanced_analytics_engine

class AdvancedAnalyticsWidget(QWidget):
    """Advanced analytics dashboard widget"""
    
    def __init__(self, tenant_id: str = "default"):
        super().__init__()
        self.tenant_id = tenant_id
        self.analytics_engine = create_advanced_analytics_engine(tenant_id)
        self.setup_ui()
        self.setup_timer()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel("🔬 Advanced Analytics Dashboard")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #2c3e50; margin: 10px;")
        header_layout.addWidget(title)
        
        refresh_btn = QPushButton("🔄 Refresh")
        refresh_btn.clicked.connect(self.refresh_data)
        refresh_btn.setStyleSheet("padding: 8px 16px; background: #3498db; color: white; border: none; border-radius: 4px;")
        header_layout.addWidget(refresh_btn)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Create tabs for different analytics views
        self.tab_widget = QTabWidget()
        self.tab_widget.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #bdc3c7; background: white; }
            QTabBar::tab { padding: 8px 16px; margin: 2px; }
            QTabBar::tab:selected { background: #3498db; color: white; }
        """)
        
        # Trend Analysis Tab
        self.trend_tab = self.create_trend_analysis_tab()
        self.tab_widget.addTab(self.trend_tab, "📈 Trends")
        
        # Anomaly Detection Tab
        self.anomaly_tab = self.create_anomaly_detection_tab()
        self.tab_widget.addTab(self.anomaly_tab, "🚨 Anomalies")
        
        # Predictive Insights Tab
        self.prediction_tab = self.create_prediction_tab()
        self.tab_widget.addTab(self.prediction_tab, "🔮 Predictions")
        
        # Security Maturity Tab
        self.maturity_tab = self.create_maturity_tab()
        self.tab_widget.addTab(self.maturity_tab, "🎯 Maturity")
        
        layout.addWidget(self.tab_widget)
        
        # Status bar
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #7f8c8d; font-size: 12px; padding: 5px;")
        layout.addWidget(self.status_label)
    
    def create_trend_analysis_tab(self) -> QWidget:
        """Create trend analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Trend analysis table
        self.trend_table = QTableWidget()
        self.trend_table.setColumnCount(6)
        self.trend_table.setHorizontalHeaderLabels([
            "Metric", "Current", "Previous", "Change %", "Trend", "Confidence"
        ])
        self.trend_table.horizontalHeader().setStretchLastSection(True)
        self.trend_table.setAlternatingRowColors(True)
        self.trend_table.setStyleSheet("""
            QTableWidget { gridline-color: #ecf0f1; }
            QTableWidget::item { padding: 8px; }
        """)
        
        layout.addWidget(QLabel("📊 Security Trend Analysis"))
        layout.addWidget(self.trend_table)
        
        return widget
    
    def create_anomaly_detection_tab(self) -> QWidget:
        """Create anomaly detection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Anomaly controls
        controls_layout = QHBoxLayout()
        controls_layout.addWidget(QLabel("Time Window:"))
        
        self.anomaly_timeframe = QComboBox()
        self.anomaly_timeframe.addItems(["Last 6 Hours", "Last 12 Hours", "Last 24 Hours", "Last 48 Hours"])
        self.anomaly_timeframe.setCurrentText("Last 24 Hours")
        controls_layout.addWidget(self.anomaly_timeframe)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # Anomaly list
        self.anomaly_list = QListWidget()
        self.anomaly_list.setStyleSheet("""
            QListWidget::item { padding: 10px; margin: 2px; border-radius: 4px; }
            QListWidget::item:selected { background: #3498db; color: white; }
        """)
        
        layout.addWidget(QLabel("🚨 Detected Anomalies"))
        layout.addWidget(self.anomaly_list)
        
        return widget
    
    def create_prediction_tab(self) -> QWidget:
        """Create predictive insights tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Prediction cards layout
        cards_layout = QGridLayout()
        
        # Risk forecast card
        self.risk_forecast_card = self.create_prediction_card("Risk Forecast", "🎯")
        cards_layout.addWidget(self.risk_forecast_card, 0, 0)
        
        # Vulnerability prediction card
        self.vuln_prediction_card = self.create_prediction_card("Vulnerability Discovery", "🔍")
        cards_layout.addWidget(self.vuln_prediction_card, 0, 1)
        
        # Resource planning card
        self.resource_card = self.create_prediction_card("Resource Planning", "📊")
        cards_layout.addWidget(self.resource_card, 1, 0)
        
        # Attack scenarios card
        self.attack_card = self.create_prediction_card("Attack Scenarios", "⚔️")
        cards_layout.addWidget(self.attack_card, 1, 1)
        
        layout.addLayout(cards_layout)
        layout.addStretch()
        
        return widget
    
    def create_maturity_tab(self) -> QWidget:
        """Create security maturity tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Maturity score display
        score_layout = QHBoxLayout()
        
        self.maturity_score_label = QLabel("Security Maturity Score")
        self.maturity_score_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        score_layout.addWidget(self.maturity_score_label)
        
        self.maturity_score_value = QLabel("--")
        self.maturity_score_value.setStyleSheet("font-size: 24px; font-weight: bold; color: #3498db;")
        score_layout.addWidget(self.maturity_score_value)
        score_layout.addStretch()
        
        layout.addLayout(score_layout)
        
        # Maturity breakdown
        self.maturity_breakdown = QTableWidget()
        self.maturity_breakdown.setColumnCount(2)
        self.maturity_breakdown.setHorizontalHeaderLabels(["Scan Type", "Maturity Score"])
        self.maturity_breakdown.horizontalHeader().setStretchLastSection(True)
        
        layout.addWidget(QLabel("📋 Maturity Breakdown"))
        layout.addWidget(self.maturity_breakdown)
        
        # Recommendations
        self.recommendations_list = QListWidget()
        self.recommendations_list.setMaximumHeight(150)
        
        layout.addWidget(QLabel("💡 Recommendations"))
        layout.addWidget(self.recommendations_list)
        
        return widget
    
    def create_prediction_card(self, title: str, icon: str) -> QGroupBox:
        """Create a prediction card widget"""
        card = QGroupBox(f"{icon} {title}")
        card.setStyleSheet("""
            QGroupBox { 
                font-weight: bold; 
                border: 2px solid #bdc3c7; 
                border-radius: 8px; 
                margin: 5px; 
                padding-top: 15px;
            }
            QGroupBox::title { 
                subcontrol-origin: margin; 
                left: 10px; 
                padding: 0 5px 0 5px; 
            }
        """)
        
        layout = QVBoxLayout(card)
        
        # Content area
        content_label = QLabel("Loading...")
        content_label.setWordWrap(True)
        content_label.setStyleSheet("padding: 10px; background: #f8f9fa; border-radius: 4px;")
        layout.addWidget(content_label)
        
        # Store reference for updates
        setattr(self, f"{title.lower().replace(' ', '_')}_content", content_label)
        
        return card
    
    def setup_timer(self):
        """Setup auto-refresh timer"""
        self.timer = QTimer()
        self.timer.timeout.connect(self.refresh_data)
        self.timer.start(30000)  # Refresh every 30 seconds
    
    def refresh_data(self):
        """Refresh all analytics data"""
        self.status_label.setText("Refreshing analytics data...")
        
        try:
            # Update trend analysis
            self.update_trend_analysis()
            
            # Update anomaly detection
            self.update_anomaly_detection()
            
            # Update predictions
            self.update_predictions()
            
            # Update maturity assessment
            self.update_maturity_assessment()
            
            self.status_label.setText(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")
        except Exception as e:
            self.status_label.setText(f"Error: {str(e)}")
    
    def update_trend_analysis(self):
        """Update trend analysis data"""
        trends = self.analytics_engine.analyze_security_trends()
        
        self.trend_table.setRowCount(len(trends))
        
        for i, trend in enumerate(trends):
            self.trend_table.setItem(i, 0, QTableWidgetItem(trend.metric_name.replace('_', ' ').title()))
            self.trend_table.setItem(i, 1, QTableWidgetItem(str(int(trend.current_value))))
            self.trend_table.setItem(i, 2, QTableWidgetItem(str(int(trend.previous_value))))
            
            # Format change percentage with color
            change_item = QTableWidgetItem(f"{trend.change_percentage:+.1f}%")
            if trend.change_percentage > 0:
                change_item.setForeground(QColor("#e74c3c"))  # Red for increase
            elif trend.change_percentage < 0:
                change_item.setForeground(QColor("#27ae60"))  # Green for decrease
            self.trend_table.setItem(i, 3, change_item)
            
            # Trend direction with icon
            trend_icons = {'increasing': '📈', 'decreasing': '📉', 'stable': '➡️'}
            trend_item = QTableWidgetItem(f"{trend_icons.get(trend.trend_direction, '➡️')} {trend.trend_direction.title()}")
            self.trend_table.setItem(i, 4, trend_item)
            
            # Confidence
            confidence_item = QTableWidgetItem(f"{trend.confidence:.1%}")
            self.trend_table.setItem(i, 5, confidence_item)
    
    def update_anomaly_detection(self):
        """Update anomaly detection data"""
        # Get timeframe from combo box
        timeframe_map = {
            "Last 6 Hours": 6,
            "Last 12 Hours": 12,
            "Last 24 Hours": 24,
            "Last 48 Hours": 48
        }
        hours = timeframe_map.get(self.anomaly_timeframe.currentText(), 24)
        
        anomalies = self.analytics_engine.detect_anomalies(hours_back=hours)
        
        self.anomaly_list.clear()
        
        if not anomalies:
            item = QListWidgetItem("✅ No anomalies detected")
            item.setForeground(QColor("#27ae60"))
            self.anomaly_list.addItem(item)
            return
        
        for anomaly in anomalies:
            # Format anomaly display
            severity_icons = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }
            
            icon = severity_icons.get(anomaly.severity, '🔵')
            text = f"{icon} {anomaly.description}\n"
            text += f"   Metric: {anomaly.metric_name} | "
            text += f"Actual: {anomaly.actual_value:.1f} | "
            text += f"Expected: {anomaly.expected_value:.1f} | "
            text += f"Deviation: {anomaly.deviation_score:.1f}σ"
            
            item = QListWidgetItem(text)
            
            # Color code by severity
            severity_colors = {
                'critical': "#e74c3c",
                'high': "#e67e22",
                'medium': "#f39c12",
                'low': "#27ae60"
            }
            item.setForeground(QColor(severity_colors.get(anomaly.severity, "#34495e")))
            
            self.anomaly_list.addItem(item)
    
    def update_predictions(self):
        """Update predictive insights"""
        insights = self.analytics_engine.generate_predictive_insights()
        
        # Update risk forecast
        risk_forecast = insights.get('risk_forecast', {})
        risk_content = f"Predicted Risk Level: {risk_forecast.get('prediction', 'Unknown')}\n"
        risk_content += f"Confidence: {risk_forecast.get('confidence', 0):.1%}\n"
        risk_content += f"Timeframe: {risk_forecast.get('timeframe', 'N/A')}\n"
        risk_content += f"Current Avg Risk: {risk_forecast.get('current_avg_risk', 0):.1f}/10"
        self.risk_forecast_content.setText(risk_content)
        
        # Update vulnerability prediction
        vuln_pred = insights.get('vulnerability_prediction', {})
        vuln_content = f"Weekly Discoveries: {vuln_pred.get('predicted_weekly_discoveries', 0)}\n"
        vuln_content += f"Daily Rate: {vuln_pred.get('current_daily_rate', 0):.1f}\n"
        vuln_content += f"Trend: {vuln_pred.get('trend', 'stable').title()}\n"
        vuln_content += f"Confidence: {vuln_pred.get('confidence', 0):.1%}"
        self.vulnerability_discovery_content.setText(vuln_content)
        
        # Update resource planning
        resource_pred = insights.get('resource_planning', {})
        resource_content = f"Storage Needed: {resource_pred.get('predicted_storage_mb', 0):.1f} MB\n"
        resource_content += f"Weekly Scan Time: {resource_pred.get('predicted_weekly_scan_time_minutes', 0):.0f} min\n"
        resource_content += f"Cleanup Frequency: {resource_pred.get('recommended_cleanup_frequency', 'monthly').title()}"
        self.resource_planning_content.setText(resource_content)
        
        # Update attack scenarios
        attack_pred = insights.get('attack_likelihood', {})
        scenarios = attack_pred.get('likely_scenarios', [])
        attack_content = f"Overall Likelihood: {attack_pred.get('overall_attack_likelihood', 'Low')}\n\n"
        
        if scenarios:
            attack_content += "Top Scenarios:\n"
            for scenario in scenarios[:3]:
                attack_content += f"• {scenario.get('scenario', 'Unknown')}: {scenario.get('likelihood_percentage', 0)}%\n"
        else:
            attack_content += "No specific attack scenarios identified"
        
        self.attack_scenarios_content.setText(attack_content)
    
    def update_maturity_assessment(self):
        """Update security maturity assessment"""
        maturity = self.analytics_engine.calculate_security_maturity()
        
        # Update overall score
        overall_score = maturity.get('overall_score', 0)
        maturity_level = maturity.get('maturity_level', 'Unknown')
        color = maturity.get('color', '#3498db')
        
        self.maturity_score_value.setText(f"{overall_score:.0f}/100")
        self.maturity_score_value.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
        self.maturity_score_label.setText(f"Security Maturity Score - {maturity_level}")
        
        # Update breakdown table
        scan_scores = maturity.get('scan_type_scores', {})
        self.maturity_breakdown.setRowCount(len(scan_scores))
        
        for i, (scan_type, score) in enumerate(scan_scores.items()):
            self.maturity_breakdown.setItem(i, 0, QTableWidgetItem(scan_type.replace('_', ' ').title()))
            score_item = QTableWidgetItem(f"{score:.0f}/100")
            
            # Color code scores
            if score >= 80:
                score_item.setForeground(QColor("#27ae60"))
            elif score >= 60:
                score_item.setForeground(QColor("#f39c12"))
            else:
                score_item.setForeground(QColor("#e74c3c"))
            
            self.maturity_breakdown.setItem(i, 1, score_item)
        
        # Update recommendations
        recommendations = maturity.get('recommendations', [])
        self.recommendations_list.clear()
        
        for rec in recommendations:
            item = QListWidgetItem(f"💡 {rec}")
            self.recommendations_list.addItem(item)
    
    def export_analytics_report(self):
        """Export analytics report"""
        try:
            # Get all analytics data
            trends = self.analytics_engine.analyze_security_trends()
            anomalies = self.analytics_engine.detect_anomalies()
            insights = self.analytics_engine.generate_predictive_insights()
            maturity = self.analytics_engine.calculate_security_maturity()
            
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'tenant_id': self.tenant_id,
                'trends': [
                    {
                        'metric': t.metric_name,
                        'current': t.current_value,
                        'previous': t.previous_value,
                        'change_percentage': t.change_percentage,
                        'trend_direction': t.trend_direction,
                        'confidence': t.confidence
                    } for t in trends
                ],
                'anomalies': [
                    {
                        'metric': a.metric_name,
                        'actual_value': a.actual_value,
                        'expected_value': a.expected_value,
                        'deviation_score': a.deviation_score,
                        'severity': a.severity,
                        'description': a.description
                    } for a in anomalies
                ],
                'predictions': insights,
                'maturity': maturity
            }
            
            # Save to file
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Analytics Report", 
                f"huggin_analytics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "JSON Files (*.json)"
            )
            
            if filename:
                with open(filename, 'w') as f:
                    json.dump(report_data, f, indent=2, default=str)
                
                QMessageBox.information(self, "Export Complete", f"Analytics report exported to:\n{filename}")
        
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export analytics report:\n{str(e)}")

def create_advanced_analytics_widget(tenant_id: str = "default") -> AdvancedAnalyticsWidget:
    """Create advanced analytics widget for specific tenant"""
    return AdvancedAnalyticsWidget(tenant_id=tenant_id)