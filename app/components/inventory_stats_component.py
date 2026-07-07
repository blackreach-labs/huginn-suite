from PyQt6.QtWidgets import QWidget, QHBoxLayout, QVBoxLayout, QLabel, QFrame
from PyQt6.QtCore import Qt

class InventoryStatsComponent(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.apply_theme()

    def setup_ui(self):
        """Setup statistics UI"""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 10, 20, 10)
        
        # Create stat widgets
        self.total_label = self.create_stat_widget("0", "Total Assets")
        self.discovered_label = self.create_stat_widget("0", "Discovered")
        self.identified_label = self.create_stat_widget("0", "Identified")
        self.known_label = self.create_stat_widget("0", "Known")
        self.recent_label = self.create_stat_widget("0", "Recent Activity")
        
        layout.addWidget(self.total_label)
        layout.addWidget(self.discovered_label)
        layout.addWidget(self.identified_label)
        layout.addWidget(self.known_label)
        layout.addWidget(self.recent_label)

    def create_stat_widget(self, value, description):
        """Create individual stat widget"""
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        
        value_label = QLabel(value)
        value_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        value_label.setStyleSheet("font-size: 18pt; font-weight: bold; color: #64C8FF;")
        
        desc_label = QLabel(description)
        desc_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        desc_label.setStyleSheet("font-size: 10pt; color: #87CEEB;")
        desc_label.setWordWrap(True)
        
        layout.addWidget(value_label)
        layout.addWidget(desc_label)
        
        container.value_label = value_label
        return container

    def update_stats(self, assets):
        """Update statistics from assets"""
        total = len(assets)
        status_counts = {"DISCOVERED": 0, "IDENTIFIED": 0, "KNOWN": 0}
        
        for asset in assets:
            status = asset.get('status', 'DISCOVERED')
            if status in status_counts:
                status_counts[status] += 1
        
        # Update labels
        self.total_label.value_label.setText(str(total))
        self.discovered_label.value_label.setText(str(status_counts["DISCOVERED"]))
        self.identified_label.value_label.setText(str(status_counts["IDENTIFIED"]))
        self.known_label.value_label.setText(str(status_counts["KNOWN"]))
        self.recent_label.value_label.setText("0")  # Placeholder

    def apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        self.setFixedHeight(100)