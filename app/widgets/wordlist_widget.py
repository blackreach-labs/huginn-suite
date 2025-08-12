# app/widgets/wordlist_widget.py
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QPushButton, QLineEdit, QTextEdit, QTableWidget, 
                            QTableWidgetItem, QGroupBox, QTabWidget, QComboBox,
                            QDialog, QDialogButtonBox, QFormLayout, QFileDialog,
                            QCheckBox, QListWidget, QListWidgetItem)
from PyQt6.QtCore import Qt, pyqtSignal
from app.core.wordlist_manager import wordlist_manager

class WordlistDialog(QDialog):
    """Dialog for creating/editing wordlists"""
    
    def __init__(self, wordlist_data=None, parent=None):
        super().__init__(parent)
        self.wordlist_data = wordlist_data
        self.setup_ui()
        
        if wordlist_data:
            self.load_wordlist_data()
    
    def setup_ui(self):
        self.setWindowTitle("Wordlist Editor")
        self.setFixedSize(500, 400)
        
        layout = QVBoxLayout(self)
        
        # Form layout
        form_layout = QFormLayout()
        
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter wordlist name...")
        
        self.category_combo = QComboBox()
        self.category_combo.addItems(["custom", "dns", "directories", "passwords", "usernames"])
        self.category_combo.setEditable(True)
        
        self.description_input = QLineEdit()
        self.description_input.setPlaceholderText("Enter description...")
        
        form_layout.addRow("Name:", self.name_input)
        form_layout.addRow("Category:", self.category_combo)
        form_layout.addRow("Description:", self.description_input)
        
        # Content area
        content_layout = QVBoxLayout()
        content_layout.addWidget(QLabel("Content (one word per line):"))
        
        self.content_text = QTextEdit()
        self.content_text.setPlaceholderText("Enter words, one per line...")
        
        # Import button
        import_layout = QHBoxLayout()
        self.import_button = QPushButton("📁 Import from File")
        self.import_button.clicked.connect(self.import_from_file)
        import_layout.addWidget(self.import_button)
        import_layout.addStretch()
        
        content_layout.addLayout(import_layout)
        content_layout.addWidget(self.content_text)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | 
                                 QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addLayout(form_layout)
        layout.addLayout(content_layout)
        layout.addWidget(buttons)
    
    def load_wordlist_data(self):
        """Load existing wordlist data"""
        if self.wordlist_data:
            self.name_input.setText(self.wordlist_data.get('name', ''))
            self.category_combo.setCurrentText(self.wordlist_data.get('category', 'custom'))
            self.description_input.setText(self.wordlist_data.get('description', ''))
            
            # Load content
            content = wordlist_manager.get_wordlist_content(self.wordlist_data['id'])
            if content:
                self.content_text.setPlainText('\n'.join(content))
    
    def import_from_file(self):
        """Import wordlist from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Wordlist", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                self.content_text.setPlainText(content)
            except Exception:
                pass
    
    def get_wordlist_data(self):
        """Get wordlist data from form"""
        content_text = self.content_text.toPlainText().strip()
        content = [line.strip() for line in content_text.split('\n') if line.strip()]
        
        return {
            'name': self.name_input.text().strip(),
            'category': self.category_combo.currentText().strip(),
            'description': self.description_input.text().strip(),
            'content': content
        }

class MergeDialog(QDialog):
    """Dialog for merging wordlists"""
    
    def __init__(self, wordlists, parent=None):
        super().__init__(parent)
        self.wordlists = wordlists
        self.setup_ui()
    
    def setup_ui(self):
        self.setWindowTitle("Merge Wordlists")
        self.setFixedSize(400, 300)
        
        layout = QVBoxLayout(self)
        
        # Name input
        name_layout = QHBoxLayout()
        name_layout.addWidget(QLabel("New Name:"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Enter merged wordlist name...")
        name_layout.addWidget(self.name_input)
        
        # Wordlist selection
        layout.addWidget(QLabel("Select wordlists to merge:"))
        
        self.wordlist_list = QListWidget()
        for wl in self.wordlists:
            item = QListWidgetItem(f"{wl['name']} ({wl['word_count']} words)")
            item.setData(Qt.ItemDataRole.UserRole, wl['id'])
            item.setCheckState(Qt.CheckState.Unchecked)
            self.wordlist_list.addItem(item)
        
        # Options
        self.remove_duplicates_cb = QCheckBox("Remove duplicates")
        self.remove_duplicates_cb.setChecked(True)
        
        # Buttons
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | 
                                 QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        
        layout.addLayout(name_layout)
        layout.addWidget(self.wordlist_list)
        layout.addWidget(self.remove_duplicates_cb)
        layout.addWidget(buttons)
    
    def get_merge_data(self):
        """Get merge configuration"""
        selected_ids = []
        for i in range(self.wordlist_list.count()):
            item = self.wordlist_list.item(i)
            if item.checkState() == Qt.CheckState.Checked:
                selected_ids.append(item.data(Qt.ItemDataRole.UserRole))
        
        return {
            'name': self.name_input.text().strip(),
            'wordlist_ids': selected_ids,
            'remove_duplicates': self.remove_duplicates_cb.isChecked()
        }

class WordlistWidget(QWidget):
    """Widget for wordlist management"""
    
    wordlist_selected = pyqtSignal(str)  # Signal when wordlist is selected
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.refresh_wordlists()
        
    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # Main group
        main_group = QGroupBox("📝 Custom Wordlist Manager")
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
        
        # Controls
        controls_layout = QHBoxLayout()
        
        self.new_button = QPushButton("📝 New Wordlist")
        self.new_button.clicked.connect(self.create_new_wordlist)
        
        self.edit_button = QPushButton("✏️ Edit")
        self.edit_button.clicked.connect(self.edit_selected_wordlist)
        
        self.delete_button = QPushButton("🗑️ Delete")
        self.delete_button.clicked.connect(self.delete_selected_wordlist)
        
        self.import_button = QPushButton("📁 Import")
        self.import_button.clicked.connect(self.import_wordlist)
        
        self.merge_button = QPushButton("🔗 Merge")
        self.merge_button.clicked.connect(self.merge_wordlists)
        
        self.refresh_button = QPushButton("🔄 Refresh")
        self.refresh_button.clicked.connect(self.refresh_wordlists)
        
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
        
        self.new_button.setStyleSheet(button_style.replace("100, 200, 255", "100, 255, 100"))
        self.edit_button.setStyleSheet(button_style)
        self.delete_button.setStyleSheet(button_style.replace("100, 200, 255", "255, 100, 100"))
        self.import_button.setStyleSheet(button_style)
        self.merge_button.setStyleSheet(button_style.replace("100, 200, 255", "255, 200, 100"))
        self.refresh_button.setStyleSheet(button_style)
        
        controls_layout.addWidget(self.new_button)
        controls_layout.addWidget(self.edit_button)
        controls_layout.addWidget(self.delete_button)
        controls_layout.addWidget(self.import_button)
        controls_layout.addWidget(self.merge_button)
        controls_layout.addWidget(self.refresh_button)
        controls_layout.addStretch()
        
        # Filter
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Category:"))
        
        self.category_filter = QComboBox()
        self.category_filter.addItem("All Categories")
        self.category_filter.currentTextChanged.connect(self.filter_wordlists)
        
        filter_layout.addWidget(self.category_filter)
        filter_layout.addStretch()
        
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
        
        # Wordlists table
        self.wordlists_table = QTableWidget()
        self.wordlists_table.setColumnCount(6)
        self.wordlists_table.setHorizontalHeaderLabels([
            "Name", "Category", "Words", "Type", "Description", "Created"
        ])
        self.wordlists_table.setStyleSheet("""
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
        self.wordlists_table.cellDoubleClicked.connect(self.preview_wordlist)
        self.results_tabs.addTab(self.wordlists_table, "📋 Wordlists")
        
        # Preview tab
        self.preview_text = QTextEdit()
        self.preview_text.setReadOnly(True)
        self.preview_text.setStyleSheet("""
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
        self.results_tabs.addTab(self.preview_text, "👁️ Preview")
        
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
        
        # Status label
        self.status_label = QLabel("Wordlist manager ready")
        self.status_label.setStyleSheet("color: #888; font-size: 10pt; padding: 5px;")
        
        # Add to main layout
        main_layout.addLayout(controls_layout)
        main_layout.addLayout(filter_layout)
        main_layout.addWidget(self.results_tabs)
        main_layout.addWidget(self.status_label)
        
        layout.addWidget(main_group)
        
    def refresh_wordlists(self):
        """Refresh wordlists display"""
        try:
            wordlists = wordlist_manager.get_wordlists()
            
            # Update table
            self.wordlists_table.setRowCount(len(wordlists))
            
            categories = set()
            
            for row, wl in enumerate(wordlists):
                # Name
                name_item = QTableWidgetItem(wl['name'])
                name_item.setData(Qt.ItemDataRole.UserRole, wl['id'])
                self.wordlists_table.setItem(row, 0, name_item)
                
                # Category
                category = wl.get('category', 'unknown')
                categories.add(category)
                category_item = QTableWidgetItem(category)
                self.wordlists_table.setItem(row, 1, category_item)
                
                # Word count
                count_item = QTableWidgetItem(str(wl.get('word_count', 0)))
                self.wordlists_table.setItem(row, 2, count_item)
                
                # Type
                wl_type = wl.get('type', 'unknown')
                type_item = QTableWidgetItem(wl_type)
                if wl_type == 'builtin':
                    type_item.setForeground(Qt.GlobalColor.cyan)
                else:
                    type_item.setForeground(Qt.GlobalColor.green)
                self.wordlists_table.setItem(row, 3, type_item)
                
                # Description
                desc = wl.get('description', '')
                if len(desc) > 30:
                    desc = desc[:27] + "..."
                desc_item = QTableWidgetItem(desc)
                self.wordlists_table.setItem(row, 4, desc_item)
                
                # Created date
                created = wl.get('created_date', 'N/A')
                if created != 'N/A':
                    try:
                        from datetime import datetime
                        dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                        created = dt.strftime('%Y-%m-%d')
                    except:
                        created = created[:10]
                
                created_item = QTableWidgetItem(created)
                self.wordlists_table.setItem(row, 5, created_item)
            
            self.wordlists_table.resizeColumnsToContents()
            
            # Update category filter
            current_filter = self.category_filter.currentText()
            self.category_filter.clear()
            self.category_filter.addItem("All Categories")
            for category in sorted(categories):
                self.category_filter.addItem(category)
            
            # Restore filter selection
            index = self.category_filter.findText(current_filter)
            if index >= 0:
                self.category_filter.setCurrentIndex(index)
            
            # Update statistics
            self.update_statistics()
            
            self.status_label.setText(f"Loaded {len(wordlists)} wordlists")
            self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
            
        except Exception as e:
            self.status_label.setText(f"Error loading wordlists: {str(e)}")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def create_new_wordlist(self):
        """Create new wordlist"""
        dialog = WordlistDialog(parent=self)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_wordlist_data()
            
            if not data['name'] or not data['content']:
                self.status_label.setText("❌ Name and content are required")
                self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
                return
            
            if wordlist_manager.create_wordlist(
                name=data['name'],
                content=data['content'],
                category=data['category'],
                description=data['description']
            ):
                self.refresh_wordlists()
                self.status_label.setText(f"✅ Created wordlist: {data['name']}")
                self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
            else:
                self.status_label.setText("❌ Failed to create wordlist")
                self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def edit_selected_wordlist(self):
        """Edit selected wordlist"""
        current_row = self.wordlists_table.currentRow()
        if current_row < 0:
            self.status_label.setText("❌ Please select a wordlist to edit")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        name_item = self.wordlists_table.item(current_row, 0)
        if name_item:
            wordlist_id = name_item.data(Qt.ItemDataRole.UserRole)
            
            # Get wordlist data
            wordlists = wordlist_manager.get_wordlists()
            wordlist_data = next((wl for wl in wordlists if wl['id'] == wordlist_id), None)
            
            if wordlist_data and wordlist_data['type'] == 'custom':
                dialog = WordlistDialog(wordlist_data=wordlist_data, parent=self)
                
                if dialog.exec() == QDialog.DialogCode.Accepted:
                    data = dialog.get_wordlist_data()
                    
                    if wordlist_manager.update_wordlist(
                        wordlist_id=wordlist_id,
                        name=data['name'],
                        content=data['content'],
                        description=data['description']
                    ):
                        self.refresh_wordlists()
                        self.status_label.setText(f"✅ Updated wordlist: {data['name']}")
                        self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
                    else:
                        self.status_label.setText("❌ Failed to update wordlist")
                        self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            else:
                self.status_label.setText("❌ Cannot edit built-in wordlists")
                self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def delete_selected_wordlist(self):
        """Delete selected wordlist"""
        current_row = self.wordlists_table.currentRow()
        if current_row < 0:
            self.status_label.setText("❌ Please select a wordlist to delete")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        name_item = self.wordlists_table.item(current_row, 0)
        if name_item:
            wordlist_id = name_item.data(Qt.ItemDataRole.UserRole)
            
            # Check if it's a custom wordlist
            wordlists = wordlist_manager.get_wordlists()
            wordlist_data = next((wl for wl in wordlists if wl['id'] == wordlist_id), None)
            
            if wordlist_data and wordlist_data['type'] == 'custom':
                if wordlist_manager.delete_wordlist(wordlist_id):
                    self.refresh_wordlists()
                    self.status_label.setText(f"🗑️ Deleted wordlist: {wordlist_data['name']}")
                    self.status_label.setStyleSheet("color: #FFAA00; font-size: 10pt; padding: 5px;")
                else:
                    self.status_label.setText("❌ Failed to delete wordlist")
                    self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            else:
                self.status_label.setText("❌ Cannot delete built-in wordlists")
                self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def import_wordlist(self):
        """Import wordlist from file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Wordlist", "", "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            import os
            name = os.path.basename(file_path).replace('.txt', '')
            
            if wordlist_manager.import_wordlist(file_path, name, "imported"):
                self.refresh_wordlists()
                self.status_label.setText(f"📁 Imported wordlist: {name}")
                self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
            else:
                self.status_label.setText("❌ Failed to import wordlist")
                self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def merge_wordlists(self):
        """Merge multiple wordlists"""
        wordlists = wordlist_manager.get_wordlists()
        
        if len(wordlists) < 2:
            self.status_label.setText("❌ Need at least 2 wordlists to merge")
            self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
            return
        
        dialog = MergeDialog(wordlists, parent=self)
        
        if dialog.exec() == QDialog.DialogCode.Accepted:
            data = dialog.get_merge_data()
            
            if not data['name'] or len(data['wordlist_ids']) < 2:
                self.status_label.setText("❌ Name and at least 2 wordlists required")
                self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
                return
            
            if wordlist_manager.merge_wordlists(
                wordlist_ids=data['wordlist_ids'],
                new_name=data['name'],
                remove_duplicates=data['remove_duplicates']
            ):
                self.refresh_wordlists()
                self.status_label.setText(f"🔗 Merged wordlist: {data['name']}")
                self.status_label.setStyleSheet("color: #00AA00; font-size: 10pt; padding: 5px;")
            else:
                self.status_label.setText("❌ Failed to merge wordlists")
                self.status_label.setStyleSheet("color: #FF4444; font-size: 10pt; padding: 5px;")
    
    def filter_wordlists(self):
        """Filter wordlists by category"""
        category = self.category_filter.currentText()
        
        for row in range(self.wordlists_table.rowCount()):
            if category == "All Categories":
                self.wordlists_table.setRowHidden(row, False)
            else:
                category_item = self.wordlists_table.item(row, 1)
                if category_item and category_item.text() == category:
                    self.wordlists_table.setRowHidden(row, False)
                else:
                    self.wordlists_table.setRowHidden(row, True)
    
    def preview_wordlist(self, row, column):
        """Preview wordlist content"""
        name_item = self.wordlists_table.item(row, 0)
        if name_item:
            wordlist_id = name_item.data(Qt.ItemDataRole.UserRole)
            content = wordlist_manager.get_wordlist_content(wordlist_id)
            
            if content:
                preview_text = f"Wordlist Preview: {name_item.text()}\n"
                preview_text += "=" * 40 + "\n\n"
                
                # Show first 100 words
                preview_words = content[:100]
                preview_text += '\n'.join(preview_words)
                
                if len(content) > 100:
                    preview_text += f"\n\n... and {len(content) - 100} more words"
                
                self.preview_text.setPlainText(preview_text)
                self.results_tabs.setCurrentIndex(1)  # Switch to preview tab
    
    def update_statistics(self):
        """Update statistics display"""
        stats = wordlist_manager.get_wordlist_statistics()
        
        stats_text = "Wordlist Statistics\n"
        stats_text += "=" * 20 + "\n\n"
        
        stats_text += f"Total Wordlists: {stats.get('total_wordlists', 0)}\n"
        stats_text += f"Custom Wordlists: {stats.get('custom_wordlists', 0)}\n"
        stats_text += f"Built-in Wordlists: {stats.get('builtin_wordlists', 0)}\n"
        stats_text += f"Total Words: {stats.get('total_words', 0):,}\n\n"
        
        # Categories
        categories = stats.get('categories', {})
        if categories:
            stats_text += "Categories:\n"
            stats_text += "-" * 10 + "\n"
            for category, count in categories.items():
                stats_text += f"{category}: {count}\n"
        
        self.stats_text.setPlainText(stats_text)