# app/widgets/crawl_tree_widget.py
from PyQt6.QtWidgets import QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget, QLabel
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from urllib.parse import urlparse
import os

class CrawlTreeWidget(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        
        self.label = QLabel("")
        self.label.setStyleSheet("color: #64C8FF; font-weight: bold; font-size: 12pt;")
        self.label.setVisible(False)
        self.layout.addWidget(self.label)
        
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Field", "Value", ""])
        self.tree.setHeaderHidden(False)
        self.tree.setColumnWidth(0, 300)
        self.tree.setColumnWidth(1, 80)
        self.tree.setColumnWidth(2, 60)
        self.tree.setStyleSheet("""
            QTreeWidget {
                background-color: rgba(20, 30, 40, 150);
                color: #DCDCDC;
                border: 1px solid rgba(100, 200, 255, 100);
                font-family: Consolas, Monaco, monospace;
                font-size: 12px;
            }
            QTreeWidget::item {
                padding: 4px;
                border-bottom: 1px solid rgba(100, 200, 255, 50);
            }
            QTreeWidget::item:hover {
                background-color: rgba(100, 200, 255, 50);
            }
            QTreeWidget::item:selected {
                background-color: rgba(100, 200, 255, 100);
            }
            QHeaderView::section {
                background-color: rgba(40, 50, 60, 200);
                color: #64C8FF;
                border: 1px solid rgba(100, 200, 255, 100);
                padding: 4px;
                font-weight: bold;
            }
        """)
        self.layout.addWidget(self.tree)
        
        self.url_items = {}  # Track items by URL
        self.path_items = {}  # Track items by path
        
    def add_url(self, url, parent_url="", file_size=None, status_code=None, title=None, node_type=None):
        """Add discovered URL to tree structure with file info"""
        from PyQt6.QtGui import QFont
        
        # Handle hierarchical fingerprint data
        if '/Fingerprint' in url or '/Accessible Files' in url or '/JavaScript Analysis' in url:
            return self._add_fingerprint_node(url, title, status_code, node_type)
        
        parsed = urlparse(url)
        path_parts = [part for part in parsed.path.split('/') if part]
        
        # Handle root path
        if not path_parts:
            path_parts = ['/']
        
        # Check if this path already exists to avoid duplicates
        full_path = parsed.path
        if full_path in self.path_items:
            # Update existing item with new info if provided
            existing_item = self.path_items[full_path]
            if file_size and file_size != "Unknown":
                existing_item.setText(1, str(file_size) + "b" if isinstance(file_size, int) else str(file_size))
            if status_code:
                existing_item.setText(2, str(status_code))
                # Color code by status
                if status_code == 200:
                    existing_item.setForeground(2, Qt.GlobalColor.green)
                elif status_code in [301, 302]:
                    existing_item.setForeground(2, Qt.GlobalColor.yellow)
                elif status_code == 403:
                    existing_item.setForeground(2, Qt.GlobalColor.red)
                else:
                    existing_item.setForeground(2, Qt.GlobalColor.white)
            return
        
        # Start from root
        current_item = None
        current_path = ""
        
        # Build tree structure
        for i, part in enumerate(path_parts):
            if part == '/':
                current_path = '/'
            else:
                current_path += "/" + part
            
            if current_path not in self.path_items:
                # Create new item
                if current_item is None:
                    # Root level item
                    item = QTreeWidgetItem(self.tree)
                else:
                    # Child item
                    item = QTreeWidgetItem(current_item)
                
                # Determine if it's a file or directory
                is_file = '.' in part and i == len(path_parts) - 1
                
                # Set display text and styling with columns
                if is_file:
                    # File with separate columns
                    item.setText(0, f"📄 {part}")
                    # Format file size
                    if file_size and file_size != "Unknown":
                        if isinstance(file_size, int):
                            item.setText(1, f"{file_size}b")
                        else:
                            item.setText(1, str(file_size))
                    else:
                        item.setText(1, "Unknown")
                    item.setText(2, str(status_code) if status_code else "")
                    item.setForeground(0, Qt.GlobalColor.green)
                    item.setForeground(1, Qt.GlobalColor.yellow)
                    # Color code status by value
                    if status_code == 200:
                        item.setForeground(2, Qt.GlobalColor.green)
                    elif status_code in [301, 302]:
                        item.setForeground(2, Qt.GlobalColor.yellow)
                    elif status_code == 403:
                        item.setForeground(2, Qt.GlobalColor.red)
                    else:
                        item.setForeground(2, Qt.GlobalColor.white)
                    # Make files slightly smaller font
                    font = QFont()
                    font.setPointSize(9)
                    item.setFont(0, font)
                else:
                    # Directory
                    item.setText(0, f"📁 {part}")
                    item.setText(1, "")
                    item.setText(2, str(status_code) if status_code else "")
                    item.setForeground(0, Qt.GlobalColor.cyan)
                    # Color code directory status
                    if status_code == 200:
                        item.setForeground(2, Qt.GlobalColor.green)
                    elif status_code in [301, 302]:
                        item.setForeground(2, Qt.GlobalColor.yellow)
                    elif status_code == 403:
                        item.setForeground(2, Qt.GlobalColor.red)
                    else:
                        item.setForeground(2, Qt.GlobalColor.white)
                    # Make directories bold
                    font = QFont()
                    font.setBold(True)
                    item.setFont(0, font)
                
                # Add tooltip with full URL
                item.setToolTip(0, url)
                
                self.path_items[current_path] = item
                current_item = item
                
                # Auto-expand directories but not files
                if not is_file:
                    self.tree.expandItem(item)
            else:
                current_item = self.path_items[current_path]
        
        # Update the tree display
        self.tree.update()
    
    def clear(self):
        """Clear the tree"""
        self.tree.clear()
        self.url_items.clear()
        self.path_items.clear()
    
    def get_discovered_paths(self):
        """Get all discovered paths from tree"""
        return list(self.path_items.keys())
    
    def has_path(self, path):
        """Check if a path already exists in the tree"""
        return path in self.path_items
    
    def update_path_info(self, path, file_size=None, status_code=None):
        """Update existing path with additional information"""
        if path in self.path_items:
            item = self.path_items[path]
            if file_size and file_size != "Unknown":
                if isinstance(file_size, int):
                    item.setText(1, f"{file_size}b")
                else:
                    item.setText(1, str(file_size))
            if status_code:
                item.setText(2, str(status_code))
                # Color code by status
                if status_code == 200:
                    item.setForeground(2, Qt.GlobalColor.green)
                elif status_code in [301, 302]:
                    item.setForeground(2, Qt.GlobalColor.yellow)
                elif status_code == 403:
                    item.setForeground(2, Qt.GlobalColor.red)
                else:
                    item.setForeground(2, Qt.GlobalColor.white)
    
    def _add_fingerprint_node(self, url, title, status_code, node_type):
        """Add fingerprint hierarchy nodes"""
        from PyQt6.QtGui import QFont
        
        # Parse the hierarchical URL structure
        parts = url.split('/')
        
        # Find or create parent items
        current_item = None
        current_path = ""
        
        for i, part in enumerate(parts):
            if not part:
                continue
                
            current_path += "/" + part if current_path else part
            
            if current_path not in self.path_items:
                # Create new item
                if current_item is None:
                    item = QTreeWidgetItem(self.tree)
                else:
                    item = QTreeWidgetItem(current_item)
                
                # Determine display based on part content
                if 'Fingerprint' in part and i < len(parts) - 1:
                    # Main category
                    item.setText(0, "🔍 Fingerprint")
                    item.setForeground(0, Qt.GlobalColor.cyan)
                    font = QFont()
                    font.setBold(True)
                    item.setFont(0, font)
                elif 'Accessible Files' in part and i < len(parts) - 1:
                    # Files category
                    item.setText(0, "📁 Accessible Files")
                    item.setForeground(0, Qt.GlobalColor.green)
                    font = QFont()
                    font.setBold(True)
                    item.setFont(0, font)
                elif 'JavaScript Analysis' in part and i < len(parts) - 1:
                    # JS category
                    item.setText(0, "⚡ JavaScript Analysis")
                    item.setForeground(0, Qt.GlobalColor.yellow)
                    font = QFont()
                    font.setBold(True)
                    item.setFont(0, font)
                elif i == len(parts) - 1 and title:
                    # Leaf node with actual data
                    if node_type == 'file':
                        item.setText(0, f"📄 {title}")
                        item.setForeground(0, Qt.GlobalColor.green)
                    elif node_type == 'detail':
                        item.setText(0, f"ℹ️ {title}")
                        item.setForeground(0, Qt.GlobalColor.white)
                    elif 'File_' in part:
                        item.setText(0, f"📜 {title}")
                        item.setForeground(0, Qt.GlobalColor.yellow)
                    else:
                        item.setText(0, title)
                        item.setForeground(0, Qt.GlobalColor.white)
                else:
                    # Intermediate node
                    display_part = part.replace('_', ' ').title()
                    item.setText(0, display_part)
                    item.setForeground(0, Qt.GlobalColor.lightGray)
                
                # Set status code if provided
                if status_code:
                    item.setText(2, str(status_code))
                    if status_code == 200:
                        item.setForeground(2, Qt.GlobalColor.green)
                    elif status_code in [301, 302]:
                        item.setForeground(2, Qt.GlobalColor.yellow)
                    elif status_code == 403:
                        item.setForeground(2, Qt.GlobalColor.red)
                
                # Set tooltip
                item.setToolTip(0, url)
                
                self.path_items[current_path] = item
                current_item = item
                
                # Auto-expand categories
                if any(cat in part for cat in ['Fingerprint', 'Accessible Files', 'JavaScript Analysis']):
                    self.tree.expandItem(item)
            else:
                current_item = self.path_items[current_path]
        
        self.tree.update()
    
    def update_from_crawl_data(self, crawl_data, scan_type=None):
        """Update tree from crawl data dictionary"""
        if not crawl_data:
            return
            
        # Check scan type first, then data structure
        if scan_type == "Fingerprinting" or (scan_type != "Crawler" and self._is_fingerprint_data(crawl_data)):
            self._build_fingerprint_tree(crawl_data)
        elif scan_type in ["Directory Enum", "Source Code", "Crawler", "Enterprise Scripts", "Huggin Scan"]:
            self._build_scan_type_tree(crawl_data, scan_type)
        else:
            # Regular crawl data - reset to crawl view
            self.label.setText("Crawl Results")
            self.tree.setHeaderLabels(["Path", "Size", "Status"])
            self.tree.setHeaderHidden(False)
            for url, data in crawl_data.items():
                self.add_url(
                    url=url,
                    status_code=data.get('status_code'),
                    title=data.get('title'),
                    node_type=data.get('type')
                )
    
    def _is_fingerprint_data(self, crawl_data):
        """Check if data is fingerprint hierarchical structure"""
        for key, value in crawl_data.items():
            if isinstance(value, dict) and 'name' in value and 'type' in value:
                return True
        return False
    
    def _build_fingerprint_tree(self, crawl_data):
        """Build expandable fingerprint tree structure"""
        from PyQt6.QtGui import QFont
        
        # Clear first to avoid header conflicts
        self.clear()
        
        # Set table headers for fingerprint view
        self.tree.setHeaderLabels(["Field", "Value", ""])
        self.tree.setHeaderHidden(False)
        
        for key, data in crawl_data.items():
            if isinstance(data, dict) and 'name' in data:
                # Create main category item
                category_item = QTreeWidgetItem(self.tree)
                category_item.setText(0, self._get_category_icon(data['type']) + data['name'])
                category_item.setForeground(0, self._get_category_color(data['type']))
                
                # Make categories bold and expandable
                font = QFont()
                font.setBold(True)
                category_item.setFont(0, font)
                
                # Add children if they exist
                if 'children' in data and data['children']:
                    self._add_fingerprint_children(category_item, data['children'])
                
                # Expand category by default
                self.tree.expandItem(category_item)
    
    def _add_fingerprint_children(self, parent_item, children):
        """Add children to fingerprint tree node"""
        from PyQt6.QtGui import QFont
        
        for child_data in children:
            if isinstance(child_data, dict):
                child_item = QTreeWidgetItem(parent_item)
                
                # Handle field/value structure
                if 'field' in child_data and 'value' in child_data:
                    child_item.setText(0, child_data['field'])
                    child_item.setText(1, child_data['value'])
                    child_item.setForeground(0, self._get_detail_color(child_data.get('type', 'detail')))
                    child_item.setForeground(1, Qt.GlobalColor.white)
                elif 'name' in child_data:
                    # Fallback for old structure
                    child_item.setText(0, self._get_detail_icon(child_data.get('type', 'detail')) + child_data['name'])
                    child_item.setForeground(0, self._get_detail_color(child_data.get('type', 'detail')))
                
                # Handle nested children (like JavaScript files)
                if 'children' in child_data and child_data['children']:
                    self._add_fingerprint_children(child_item, child_data['children'])
                    # Make expandable items slightly bold
                    font = QFont()
                    font.setBold(True)
                    child_item.setFont(0, font)
                    self.tree.expandItem(child_item)
    
    def _get_category_icon(self, category_type):
        """Get icon for category type"""
        icons = {
            'category': '📁 ',
            'fingerprint': '🔍 ',
            'files': '📂 ',
            'javascript': '⚡ '
        }
        return icons.get(category_type, '📁 ')
    
    def _get_category_color(self, category_type):
        """Get color for category type"""
        from PyQt6.QtCore import Qt
        colors = {
            'category': Qt.GlobalColor.cyan,
            'fingerprint': Qt.GlobalColor.cyan,
            'files': Qt.GlobalColor.green,
            'javascript': Qt.GlobalColor.yellow
        }
        return colors.get(category_type, Qt.GlobalColor.cyan)
    
    def _get_detail_icon(self, detail_type):
        """Get icon for detail type"""
        icons = {
            'detail': 'ℹ️ ',
            'file': '📄 ',
            'js_file': '📜 ',
            'security': '🔒 ',
            'server': '🖥️ ',
            'framework': '⚙️ '
        }
        return icons.get(detail_type, 'ℹ️ ')
    
    def _get_detail_color(self, detail_type):
        """Get color for detail type"""
        from PyQt6.QtCore import Qt
        colors = {
            'detail': Qt.GlobalColor.white,
            'file': Qt.GlobalColor.green,
            'js_file': Qt.GlobalColor.yellow,
            'security': Qt.GlobalColor.red,
            'server': Qt.GlobalColor.lightGray,
            'framework': Qt.GlobalColor.magenta
        }
        return colors.get(detail_type, Qt.GlobalColor.white)
    
    def _build_scan_type_tree(self, crawl_data, scan_type):
        """Build tree for specific scan types with field/value structure"""
        from PyQt6.QtGui import QFont
        from PyQt6.QtWidgets import QTreeWidgetItem
        
        self.clear()
        
        # Set appropriate headers based on scan type
        if scan_type == "Directory Enum":
            self.tree.setHeaderLabels(["Path", "Status", "Size"])
        elif scan_type == "Source Code":
            self.tree.setHeaderLabels(["Finding", "Type", "Details"])
        elif scan_type == "Crawler":
            self.tree.setHeaderLabels(["URL", "Title", "Status"])
        else:
            self.tree.setHeaderLabels(["Item", "Value", "Status"])
        
        self.tree.setHeaderHidden(False)
        
        # Handle Source Code hierarchical structure
        if scan_type == "Source Code":
            self._build_source_code_tree(crawl_data)
            return
        
        # Add items directly to tree
        for key, data in crawl_data.items():
            if isinstance(data, dict) and 'field' in data:
                item = QTreeWidgetItem(self.tree)
                item.setText(0, data.get('field', key))
                item.setText(1, data.get('value', ''))
                item.setText(2, data.get('extra', ''))
                
                # Color coding based on type
                item_type = data.get('type', 'default')
                if item_type == 'directory':
                    item.setForeground(0, Qt.GlobalColor.cyan)
                elif item_type == 'finding':
                    item.setForeground(0, Qt.GlobalColor.yellow)
                elif item_type == 'page':
                    item.setForeground(0, Qt.GlobalColor.green)
                else:
                    item.setForeground(0, Qt.GlobalColor.white)
    
    def _build_source_code_tree(self, crawl_data):
        """Build expandable Source Code tree structure"""
        from PyQt6.QtGui import QFont
        from PyQt6.QtWidgets import QTreeWidgetItem
        
        self.clear()
        self.tree.setHeaderLabels(["Finding", "Type", "Details"])
        self.tree.setHeaderHidden(False)
        
        for key, data in crawl_data.items():
            if isinstance(data, dict) and 'name' in data:
                # Create main finding category item
                category_item = QTreeWidgetItem(self.tree)
                category_item.setText(0, data['name'])
                category_item.setText(1, "Category")
                category_item.setForeground(0, Qt.GlobalColor.cyan)
                
                # Make categories bold and expandable
                font = QFont()
                font.setBold(True)
                category_item.setFont(0, font)
                
                # Add children if they exist
                if 'children' in data and data['children']:
                    for child_data in data['children']:
                        if isinstance(child_data, dict):
                            child_item = QTreeWidgetItem(category_item)
                            
                            # Handle field/value structure
                            if 'field' in child_data:
                                child_item.setText(0, child_data['field'])
                                child_item.setText(1, child_data.get('value', ''))
                                child_item.setText(2, child_data.get('extra', ''))
                                
                                # Color coding based on type
                                item_type = child_data.get('type', 'detail')
                                if item_type in ['api_key', 'credential']:
                                    child_item.setForeground(0, Qt.GlobalColor.red)
                                elif item_type in ['email', 'phone']:
                                    child_item.setForeground(0, Qt.GlobalColor.yellow)
                                elif item_type == 'comment':
                                    child_item.setForeground(0, Qt.GlobalColor.green)
                                elif item_type == 'file':
                                    child_item.setForeground(0, Qt.GlobalColor.cyan)
                                else:
                                    child_item.setForeground(0, Qt.GlobalColor.white)
                
                # Expand category by default
                self.tree.expandItem(category_item)