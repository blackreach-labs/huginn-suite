# app/components/knowledge_base_component.py
"""Knowledge Base UI Component.

Provides a comprehensive knowledge base interface with:
- Article browser with category sidebar and search bar
- Markdown article viewer with code block syntax highlighting (HTML rendering)
- Article editor with live preview (side-by-side markdown + rendered HTML)
- Bookmark list for quick access
- Contextual suggestion panel connecting to findings view
- Integrates as Tools menu entry and context-sensitive side panel

Layout: Left sidebar (categories + bookmarks + search) | Center (article list) | Right (viewer/editor)

Requirements: 11.1, 11.2, 11.3, 11.4, 11.6, 11.7
"""

import re
from typing import Dict, List, Optional

from PyQt6.QtCore import Qt, pyqtSignal, QTimer
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.knowledge_base import KnowledgeBase, ARTICLE_CATEGORIES


# ---------------------------------------------------------------------------
# Markdown to HTML conversion (lightweight, no external dependency)
# ---------------------------------------------------------------------------

def _markdown_to_html(markdown_text: str) -> str:
    """Convert markdown text to styled HTML with code block highlighting.

    Handles: headers, bold, italic, code blocks (with language hint),
    inline code, links, lists, and horizontal rules.
    """
    html_lines = []
    in_code_block = False
    code_lang = ""
    code_buffer = []

    for line in markdown_text.split("\n"):
        # Fenced code blocks
        if line.strip().startswith("```"):
            if not in_code_block:
                in_code_block = True
                code_lang = line.strip()[3:].strip()
                code_buffer = []
            else:
                # Close code block with syntax highlighting styling
                code_content = "\n".join(code_buffer)
                code_content = _highlight_code(code_content, code_lang)
                html_lines.append(
                    f'<div style="background-color:#1A1A2A; border:1px solid #3A3A5E; '
                    f'border-radius:4px; padding:8px; margin:6px 0; overflow-x:auto;">'
                    f'<pre style="margin:0; font-family:Consolas,monospace; '
                    f'font-size:12px; color:#E0E0E0;">{code_content}</pre></div>'
                )
                in_code_block = False
                code_lang = ""
            continue

        if in_code_block:
            code_buffer.append(line)
            continue

        # Headers
        if line.startswith("######"):
            html_lines.append(f'<h6 style="color:#00E5FF; margin:4px 0;">{_inline(line[6:].strip())}</h6>')
        elif line.startswith("#####"):
            html_lines.append(f'<h5 style="color:#00E5FF; margin:4px 0;">{_inline(line[5:].strip())}</h5>')
        elif line.startswith("####"):
            html_lines.append(f'<h4 style="color:#00E5FF; margin:6px 0;">{_inline(line[4:].strip())}</h4>')
        elif line.startswith("###"):
            html_lines.append(f'<h3 style="color:#00E5FF; margin:6px 0;">{_inline(line[3:].strip())}</h3>')
        elif line.startswith("##"):
            html_lines.append(f'<h2 style="color:#00E5FF; margin:8px 0;">{_inline(line[2:].strip())}</h2>')
        elif line.startswith("#"):
            html_lines.append(f'<h1 style="color:#00E5FF; margin:10px 0;">{_inline(line[1:].strip())}</h1>')
        # Horizontal rule
        elif re.match(r"^[-*_]{3,}$", line.strip()):
            html_lines.append('<hr style="border-color:#3A3A5E; margin:8px 0;">')
        # Unordered list
        elif re.match(r"^\s*[-*+]\s+", line):
            content = re.sub(r"^\s*[-*+]\s+", "", line)
            html_lines.append(f'<li style="margin:2px 0; margin-left:16px;">{_inline(content)}</li>')
        # Ordered list
        elif re.match(r"^\s*\d+\.\s+", line):
            content = re.sub(r"^\s*\d+\.\s+", "", line)
            html_lines.append(f'<li style="margin:2px 0; margin-left:16px;">{_inline(content)}</li>')
        # Empty line
        elif not line.strip():
            html_lines.append("<br>")
        # Paragraph
        else:
            html_lines.append(f'<p style="margin:4px 0;">{_inline(line)}</p>')

    # Close unclosed code block
    if in_code_block and code_buffer:
        code_content = "\n".join(code_buffer)
        code_content = _highlight_code(code_content, code_lang)
        html_lines.append(
            f'<div style="background-color:#1A1A2A; border:1px solid #3A3A5E; '
            f'border-radius:4px; padding:8px; margin:6px 0;">'
            f'<pre style="margin:0; font-family:Consolas,monospace; '
            f'font-size:12px; color:#E0E0E0;">{code_content}</pre></div>'
        )

    body = "\n".join(html_lines)
    return (
        f'<html><body style="background-color:#1E1E2E; color:#DCDCDC; '
        f'font-family:Neuropol X,sans-serif; font-size:13px; padding:8px;">'
        f'{body}</body></html>'
    )


def _inline(text: str) -> str:
    """Apply inline markdown formatting: bold, italic, inline code, links."""
    # Escape HTML entities first
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Inline code
    text = re.sub(
        r"`([^`]+)`",
        r'<code style="background-color:#2A2A3E; color:#00E5FF; padding:1px 4px; '
        r'border-radius:3px; font-family:Consolas,monospace; font-size:12px;">\1</code>',
        text,
    )
    # Bold
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"__(.+?)__", r"<b>\1</b>", text)
    # Italic
    text = re.sub(r"\*(.+?)\*", r"<i>\1</i>", text)
    text = re.sub(r"_(.+?)_", r"<i>\1</i>", text)
    # Links
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        r'<a href="\2" style="color:#4A9EFF;">\1</a>',
        text,
    )
    return text


def _highlight_code(code: str, lang: str) -> str:
    """Apply basic syntax highlighting colors to code content.

    Supports keyword highlighting for common pentest-related languages:
    python, bash, shell, sql, javascript, powershell.
    """
    # Escape HTML
    code = code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Language-specific keyword sets
    keywords_map = {
        "python": [
            "import", "from", "def", "class", "return", "if", "elif", "else",
            "for", "while", "try", "except", "finally", "with", "as", "pass",
            "break", "continue", "yield", "lambda", "None", "True", "False",
            "and", "or", "not", "in", "is", "raise", "async", "await",
        ],
        "bash": [
            "if", "then", "else", "elif", "fi", "for", "do", "done", "while",
            "case", "esac", "function", "return", "export", "source", "echo",
            "sudo", "grep", "awk", "sed", "cat", "ls", "cd", "chmod", "curl",
            "wget", "nmap", "nikto", "sqlmap", "hydra", "john", "hashcat",
        ],
        "powershell": [
            "function", "param", "if", "else", "elseif", "foreach", "while",
            "do", "switch", "try", "catch", "finally", "return", "Import-Module",
            "Get-", "Set-", "New-", "Remove-", "Invoke-", "Write-Host",
        ],
        "sql": [
            "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "CREATE",
            "DROP", "ALTER", "JOIN", "LEFT", "RIGHT", "INNER", "ON", "AND",
            "OR", "NOT", "NULL", "INTO", "VALUES", "TABLE", "INDEX", "ORDER",
            "BY", "GROUP", "HAVING", "LIMIT", "UNION",
        ],
        "javascript": [
            "function", "const", "let", "var", "return", "if", "else", "for",
            "while", "class", "new", "this", "import", "export", "from",
            "async", "await", "try", "catch", "throw", "null", "undefined",
            "true", "false",
        ],
    }

    # Normalize lang
    lang_lower = lang.lower().strip() if lang else ""
    if lang_lower in ("sh", "shell", "zsh"):
        lang_lower = "bash"
    elif lang_lower in ("ps", "ps1"):
        lang_lower = "powershell"
    elif lang_lower in ("js", "ts", "typescript"):
        lang_lower = "javascript"
    elif lang_lower in ("py", "python3"):
        lang_lower = "python"

    keywords = keywords_map.get(lang_lower, [])

    if keywords:
        # Highlight strings FIRST (before any HTML spans are inserted)
        code = re.sub(
            r'(&quot;.*?&quot;|&#x27;.*?&#x27;)',
            r'<span style="color:#CE9178;">\1</span>',
            code,
        )
        # Also handle unescaped quotes that survived (single quotes)
        code = re.sub(
            r"(?<!=)(?<!&)'([^'<]*?)'",
            r"<span style=\"color:#CE9178;\">'\1'</span>",
            code,
        )

        # Highlight comments (# for most, -- for SQL)
        if lang_lower == "sql":
            code = re.sub(
                r"(--[^\n<]*)$",
                r'<span style="color:#6A9955;">\1</span>',
                code,
                flags=re.MULTILINE,
            )
        else:
            code = re.sub(
                r"(#[^\n<]*)$",
                r'<span style="color:#6A9955;">\1</span>',
                code,
                flags=re.MULTILINE,
            )

        # Highlight keywords (word boundary)
        for kw in keywords:
            code = re.sub(
                rf"\b({re.escape(kw)})\b",
                r'<span style="color:#569CD6;">\1</span>',
                code,
            )

    return code


# ---------------------------------------------------------------------------
# Article List Item Widget
# ---------------------------------------------------------------------------

class ArticleListItemWidget(QWidget):
    """Custom widget for an article list item with category badge and bookmark."""

    bookmark_toggled = pyqtSignal(int)  # article_id

    def __init__(self, article: Dict, parent=None):
        super().__init__(parent)
        self.article_id = article["id"]
        self.bookmarked = article.get("bookmarked", False)
        self._setup_ui(article)

    def _setup_ui(self, article: Dict):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(8)

        # Bookmark toggle
        self.bookmark_btn = QPushButton("★" if self.bookmarked else "☆")
        self.bookmark_btn.setFixedSize(24, 24)
        self.bookmark_btn.setToolTip(
            "Remove bookmark" if self.bookmarked else "Bookmark article"
        )
        self.bookmark_btn.setStyleSheet(self._bookmark_style())
        self.bookmark_btn.clicked.connect(self._on_bookmark_clicked)
        layout.addWidget(self.bookmark_btn)

        # Category badge
        category = article.get("category", "")
        badge_color = _category_color(category)
        badge_label = QLabel(category[:4].upper())
        badge_label.setFixedWidth(40)
        badge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        badge_label.setStyleSheet(
            f"background-color: {badge_color}; color: #FFFFFF; "
            f"border-radius: 3px; font-size: 9px; font-weight: bold; "
            f"padding: 2px 3px;"
        )
        layout.addWidget(badge_label)

        # Title and meta
        info_layout = QVBoxLayout()
        info_layout.setSpacing(1)
        info_layout.setContentsMargins(0, 0, 0, 0)

        title_label = QLabel(article["title"])
        title_label.setStyleSheet("color: #E0E0E0; font-size: 12px; font-weight: bold;")
        info_layout.addWidget(title_label)

        tags = article.get("tags") or []
        tags_str = ", ".join(tags[:4]) if tags else ""
        meta_text = f"{category}"
        if tags_str:
            meta_text += f" • {tags_str}"
        meta_label = QLabel(meta_text)
        meta_label.setStyleSheet("color: #808080; font-size: 10px;")
        info_layout.addWidget(meta_label)

        layout.addLayout(info_layout, 1)

    def _bookmark_style(self) -> str:
        if self.bookmarked:
            return (
                "QPushButton { background: transparent; color: #FFD700; "
                "border: none; font-size: 16px; } "
                "QPushButton:hover { color: #FFF8DC; }"
            )
        return (
            "QPushButton { background: transparent; color: #666666; "
            "border: none; font-size: 16px; } "
            "QPushButton:hover { color: #FFD700; }"
        )

    def _on_bookmark_clicked(self):
        self.bookmarked = not self.bookmarked
        self.bookmark_btn.setText("★" if self.bookmarked else "☆")
        self.bookmark_btn.setToolTip(
            "Remove bookmark" if self.bookmarked else "Bookmark article"
        )
        self.bookmark_btn.setStyleSheet(self._bookmark_style())
        self.bookmark_toggled.emit(self.article_id)


def _category_color(category: str) -> str:
    """Return a color for a given category."""
    colors = {
        "Reconnaissance": "#4A9EFF",
        "Exploitation": "#FF5252",
        "Post-Exploitation": "#FF9800",
        "Web Application": "#AB47BC",
        "Network": "#00BCD4",
        "Cloud": "#66BB6A",
        "Reporting": "#78909C",
    }
    return colors.get(category, "#555555")


# ---------------------------------------------------------------------------
# Knowledge Base Component
# ---------------------------------------------------------------------------

class KnowledgeBaseComponent(QWidget):
    """Main knowledge base UI component.

    Layout: Left sidebar (categories + bookmarks + search) |
            Center (article list) |
            Right (viewer/editor)

    Signals:
        article_selected(int): Emitted when an article is selected.
        suggestion_clicked(int): Emitted when a contextual suggestion is clicked.
    """

    article_selected = pyqtSignal(int)
    suggestion_clicked = pyqtSignal(int)

    def __init__(self, knowledge_base: KnowledgeBase, parent=None):
        super().__init__(parent)
        self.kb = knowledge_base
        self._current_article_id: Optional[int] = None
        self._editing = False
        self._articles_cache: List[Dict] = []

        self._setup_ui()
        self._apply_theme()
        self._connect_signals()

        # Initial load
        QTimer.singleShot(0, self._load_categories)
        QTimer.singleShot(0, self._load_all_articles)

    # ------------------------------------------------------------------
    # UI Setup
    # ------------------------------------------------------------------

    def _setup_ui(self):
        """Build the three-panel layout."""
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Main splitter: Left | Center | Right
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # --- LEFT SIDEBAR ---
        self.left_sidebar = QWidget()
        left_layout = QVBoxLayout(self.left_sidebar)
        left_layout.setContentsMargins(8, 8, 4, 8)
        left_layout.setSpacing(6)

        # Title
        title_label = QLabel("Knowledge Base")
        title_label.setStyleSheet(
            "font-size: 14px; font-weight: bold; color: #00E5FF;"
        )
        left_layout.addWidget(title_label)

        # Search bar
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search articles...")
        self.search_input.setClearButtonEnabled(True)
        left_layout.addWidget(self.search_input)

        # Category list
        cat_label = QLabel("Categories")
        cat_label.setStyleSheet("color: #00E5FF; font-size: 11px; font-weight: bold; margin-top: 6px;")
        left_layout.addWidget(cat_label)

        self.category_list = QListWidget()
        self.category_list.setMinimumHeight(250)
        left_layout.addWidget(self.category_list)

        # Bookmarks section
        bm_label = QLabel("Bookmarks")
        bm_label.setStyleSheet("color: #FFD700; font-size: 11px; font-weight: bold; margin-top: 6px;")
        left_layout.addWidget(bm_label)

        self.bookmark_list = QListWidget()
        self.bookmark_list.setMaximumHeight(160)
        left_layout.addWidget(self.bookmark_list)

        # Contextual Suggestions section
        sug_label = QLabel("Suggestions")
        sug_label.setStyleSheet("color: #66BB6A; font-size: 11px; font-weight: bold; margin-top: 6px;")
        left_layout.addWidget(sug_label)

        self.suggestion_list = QListWidget()
        left_layout.addWidget(self.suggestion_list, 1)

        self.left_sidebar.setMinimumWidth(280)
        self.left_sidebar.setMaximumWidth(360)
        self.main_splitter.addWidget(self.left_sidebar)

        # --- CENTER: Article List ---
        self.center_panel = QWidget()
        center_layout = QVBoxLayout(self.center_panel)
        center_layout.setContentsMargins(4, 8, 4, 8)
        center_layout.setSpacing(6)

        # Center header with article count
        center_header = QHBoxLayout()
        self.article_count_label = QLabel("Articles (0)")
        self.article_count_label.setStyleSheet("color: #AAAAAA; font-size: 11px;")
        center_header.addWidget(self.article_count_label)
        center_header.addStretch()

        self.new_article_btn = QPushButton("+ New Article")
        self.new_article_btn.setMinimumHeight(26)
        center_header.addWidget(self.new_article_btn)

        center_layout.addLayout(center_header)

        self.article_list = QListWidget()
        center_layout.addWidget(self.article_list, 1)

        self.center_panel.setMinimumWidth(250)
        self.main_splitter.addWidget(self.center_panel)

        # --- RIGHT: Viewer / Editor (stacked) ---
        self.right_panel = QWidget()
        right_layout = QVBoxLayout(self.right_panel)
        right_layout.setContentsMargins(4, 8, 8, 8)
        right_layout.setSpacing(6)

        # Toolbar for viewer/editor
        toolbar = QHBoxLayout()
        self.edit_btn = QPushButton("Edit")
        self.edit_btn.setMinimumHeight(26)
        self.edit_btn.setEnabled(False)
        toolbar.addWidget(self.edit_btn)

        self.save_btn = QPushButton("Save")
        self.save_btn.setMinimumHeight(26)
        self.save_btn.setEnabled(False)
        toolbar.addWidget(self.save_btn)

        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setMinimumHeight(26)
        self.cancel_btn.setEnabled(False)
        toolbar.addWidget(self.cancel_btn)

        self.delete_btn = QPushButton("Delete")
        self.delete_btn.setMinimumHeight(26)
        self.delete_btn.setEnabled(False)
        self.delete_btn.setStyleSheet(
            "QPushButton { color: #FF5252; } "
            "QPushButton:hover { background-color: #FF5252; color: #FFFFFF; }"
        )
        toolbar.addWidget(self.delete_btn)

        toolbar.addStretch()

        self.bookmark_article_btn = QPushButton("☆ Bookmark")
        self.bookmark_article_btn.setMinimumHeight(26)
        self.bookmark_article_btn.setEnabled(False)
        toolbar.addWidget(self.bookmark_article_btn)

        right_layout.addLayout(toolbar)

        # Stacked widget: viewer vs editor
        self.right_stack = QStackedWidget()

        # Page 0: Viewer (rendered HTML)
        self.viewer = QTextEdit()
        self.viewer.setReadOnly(True)
        self.viewer.setPlaceholderText("Select an article to view...")
        self.right_stack.addWidget(self.viewer)

        # Page 1: Editor (side-by-side markdown + preview)
        self.editor_widget = QWidget()
        editor_layout = QVBoxLayout(self.editor_widget)
        editor_layout.setContentsMargins(0, 0, 0, 0)
        editor_layout.setSpacing(4)

        # Metadata fields for editor
        meta_frame = QFrame()
        meta_frame.setObjectName("metaFrame")
        meta_form = QFormLayout(meta_frame)
        meta_form.setContentsMargins(4, 4, 4, 4)

        self.edit_title = QLineEdit()
        self.edit_title.setPlaceholderText("Article title")
        meta_form.addRow("Title:", self.edit_title)

        self.edit_category = QComboBox()
        self.edit_category.addItems(ARTICLE_CATEGORIES)
        meta_form.addRow("Category:", self.edit_category)

        self.edit_tags = QLineEdit()
        self.edit_tags.setPlaceholderText("tag1, tag2, tag3")
        meta_form.addRow("Tags:", self.edit_tags)

        editor_layout.addWidget(meta_frame)

        # Side-by-side: markdown editor | rendered preview
        self.editor_splitter = QSplitter(Qt.Orientation.Horizontal)

        self.markdown_editor = QTextEdit()
        self.markdown_editor.setPlaceholderText(
            "Write article content in Markdown...\n\n"
            "Supports: # Headers, **bold**, *italic*, `code`, ```code blocks```, "
            "- lists, [links](url)"
        )
        self.markdown_editor.setFont(QFont("Neuropol X", 11))
        self.editor_splitter.addWidget(self.markdown_editor)

        self.live_preview = QTextEdit()
        self.live_preview.setReadOnly(True)
        self.live_preview.setPlaceholderText("Live preview will appear here...")
        self.editor_splitter.addWidget(self.live_preview)

        self.editor_splitter.setStretchFactor(0, 1)
        self.editor_splitter.setStretchFactor(1, 1)

        editor_layout.addWidget(self.editor_splitter, 1)
        self.right_stack.addWidget(self.editor_widget)

        right_layout.addWidget(self.right_stack, 1)

        self.right_panel.setMinimumWidth(400)
        self.main_splitter.addWidget(self.right_panel)

        # Splitter proportions
        self.main_splitter.setStretchFactor(0, 1)  # Left sidebar
        self.main_splitter.setStretchFactor(1, 2)  # Center article list
        self.main_splitter.setStretchFactor(2, 3)  # Right viewer/editor

        main_layout.addWidget(self.main_splitter)

    # ------------------------------------------------------------------
    # Theme
    # ------------------------------------------------------------------

    def _apply_theme(self):
        """Theme is applied globally by UnifiedThemeManager."""
        pass

    # ------------------------------------------------------------------
    # Signal Connections
    # ------------------------------------------------------------------

    def _connect_signals(self):
        """Connect UI signals to handlers."""
        # Search
        self.search_input.textChanged.connect(self._on_search_changed)
        self.search_input.returnPressed.connect(self._on_search)

        # Category selection
        self.category_list.currentRowChanged.connect(self._on_category_selected)

        # Bookmark list
        self.bookmark_list.currentRowChanged.connect(self._on_bookmark_selected)
        self.bookmark_list.itemClicked.connect(self._on_bookmark_clicked)

        # Suggestion list
        self.suggestion_list.itemDoubleClicked.connect(self._on_suggestion_clicked)

        # Article list
        self.article_list.currentRowChanged.connect(self._on_article_selected)

        # Toolbar
        self.new_article_btn.clicked.connect(self._on_new_article)
        self.edit_btn.clicked.connect(self._on_edit)
        self.save_btn.clicked.connect(self._on_save)
        self.cancel_btn.clicked.connect(self._on_cancel_edit)
        self.delete_btn.clicked.connect(self._on_delete)
        self.bookmark_article_btn.clicked.connect(self._on_toggle_bookmark)

        # Live preview update on editor changes
        self.markdown_editor.textChanged.connect(self._on_editor_text_changed)

        # KnowledgeBase signals
        self.kb.article_created.connect(self._on_kb_changed)
        self.kb.article_updated.connect(self._on_kb_changed)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def show_suggestions(
        self,
        finding_category: Optional[str] = None,
        keywords: Optional[List[str]] = None,
    ) -> None:
        """Load contextual suggestions based on finding context.

        Call this from the findings view to populate the suggestion panel.

        Args:
            finding_category: The finding's category.
            keywords: Keywords from the finding.
        """
        suggestions = self.kb.get_suggestions(
            finding_category=finding_category,
            keywords=keywords,
        )
        self.suggestion_list.clear()
        for article in suggestions[:15]:
            item = QListWidgetItem(f"💡 {article['title']}")
            item.setData(Qt.ItemDataRole.UserRole, article["id"])
            item.setToolTip(f"{article['category']} — {article['title']}")
            self.suggestion_list.addItem(item)

    def open_article(self, article_id: int) -> None:
        """Programmatically open a specific article in the viewer.

        Args:
            article_id: The article ID to display.
        """
        article = self.kb.get_article(article_id)
        if article:
            self._current_article_id = article_id

            # Load all articles into center list first (block signals to prevent
            # the clear() from triggering _on_article_selected with row -1)
            self.article_list.blockSignals(True)
            self._articles_cache = self.kb.list_articles()
            self._populate_article_list(self._articles_cache)
            self._load_bookmarks()

            # Select the matching article in the center list
            for i in range(self.article_list.count()):
                item = self.article_list.item(i)
                if item and item.data(Qt.ItemDataRole.UserRole) == article_id:
                    self.article_list.setCurrentRow(i)
                    break
            self.article_list.blockSignals(False)

            # Now show the article content
            self._show_article_in_viewer(article)
            self._set_toolbar_state(viewing=True)
            self.article_selected.emit(article_id)

    def refresh(self) -> None:
        """Refresh all panels."""
        self._load_categories()
        self._load_all_articles()
        self._load_bookmarks()

    # ------------------------------------------------------------------
    # Data Loading
    # ------------------------------------------------------------------

    def _load_categories(self):
        """Load categories into the sidebar list."""
        self.category_list.blockSignals(True)
        self.category_list.clear()

        # "All" entry
        all_item = QListWidgetItem("📁 All Articles")
        all_item.setData(Qt.ItemDataRole.UserRole, None)
        self.category_list.addItem(all_item)

        categories = self.kb.get_categories()
        for cat in categories:
            item = QListWidgetItem(f"  {cat}")
            item.setData(Qt.ItemDataRole.UserRole, cat)
            self.category_list.addItem(item)

        self.category_list.blockSignals(False)
        self.category_list.setCurrentRow(0)

    def _load_all_articles(self):
        """Load all articles into the center article list."""
        self._articles_cache = self.kb.list_articles()
        self._populate_article_list(self._articles_cache)
        self._load_bookmarks()

    def _load_articles_for_category(self, category: Optional[str]):
        """Load articles filtered by category."""
        if category:
            self._articles_cache = self.kb.list_articles(category=category)
        else:
            self._articles_cache = self.kb.list_articles()
        self._populate_article_list(self._articles_cache)

    def _load_bookmarks(self):
        """Load bookmarked articles into the bookmark list."""
        self.bookmark_list.clear()
        bookmarked = self.kb.list_articles(bookmarked_only=True)
        for article in bookmarked:
            item = QListWidgetItem(f"★ {article['title']}")
            item.setData(Qt.ItemDataRole.UserRole, article["id"])
            item.setToolTip(article["category"])
            self.bookmark_list.addItem(item)

    def _populate_article_list(self, articles: List[Dict]):
        """Populate the center article list with article items."""
        self.article_list.clear()
        self.article_count_label.setText(f"Articles ({len(articles)})")

        for article in articles:
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, article["id"])
            widget = ArticleListItemWidget(article)
            widget.bookmark_toggled.connect(self._on_item_bookmark_toggled)
            item.setSizeHint(widget.sizeHint())
            self.article_list.addItem(item)
            self.article_list.setItemWidget(item, widget)

    # ------------------------------------------------------------------
    # Handlers: Search
    # ------------------------------------------------------------------

    def _on_search_changed(self, text: str):
        """Handle incremental search as user types."""
        if not text.strip():
            # Restore category-based view
            current_cat = None
            cat_item = self.category_list.currentItem()
            if cat_item:
                current_cat = cat_item.data(Qt.ItemDataRole.UserRole)
            self._load_articles_for_category(current_cat)
            return
        # Debounce: wait for returnPressed for actual search
        # But still filter locally for responsiveness
        query_lower = text.lower()
        filtered = [
            a for a in self._articles_cache
            if query_lower in a["title"].lower()
            or (a.get("tags") and any(query_lower in t.lower() for t in a["tags"]))
        ]
        self._populate_article_list(filtered)

    def _on_search(self):
        """Handle Enter press in search bar - full FTS search."""
        query = self.search_input.text().strip()
        if not query:
            self._load_all_articles()
            return

        results = self.kb.search_articles(query)
        self._articles_cache = results
        self._populate_article_list(results)

    # ------------------------------------------------------------------
    # Handlers: Category
    # ------------------------------------------------------------------

    def _on_category_selected(self, row: int):
        """Handle category selection in sidebar."""
        if row < 0:
            return
        item = self.category_list.item(row)
        if item is None:
            return
        category = item.data(Qt.ItemDataRole.UserRole)
        self.search_input.clear()
        self._load_articles_for_category(category)

    # ------------------------------------------------------------------
    # Handlers: Bookmarks
    # ------------------------------------------------------------------

    def _on_bookmark_selected(self, row: int):
        """Handle bookmark item selection - open article."""
        if row < 0:
            return
        item = self.bookmark_list.item(row)
        if item is None:
            return
        article_id = item.data(Qt.ItemDataRole.UserRole)
        if article_id:
            self.open_article(article_id)

    def _on_bookmark_clicked(self, item):
        """Handle bookmark item click (works even if row hasn't changed)."""
        if item is None:
            return
        article_id = item.data(Qt.ItemDataRole.UserRole)
        if article_id:
            self.open_article(article_id)

    # ------------------------------------------------------------------
    # Handlers: Suggestions
    # ------------------------------------------------------------------

    def _on_suggestion_clicked(self, item: QListWidgetItem):
        """Handle double-click on a suggestion item."""
        article_id = item.data(Qt.ItemDataRole.UserRole)
        if article_id:
            self.open_article(article_id)
            self.suggestion_clicked.emit(article_id)

    # ------------------------------------------------------------------
    # Handlers: Article Selection
    # ------------------------------------------------------------------

    def _on_article_selected(self, row: int):
        """Handle article selection in the center list."""
        if row < 0:
            self._current_article_id = None
            self.viewer.clear()
            self._set_toolbar_state(viewing=False)
            return

        item = self.article_list.item(row)
        if item is None:
            return

        article_id = item.data(Qt.ItemDataRole.UserRole)
        if article_id is None:
            return

        article = self.kb.get_article(article_id)
        if article:
            self._current_article_id = article_id
            self._show_article_in_viewer(article)
            self._set_toolbar_state(viewing=True)
            self.article_selected.emit(article_id)

    def _show_article_in_viewer(self, article: Dict):
        """Render an article's markdown content as HTML in the viewer."""
        # Build header HTML
        header = (
            f'<h1 style="color:#00E5FF; margin-bottom:4px;">{article["title"]}</h1>'
            f'<p style="color:#808080; font-size:11px; margin:2px 0;">'
            f'Category: {article["category"]}'
        )
        tags = article.get("tags") or []
        if tags:
            header += f' &nbsp;|&nbsp; Tags: {", ".join(tags)}'
        if article.get("author"):
            header += f' &nbsp;|&nbsp; Author: {article["author"]}'
        header += f'</p><hr style="border-color:#3A3A5E; margin:8px 0;">'

        # Render body
        body_html = _markdown_to_html(article["content"])
        # Insert header before body
        full_html = body_html.replace(
            '<html><body',
            f'<html><body'
        ).replace(
            'padding:8px;">',
            f'padding:8px;">{header}',
            1,
        )

        self.viewer.setHtml(full_html)
        self.right_stack.setCurrentIndex(0)

        # Update bookmark button state
        if article.get("bookmarked"):
            self.bookmark_article_btn.setText("★ Bookmarked")
        else:
            self.bookmark_article_btn.setText("☆ Bookmark")

    # ------------------------------------------------------------------
    # Handlers: New Article
    # ------------------------------------------------------------------

    def _on_new_article(self):
        """Switch to editor mode for a new article."""
        self._current_article_id = None
        self._editing = True

        self.edit_title.clear()
        self.edit_category.setCurrentIndex(0)
        self.edit_tags.clear()
        self.markdown_editor.clear()
        self.live_preview.clear()

        self.right_stack.setCurrentIndex(1)
        self._set_toolbar_state(editing=True)
        self.edit_title.setFocus()

    # ------------------------------------------------------------------
    # Handlers: Edit
    # ------------------------------------------------------------------

    def _on_edit(self):
        """Switch current article to editor mode."""
        if self._current_article_id is None:
            return

        article = self.kb.get_article(self._current_article_id)
        if not article:
            return

        self._editing = True
        self.edit_title.setText(article["title"])

        # Set category combo
        idx = self.edit_category.findText(article["category"])
        if idx >= 0:
            self.edit_category.setCurrentIndex(idx)

        tags = article.get("tags") or []
        self.edit_tags.setText(", ".join(tags))
        self.markdown_editor.setPlainText(article["content"])

        # Render initial preview
        self._update_live_preview()

        self.right_stack.setCurrentIndex(1)
        self._set_toolbar_state(editing=True)

    def _on_editor_text_changed(self):
        """Update live preview when markdown editor content changes."""
        if self.right_stack.currentIndex() == 1:
            self._update_live_preview()

    def _update_live_preview(self):
        """Render the markdown editor content to the live preview pane."""
        md_text = self.markdown_editor.toPlainText()
        html = _markdown_to_html(md_text)
        self.live_preview.setHtml(html)

    # ------------------------------------------------------------------
    # Handlers: Save
    # ------------------------------------------------------------------

    def _on_save(self):
        """Save the article (create or update)."""
        title = self.edit_title.text().strip()
        category = self.edit_category.currentText()
        tags_text = self.edit_tags.text().strip()
        content = self.markdown_editor.toPlainText()

        if not title:
            QMessageBox.warning(self, "Validation", "Article title is required.")
            return
        if not content.strip():
            QMessageBox.warning(self, "Validation", "Article content cannot be empty.")
            return

        tags = [t.strip() for t in tags_text.split(",") if t.strip()] if tags_text else None

        try:
            if self._current_article_id is None:
                # Create new article
                article_id = self.kb.create_article(
                    title=title,
                    content=content,
                    category=category,
                    tags=tags,
                )
                self._current_article_id = article_id
            else:
                # Update existing
                self.kb.update_article(
                    self._current_article_id,
                    title=title,
                    content=content,
                    category=category,
                    tags=tags,
                )

            self._editing = False
            self.right_stack.setCurrentIndex(0)
            self._set_toolbar_state(viewing=True)

            # Refresh and show article
            self._load_all_articles()
            self._load_categories()
            article = self.kb.get_article(self._current_article_id)
            if article:
                self._show_article_in_viewer(article)

        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save article: {e}")

    # ------------------------------------------------------------------
    # Handlers: Cancel
    # ------------------------------------------------------------------

    def _on_cancel_edit(self):
        """Cancel editing and return to viewer."""
        self._editing = False
        self.right_stack.setCurrentIndex(0)

        if self._current_article_id:
            article = self.kb.get_article(self._current_article_id)
            if article:
                self._show_article_in_viewer(article)
                self._set_toolbar_state(viewing=True)
                return

        self.viewer.clear()
        self._set_toolbar_state(viewing=False)

    # ------------------------------------------------------------------
    # Handlers: Delete
    # ------------------------------------------------------------------

    def _on_delete(self):
        """Delete the current article."""
        if self._current_article_id is None:
            return

        reply = QMessageBox.question(
            self,
            "Delete Article",
            "Are you sure you want to delete this article?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                self.kb.delete_article(self._current_article_id)
                self._current_article_id = None
                self.viewer.clear()
                self._set_toolbar_state(viewing=False)
                self._load_all_articles()
                self._load_categories()
                self._load_bookmarks()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete: {e}")

    # ------------------------------------------------------------------
    # Handlers: Bookmark
    # ------------------------------------------------------------------

    def _on_toggle_bookmark(self):
        """Toggle bookmark on the current article."""
        if self._current_article_id is None:
            return

        new_state = self.kb.toggle_bookmark(self._current_article_id)
        if new_state is not None:
            if new_state:
                self.bookmark_article_btn.setText("★ Bookmarked")
            else:
                self.bookmark_article_btn.setText("☆ Bookmark")
            self._load_bookmarks()

    def _on_item_bookmark_toggled(self, article_id: int):
        """Handle bookmark toggle from an article list item widget."""
        self.kb.toggle_bookmark(article_id)
        self._load_bookmarks()

        # Update viewer button if this is the currently viewed article
        if article_id == self._current_article_id:
            article = self.kb.get_article(article_id)
            if article and article.get("bookmarked"):
                self.bookmark_article_btn.setText("★ Bookmarked")
            else:
                self.bookmark_article_btn.setText("☆ Bookmark")

    # ------------------------------------------------------------------
    # Handlers: KnowledgeBase Signals
    # ------------------------------------------------------------------

    def _on_kb_changed(self, article_id: int):
        """Handle article create/update signals from the engine."""
        self._load_all_articles()
        self._load_bookmarks()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _set_toolbar_state(self, viewing: bool = False, editing: bool = False):
        """Set toolbar button enabled states."""
        self.edit_btn.setEnabled(viewing and not editing)
        self.delete_btn.setEnabled(viewing and not editing)
        self.bookmark_article_btn.setEnabled(viewing and not editing)
        self.save_btn.setEnabled(editing)
        self.cancel_btn.setEnabled(editing)
