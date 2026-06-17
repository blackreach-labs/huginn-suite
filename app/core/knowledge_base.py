# app/core/knowledge_base.py
"""Knowledge Base engine.

Manages a searchable repository of penetration testing techniques, commands,
and cheat sheets stored in a separate SQLite database
(resources/knowledge_base/knowledge_base.db). Provides CRUD operations,
FTS5-based full-text search, contextual suggestions, and bookmarking.

Articles are organized by category and support markdown formatting with code
blocks, tables, and hyperlinks. The engine seeds 100+ pre-built articles on
first initialization covering common pentest commands and techniques.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from PyQt6.QtCore import QObject, pyqtSignal

from app.core.builtin_articles import BUILTIN_ARTICLES
from app.core.database_pool import DatabaseConnectionPool
from app.core.logger import logger


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

KNOWLEDGE_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    category TEXT NOT NULL,
    tags TEXT,
    author TEXT,
    is_builtin INTEGER DEFAULT 0,
    bookmarked INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS articles_fts USING fts5(
    title, content, tags, category,
    content=articles, content_rowid=rowid
);

-- Triggers to keep FTS in sync
CREATE TRIGGER IF NOT EXISTS articles_ai AFTER INSERT ON articles BEGIN
    INSERT INTO articles_fts(rowid, title, content, tags, category)
    VALUES (new.rowid, new.title, new.content, new.tags, new.category);
END;

CREATE TRIGGER IF NOT EXISTS articles_ad AFTER DELETE ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, content, tags, category)
    VALUES ('delete', old.rowid, old.title, old.content, old.tags, old.category);
END;

CREATE TRIGGER IF NOT EXISTS articles_au AFTER UPDATE ON articles BEGIN
    INSERT INTO articles_fts(articles_fts, rowid, title, content, tags, category)
    VALUES ('delete', old.rowid, old.title, old.content, old.tags, old.category);
    INSERT INTO articles_fts(rowid, title, content, tags, category)
    VALUES (new.rowid, new.title, new.content, new.tags, new.category);
END;

CREATE INDEX IF NOT EXISTS idx_articles_category ON articles(category);
CREATE INDEX IF NOT EXISTS idx_articles_bookmarked ON articles(bookmarked);
CREATE INDEX IF NOT EXISTS idx_articles_builtin ON articles(is_builtin);
"""

# Valid article categories
ARTICLE_CATEGORIES = [
    "Reconnaissance",
    "Exploitation",
    "Post-Exploitation",
    "Web Application",
    "Network",
    "Cloud",
    "Reporting",
]


# ---------------------------------------------------------------------------
# KnowledgeBase
# ---------------------------------------------------------------------------

class KnowledgeBase(QObject):
    """Manages the knowledge base with FTS5 search and contextual suggestions.

    The knowledge base database lives at resources/knowledge_base/knowledge_base.db
    and is separate from any engagement database.

    Signals:
        article_created(int): Emitted with the article ID when created.
        article_updated(int): Emitted with the article ID when updated.
    """

    article_created = pyqtSignal(int)
    article_updated = pyqtSignal(int)

    def __init__(self, db_path: Optional[str] = None):
        """Initialize the KnowledgeBase.

        Args:
            db_path: Path to the knowledge base database. If None, defaults to
                resources/knowledge_base/knowledge_base.db relative to project root.
        """
        super().__init__()

        if db_path is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            db_path = str(
                project_root / "resources" / "knowledge_base" / "knowledge_base.db"
            )

        self._db_path = db_path

        # Ensure directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        # Initialize database pool and schema
        self._pool = DatabaseConnectionPool(self._db_path, pool_size=5)
        self._init_schema()

        # Seed built-in articles on first use
        self._seed_if_empty()

    @property
    def db_path(self) -> str:
        """Path to the knowledge base database."""
        return self._db_path

    # ------------------------------------------------------------------
    # Schema Initialization
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create articles table and FTS5 virtual table if they don't exist."""
        try:
            with self._pool.get_connection() as conn:
                conn.executescript(KNOWLEDGE_BASE_SCHEMA)
                conn.commit()
            logger.info("Knowledge base schema initialized.")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize knowledge base schema: {e}")
            raise

    # ------------------------------------------------------------------
    # CRUD Operations
    # ------------------------------------------------------------------

    def create_article(
        self,
        title: str,
        content: str,
        category: str,
        tags: Optional[List[str]] = None,
        author: Optional[str] = None,
        is_builtin: bool = False,
    ) -> int:
        """Create a new knowledge base article.

        Args:
            title: Article title.
            content: Markdown-formatted article content.
            category: Article category (Reconnaissance, Exploitation, etc.).
            tags: List of keyword tags for search and suggestions.
            author: Author identifier.
            is_builtin: Whether this is a built-in article.

        Returns:
            The article ID.
        """
        now = datetime.now(timezone.utc).isoformat()
        tags_json = json.dumps(tags) if tags else None

        with self._pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """INSERT INTO articles
                   (title, content, category, tags, author, is_builtin,
                    bookmarked, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)""",
                (
                    title, content, category, tags_json, author,
                    1 if is_builtin else 0, now, now,
                ),
            )
            conn.commit()
            article_id = cursor.lastrowid

        logger.debug(f"Article created: {article_id} ({title})")
        self.article_created.emit(article_id)
        return article_id

    def update_article(
        self,
        article_id: int,
        **fields,
    ) -> bool:
        """Update an article's fields.

        Supported fields: title, content, category, tags, author.

        Args:
            article_id: The article ID.
            **fields: Field names and values to update.

        Returns:
            True if the article was updated.
        """
        allowed_fields = {"title", "content", "category", "tags", "author"}
        updates = []
        params = []

        for key, value in fields.items():
            if key not in allowed_fields:
                continue
            if key == "tags" and value is not None:
                value = json.dumps(value)
            updates.append(f"{key} = ?")
            params.append(value)

        if not updates:
            return False

        now = datetime.now(timezone.utc).isoformat()
        updates.append("updated_at = ?")
        params.append(now)
        params.append(article_id)

        query = f"UPDATE articles SET {', '.join(updates)} WHERE id = ?"

        with self._pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            conn.commit()
            affected = cursor.rowcount

        if affected > 0:
            logger.debug(f"Article updated: {article_id}")
            self.article_updated.emit(article_id)
            return True
        return False

    def delete_article(self, article_id: int) -> bool:
        """Delete an article by ID.

        Args:
            article_id: The article ID.

        Returns:
            True if the article was deleted.
        """
        with self._pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM articles WHERE id = ?", (article_id,))
            conn.commit()
            affected = cursor.rowcount

        if affected > 0:
            logger.debug(f"Article deleted: {article_id}")
            return True
        return False

    def get_article(self, article_id: int) -> Optional[Dict]:
        """Get a single article by ID.

        Returns:
            Article dict or None if not found.
        """
        rows = self._pool.execute_query(
            """SELECT id, title, content, category, tags, author,
                      is_builtin, bookmarked, created_at, updated_at
               FROM articles WHERE id = ?""",
            (article_id,),
        )
        if not rows:
            return None
        return self._row_to_dict(rows[0])

    def list_articles(
        self,
        category: Optional[str] = None,
        bookmarked_only: bool = False,
    ) -> List[Dict]:
        """List articles with optional filtering.

        Args:
            category: Filter by category.
            bookmarked_only: If True, return only bookmarked articles.

        Returns:
            List of article dicts.
        """
        query = """SELECT id, title, content, category, tags, author,
                          is_builtin, bookmarked, created_at, updated_at
                   FROM articles WHERE 1=1"""
        params: list = []

        if category:
            query += " AND category = ?"
            params.append(category)
        if bookmarked_only:
            query += " AND bookmarked = 1"

        query += " ORDER BY title ASC"

        rows = self._pool.execute_query(query, tuple(params))
        return [self._row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # FTS5 Search
    # ------------------------------------------------------------------

    def search_articles(self, query: str) -> List[Dict]:
        """Search articles using FTS5 across title, content, tags, and category.

        Args:
            query: Search query string. Supports FTS5 syntax (AND, OR, NOT, prefix*).

        Returns:
            List of matching article dicts ordered by relevance.
        """
        if not query or not query.strip():
            return self.list_articles()

        safe_query = self._build_fts_query(query)

        sql = """SELECT a.id, a.title, a.content, a.category, a.tags, a.author,
                        a.is_builtin, a.bookmarked, a.created_at, a.updated_at
                 FROM articles a
                 JOIN articles_fts fts ON a.rowid = fts.rowid
                 WHERE articles_fts MATCH ?
                 ORDER BY rank"""

        try:
            rows = self._pool.execute_query(sql, (safe_query,))
            return [self._row_to_dict(row) for row in rows]
        except sqlite3.OperationalError as e:
            logger.warning(f"FTS query failed, falling back to LIKE: {e}")
            return self._search_fallback(query)

    def _build_fts_query(self, query: str) -> str:
        """Build a safe FTS5 query string from user input.

        Splits the input into tokens and combines them with implicit AND.
        Each token gets a prefix match (*) for partial matching.
        """
        special_chars = '"*(){}[]^~:'
        cleaned = query
        for ch in special_chars:
            cleaned = cleaned.replace(ch, " ")

        tokens = cleaned.split()
        if not tokens:
            return '""'

        parts = []
        for token in tokens:
            token = token.strip()
            if token:
                parts.append(f'"{token}"*')

        return " AND ".join(parts) if parts else '""'

    def _search_fallback(self, query: str) -> List[Dict]:
        """LIKE-based fallback search when FTS fails."""
        like_term = f"%{query}%"
        sql = """SELECT id, title, content, category, tags, author,
                        is_builtin, bookmarked, created_at, updated_at
                 FROM articles
                 WHERE title LIKE ? OR content LIKE ? OR tags LIKE ?
                    OR category LIKE ?
                 ORDER BY title ASC"""
        rows = self._pool.execute_query(
            sql, (like_term, like_term, like_term, like_term)
        )
        return [self._row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Contextual Suggestions
    # ------------------------------------------------------------------

    def get_suggestions(
        self,
        finding_category: Optional[str] = None,
        keywords: Optional[List[str]] = None,
    ) -> List[Dict]:
        """Get article suggestions based on finding category and keywords.

        Matches articles whose category aligns with the finding category or
        whose tags overlap with the provided keywords.

        Args:
            finding_category: The finding's category (e.g. "Web Application").
            keywords: Keywords extracted from the finding description/technique.

        Returns:
            List of suggested article dicts, ordered by relevance.
        """
        if not finding_category and not keywords:
            return []

        # Map finding categories to knowledge base categories
        category_mapping = {
            "Web Application": ["Web Application", "Exploitation"],
            "Network": ["Network", "Reconnaissance"],
            "Infrastructure": ["Network", "Exploitation", "Post-Exploitation"],
            "Cloud": ["Cloud", "Reconnaissance"],
            "Mobile": ["Exploitation", "Web Application"],
            "Physical": ["Reconnaissance", "Post-Exploitation"],
        }

        results = []
        seen_ids = set()

        # 1. Try FTS search with keywords for best relevance
        if keywords:
            keyword_query = " OR ".join(
                f'"{k}"*' for k in keywords if k.strip()
            )
            if keyword_query:
                try:
                    sql = """SELECT a.id, a.title, a.content, a.category, a.tags,
                                    a.author, a.is_builtin, a.bookmarked,
                                    a.created_at, a.updated_at
                             FROM articles a
                             JOIN articles_fts fts ON a.rowid = fts.rowid
                             WHERE articles_fts MATCH ?
                             ORDER BY rank
                             LIMIT 20"""
                    rows = self._pool.execute_query(sql, (keyword_query,))
                    for row in rows:
                        article = self._row_to_dict(row)
                        if article["id"] not in seen_ids:
                            results.append(article)
                            seen_ids.add(article["id"])
                except sqlite3.OperationalError:
                    pass

        # 2. Add articles matching the finding's mapped categories
        if finding_category:
            mapped_categories = category_mapping.get(
                finding_category, [finding_category]
            )
            placeholders = ", ".join("?" * len(mapped_categories))
            sql = f"""SELECT id, title, content, category, tags, author,
                             is_builtin, bookmarked, created_at, updated_at
                      FROM articles
                      WHERE category IN ({placeholders})
                      ORDER BY title ASC
                      LIMIT 20"""
            rows = self._pool.execute_query(sql, tuple(mapped_categories))
            for row in rows:
                article = self._row_to_dict(row)
                if article["id"] not in seen_ids:
                    results.append(article)
                    seen_ids.add(article["id"])

        # 3. If keywords provided, also match against tags via LIKE
        if keywords and len(results) < 10:
            for keyword in keywords[:5]:
                like_term = f"%{keyword}%"
                sql = """SELECT id, title, content, category, tags, author,
                                is_builtin, bookmarked, created_at, updated_at
                         FROM articles
                         WHERE tags LIKE ?
                         LIMIT 5"""
                rows = self._pool.execute_query(sql, (like_term,))
                for row in rows:
                    article = self._row_to_dict(row)
                    if article["id"] not in seen_ids:
                        results.append(article)
                        seen_ids.add(article["id"])

        return results

    # ------------------------------------------------------------------
    # Bookmarking
    # ------------------------------------------------------------------

    def toggle_bookmark(self, article_id: int) -> Optional[bool]:
        """Toggle the bookmark state of an article.

        Args:
            article_id: The article ID.

        Returns:
            The new bookmark state (True/False), or None if article not found.
        """
        article = self.get_article(article_id)
        if article is None:
            return None

        new_state = 0 if article["bookmarked"] else 1

        with self._pool.get_connection() as conn:
            conn.execute(
                "UPDATE articles SET bookmarked = ? WHERE id = ?",
                (new_state, article_id),
            )
            conn.commit()

        logger.debug(
            f"Article {article_id} bookmark toggled to {bool(new_state)}"
        )
        return bool(new_state)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _row_to_dict(self, row: tuple) -> Dict:
        """Convert a database row tuple to an article dict."""
        return {
            "id": row[0],
            "title": row[1],
            "content": row[2],
            "category": row[3],
            "tags": json.loads(row[4]) if row[4] else None,
            "author": row[5],
            "is_builtin": bool(row[6]),
            "bookmarked": bool(row[7]),
            "created_at": row[8],
            "updated_at": row[9],
        }

    def get_article_count(self) -> int:
        """Get total number of articles in the knowledge base."""
        rows = self._pool.execute_query("SELECT COUNT(*) FROM articles")
        return rows[0][0] if rows else 0

    def get_categories(self) -> List[str]:
        """Get all distinct categories currently in use."""
        rows = self._pool.execute_query(
            "SELECT DISTINCT category FROM articles ORDER BY category"
        )
        return [row[0] for row in rows]

    def close(self) -> None:
        """Close the database connection pool."""
        self._pool.close_all()

    # ------------------------------------------------------------------
    # Seed Built-in Articles
    # ------------------------------------------------------------------

    def _seed_if_empty(self) -> None:
        """Seed built-in articles if the database is empty."""
        count = self.get_article_count()
        if count > 0:
            return

        logger.info("Seeding built-in knowledge base articles...")
        for article in BUILTIN_ARTICLES:
            self.create_article(
                title=article["title"],
                content=article["content"],
                category=article["category"],
                tags=article.get("tags"),
                author="Huginn",
                is_builtin=True,
            )
        logger.info(f"Seeded {len(BUILTIN_ARTICLES)} built-in articles.")


