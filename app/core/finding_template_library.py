# app/core/finding_template_library.py
"""Finding Template Library engine.

Manages reusable vulnerability finding templates stored in a separate SQLite
database (resources/templates/finding_templates.db). Provides CRUD operations,
FTS5-based search, template-to-finding conversion, and JSON import/export.

Templates are isolated from per-engagement findings — editing a master template
never affects findings already created from it.
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from PyQt6.QtCore import QObject, pyqtSignal

from app.core.database_pool import DatabaseConnectionPool
from app.core.logger import logger


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

TEMPLATES_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS templates (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT NOT NULL,
    impact TEXT NOT NULL,
    remediation TEXT NOT NULL,
    "references" TEXT,
    cvss_vector TEXT,
    cwe_id TEXT,
    tags TEXT,
    is_builtin INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS templates_fts USING fts5(
    title, description, tags, category, cwe_id,
    content=templates, content_rowid=rowid
);

-- Triggers to keep FTS in sync
CREATE TRIGGER IF NOT EXISTS templates_ai AFTER INSERT ON templates BEGIN
    INSERT INTO templates_fts(rowid, title, description, tags, category, cwe_id)
    VALUES (new.rowid, new.title, new.description, new.tags, new.category, new.cwe_id);
END;

CREATE TRIGGER IF NOT EXISTS templates_ad AFTER DELETE ON templates BEGIN
    INSERT INTO templates_fts(templates_fts, rowid, title, description, tags, category, cwe_id)
    VALUES ('delete', old.rowid, old.title, old.description, old.tags, old.category, old.cwe_id);
END;

CREATE TRIGGER IF NOT EXISTS templates_au AFTER UPDATE ON templates BEGIN
    INSERT INTO templates_fts(templates_fts, rowid, title, description, tags, category, cwe_id)
    VALUES ('delete', old.rowid, old.title, old.description, old.tags, old.category, old.cwe_id);
    INSERT INTO templates_fts(rowid, title, description, tags, category, cwe_id)
    VALUES (new.rowid, new.title, new.description, new.tags, new.category, new.cwe_id);
END;

CREATE INDEX IF NOT EXISTS idx_templates_severity ON templates(severity);
CREATE INDEX IF NOT EXISTS idx_templates_category ON templates(category);
CREATE INDEX IF NOT EXISTS idx_templates_cwe ON templates(cwe_id);
CREATE INDEX IF NOT EXISTS idx_templates_builtin ON templates(is_builtin);
"""

# Valid template categories
TEMPLATE_CATEGORIES = [
    "Web Application",
    "Network",
    "Infrastructure",
    "Cloud",
    "Mobile",
    "Physical",
]

VALID_SEVERITIES = ["Critical", "High", "Medium", "Low", "Informational"]


# ---------------------------------------------------------------------------
# FindingTemplateLibrary
# ---------------------------------------------------------------------------

class FindingTemplateLibrary(QObject):
    """Manages the finding template library with FTS5 search.

    The templates database lives at resources/templates/finding_templates.db
    and is separate from any engagement database. Templates can be used to
    quickly create findings in an engagement, but there is no ongoing linkage.

    Signals:
        template_created(str): Emitted with the template_id when created.
        template_updated(str): Emitted with the template_id when updated.
        template_deleted(str): Emitted with the template_id when deleted.
    """

    template_created = pyqtSignal(str)
    template_updated = pyqtSignal(str)
    template_deleted = pyqtSignal(str)

    def __init__(self, db_path: Optional[str] = None):
        """Initialize the FindingTemplateLibrary.

        Args:
            db_path: Path to the templates database. If None, defaults to
                resources/templates/finding_templates.db relative to project root.
        """
        super().__init__()

        if db_path is None:
            project_root = Path(__file__).resolve().parent.parent.parent
            db_path = str(project_root / "resources" / "templates" / "finding_templates.db")

        self._db_path = db_path

        # Ensure directory exists
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        # Initialize database pool and schema
        self._pool = DatabaseConnectionPool(self._db_path, pool_size=5)
        self._init_schema()

        # Seed built-in templates on first use
        self._seed_if_empty()

    @property
    def db_path(self) -> str:
        """Path to the templates database."""
        return self._db_path

    # ------------------------------------------------------------------
    # Schema Initialization
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        """Create templates table and FTS5 virtual table if they don't exist."""
        try:
            with self._pool.get_connection() as conn:
                conn.executescript(TEMPLATES_DB_SCHEMA)
                conn.commit()
            logger.info("Finding templates schema initialized.")
        except sqlite3.Error as e:
            logger.error(f"Failed to initialize templates schema: {e}")
            raise

    # ------------------------------------------------------------------
    # CRUD Operations
    # ------------------------------------------------------------------

    def create_template(
        self,
        title: str,
        severity: str,
        category: str,
        description: str,
        impact: str,
        remediation: str,
        references: Optional[List[str]] = None,
        cvss_vector: Optional[str] = None,
        cwe_id: Optional[str] = None,
        tags: Optional[List[str]] = None,
        is_builtin: bool = False,
        template_id: Optional[str] = None,
    ) -> str:
        """Create a new finding template.

        Args:
            title: Template title.
            severity: Severity level (Critical, High, Medium, Low, Informational).
            category: Category (Web Application, Network, Infrastructure, Cloud, Mobile, Physical).
            description: Vulnerability description.
            impact: Business/technical impact statement.
            remediation: Remediation guidance.
            references: List of reference URLs.
            cvss_vector: CVSS vector string.
            cwe_id: CWE identifier (e.g. "CWE-79").
            tags: List of keyword tags for search.
            is_builtin: Whether this is a built-in template.
            template_id: Optional custom ID (UUID generated if None).

        Returns:
            The template ID.
        """
        tid = template_id or str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        refs_json = json.dumps(references) if references else None
        tags_json = json.dumps(tags) if tags else None

        with self._pool.get_connection() as conn:
            conn.execute(
                """INSERT INTO templates
                   (id, title, severity, category, description, impact,
                    remediation, "references", cvss_vector, cwe_id, tags,
                    is_builtin, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    tid, title, severity, category, description, impact,
                    remediation, refs_json, cvss_vector, cwe_id, tags_json,
                    1 if is_builtin else 0, now, now,
                ),
            )
            conn.commit()

        logger.debug(f"Template created: {tid} ({title})")
        self.template_created.emit(tid)
        return tid

    def update_template(
        self,
        template_id: str,
        **fields,
    ) -> bool:
        """Update a template's fields.

        Supported fields: title, severity, category, description, impact,
        remediation, references, cvss_vector, cwe_id, tags.

        Args:
            template_id: The template UUID.
            **fields: Field names and values to update.

        Returns:
            True if the template was updated.
        """
        allowed_fields = {
            "title", "severity", "category", "description", "impact",
            "remediation", "references", "cvss_vector", "cwe_id", "tags",
        }
        updates = []
        params = []

        for key, value in fields.items():
            if key not in allowed_fields:
                continue
            if key == "references" and value is not None:
                value = json.dumps(value)
            elif key == "tags" and value is not None:
                value = json.dumps(value)
            # Quote "references" as it's a SQL reserved word
            col_name = f'"{key}"' if key == "references" else key
            updates.append(f"{col_name} = ?")
            params.append(value)

        if not updates:
            return False

        now = datetime.now(timezone.utc).isoformat()
        updates.append("updated_at = ?")
        params.append(now)
        params.append(template_id)

        query = f"UPDATE templates SET {', '.join(updates)} WHERE id = ?"

        with self._pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, tuple(params))
            conn.commit()
            affected = cursor.rowcount

        if affected > 0:
            logger.debug(f"Template updated: {template_id}")
            self.template_updated.emit(template_id)
            return True
        return False

    def delete_template(self, template_id: str) -> bool:
        """Delete a template by ID.

        Args:
            template_id: The template UUID.

        Returns:
            True if the template was deleted.
        """
        with self._pool.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM templates WHERE id = ?", (template_id,))
            conn.commit()
            affected = cursor.rowcount

        if affected > 0:
            logger.debug(f"Template deleted: {template_id}")
            self.template_deleted.emit(template_id)
            return True
        return False

    def get_template(self, template_id: str) -> Optional[Dict]:
        """Get a single template by ID.

        Returns:
            Template dict or None if not found.
        """
        rows = self._pool.execute_query(
            """SELECT id, title, severity, category, description, impact,
                      remediation, "references", cvss_vector, cwe_id, tags,
                      is_builtin, created_at, updated_at
               FROM templates WHERE id = ?""",
            (template_id,),
        )
        if not rows:
            return None
        return self._row_to_dict(rows[0])

    def list_templates(
        self,
        category: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict]:
        """List all templates with optional category/severity filter.

        Args:
            category: Filter by category.
            severity: Filter by severity.

        Returns:
            List of template dicts.
        """
        query = """SELECT id, title, severity, category, description, impact,
                          remediation, "references", cvss_vector, cwe_id, tags,
                          is_builtin, created_at, updated_at
                   FROM templates WHERE 1=1"""
        params: list = []

        if category:
            query += " AND category = ?"
            params.append(category)
        if severity:
            query += " AND severity = ?"
            params.append(severity)

        query += " ORDER BY title ASC"

        rows = self._pool.execute_query(query, tuple(params))
        return [self._row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # FTS5 Search
    # ------------------------------------------------------------------

    def search_templates(self, query: str) -> List[Dict]:
        """Search templates using FTS5 across title, description, tags, category, cwe_id.

        Args:
            query: Search query string. Supports FTS5 syntax (AND, OR, NOT, prefix*).

        Returns:
            List of matching template dicts ordered by relevance.
        """
        if not query or not query.strip():
            return self.list_templates()

        # Escape special FTS5 characters and build a prefix query for user-friendliness
        safe_query = self._build_fts_query(query)

        sql = """SELECT t.id, t.title, t.severity, t.category, t.description,
                        t.impact, t.remediation, t."references", t.cvss_vector,
                        t.cwe_id, t.tags, t.is_builtin, t.created_at, t.updated_at
                 FROM templates t
                 JOIN templates_fts fts ON t.rowid = fts.rowid
                 WHERE templates_fts MATCH ?
                 ORDER BY rank"""

        try:
            rows = self._pool.execute_query(sql, (safe_query,))
            return [self._row_to_dict(row) for row in rows]
        except sqlite3.OperationalError as e:
            # Fall back to LIKE-based search if FTS query fails
            logger.warning(f"FTS query failed, falling back to LIKE: {e}")
            return self._search_fallback(query)

    def _build_fts_query(self, query: str) -> str:
        """Build a safe FTS5 query string from user input.

        Splits the input into tokens and combines them with implicit AND.
        Each token gets a prefix match (*) for partial matching.
        """
        # Remove FTS5 special characters that could break the query
        special_chars = '"*(){}[]^~:'
        cleaned = query
        for ch in special_chars:
            cleaned = cleaned.replace(ch, " ")

        tokens = cleaned.split()
        if not tokens:
            return '""'

        # Build OR across columns for each token with prefix matching
        parts = []
        for token in tokens:
            token = token.strip()
            if token:
                parts.append(f'"{token}"*')

        return " AND ".join(parts) if parts else '""'

    def _search_fallback(self, query: str) -> List[Dict]:
        """LIKE-based fallback search when FTS fails."""
        like_term = f"%{query}%"
        sql = """SELECT id, title, severity, category, description, impact,
                        remediation, "references", cvss_vector, cwe_id, tags,
                        is_builtin, created_at, updated_at
                 FROM templates
                 WHERE title LIKE ? OR description LIKE ? OR tags LIKE ?
                    OR category LIKE ? OR cwe_id LIKE ?
                 ORDER BY title ASC"""
        rows = self._pool.execute_query(
            sql, (like_term, like_term, like_term, like_term, like_term)
        )
        return [self._row_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Template → Finding Conversion
    # ------------------------------------------------------------------

    def create_finding_from_template(
        self,
        template_id: str,
        engagement_db,
        overrides: Optional[Dict] = None,
    ) -> Optional[int]:
        """Create a finding in an engagement database from a template.

        Copies all template fields into a new finding record. The finding
        stores the template_id for reference but there is NO ongoing linkage —
        subsequent template edits do not affect the created finding.

        Args:
            template_id: The source template UUID.
            engagement_db: An EngagementDatabase instance (must be connected).
            overrides: Optional dict of field overrides for per-instance customization.

        Returns:
            The new finding row ID, or None if template not found.
        """
        template = self.get_template(template_id)
        if template is None:
            logger.error(f"Template not found: {template_id}")
            return None

        now = datetime.now(timezone.utc).isoformat()

        # Build finding fields from template, applying overrides
        finding_data = {
            "title": template["title"],
            "severity": template["severity"],
            "description": template["description"],
            "impact": template["impact"],
            "remediation": template["remediation"],
            "cvss_vector": template["cvss_vector"],
            "cwe_id": template["cwe_id"],
            "category": template["category"],
            "template_id": template_id,
        }

        # Apply per-instance overrides
        if overrides:
            for key, value in overrides.items():
                if key in finding_data:
                    finding_data[key] = value

        # Insert into the engagement's findings table
        row_id = engagement_db.execute_write(
            """INSERT INTO findings
               (title, severity, description, impact, remediation,
                cvss_vector, cwe_id, category, template_id, status,
                created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?)""",
            (
                finding_data["title"],
                finding_data["severity"],
                finding_data["description"],
                finding_data["impact"],
                finding_data["remediation"],
                finding_data["cvss_vector"],
                finding_data["cwe_id"],
                finding_data["category"],
                finding_data["template_id"],
                now,
                now,
            ),
        )

        logger.debug(f"Finding created from template {template_id}: finding_id={row_id}")
        return row_id

    # ------------------------------------------------------------------
    # Export / Import
    # ------------------------------------------------------------------

    def export_templates(
        self,
        output_path: str,
        template_ids: Optional[List[str]] = None,
    ) -> bool:
        """Export templates to a portable JSON file.

        Args:
            output_path: Path to the output JSON file.
            template_ids: Optional list of specific template IDs to export.
                If None, exports all templates.

        Returns:
            True if export was successful.
        """
        if template_ids:
            templates = [self.get_template(tid) for tid in template_ids]
            templates = [t for t in templates if t is not None]
        else:
            templates = self.list_templates()

        export_data = {
            "version": "1.0",
            "export_date": datetime.now(timezone.utc).isoformat(),
            "template_count": len(templates),
            "templates": templates,
        }

        try:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            logger.info(f"Exported {len(templates)} templates to {output_path}")
            return True
        except (OSError, TypeError) as e:
            logger.error(f"Failed to export templates: {e}")
            return False

    def import_templates(
        self,
        input_path: str,
        overwrite_existing: bool = False,
    ) -> Tuple[int, int, List[str]]:
        """Import templates from a JSON file.

        Args:
            input_path: Path to the JSON file to import.
            overwrite_existing: If True, overwrite templates with matching IDs.

        Returns:
            Tuple of (imported_count, skipped_count, warnings).
        """
        warnings: List[str] = []
        imported = 0
        skipped = 0

        try:
            with open(input_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            warnings.append(f"Failed to read import file: {e}")
            return 0, 0, warnings

        templates = data.get("templates", [])
        if not templates:
            warnings.append("No templates found in import file.")
            return 0, 0, warnings

        for tmpl in templates:
            try:
                tid = tmpl.get("id", str(uuid.uuid4()))
                existing = self.get_template(tid)

                if existing and not overwrite_existing:
                    skipped += 1
                    continue

                if existing and overwrite_existing:
                    # Update existing
                    self.update_template(
                        tid,
                        title=tmpl.get("title", existing["title"]),
                        severity=tmpl.get("severity", existing["severity"]),
                        category=tmpl.get("category", existing["category"]),
                        description=tmpl.get("description", existing["description"]),
                        impact=tmpl.get("impact", existing["impact"]),
                        remediation=tmpl.get("remediation", existing["remediation"]),
                        references=tmpl.get("references"),
                        cvss_vector=tmpl.get("cvss_vector"),
                        cwe_id=tmpl.get("cwe_id"),
                        tags=tmpl.get("tags"),
                    )
                    imported += 1
                else:
                    # Create new
                    self.create_template(
                        title=tmpl["title"],
                        severity=tmpl["severity"],
                        category=tmpl["category"],
                        description=tmpl["description"],
                        impact=tmpl["impact"],
                        remediation=tmpl["remediation"],
                        references=tmpl.get("references"),
                        cvss_vector=tmpl.get("cvss_vector"),
                        cwe_id=tmpl.get("cwe_id"),
                        tags=tmpl.get("tags"),
                        is_builtin=tmpl.get("is_builtin", False),
                        template_id=tid,
                    )
                    imported += 1
            except (KeyError, TypeError) as e:
                warnings.append(f"Skipped malformed template: {e}")
                skipped += 1

        logger.info(f"Import complete: {imported} imported, {skipped} skipped")
        return imported, skipped, warnings

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _row_to_dict(self, row: tuple) -> Dict:
        """Convert a database row tuple to a template dict."""
        return {
            "id": row[0],
            "title": row[1],
            "severity": row[2],
            "category": row[3],
            "description": row[4],
            "impact": row[5],
            "remediation": row[6],
            "references": json.loads(row[7]) if row[7] else None,
            "cvss_vector": row[8],
            "cwe_id": row[9],
            "tags": json.loads(row[10]) if row[10] else None,
            "is_builtin": bool(row[11]),
            "created_at": row[12],
            "updated_at": row[13],
        }

    def get_template_count(self) -> int:
        """Get total number of templates in the library."""
        rows = self._pool.execute_query("SELECT COUNT(*) FROM templates")
        return rows[0][0] if rows else 0

    def get_categories(self) -> List[str]:
        """Get all distinct categories currently in use."""
        rows = self._pool.execute_query(
            "SELECT DISTINCT category FROM templates ORDER BY category"
        )
        return [row[0] for row in rows]

    def close(self) -> None:
        """Close the database connection pool."""
        self._pool.close_all()

    # ------------------------------------------------------------------
    # Seed Built-in Templates
    # ------------------------------------------------------------------

    def _seed_if_empty(self) -> None:
        """Seed built-in templates if the database is empty."""
        count = self.get_template_count()
        if count > 0:
            return

        logger.info("Seeding built-in finding templates...")
        for tmpl in BUILTIN_TEMPLATES:
            self.create_template(
                title=tmpl["title"],
                severity=tmpl["severity"],
                category=tmpl["category"],
                description=tmpl["description"],
                impact=tmpl["impact"],
                remediation=tmpl["remediation"],
                references=tmpl.get("references"),
                cvss_vector=tmpl.get("cvss_vector"),
                cwe_id=tmpl.get("cwe_id"),
                tags=tmpl.get("tags"),
                is_builtin=True,
            )
        logger.info(f"Seeded {len(BUILTIN_TEMPLATES)} built-in templates.")


# ---------------------------------------------------------------------------
# Built-in Templates Data (50+ covering OWASP Top 10, Network, Config)
# ---------------------------------------------------------------------------

BUILTIN_TEMPLATES: List[Dict] = [
    # ===== OWASP Top 10 - Web Application =====
    {
        "title": "SQL Injection",
        "severity": "Critical",
        "category": "Web Application",
        "description": "The application is vulnerable to SQL injection attacks. User-supplied input is incorporated into SQL queries without proper sanitization or parameterization, allowing attackers to manipulate database queries.",
        "impact": "An attacker can read, modify, or delete arbitrary database contents, bypass authentication, and potentially execute operating system commands on the database server.",
        "remediation": "Use parameterized queries (prepared statements) for all database interactions. Implement input validation using allowlists. Apply the principle of least privilege to database accounts.",
        "references": ["https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/89.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-89",
        "tags": ["injection", "sql", "database", "owasp-top-10", "a03"],
    },
    {
        "title": "Cross-Site Scripting (Reflected XSS)",
        "severity": "High",
        "category": "Web Application",
        "description": "The application reflects user-supplied input in HTTP responses without proper encoding, allowing injection of arbitrary JavaScript code that executes in victims' browsers.",
        "impact": "An attacker can steal session cookies, redirect users to malicious sites, deface web content, or perform actions on behalf of authenticated users.",
        "remediation": "Implement context-aware output encoding for all user-supplied data. Use Content Security Policy (CSP) headers. Validate input against expected patterns.",
        "references": ["https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/79.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "cwe_id": "CWE-79",
        "tags": ["xss", "reflected", "injection", "owasp-top-10", "a03"],
    },
    {
        "title": "Cross-Site Scripting (Stored XSS)",
        "severity": "High",
        "category": "Web Application",
        "description": "The application stores user-supplied input and later includes it in HTTP responses without proper encoding. Malicious scripts persist in the application and execute for all users who view the affected content.",
        "impact": "Persistent compromise of user sessions, widespread credential theft, malware distribution, and complete control over affected user accounts.",
        "remediation": "Implement context-aware output encoding for all stored user data. Sanitize input on storage. Deploy Content Security Policy headers with strict directives.",
        "references": ["https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/79.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
        "cwe_id": "CWE-79",
        "tags": ["xss", "stored", "persistent", "injection", "owasp-top-10", "a03"],
    },
    {
        "title": "Broken Authentication",
        "severity": "Critical",
        "category": "Web Application",
        "description": "The application has authentication weaknesses that allow attackers to compromise passwords, session tokens, or exploit implementation flaws to assume other users' identities.",
        "impact": "Attackers can gain unauthorized access to user accounts, potentially including administrative accounts, leading to data theft, fraud, or complete system compromise.",
        "remediation": "Implement multi-factor authentication. Enforce strong password policies. Use secure session management with proper timeout and invalidation. Rate-limit authentication attempts.",
        "references": ["https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/", "https://cwe.mitre.org/data/definitions/287.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-287",
        "tags": ["authentication", "session", "credential", "owasp-top-10", "a07"],
    },
    {
        "title": "Broken Access Control",
        "severity": "High",
        "category": "Web Application",
        "description": "The application does not properly enforce access controls, allowing users to act outside their intended permissions. This includes accessing other users' data, modifying access rights, or performing privileged operations.",
        "impact": "Unauthorized access to sensitive data, modification of other users' data, privilege escalation, and potential full administrative access.",
        "remediation": "Implement server-side access control checks for every request. Deny by default. Use role-based access control (RBAC). Log and alert on access control failures.",
        "references": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/", "https://cwe.mitre.org/data/definitions/284.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-284",
        "tags": ["access-control", "authorization", "idor", "privilege-escalation", "owasp-top-10", "a01"],
    },
    {
        "title": "Insecure Direct Object Reference (IDOR)",
        "severity": "High",
        "category": "Web Application",
        "description": "The application exposes direct references to internal objects (database records, files, etc.) in URLs or parameters without proper authorization checks, allowing users to access resources belonging to other users.",
        "impact": "Unauthorized access to other users' data, potential data breach affecting all application users, and violation of data privacy requirements.",
        "remediation": "Implement proper authorization checks for every object access. Use indirect object references or UUIDs. Validate that the authenticated user has permission to access the requested resource.",
        "references": ["https://owasp.org/Top10/A01_2021-Broken_Access_Control/", "https://cwe.mitre.org/data/definitions/639.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "cwe_id": "CWE-639",
        "tags": ["idor", "access-control", "authorization", "owasp-top-10", "a01"],
    },
    {
        "title": "Security Misconfiguration",
        "severity": "Medium",
        "category": "Web Application",
        "description": "The application or its underlying infrastructure is configured insecurely, including default credentials, unnecessary features enabled, verbose error messages, or missing security headers.",
        "impact": "Information disclosure, unauthorized access through default accounts, and expanded attack surface through unnecessary services or features.",
        "remediation": "Implement a hardening process for all environments. Remove default accounts and passwords. Disable unnecessary features and services. Configure proper security headers. Implement automated configuration auditing.",
        "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "https://cwe.mitre.org/data/definitions/16.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-16",
        "tags": ["misconfiguration", "hardening", "default-credentials", "owasp-top-10", "a05"],
    },
    {
        "title": "Sensitive Data Exposure",
        "severity": "High",
        "category": "Web Application",
        "description": "The application does not adequately protect sensitive data such as credentials, financial information, or personal data. Data may be transmitted in cleartext, stored without encryption, or exposed through other weaknesses.",
        "impact": "Theft of sensitive personal, financial, or health data leading to identity theft, financial fraud, regulatory penalties, and reputational damage.",
        "remediation": "Encrypt all sensitive data at rest and in transit. Use strong, current encryption algorithms. Disable caching for sensitive responses. Apply data minimization principles.",
        "references": ["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/", "https://cwe.mitre.org/data/definitions/311.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-311",
        "tags": ["data-exposure", "encryption", "cryptography", "owasp-top-10", "a02"],
    },
    {
        "title": "Cross-Site Request Forgery (CSRF)",
        "severity": "Medium",
        "category": "Web Application",
        "description": "The application does not verify that requests originate from the expected user interface, allowing attackers to craft malicious pages that force authenticated users to perform unintended actions.",
        "impact": "Attackers can perform state-changing operations on behalf of authenticated users, including changing email addresses, passwords, or making transactions.",
        "remediation": "Implement anti-CSRF tokens for all state-changing requests. Use SameSite cookie attribute. Verify the Origin/Referer header for sensitive operations.",
        "references": ["https://owasp.org/www-community/attacks/csrf", "https://cwe.mitre.org/data/definitions/352.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
        "cwe_id": "CWE-352",
        "tags": ["csrf", "session", "owasp-top-10", "a01"],
    },
    {
        "title": "Server-Side Request Forgery (SSRF)",
        "severity": "High",
        "category": "Web Application",
        "description": "The application fetches remote resources based on user-supplied URLs without proper validation, allowing attackers to make requests to internal services, cloud metadata endpoints, or other restricted resources.",
        "impact": "Access to internal services not exposed to the internet, reading cloud instance metadata (credentials), port scanning of internal networks, and potential remote code execution.",
        "remediation": "Validate and sanitize all user-supplied URLs. Use allowlists for permitted domains and protocols. Block requests to private/internal IP ranges. Disable unnecessary URL schemes.",
        "references": ["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/", "https://cwe.mitre.org/data/definitions/918.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        "cwe_id": "CWE-918",
        "tags": ["ssrf", "server-side", "internal-access", "owasp-top-10", "a10"],
    },
    {
        "title": "Insecure Deserialization",
        "severity": "Critical",
        "category": "Web Application",
        "description": "The application deserializes untrusted data without sufficient validation, allowing attackers to manipulate serialized objects to achieve remote code execution, replay attacks, or privilege escalation.",
        "impact": "Remote code execution on the application server, authentication bypass, denial of service, or arbitrary object manipulation.",
        "remediation": "Avoid deserializing untrusted data. If required, implement integrity checks (digital signatures) on serialized objects. Restrict deserialization to expected types. Monitor and log deserialization failures.",
        "references": ["https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/", "https://cwe.mitre.org/data/definitions/502.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-502",
        "tags": ["deserialization", "rce", "owasp-top-10", "a08"],
    },
    {
        "title": "XML External Entity (XXE) Injection",
        "severity": "High",
        "category": "Web Application",
        "description": "The application processes XML input containing references to external entities. Attackers can exploit this to read local files, perform SSRF attacks, or cause denial of service.",
        "impact": "Reading arbitrary files from the server, SSRF to internal services, denial of service through entity expansion (Billion Laughs), and potential remote code execution.",
        "remediation": "Disable DTD processing and external entity resolution in XML parsers. Use less complex data formats (JSON). If XML is required, validate and sanitize input.",
        "references": ["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/", "https://cwe.mitre.org/data/definitions/611.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
        "cwe_id": "CWE-611",
        "tags": ["xxe", "xml", "injection", "file-read", "owasp-top-10"],
    },
    {
        "title": "Command Injection",
        "severity": "Critical",
        "category": "Web Application",
        "description": "The application passes user-supplied input to operating system commands without proper sanitization, allowing attackers to execute arbitrary commands on the host system.",
        "impact": "Full compromise of the host operating system, data exfiltration, lateral movement, installation of backdoors, and denial of service.",
        "remediation": "Avoid calling OS commands with user input. If necessary, use parameterized APIs (not shell commands). Implement strict input validation with allowlists. Run with minimal privileges.",
        "references": ["https://owasp.org/Top10/A03_2021-Injection/", "https://cwe.mitre.org/data/definitions/78.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-78",
        "tags": ["command-injection", "rce", "os-command", "injection", "owasp-top-10", "a03"],
    },
    {
        "title": "Insufficient Logging and Monitoring",
        "severity": "Medium",
        "category": "Web Application",
        "description": "The application does not generate adequate security logs, does not monitor for suspicious activity, or does not alert on potential attacks, allowing attackers to maintain persistence undetected.",
        "impact": "Delayed detection of breaches, inability to perform forensic analysis, continued attacker presence, and failure to meet compliance requirements.",
        "remediation": "Implement comprehensive logging of authentication events, access control failures, and input validation failures. Set up real-time monitoring and alerting. Retain logs for adequate periods.",
        "references": ["https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/", "https://cwe.mitre.org/data/definitions/778.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
        "cwe_id": "CWE-778",
        "tags": ["logging", "monitoring", "detection", "owasp-top-10", "a09"],
    },
    {
        "title": "Vulnerable and Outdated Components",
        "severity": "High",
        "category": "Web Application",
        "description": "The application uses components (libraries, frameworks, software modules) with known vulnerabilities. These may be outdated, unsupported, or unpatched versions.",
        "impact": "Exploitation of known vulnerabilities in third-party components, potentially leading to remote code execution, data breaches, or denial of service.",
        "remediation": "Maintain an inventory of all components and their versions. Continuously monitor for vulnerabilities. Implement automated dependency scanning in CI/CD pipelines. Apply patches promptly.",
        "references": ["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/", "https://cwe.mitre.org/data/definitions/1104.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-1104",
        "tags": ["components", "outdated", "patching", "dependencies", "owasp-top-10", "a06"],
    },
    # ===== Network Vulnerabilities =====
    {
        "title": "Unencrypted Protocol in Use (Telnet)",
        "severity": "High",
        "category": "Network",
        "description": "The target system exposes a Telnet service which transmits all data including credentials in cleartext, making it trivial for network-positioned attackers to intercept sensitive information.",
        "impact": "Credential theft through network sniffing, session hijacking, and man-in-the-middle attacks leading to unauthorized system access.",
        "remediation": "Disable Telnet and replace with SSH for all remote administration. If Telnet is required for legacy devices, restrict access via network segmentation and VPN.",
        "references": ["https://cwe.mitre.org/data/definitions/319.html"],
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-319",
        "tags": ["telnet", "cleartext", "unencrypted", "network", "protocol"],
    },
    {
        "title": "Unencrypted Protocol in Use (FTP)",
        "severity": "Medium",
        "category": "Network",
        "description": "The target system uses plain FTP which transmits credentials and data in cleartext. Network-positioned attackers can intercept file transfers and authentication credentials.",
        "impact": "Exposure of credentials and transferred files to network eavesdroppers. Potential for man-in-the-middle modification of transferred data.",
        "remediation": "Replace FTP with SFTP or FTPS. If FTP must remain, restrict to non-sensitive transfers and isolate on a dedicated VLAN with limited access.",
        "references": ["https://cwe.mitre.org/data/definitions/319.html"],
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-319",
        "tags": ["ftp", "cleartext", "unencrypted", "network", "file-transfer"],
    },
    {
        "title": "SMB Signing Not Required",
        "severity": "Medium",
        "category": "Network",
        "description": "The target SMB server does not require message signing. This allows man-in-the-middle attacks including SMB relay attacks where an attacker can intercept and relay authentication attempts.",
        "impact": "SMB relay attacks enabling unauthorized access to network resources, potential domain compromise through NTLM relay to critical services.",
        "remediation": "Enable and require SMB signing on all systems. Configure via Group Policy: 'Microsoft network server: Digitally sign communications (always)' set to Enabled.",
        "references": ["https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always"],
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-294",
        "tags": ["smb", "signing", "relay", "ntlm", "network", "windows"],
    },
    {
        "title": "SNMP Default Community Strings",
        "severity": "High",
        "category": "Network",
        "description": "The target device responds to SNMP queries using default community strings (public/private). This exposes device configuration, network topology, and potentially allows configuration modification.",
        "impact": "Disclosure of sensitive system information, network topology mapping, and potential unauthorized configuration changes on network infrastructure.",
        "remediation": "Change default SNMP community strings to complex, unique values. Migrate to SNMPv3 with authentication and encryption. Restrict SNMP access via ACLs.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cwe_id": "CWE-798",
        "tags": ["snmp", "default-credentials", "network", "community-string"],
    },
    {
        "title": "DNS Zone Transfer Allowed",
        "severity": "Medium",
        "category": "Network",
        "description": "The DNS server allows zone transfer (AXFR) requests from unauthorized hosts, disclosing all DNS records in the zone including internal hostnames, IP addresses, and service records.",
        "impact": "Complete disclosure of the organization's DNS zone data, enabling attackers to map internal network infrastructure, identify targets, and plan further attacks.",
        "remediation": "Restrict zone transfers to authorized secondary DNS servers only. Configure ACLs on the DNS server to deny AXFR/IXFR requests from unauthorized sources.",
        "references": ["https://cwe.mitre.org/data/definitions/200.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-200",
        "tags": ["dns", "zone-transfer", "axfr", "reconnaissance", "network"],
    },
    {
        "title": "Weak SSL/TLS Configuration",
        "severity": "Medium",
        "category": "Network",
        "description": "The target service supports weak SSL/TLS protocol versions (SSLv3, TLS 1.0, TLS 1.1) or cipher suites (RC4, DES, NULL ciphers) that are vulnerable to known attacks.",
        "impact": "Potential decryption of encrypted communications through protocol downgrade attacks (POODLE, BEAST), cipher suite weaknesses, or brute-force of weak keys.",
        "remediation": "Disable SSLv3, TLS 1.0, and TLS 1.1. Enable only TLS 1.2 and TLS 1.3 with strong cipher suites. Prioritize AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
        "references": ["https://cwe.mitre.org/data/definitions/326.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-326",
        "tags": ["ssl", "tls", "encryption", "cipher", "network", "cryptography"],
    },
    {
        "title": "Expired SSL/TLS Certificate",
        "severity": "Low",
        "category": "Network",
        "description": "The target service presents an SSL/TLS certificate that has expired. While encryption still functions, clients may reject the connection or users may ignore security warnings.",
        "impact": "Users conditioned to bypass certificate warnings, potential for man-in-the-middle attacks when users accept invalid certificates, and service disruptions.",
        "remediation": "Renew the SSL/TLS certificate before expiration. Implement certificate monitoring and automated renewal where possible (e.g., Let's Encrypt with auto-renewal).",
        "references": ["https://cwe.mitre.org/data/definitions/298.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-298",
        "tags": ["ssl", "tls", "certificate", "expired", "network"],
    },
    {
        "title": "Self-Signed SSL/TLS Certificate",
        "severity": "Low",
        "category": "Network",
        "description": "The target service uses a self-signed SSL/TLS certificate not issued by a trusted Certificate Authority. Users cannot verify the server's identity.",
        "impact": "Inability to verify server identity enables man-in-the-middle attacks. Users may ignore certificate warnings, establishing unsafe behavior patterns.",
        "remediation": "Replace self-signed certificates with certificates issued by a trusted Certificate Authority. For internal services, deploy an internal CA with proper trust distribution.",
        "references": ["https://cwe.mitre.org/data/definitions/295.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-295",
        "tags": ["ssl", "tls", "certificate", "self-signed", "network"],
    },
    {
        "title": "Open Network Ports (Unnecessary Services)",
        "severity": "Low",
        "category": "Network",
        "description": "The target system exposes network services that are not required for its intended function, increasing the attack surface available to adversaries.",
        "impact": "Expanded attack surface, potential exploitation of vulnerabilities in unnecessary services, and increased complexity for security monitoring.",
        "remediation": "Disable or remove unnecessary services. Implement host-based firewalls to restrict access to required ports only. Follow the principle of least functionality.",
        "references": ["https://cwe.mitre.org/data/definitions/16.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
        "cwe_id": "CWE-16",
        "tags": ["ports", "services", "attack-surface", "hardening", "network"],
    },
    {
        "title": "LLMNR/NBT-NS Poisoning",
        "severity": "High",
        "category": "Network",
        "description": "The network allows Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) broadcasts, enabling attackers to respond to name resolution requests and capture NTLM hashes.",
        "impact": "Capture of NTLMv2 hashes leading to offline password cracking or relay attacks, potentially resulting in domain compromise.",
        "remediation": "Disable LLMNR via Group Policy (Computer Configuration > Administrative Templates > Network > DNS Client > Turn Off Multicast Name Resolution). Disable NBT-NS on all interfaces.",
        "references": ["https://attack.mitre.org/techniques/T1557/001/"],
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-294",
        "tags": ["llmnr", "nbt-ns", "poisoning", "ntlm", "relay", "network", "windows"],
    },
    {
        "title": "IPv6 Router Advertisement Spoofing",
        "severity": "Medium",
        "category": "Network",
        "description": "The network segment supports IPv6 and does not implement Router Advertisement (RA) Guard, allowing attackers to inject rogue router advertisements and intercept traffic.",
        "impact": "Man-in-the-middle attacks via rogue IPv6 router, traffic interception, DNS spoofing through DHCPv6, and credential capture.",
        "remediation": "Implement RA Guard on network switches. Deploy IPv6 First-Hop Security features. If IPv6 is not required, disable it on host interfaces and use switch ACLs to block RA frames.",
        "references": ["https://tools.ietf.org/html/rfc6105"],
        "cvss_vector": "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-290",
        "tags": ["ipv6", "router-advertisement", "mitm", "network", "spoofing"],
    },
    # ===== Infrastructure =====
    {
        "title": "Default Administrative Credentials",
        "severity": "Critical",
        "category": "Infrastructure",
        "description": "The target system or device uses default manufacturer credentials for administrative access that have not been changed from the factory settings.",
        "impact": "Complete administrative control of the affected system, enabling configuration changes, data access, persistence mechanisms, and use as a pivot point.",
        "remediation": "Immediately change all default credentials. Implement a password management policy requiring unique, complex credentials for all administrative accounts.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-798",
        "tags": ["default-credentials", "password", "infrastructure", "admin"],
    },
    {
        "title": "Missing Operating System Patches",
        "severity": "High",
        "category": "Infrastructure",
        "description": "The target system is missing critical operating system security patches, leaving it vulnerable to known exploits for which patches have been publicly available.",
        "impact": "Exploitation of known vulnerabilities potentially leading to remote code execution, privilege escalation, or denial of service.",
        "remediation": "Implement a regular patch management process. Deploy missing security patches within vendor-recommended timeframes. Use automated patching tools where possible.",
        "references": ["https://cwe.mitre.org/data/definitions/1104.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-1104",
        "tags": ["patching", "updates", "infrastructure", "os", "vulnerability-management"],
    },
    {
        "title": "Weak Password Policy",
        "severity": "Medium",
        "category": "Infrastructure",
        "description": "The system enforces an insufficient password policy allowing short passwords, common dictionary words, or lacking complexity requirements, account lockout, or password history.",
        "impact": "Increased susceptibility to brute-force and credential stuffing attacks, potentially leading to unauthorized access to user and administrative accounts.",
        "remediation": "Enforce minimum 12-character passwords. Implement account lockout after failed attempts. Check passwords against common breach lists. Consider passphrase-based policies.",
        "references": ["https://cwe.mitre.org/data/definitions/521.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-521",
        "tags": ["password", "policy", "brute-force", "infrastructure", "authentication"],
    },
    {
        "title": "Unrestricted Remote Desktop Protocol (RDP) Access",
        "severity": "High",
        "category": "Infrastructure",
        "description": "Remote Desktop Protocol (RDP) service is exposed to untrusted networks without proper access controls, MFA, or Network Level Authentication (NLA).",
        "impact": "Brute-force attacks against RDP credentials, exploitation of RDP vulnerabilities (BlueKeep, DejaBlue), and direct remote access upon credential compromise.",
        "remediation": "Restrict RDP access via firewall rules and VPN. Enable Network Level Authentication (NLA). Implement MFA for remote access. Consider using an RDP gateway.",
        "references": ["https://attack.mitre.org/techniques/T1021/001/"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cwe_id": "CWE-284",
        "tags": ["rdp", "remote-access", "infrastructure", "windows", "brute-force"],
    },
    {
        "title": "Unpatched Third-Party Software",
        "severity": "High",
        "category": "Infrastructure",
        "description": "Third-party applications installed on the target system have known vulnerabilities due to outdated versions without available security patches applied.",
        "impact": "Exploitation of known vulnerabilities in third-party software, potentially leading to remote code execution, data theft, or system compromise.",
        "remediation": "Inventory all third-party software. Implement vulnerability scanning for installed applications. Establish a patch management process covering third-party software. Remove unused applications.",
        "references": ["https://cwe.mitre.org/data/definitions/1104.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-1104",
        "tags": ["patching", "third-party", "software", "infrastructure", "vulnerability-management"],
    },
    {
        "title": "Insecure File Share Permissions",
        "severity": "Medium",
        "category": "Infrastructure",
        "description": "Network file shares have overly permissive access controls allowing unauthorized users to read or write sensitive files. This may include Everyone or Authenticated Users with excessive permissions.",
        "impact": "Unauthorized access to sensitive documents, intellectual property theft, data tampering, and potential malware distribution via writable shares.",
        "remediation": "Review and restrict file share permissions using least-privilege principles. Remove generic groups (Everyone, Domain Users) from sensitive shares. Implement regular access reviews.",
        "references": ["https://cwe.mitre.org/data/definitions/276.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
        "cwe_id": "CWE-276",
        "tags": ["file-share", "permissions", "smb", "infrastructure", "access-control"],
    },
    {
        "title": "No Endpoint Protection Installed",
        "severity": "Medium",
        "category": "Infrastructure",
        "description": "The target system lacks endpoint detection and response (EDR) or antivirus software, leaving it without real-time protection against malware and known attack tools.",
        "impact": "Malware execution without detection, inability to detect common attack tools, lack of forensic visibility, and increased risk from commodity threats.",
        "remediation": "Deploy EDR/antivirus solutions on all endpoints. Ensure real-time protection is enabled with automatic signature updates. Implement application whitelisting for critical systems.",
        "references": ["https://attack.mitre.org/mitigations/M1049/"],
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
        "cwe_id": "CWE-693",
        "tags": ["edr", "antivirus", "endpoint", "infrastructure", "detection"],
    },
    {
        "title": "Local Administrator Account Enabled",
        "severity": "Medium",
        "category": "Infrastructure",
        "description": "The default local Administrator account is enabled and potentially shared across multiple systems with a common password, facilitating lateral movement via pass-the-hash attacks.",
        "impact": "Lateral movement across systems sharing local admin credentials, persistent backdoor access, and difficulty in attribution of malicious activity.",
        "remediation": "Implement Microsoft LAPS (Local Administrator Password Solution) to manage unique local admin passwords. Disable the built-in Administrator account where possible. Use tiered administration.",
        "references": ["https://attack.mitre.org/techniques/T1078/003/"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-250",
        "tags": ["local-admin", "laps", "lateral-movement", "infrastructure", "windows"],
    },
    # ===== Cloud =====
    {
        "title": "Publicly Accessible Storage Bucket",
        "severity": "Critical",
        "category": "Cloud",
        "description": "A cloud storage bucket (S3/GCS/Azure Blob) is configured with public access, allowing anyone on the internet to list, read, or potentially write objects without authentication.",
        "impact": "Exposure of sensitive data to the public internet, data theft, regulatory violations, and potential data manipulation if write access is granted.",
        "remediation": "Remove public access from storage buckets. Enable Block Public Access settings at the account level. Implement bucket policies with explicit deny for public access. Enable access logging.",
        "references": ["https://cwe.mitre.org/data/definitions/284.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-284",
        "tags": ["cloud", "s3", "storage", "public-access", "misconfiguration"],
    },
    {
        "title": "Overly Permissive IAM Policy",
        "severity": "High",
        "category": "Cloud",
        "description": "Cloud IAM policies grant excessive permissions (e.g., wildcard actions '*' or overly broad resource scopes) violating the principle of least privilege.",
        "impact": "Privilege escalation paths, unauthorized access to cloud resources, potential for complete cloud account takeover through chained permissions.",
        "remediation": "Implement least-privilege IAM policies. Remove wildcard permissions. Use IAM Access Analyzer to identify overly permissive policies. Implement service control policies (SCPs) as guardrails.",
        "references": ["https://cwe.mitre.org/data/definitions/250.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-250",
        "tags": ["cloud", "iam", "permissions", "privilege-escalation", "least-privilege"],
    },
    {
        "title": "Cloud Instance Metadata Service Accessible",
        "severity": "High",
        "category": "Cloud",
        "description": "The cloud instance metadata service (IMDS) is accessible without requiring IMDSv2 (session tokens), allowing SSRF attacks to retrieve instance credentials and sensitive configuration data.",
        "impact": "Retrieval of temporary IAM credentials via SSRF, access to sensitive instance configuration, and potential lateral movement using stolen cloud credentials.",
        "remediation": "Enforce IMDSv2 (require session tokens) on all instances. Restrict metadata service access via network policies. Implement hop limit of 1 for metadata requests.",
        "references": ["https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
        "cwe_id": "CWE-918",
        "tags": ["cloud", "metadata", "imds", "ssrf", "credentials"],
    },
    {
        "title": "Unencrypted Cloud Storage",
        "severity": "Medium",
        "category": "Cloud",
        "description": "Cloud storage resources are configured without server-side encryption, leaving data at rest unprotected against unauthorized physical access or storage-level breaches.",
        "impact": "Data exposure in the event of storage-level compromise, failure to meet compliance requirements (HIPAA, PCI-DSS, GDPR), and regulatory penalties.",
        "remediation": "Enable server-side encryption for all cloud storage resources. Use customer-managed keys (CMK) for sensitive data. Enable default encryption policies at the account/organization level.",
        "references": ["https://cwe.mitre.org/data/definitions/311.html"],
        "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-311",
        "tags": ["cloud", "encryption", "storage", "compliance", "data-at-rest"],
    },
    {
        "title": "Security Group Allows Unrestricted Ingress",
        "severity": "High",
        "category": "Cloud",
        "description": "Cloud security groups or network ACLs allow unrestricted inbound access (0.0.0.0/0) to sensitive ports (SSH, RDP, database ports), exposing services to the public internet.",
        "impact": "Brute-force attacks against exposed services, exploitation of service vulnerabilities from the internet, and unauthorized access attempts.",
        "remediation": "Restrict security group ingress rules to specific source IP ranges. Use VPN or bastion hosts for administrative access. Implement network segmentation with private subnets.",
        "references": ["https://cwe.mitre.org/data/definitions/284.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cwe_id": "CWE-284",
        "tags": ["cloud", "security-group", "firewall", "network", "ingress"],
    },
    {
        "title": "Missing CloudTrail/Audit Logging",
        "severity": "Medium",
        "category": "Cloud",
        "description": "Cloud audit logging (CloudTrail, Cloud Audit Logs, Azure Activity Logs) is not enabled or is not configured for all regions and services, creating visibility gaps.",
        "impact": "Inability to detect unauthorized access or configuration changes, compromised incident response capabilities, and failure to meet compliance requirements.",
        "remediation": "Enable cloud audit logging across all regions and services. Configure log retention per compliance requirements. Set up alerting for sensitive API calls and anomalous activity.",
        "references": ["https://cwe.mitre.org/data/definitions/778.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N",
        "cwe_id": "CWE-778",
        "tags": ["cloud", "logging", "audit", "cloudtrail", "monitoring", "compliance"],
    },
    # ===== Mobile =====
    {
        "title": "Insecure Local Data Storage",
        "severity": "High",
        "category": "Mobile",
        "description": "The mobile application stores sensitive data (credentials, tokens, PII) in insecure locations such as shared preferences, plaintext files, or unencrypted databases accessible to other applications or via device backup.",
        "impact": "Exposure of sensitive user data through device compromise, backup extraction, or malicious applications with storage access permissions.",
        "remediation": "Use platform-specific secure storage (iOS Keychain, Android Keystore). Encrypt sensitive data at rest. Exclude sensitive data from backups. Implement proper file permissions.",
        "references": ["https://owasp.org/www-project-mobile-top-10/2016-risks/m2-insecure-data-storage"],
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-312",
        "tags": ["mobile", "data-storage", "encryption", "keychain", "owasp-mobile"],
    },
    {
        "title": "Missing Certificate Pinning",
        "severity": "Medium",
        "category": "Mobile",
        "description": "The mobile application does not implement certificate pinning, allowing attackers with access to install trusted certificates to intercept HTTPS traffic (man-in-the-middle).",
        "impact": "Interception of all application API traffic including authentication tokens and sensitive data when an attacker can install a trusted certificate on the device.",
        "remediation": "Implement certificate pinning using public key pinning or certificate pinning. Include backup pins for certificate rotation. Implement pinning validation failure handling.",
        "references": ["https://owasp.org/www-project-mobile-top-10/2016-risks/m3-insecure-communication"],
        "cvss_vector": "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-295",
        "tags": ["mobile", "certificate-pinning", "tls", "mitm", "owasp-mobile"],
    },
    {
        "title": "Insufficient Binary Protections",
        "severity": "Medium",
        "category": "Mobile",
        "description": "The mobile application binary lacks obfuscation, anti-tampering controls, and runtime integrity checks, making it easy to reverse-engineer and modify.",
        "impact": "Reverse engineering of application logic, intellectual property theft, creation of modified/pirated versions, and bypass of client-side security controls.",
        "remediation": "Implement code obfuscation (ProGuard/R8 for Android, bitcode for iOS). Add anti-tampering checks. Implement root/jailbreak detection. Use integrity verification for critical operations.",
        "references": ["https://owasp.org/www-project-mobile-top-10/2016-risks/m8-code-tampering"],
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-693",
        "tags": ["mobile", "binary", "obfuscation", "reverse-engineering", "owasp-mobile"],
    },
    {
        "title": "Insecure Inter-Process Communication",
        "severity": "Medium",
        "category": "Mobile",
        "description": "The mobile application exposes IPC mechanisms (intents, URL schemes, content providers) without proper access controls, allowing other applications to invoke functionality or access data.",
        "impact": "Unauthorized access to application functionality, data leakage through exported components, and potential for malicious applications to manipulate app behavior.",
        "remediation": "Restrict exported components to those explicitly required. Implement permission checks on all IPC endpoints. Validate all input received via IPC mechanisms. Use signature-level permissions.",
        "references": ["https://owasp.org/www-project-mobile-top-10/2016-risks/m1-improper-platform-usage"],
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-927",
        "tags": ["mobile", "ipc", "intents", "content-provider", "owasp-mobile"],
    },
    {
        "title": "Hardcoded Secrets in Mobile Application",
        "severity": "High",
        "category": "Mobile",
        "description": "The mobile application contains hardcoded secrets such as API keys, encryption keys, or backend credentials embedded in the application binary or configuration files.",
        "impact": "Extraction of secrets through reverse engineering, unauthorized API access, compromise of backend services, and potential financial impact from API abuse.",
        "remediation": "Remove all hardcoded secrets from application code. Use secure key management services. Implement token-based authentication with short-lived credentials. Rotate any exposed keys immediately.",
        "references": ["https://cwe.mitre.org/data/definitions/798.html"],
        "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
        "cwe_id": "CWE-798",
        "tags": ["mobile", "hardcoded", "secrets", "api-keys", "credentials"],
    },
    # ===== Physical =====
    {
        "title": "Tailgating Access Achieved",
        "severity": "High",
        "category": "Physical",
        "description": "Physical access to a restricted area was gained by following an authorized person through a controlled entrance without presenting valid credentials or being challenged.",
        "impact": "Unauthorized physical access to restricted areas, potential for device theft, data exfiltration, hardware implant installation, or further social engineering.",
        "remediation": "Implement anti-tailgating measures (mantraps, turnstiles). Conduct security awareness training on challenging unknown individuals. Deploy CCTV monitoring at access points. Consider security guards.",
        "references": ["https://attack.mitre.org/techniques/T1200/"],
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-284",
        "tags": ["physical", "tailgating", "access-control", "social-engineering"],
    },
    {
        "title": "Badge Cloning Successful",
        "severity": "Critical",
        "category": "Physical",
        "description": "Access control badges use insecure low-frequency RFID technology (e.g., 125kHz HID Prox) that was successfully cloned using readily available equipment, granting unauthorized physical access.",
        "impact": "Unrestricted physical access using a cloned badge, difficulty in detecting unauthorized access since the badge appears legitimate in access logs.",
        "remediation": "Migrate to high-frequency, encrypted smart card technology (HID iCLASS SE, SEOS, or MIFARE DESFire). Implement multi-factor physical access (badge + PIN). Deploy badge shielding sleeves.",
        "references": ["https://attack.mitre.org/techniques/T1200/"],
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-287",
        "tags": ["physical", "badge-cloning", "rfid", "access-control"],
    },
    {
        "title": "Lock Bypass Achieved",
        "severity": "High",
        "category": "Physical",
        "description": "Physical locks protecting sensitive areas were bypassed using picking, bumping, or other non-destructive techniques, indicating insufficient physical security controls.",
        "impact": "Unauthorized access to restricted areas, server rooms, or secure storage. Potential for data theft, hardware tampering, or installation of persistent access devices.",
        "remediation": "Install high-security locks (Abloy Protec2, Medeco) resistant to picking and bumping. Implement electronic access control as a complement to physical locks. Install tamper detection sensors.",
        "references": ["https://attack.mitre.org/techniques/T1200/"],
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-284",
        "tags": ["physical", "lock-bypass", "picking", "access-control"],
    },
    {
        "title": "Sensitive Information in Dumpster",
        "severity": "Medium",
        "category": "Physical",
        "description": "Sensitive documents, storage media, or hardware containing organizational data were found in waste containers without proper destruction, exposing confidential information.",
        "impact": "Information disclosure including credentials, network diagrams, employee data, or client information. May enable targeted social engineering or network attacks.",
        "remediation": "Implement a document destruction policy with cross-cut shredders for paper. Use certified media destruction for storage devices. Deploy locked secure disposal bins. Conduct employee training.",
        "references": ["https://attack.mitre.org/techniques/T1589/"],
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-200",
        "tags": ["physical", "dumpster-diving", "information-disclosure", "data-destruction"],
    },
    {
        "title": "Unattended Workstation Access",
        "severity": "Medium",
        "category": "Physical",
        "description": "Unlocked and unattended workstations were observed in the environment, allowing anyone with physical access to use authenticated sessions without needing credentials.",
        "impact": "Access to authenticated systems and applications, data theft, email impersonation, malware installation, and actions performed under the legitimate user's identity.",
        "remediation": "Implement automatic screen lock policies (e.g., 5-minute timeout). Deploy proximity-based locking solutions. Conduct user awareness training on locking workstations. Monitor for policy violations.",
        "references": ["https://cwe.mitre.org/data/definitions/284.html"],
        "cvss_vector": "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "cwe_id": "CWE-284",
        "tags": ["physical", "workstation", "screen-lock", "access-control"],
    },
    # ===== Additional Web Application Templates =====
    {
        "title": "Directory Traversal / Path Traversal",
        "severity": "High",
        "category": "Web Application",
        "description": "The application allows users to access files outside the intended directory by manipulating file path parameters with sequences like '../'. This can expose sensitive system files.",
        "impact": "Reading arbitrary files from the server including configuration files with credentials, source code, and operating system files like /etc/passwd.",
        "remediation": "Validate and sanitize file path inputs. Use a chroot or sandbox for file access. Implement allowlists for permitted file paths. Avoid passing user input directly to file system APIs.",
        "references": ["https://owasp.org/www-community/attacks/Path_Traversal", "https://cwe.mitre.org/data/definitions/22.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "cwe_id": "CWE-22",
        "tags": ["path-traversal", "directory-traversal", "file-access", "lfi", "web"],
    },
    {
        "title": "Server-Side Template Injection (SSTI)",
        "severity": "Critical",
        "category": "Web Application",
        "description": "User input is embedded directly into server-side templates without sanitization, allowing attackers to inject template directives that execute arbitrary code on the server.",
        "impact": "Remote code execution on the application server, complete server compromise, data exfiltration, and lateral movement into internal networks.",
        "remediation": "Never pass user input directly into template engines. Use logic-less templates or sandboxed template environments. Implement input validation and output encoding.",
        "references": ["https://portswigger.net/research/server-side-template-injection", "https://cwe.mitre.org/data/definitions/1336.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-1336",
        "tags": ["ssti", "template-injection", "rce", "web", "injection"],
    },
    {
        "title": "HTTP Security Headers Missing",
        "severity": "Low",
        "category": "Web Application",
        "description": "The application does not implement recommended HTTP security headers including Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Strict-Transport-Security, and others.",
        "impact": "Increased vulnerability to clickjacking, MIME-type confusion attacks, cross-site scripting, and protocol downgrade attacks.",
        "remediation": "Implement all recommended security headers: Content-Security-Policy, X-Frame-Options (DENY/SAMEORIGIN), X-Content-Type-Options (nosniff), Strict-Transport-Security, Referrer-Policy, and Permissions-Policy.",
        "references": ["https://owasp.org/www-project-secure-headers/"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "cwe_id": "CWE-693",
        "tags": ["headers", "csp", "hsts", "clickjacking", "web", "hardening"],
    },
    {
        "title": "Unrestricted File Upload",
        "severity": "High",
        "category": "Web Application",
        "description": "The application allows file uploads without adequate validation of file type, content, or size, potentially allowing upload of executable files or web shells.",
        "impact": "Remote code execution via uploaded web shells, denial of service through large file uploads, and storage of malicious content for distribution.",
        "remediation": "Validate file type by content (magic bytes), not just extension. Store uploads outside the web root. Use random filenames. Implement file size limits. Scan uploads for malware.",
        "references": ["https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload", "https://cwe.mitre.org/data/definitions/434.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "cwe_id": "CWE-434",
        "tags": ["file-upload", "web-shell", "rce", "web", "validation"],
    },
    {
        "title": "Mass Assignment Vulnerability",
        "severity": "Medium",
        "category": "Web Application",
        "description": "The application automatically binds user-supplied request parameters to internal object properties without proper filtering, allowing attackers to modify fields they shouldn't have access to.",
        "impact": "Privilege escalation by modifying role/admin fields, bypassing business logic, unauthorized data modification, and potential account takeover.",
        "remediation": "Implement allowlists for bindable parameters. Use DTOs (Data Transfer Objects) to control which fields are accepted. Never bind directly from request to model without filtering.",
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/", "https://cwe.mitre.org/data/definitions/915.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "cwe_id": "CWE-915",
        "tags": ["mass-assignment", "api", "web", "owasp-api", "authorization"],
    },
    # ===== Additional Configuration Weaknesses =====
    {
        "title": "Unnecessary HTTP Methods Enabled",
        "severity": "Low",
        "category": "Web Application",
        "description": "The web server allows HTTP methods beyond GET and POST, including potentially dangerous methods such as PUT, DELETE, TRACE, or OPTIONS that may expose additional attack vectors.",
        "impact": "Potential for cross-site tracing attacks (TRACE), unauthorized file modification (PUT/DELETE), and information disclosure about server capabilities.",
        "remediation": "Disable unnecessary HTTP methods. Allow only GET, POST, and HEAD for standard web applications. Configure the web server to return 405 Method Not Allowed for unsupported methods.",
        "references": ["https://cwe.mitre.org/data/definitions/16.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-16",
        "tags": ["http-methods", "trace", "put", "configuration", "web", "hardening"],
    },
    {
        "title": "Information Disclosure via Error Messages",
        "severity": "Low",
        "category": "Web Application",
        "description": "The application displays detailed error messages or stack traces to users, revealing internal implementation details, file paths, database structures, or technology versions.",
        "impact": "Leakage of internal application architecture details useful for planning targeted attacks, identification of specific technology versions with known vulnerabilities.",
        "remediation": "Implement custom error pages that display generic messages to users. Log detailed errors server-side only. Ensure production mode is enabled and debug mode is disabled.",
        "references": ["https://cwe.mitre.org/data/definitions/209.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "cwe_id": "CWE-209",
        "tags": ["information-disclosure", "error-messages", "stack-trace", "web", "configuration"],
    },
    {
        "title": "Insecure CORS Configuration",
        "severity": "Medium",
        "category": "Web Application",
        "description": "The application implements an overly permissive Cross-Origin Resource Sharing (CORS) policy, such as reflecting the Origin header or allowing credentials with wildcard origins.",
        "impact": "Theft of sensitive data by malicious websites through cross-origin requests, CSRF-like attacks bypassing same-origin protections, and session credential theft.",
        "remediation": "Implement strict CORS policies with explicit allowed origins. Never reflect arbitrary Origins with credentials. Validate the Origin header server-side against an allowlist.",
        "references": ["https://portswigger.net/web-security/cors", "https://cwe.mitre.org/data/definitions/942.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
        "cwe_id": "CWE-942",
        "tags": ["cors", "cross-origin", "web", "configuration", "access-control"],
    },
    {
        "title": "Lack of Rate Limiting",
        "severity": "Medium",
        "category": "Web Application",
        "description": "The application does not implement rate limiting on sensitive endpoints (login, password reset, API calls), allowing unlimited requests that enable brute-force attacks and resource exhaustion.",
        "impact": "Brute-force attacks against authentication, enumeration of valid accounts, API abuse, and potential denial of service through resource exhaustion.",
        "remediation": "Implement rate limiting on all authentication endpoints. Use progressive delays or account lockout. Deploy WAF rules for automated attack detection. Implement API rate limiting per client.",
        "references": ["https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/", "https://cwe.mitre.org/data/definitions/770.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L",
        "cwe_id": "CWE-770",
        "tags": ["rate-limiting", "brute-force", "api", "dos", "web", "authentication"],
    },
    {
        "title": "Outdated Web Server Software",
        "severity": "Medium",
        "category": "Infrastructure",
        "description": "The web server software (Apache, Nginx, IIS) is running an outdated version with known security vulnerabilities for which patches are available.",
        "impact": "Exploitation of known vulnerabilities specific to the web server version, potentially leading to remote code execution, information disclosure, or denial of service.",
        "remediation": "Update the web server to the latest stable version. Subscribe to security advisories for the specific server software. Implement automated patch management.",
        "references": ["https://cwe.mitre.org/data/definitions/1104.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "cwe_id": "CWE-1104",
        "tags": ["web-server", "outdated", "patching", "infrastructure", "apache", "nginx"],
    },
    {
        "title": "Database Accessible from Internet",
        "severity": "Critical",
        "category": "Infrastructure",
        "description": "A database service (MySQL, PostgreSQL, MSSQL, MongoDB) is directly accessible from the internet without proper network segmentation or firewall restrictions.",
        "impact": "Brute-force attacks against database credentials, exploitation of database vulnerabilities, direct data theft, and potential for complete database compromise.",
        "remediation": "Place databases in private network segments not accessible from the internet. Use firewalls to restrict access to application servers only. Implement database authentication and encryption.",
        "references": ["https://cwe.mitre.org/data/definitions/284.html"],
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_id": "CWE-284",
        "tags": ["database", "exposure", "network-segmentation", "infrastructure", "internet-facing"],
    },
]
