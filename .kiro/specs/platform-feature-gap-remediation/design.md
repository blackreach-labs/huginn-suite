# Design Document: Platform Feature Gap Remediation

## Overview

This design transforms Huginn from a scanning/exploitation tool into a complete engagement management platform by adding 19 capabilities across three priority tiers. The system introduces per-engagement SQLite database isolation, file-based team collaboration via encrypted ZIP archives, and new methodology modules integrated as sub-tabs within existing pages.

## Architecture

The architecture extends existing patterns (QObject signals, CommandWorker, centralized_scan_data, DatabaseConnectionPool) with two structural additions:

1. **Per-engagement SQLite database isolation** — Each engagement gets its own `.db` file, with a master index database tracking all engagements
2. **File-based team collaboration** — Engagement data shared as AES-256 encrypted ZIP archives

All new modules follow the established convention: core engines in `app/core/`, UI components in `app/components/`, signals for async communication, and lazy initialization for performance.

### File Structure

```
app/core/
├── engagement_manager.py           # Lifecycle, state machine, DB isolation
├── engagement_database.py          # Per-engagement DB connection/schema
├── finding_template_library.py     # Template CRUD, search, import/export
├── evidence_manager.py             # Capture, annotate, link, hash, compress
├── note_system.py                  # Scoped notes, revisions, FTS
├── attack_mapper.py                # MITRE ATT&CK mapping, coverage matrix
├── retest_workflow.py              # Retest cycles, status tracking, metrics
├── cvss_calculator.py              # CVSS v3.1/v4.0 scoring
├── timeline_logger.py              # Activity logging, filtering
├── import_export_engine.py         # Nessus/Burp/SARIF/CSV parsing
├── collaboration_manager.py        # Encrypted ZIP export/import
├── knowledge_base.py               # Article storage, FTS, suggestions
├── report_customizer.py            # Templates, branding, multi-format output
├── attack_surface_mapper.py        # Graph model, path analysis
├── api_pentest_engine.py           # OWASP API Top 10 workflows
├── container_assessment_engine.py  # Docker/K8s assessment
├── mobile_testing_engine.py        # OWASP Mobile Top 10 workflows
├── physical_security_engine.py     # Physical access tracking
├── gcp_pentest_engine.py           # GCP enumeration/exploitation
└── scheduling_engine.py            # Cron-based recurring scans

app/components/
├── engagement_setup_component.py   # Engagement Setup page (new tab)
├── finding_templates_component.py  # Reporting page (new tab)
├── evidence_manager_component.py   # Post-Exploitation page (enhances existing)
├── notes_panel_component.py        # Floating panel, all pages
├── attack_matrix_component.py      # Reporting page (new tab)
├── retest_workflow_component.py    # Reporting page (new tab)
├── cvss_calculator_component.py    # Dialog/panel, findings integration
├── timeline_component.py           # Engagement Setup page (new tab)
├── import_export_component.py      # Tools menu dialog
├── collaboration_component.py      # File menu dialog
├── knowledge_base_component.py     # Tools menu, context suggestions
├── report_designer_component.py    # Reporting page (enhances existing)
├── attack_surface_graph_component.py # Reporting page (new tab)
├── api_pentest_component.py        # Vulnerability Analysis page (sub-tab)
├── container_assessment_component.py # Exploitation page (sub-tab)
├── mobile_testing_component.py     # Exploitation page (sub-tab)
├── physical_security_component.py  # Engagement Setup page (sub-tab)
├── gcp_pentest_component.py        # Recon & Enumeration page (sub-tab)
└── scan_scheduler_component.py     # Tools menu / Engagement Setup
```

## Components and Interfaces

## Data Models

### Database Isolation Model

```
resources/
├── huginn_master_index.db          # Master Index Database
├── engagements/
│   ├── {engagement_id}/
│   │   ├── engagement.db           # Per-engagement isolated database
│   │   ├── evidence/               # Evidence file storage
│   │   └── documents/              # Scoping docs, RoE, etc.
│   └── ...
├── templates/
│   ├── finding_templates.db        # Finding template library
│   └── report_templates/           # Report template definitions
├── knowledge_base/
│   └── knowledge_base.db           # Knowledge base articles
└── centralized_scan_data.db        # Existing (unchanged)
```

### Master Index Database Schema

```python
# app/core/engagement_manager.py

MASTER_INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,                    -- UUID
    name TEXT NOT NULL,
    client_name TEXT NOT NULL,
    engagement_type TEXT NOT NULL,          -- internal, external, web, mobile, physical, cloud
    status TEXT NOT NULL DEFAULT 'draft',   -- draft, scoping, active, paused, retest, reporting, closed
    start_date TEXT,
    end_date TEXT,
    db_path TEXT NOT NULL,                  -- Relative path to engagement.db
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS engagement_state_transitions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state TEXT NOT NULL,
    transitioned_at TEXT NOT NULL,
    actor TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);

CREATE TABLE IF NOT EXISTS scheduled_scans (
    id TEXT PRIMARY KEY,
    engagement_id TEXT,
    name TEXT NOT NULL,
    scan_config TEXT NOT NULL,              -- JSON blob
    target_list TEXT NOT NULL,              -- JSON array
    recurrence_pattern TEXT NOT NULL,       -- cron expression or 'once'
    next_execution TEXT NOT NULL,
    last_execution TEXT,
    status TEXT DEFAULT 'active',           -- active, disabled, completed
    failure_count INTEGER DEFAULT 0,
    last_failure_reason TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(id)
);
"""
```

### Per-Engagement Database Schema

```python
# app/core/engagement_database.py

ENGAGEMENT_DB_SCHEMA = """
-- Engagement metadata
CREATE TABLE IF NOT EXISTS engagement_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Rules of Engagement
CREATE TABLE IF NOT EXISTS rules_of_engagement (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    authorized_ip_ranges TEXT,             -- JSON array
    excluded_systems TEXT,                  -- JSON array
    testing_hours TEXT,                     -- JSON: {start, end, timezone, days}
    emergency_contacts TEXT,               -- JSON array of {name, phone, email}
    escalation_procedures TEXT,
    custom_rules TEXT,
    updated_at TEXT NOT NULL
);

-- Client contacts
CREATE TABLE IF NOT EXISTS client_contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    role TEXT,
    email TEXT,
    phone TEXT,
    availability_window TEXT,              -- JSON: {start, end, timezone}
    created_at TEXT NOT NULL
);

-- Documents
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    document_type TEXT NOT NULL,            -- scope, roe, sow, nda, other
    content BLOB NOT NULL,
    mime_type TEXT,
    upload_date TEXT NOT NULL,
    metadata TEXT                           -- JSON
);

-- Timeline milestones
CREATE TABLE IF NOT EXISTS milestones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    milestone_type TEXT NOT NULL,           -- planned_start, actual_start, planned_end, actual_end, checkpoint
    date TEXT NOT NULL,
    notes TEXT
);

-- Findings (engagement-specific)
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT,
    impact TEXT,
    remediation TEXT,
    cvss_score REAL,
    cvss_vector TEXT,
    cwe_id TEXT,
    category TEXT,
    status TEXT DEFAULT 'open',            -- open, confirmed, false_positive, remediated, accepted
    template_id TEXT,                       -- Reference to source template (if any)
    target_id INTEGER,
    service_id INTEGER,
    attack_technique_ids TEXT,             -- JSON array of ATT&CK technique IDs
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Evidence
CREATE TABLE IF NOT EXISTS evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_type TEXT NOT NULL,            -- screenshot, text_snippet, file, http_pair, terminal_output
    title TEXT,
    data BLOB,
    compressed INTEGER DEFAULT 0,
    sha256_hash TEXT NOT NULL,
    mime_type TEXT,
    source_context TEXT,
    tags TEXT,                              -- JSON array
    target_id INTEGER,
    annotations TEXT,                       -- JSON array of annotation objects
    created_at TEXT NOT NULL
);

-- Evidence-Finding linkage (many-to-many)
CREATE TABLE IF NOT EXISTS evidence_finding_links (
    evidence_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    linked_at TEXT NOT NULL,
    PRIMARY KEY (evidence_id, finding_id),
    FOREIGN KEY (evidence_id) REFERENCES evidence(id),
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

-- Notes
CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_type TEXT NOT NULL,               -- target, service, vulnerability
    scope_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    content_format TEXT DEFAULT 'markdown', -- markdown, plaintext
    author TEXT,
    pinned INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Note revisions
CREATE TABLE IF NOT EXISTS note_revisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    revised_at TEXT NOT NULL,
    FOREIGN KEY (note_id) REFERENCES notes(id)
);

-- ATT&CK mappings
CREATE TABLE IF NOT EXISTS attack_mappings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id INTEGER NOT NULL,
    technique_id TEXT NOT NULL,             -- e.g., T1059.001
    tactic TEXT NOT NULL,
    procedure_description TEXT,
    status TEXT DEFAULT 'tested',           -- tested, successful, not_tested
    FOREIGN KEY (finding_id) REFERENCES findings(id)
);

-- Retest cycles
CREATE TABLE IF NOT EXISTS retest_cycles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_number INTEGER NOT NULL,
    start_date TEXT NOT NULL,
    end_date TEXT,
    status TEXT DEFAULT 'in_progress',     -- in_progress, completed
    notes TEXT,
    created_at TEXT NOT NULL
);

-- Retest results
CREATE TABLE IF NOT EXISTS retest_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cycle_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    retest_status TEXT NOT NULL,            -- not_tested, fixed, partially_fixed, not_fixed, regressed
    retester_notes TEXT,
    evidence_id INTEGER,
    retested_at TEXT NOT NULL,
    FOREIGN KEY (cycle_id) REFERENCES retest_cycles(id),
    FOREIGN KEY (finding_id) REFERENCES findings(id),
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
);

-- Timeline / Activity Log
CREATE TABLE IF NOT EXISTS timeline_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_type TEXT NOT NULL,              -- scan_start, scan_complete, finding_discovered, exploit_attempt, state_transition, manual
    actor TEXT,
    affected_entity_type TEXT,
    affected_entity_id INTEGER,
    description TEXT NOT NULL,
    metadata TEXT,                          -- JSON
    timestamp TEXT NOT NULL
);

-- Physical security attempts
CREATE TABLE IF NOT EXISTS physical_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    location TEXT NOT NULL,
    attempt_time TEXT NOT NULL,
    method TEXT NOT NULL,                   -- tailgating, lock_bypass, badge_cloning, dumpster_diving, social_engineering
    outcome TEXT NOT NULL,                  -- success, failure, partial
    evidence_id INTEGER,
    notes TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(id)
);

-- Physical site annotations
CREATE TABLE IF NOT EXISTS site_annotations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    floor_plan_evidence_id INTEGER NOT NULL,
    annotation_type TEXT NOT NULL,          -- entry_point, camera, access_control_zone
    coordinates TEXT NOT NULL,              -- JSON: {x, y, width, height}
    label TEXT,
    notes TEXT,
    FOREIGN KEY (floor_plan_evidence_id) REFERENCES evidence(id)
);

-- Physical security control ratings
CREATE TABLE IF NOT EXISTS physical_control_ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    location TEXT NOT NULL,
    control_type TEXT NOT NULL,
    effectiveness_rating INTEGER NOT NULL,  -- 1-5
    notes TEXT,
    assessed_at TEXT NOT NULL
);
"""
```

### Finding Templates Database Schema

```python
# app/core/finding_template_library.py

TEMPLATES_DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS templates (
    id TEXT PRIMARY KEY,                    -- UUID
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT NOT NULL,                 -- web_application, network, infrastructure, cloud, mobile, physical
    description TEXT NOT NULL,
    impact TEXT NOT NULL,
    remediation TEXT NOT NULL,
    references TEXT,                        -- JSON array of URLs
    cvss_vector TEXT,
    cwe_id TEXT,
    tags TEXT,                              -- JSON array for search
    is_builtin INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS templates_fts USING fts5(
    title, description, tags, category, cwe_id,
    content=templates, content_rowid=rowid
);
"""
```

### Knowledge Base Database Schema

```python
# app/core/knowledge_base.py

KNOWLEDGE_BASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT NOT NULL,                  -- Markdown
    category TEXT NOT NULL,
    tags TEXT,                              -- JSON array
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
"""
```

---

### Module Architecture (Components and Interfaces)

### Core Engine Modules (app/core/)

| Module | File | Responsibility |
|--------|------|----------------|
| Engagement Manager | `engagement_manager.py` | Lifecycle, state machine, DB isolation |
| Engagement Database | `engagement_database.py` | Per-engagement DB connection/schema |
| Finding Template Library | `finding_template_library.py` | Template CRUD, search, import/export |
| Evidence Manager | `evidence_manager.py` | Capture, annotate, link, hash, compress |
| Note System | `note_system.py` | Scoped notes, revisions, FTS |
| ATT&CK Mapper | `attack_mapper.py` | MITRE mapping, coverage matrix data |
| Retest Workflow | `retest_workflow.py` | Retest cycles, status tracking, metrics |
| CVSS Calculator | `cvss_calculator.py` | v3.1/v4.0 scoring, vector strings |
| Timeline Logger | `timeline_logger.py` | Activity logging, filtering |
| Import/Export Engine | `import_export_engine.py` | Nessus/Burp/SARIF/CSV parsing |
| Collaboration Manager | `collaboration_manager.py` | Encrypted ZIP export/import |
| Knowledge Base | `knowledge_base.py` | Article storage, FTS, suggestions |
| Report Customizer | `report_customizer.py` | Templates, branding, multi-format |
| Attack Surface Mapper | `attack_surface_mapper.py` | Graph model, path analysis |
| API Pentest Module | `api_pentest_engine.py` | OWASP API Top 10 workflows |
| Container Assessment | `container_assessment_engine.py` | Docker/K8s checks |
| Mobile Testing | `mobile_testing_engine.py` | OWASP Mobile Top 10 workflows |
| Physical Security | `physical_security_engine.py` | Access tracking, annotations |
| GCP Pentest Engine | `gcp_pentest_engine.py` | GCP enumeration/exploitation |
| Scheduling Engine | `scheduling_engine.py` | Cron-based recurring scans |

### UI Components (app/components/)

| Component | File | Integration Point |
|-----------|------|-------------------|
| Engagement Setup | `engagement_setup_component.py` | Engagement Setup page (new tab) |
| Finding Templates | `finding_templates_component.py` | Reporting page (new tab) |
| Evidence Manager | `evidence_manager_component.py` | Post-Exploitation page (enhances existing) |
| Notes Panel | `notes_panel_component.py` | Floating panel, all pages |
| ATT&CK Matrix | `attack_matrix_component.py` | Reporting page (new tab) |
| Retest Workflow | `retest_workflow_component.py` | Reporting page (new tab) |
| CVSS Calculator | `cvss_calculator_component.py` | Dialog/panel, findings integration |
| Timeline View | `timeline_component.py` | Engagement Setup page (new tab) |
| Import/Export | `import_export_component.py` | Tools menu dialog |
| Collaboration | `collaboration_component.py` | File menu dialog |
| Knowledge Base | `knowledge_base_component.py` | Tools menu, context suggestions |
| Report Designer | `report_designer_component.py` | Reporting page (enhances existing) |
| Attack Surface Graph | `attack_surface_graph_component.py` | Reporting page (new tab) |
| API Pentest | `api_pentest_component.py` | Vulnerability Analysis page (sub-tab) |
| Container Assessment | `container_assessment_component.py` | Exploitation page (sub-tab) |
| Mobile Testing | `mobile_testing_component.py` | Exploitation page (sub-tab) |
| Physical Security | `physical_security_component.py` | Engagement Setup page (sub-tab) |
| GCP Pentest | `gcp_pentest_component.py` | Recon & Enumeration page (sub-tab) |
| Scan Scheduler | `scan_scheduler_component.py` | Tools menu / Engagement Setup |

---

## Component Design

### 1. Engagement Manager

```python
# app/core/engagement_manager.py
from PyQt6.QtCore import QObject, pyqtSignal
from enum import Enum
from typing import Optional, List, Dict
import uuid
from datetime import datetime
from .database_pool import DatabaseConnectionPool

class EngagementState(Enum):
    DRAFT = "draft"
    SCOPING = "scoping"
    ACTIVE = "active"
    PAUSED = "paused"
    RETEST = "retest"
    REPORTING = "reporting"
    CLOSED = "closed"

# Valid state transitions
VALID_TRANSITIONS = {
    EngagementState.DRAFT: [EngagementState.SCOPING],
    EngagementState.SCOPING: [EngagementState.ACTIVE],
    EngagementState.ACTIVE: [EngagementState.PAUSED, EngagementState.RETEST, EngagementState.REPORTING],
    EngagementState.PAUSED: [EngagementState.ACTIVE, EngagementState.CLOSED],
    EngagementState.RETEST: [EngagementState.REPORTING, EngagementState.ACTIVE],
    EngagementState.REPORTING: [EngagementState.CLOSED, EngagementState.RETEST],
    EngagementState.CLOSED: [],
}

class EngagementManager(QObject):
    engagement_created = pyqtSignal(str)           # engagement_id
    engagement_opened = pyqtSignal(str)            # engagement_id
    state_changed = pyqtSignal(str, str, str)      # engagement_id, old_state, new_state
    
    def __init__(self, master_db_path: str = None):
        super().__init__()
        self.master_pool = DatabaseConnectionPool(master_db_path)
        self.active_engagement_id: Optional[str] = None
        self.active_db: Optional[EngagementDatabase] = None
    
    def create_engagement(self, name: str, client_name: str,
                         engagement_type: str, start_date: str,
                         end_date: str) -> str:
        """Create new engagement with isolated database."""
        ...
    
    def open_engagement(self, engagement_id: str) -> bool:
        """Open engagement and connect to its isolated database."""
        ...
    
    def transition_state(self, engagement_id: str,
                        new_state: EngagementState) -> bool:
        """Validate and apply state transition."""
        ...
    
    def list_engagements(self, status_filter: str = None,
                        search_query: str = None) -> List[Dict]:
        """List engagements from master index."""
        ...
```

### 2. Evidence Manager

```python
# app/core/evidence_manager.py
from PyQt6.QtCore import QObject, pyqtSignal
import hashlib
import zlib
from typing import List, Dict, Optional
from dataclasses import dataclass

@dataclass
class Annotation:
    annotation_type: str   # rectangle, arrow, text_label, redaction
    coordinates: Dict      # {x, y, width, height} or {x1, y1, x2, y2}
    properties: Dict       # color, text, thickness, etc.

class EvidenceManager(QObject):
    evidence_stored = pyqtSignal(int)       # evidence_id
    evidence_linked = pyqtSignal(int, int)  # evidence_id, finding_id
    
    COMPRESSION_THRESHOLD = 10 * 1024 * 1024  # 10 MB
    
    def store_evidence(self, evidence_type: str, data: bytes,
                      title: str = "", source_context: str = "",
                      tags: List[str] = None) -> int:
        """Store evidence with hash and optional compression."""
        sha256 = hashlib.sha256(data).hexdigest()
        compressed = 0
        if len(data) > self.COMPRESSION_THRESHOLD:
            data = zlib.compress(data)
            compressed = 1
        # Insert into engagement DB
        ...
    
    def retrieve_evidence(self, evidence_id: int) -> bytes:
        """Retrieve evidence, decompressing if needed."""
        ...
    
    def add_annotation(self, evidence_id: int, annotation: Annotation) -> None:
        """Add non-destructive annotation (stored as JSON, original data unchanged)."""
        ...
    
    def link_to_finding(self, evidence_id: int, finding_id: int) -> None:
        """Create bidirectional link between evidence and finding."""
        ...
    
    def get_evidence_for_finding(self, finding_id: int) -> List[Dict]:
        """Get all evidence linked to a finding."""
        ...
    
    def get_findings_for_evidence(self, evidence_id: int) -> List[Dict]:
        """Get all findings linked to evidence."""
        ...
    
    def on_finding_deleted(self, finding_id: int) -> None:
        """Handle finding deletion: unlink but retain evidence."""
        ...
```

### 3. CVSS Calculator

```python
# app/core/cvss_calculator.py
from typing import Dict, Tuple
from enum import Enum

class CVSSVersion(Enum):
    V3_1 = "3.1"
    V4_0 = "4.0"

SEVERITY_RANGES = {
    "None": (0.0, 0.0),
    "Low": (0.1, 3.9),
    "Medium": (4.0, 6.9),
    "High": (7.0, 8.9),
    "Critical": (9.0, 10.0),
}

class CVSSCalculator:
    def compute_score(self, version: CVSSVersion,
                     metrics: Dict[str, str]) -> Tuple[float, float, float]:
        """Compute base, temporal, and environmental scores."""
        ...
    
    def generate_vector_string(self, version: CVSSVersion,
                              metrics: Dict[str, str]) -> str:
        """Generate standard CVSS vector string from metrics."""
        ...
    
    def parse_vector_string(self, vector: str) -> Tuple[CVSSVersion, Dict[str, str]]:
        """Parse vector string back to version and metrics."""
        ...
    
    def get_severity_label(self, base_score: float) -> str:
        """Map base score to severity label."""
        for label, (low, high) in SEVERITY_RANGES.items():
            if low <= base_score <= high:
                return label
        return "None"
```

### 4. Import/Export Engine

```python
# app/core/import_export_engine.py
from PyQt6.QtCore import QObject, pyqtSignal
from typing import List, Dict, Tuple
from dataclasses import dataclass

@dataclass
class ImportRecord:
    """Normalized record from any import format."""
    host: str
    port: int = 0
    vulnerability_name: str = ""
    severity: str = "info"
    description: str = ""
    evidence: str = ""
    source_format: str = ""
    raw_data: Dict = None

class ImportExportEngine(QObject):
    import_progress = pyqtSignal(int, int)    # current, total
    import_warning = pyqtSignal(str)          # warning message
    
    def parse_nessus_xml(self, file_path: str) -> Tuple[List[ImportRecord], List[str]]:
        """Parse Nessus XML, return (records, warnings)."""
        ...
    
    def parse_burp_xml(self, file_path: str) -> Tuple[List[ImportRecord], List[str]]:
        """Parse Burp Suite XML export."""
        ...
    
    def parse_sarif(self, file_path: str) -> Tuple[List[ImportRecord], List[str]]:
        """Parse SARIF JSON format."""
        ...
    
    def parse_csv(self, file_path: str,
                 column_mapping: Dict[str, str]) -> Tuple[List[ImportRecord], List[str]]:
        """Parse CSV with configurable column mapping."""
        ...
    
    def export_findings(self, findings: List[Dict],
                       format: str, output_path: str) -> bool:
        """Export findings in specified format."""
        ...
```

### 5. Collaboration Manager

```python
# app/core/collaboration_manager.py
from PyQt6.QtCore import QObject, pyqtSignal
import zipfile
import json
import hashlib
from typing import List, Dict, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

class CollaborationManager(QObject):
    export_progress = pyqtSignal(int, int)    # current, total
    import_progress = pyqtSignal(int, int)
    
    def export_engagement(self, engagement_id: str, passphrase: str,
                         output_path: str,
                         selected_findings: List[int] = None,
                         selected_evidence: List[int] = None) -> bool:
        """Export engagement as AES-256 encrypted ZIP."""
        ...
    
    def import_engagement(self, package_path: str,
                         passphrase: str) -> Optional[str]:
        """Import engagement package, returns new engagement_id or None."""
        ...
    
    def _derive_key(self, passphrase: str, salt: bytes) -> bytes:
        """Derive AES-256 key from passphrase using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return kdf.derive(passphrase.encode())
    
    def _create_manifest(self, files: List[str]) -> Dict:
        """Create manifest with file checksums."""
        ...
    
    def _validate_manifest(self, manifest: Dict, extracted_dir: str) -> bool:
        """Validate all file checksums against manifest."""
        ...
```

### 6. GCP Pentest Engine

```python
# app/core/gcp_pentest_engine.py
from PyQt6.QtCore import QObject, pyqtSignal, QRunnable
from typing import Dict, List, Optional

class GCPWorkerSignals(QObject):
    output = pyqtSignal(str)
    error = pyqtSignal(str)
    finished = pyqtSignal()
    progress = pyqtSignal(int)
    results_ready = pyqtSignal(dict)

class GCPPentestEngine(QObject):
    """GCP Penetration Testing Engine - mirrors AWS/Azure engine patterns."""
    
    pentest_event = pyqtSignal(str, str)  # event_type, message
    
    def __init__(self):
        super().__init__()
        self.credentials = None
        self.project_id = None
        self.discovered_resources = {}
        self.privilege_paths = []
    
    def configure_session(self, service_account_key: str = None,
                         oauth_token: str = None,
                         project_id: str = None) -> tuple:
        """Configure GCP session with credentials."""
        ...
    
    def enumerate_iam(self) -> List[Dict]:
        """Enumerate IAM policies and bindings."""
        ...
    
    def enumerate_storage(self) -> List[Dict]:
        """Discover and assess storage buckets."""
        ...
    
    def enumerate_compute(self) -> List[Dict]:
        """Discover compute instances and metadata."""
        ...
    
    def check_privilege_escalation(self, iam_policies: List[Dict]) -> List[Dict]:
        """Analyze IAM for privilege escalation paths."""
        ...
    
    def check_public_buckets(self, buckets: List[Dict]) -> List[Dict]:
        """Test for publicly accessible storage buckets."""
        ...
```

### 7. Scheduling Engine

```python
# app/core/scheduling_engine.py
from PyQt6.QtCore import QObject, pyqtSignal, QTimer
from typing import Dict, List, Optional
from datetime import datetime
import threading

class SchedulingEngine(QObject):
    scan_triggered = pyqtSignal(str)          # schedule_id
    scan_completed = pyqtSignal(str, dict)    # schedule_id, results
    scan_failed = pyqtSignal(str, str)        # schedule_id, error
    
    def __init__(self, master_db_pool):
        super().__init__()
        self.master_db_pool = master_db_pool
        self.check_timer = QTimer(self)
        self.check_timer.timeout.connect(self._check_pending)
        self.check_timer.start(60000)  # Check every minute
    
    def create_schedule(self, name: str, scan_config: Dict,
                       target_list: List[str],
                       recurrence: str,
                       engagement_id: str = None) -> str:
        """Create scheduled scan with cron expression."""
        ...
    
    def compute_next_execution(self, cron_expr: str,
                              from_time: datetime = None) -> datetime:
        """Compute next execution time from cron expression."""
        ...
    
    def disable_schedule(self, schedule_id: str) -> bool:
        """Suspend without deleting configuration."""
        ...
    
    def enable_schedule(self, schedule_id: str) -> bool:
        """Re-enable suspended schedule."""
        ...
    
    def _check_pending(self):
        """Check for scans due for execution."""
        ...
    
    def _handle_failure(self, schedule_id: str, reason: str):
        """Increment failure counter, log reason."""
        ...
```

### 8. Container Assessment Engine

```python
# app/core/container_assessment_engine.py
from PyQt6.QtCore import QObject, pyqtSignal
from typing import Dict, List

# CIS Docker Benchmark checks
CIS_DOCKER_CHECKS = {
    "CIS-DI-0001": "Ensure a separate partition for containers has been created",
    "CIS-DI-0002": "Ensure only trusted users are allowed to control Docker daemon",
    "CIS-DI-0003": "Ensure Docker is up to date",
    # ... additional checks
}

class ContainerAssessmentEngine(QObject):
    assessment_event = pyqtSignal(str, str)
    finding_discovered = pyqtSignal(dict)
    
    def check_docker_daemon(self, target: str) -> List[Dict]:
        """Check Docker daemon for misconfigurations."""
        ...
    
    def enumerate_kubernetes(self, kubeconfig: str = None,
                            api_server: str = None) -> Dict:
        """Enumerate K8s cluster resources."""
        ...
    
    def check_rbac_misconfigs(self, roles: List[Dict],
                             bindings: List[Dict]) -> List[Dict]:
        """Check for overly permissive RBAC configurations."""
        ...
    
    def scan_container_image(self, image_ref: str) -> List[Dict]:
        """Scan container image for vulnerabilities."""
        ...
    
    def get_escape_guidance(self, container_context: Dict) -> List[Dict]:
        """Get container escape technique guidance based on context."""
        ...
```

### 9. Attack Surface Mapper

```python
# app/core/attack_surface_mapper.py
from PyQt6.QtCore import QObject, pyqtSignal
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass

@dataclass
class GraphNode:
    node_id: str
    node_type: str       # target, service, vulnerability
    label: str
    properties: Dict
    
@dataclass
class GraphEdge:
    source_id: str
    target_id: str
    edge_type: str       # hosts, has_vulnerability, lateral_movement, exploits
    properties: Dict

class AttackSurfaceMapper(QObject):
    graph_updated = pyqtSignal()
    path_discovered = pyqtSignal(list)
    
    def __init__(self):
        super().__init__()
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
    
    def add_node(self, node: GraphNode) -> None:
        """Add node and emit update signal."""
        ...
    
    def add_edge(self, edge: GraphEdge) -> None:
        """Add edge connecting two nodes."""
        ...
    
    def find_attack_paths(self, entry_node_id: str,
                         target_node_id: str) -> List[List[str]]:
        """Find all paths from entry to target using BFS."""
        ...
    
    def filter_graph(self, subnet: str = None,
                    service_type: str = None,
                    severity: str = None,
                    date_range: Tuple[str, str] = None) -> Tuple[List[GraphNode], List[GraphEdge]]:
        """Return filtered subgraph."""
        ...
    
    def export_svg(self, layout: str = "force_directed") -> str:
        """Export graph as SVG string."""
        ...
```

---

## Integration Points

### Signal Connections

The new modules integrate with the existing application via QObject signals:

```python
# In the main application setup or page initialization:

# Timeline Logger hooks into all major operations
engagement_manager.state_changed.connect(timeline_logger.log_state_transition)
evidence_manager.evidence_stored.connect(timeline_logger.log_evidence_captured)
scanner_engine.scan_started.connect(timeline_logger.log_scan_start)
scanner_engine.scan_completed.connect(timeline_logger.log_scan_complete)

# Evidence Manager connects to finding deletion
pentest_database.finding_deleted.connect(evidence_manager.on_finding_deleted)

# Attack Surface Mapper listens for new discoveries
centralized_scan_data.result_added.connect(attack_surface_mapper.on_scan_result)
pentest_database.target_added.connect(attack_surface_mapper.on_target_discovered)

# Scheduling Engine triggers scans
scheduling_engine.scan_triggered.connect(scan_controller.execute_scheduled_scan)

# Knowledge Base suggestions on finding view
findings_component.finding_selected.connect(knowledge_base.get_suggestions)
```

### Engagement Context Injection

When an engagement is opened, the active engagement database is injected into all modules that need engagement-scoped data:

```python
def on_engagement_opened(self, engagement_id: str):
    """Connect modules to the active engagement database."""
    eng_db = engagement_manager.active_db
    
    evidence_manager.set_database(eng_db)
    note_system.set_database(eng_db)
    timeline_logger.set_database(eng_db)
    retest_workflow.set_database(eng_db)
    attack_mapper.set_database(eng_db)
    attack_surface_mapper.rebuild_from_database(eng_db)
    import_export_engine.set_database(eng_db)
```

### Existing Module Integration

| Existing Module | Integration |
|----------------|-------------|
| `pentest_database.py` | Findings migrate to engagement DB; legacy DB remains for non-engagement use |
| `evidence_collector.py` | Wraps into new Evidence Manager with DB-backed storage |
| `advanced_reporting.py` | Report Customizer extends with templates and branding |
| `centralized_scan_data.py` | Results feed into Attack Surface Mapper and Timeline Logger |
| `scheduler.py` | Scheduling Engine replaces with engagement-aware, cron-based implementation |
| `compliance_mapper.py` | ATT&CK Mapper extends compliance mapping with full ATT&CK matrix |
| `aws_pentest_engine.py` | GCP engine follows identical pattern |
| `vulnerability_database.py` | Finding Templates provide standardized finding creation |

---

## Error Handling

| Error Scenario | Handling Strategy |
|---------------|-------------------|
| Engagement DB file missing | Log error, remove from master index, notify user |
| Encrypted ZIP wrong passphrase | Reject immediately, no partial extraction, clear error message |
| Import file malformed records | Skip invalid records, log warnings, continue valid records, show summary |
| Concurrent DB access | WAL mode + connection pooling (existing `database_pool.py` pattern) |
| Evidence file exceeds memory | Streaming compression/decompression, chunk-based processing |
| Scheduled scan fails | Increment failure counter, log reason, retry at next interval |
| State transition invalid | Raise `InvalidTransitionError`, no state change, log attempt |
| ATT&CK data outdated | Bundle ATT&CK JSON, provide update mechanism via settings |
| CVSS computation invalid metrics | Return validation error with list of invalid fields |
| Graph too large for rendering | Progressive loading, node limit with pagination |

---

## Testing Strategy

### Unit Tests
- Validate specific behavior of each module's core functions with concrete examples
- Focus on edge cases: empty inputs, boundary values, invalid state transitions
- Test individual format parsers (Nessus, Burp, SARIF) with known sample files
- Verify CVSS computation against known test vectors from the FIRST specification

### Property-Based Tests
- Minimum 100 iterations per property test
- Cover all 38 correctness properties defined below
- Focus on round-trip properties (serialize/deserialize, export/import, store/retrieve)
- Verify invariants (hash consistency, state machine validity, metrics arithmetic)
- Test filter correctness (search, timeline filtering, severity thresholds)

### Integration Tests
- GCP/AWS/Azure engine authentication and enumeration (with mocked API responses)
- Container/K8s assessment against Docker daemon and K8s API (with mocked responses)
- End-to-end engagement lifecycle: create → populate → export → import → verify
- Scheduled scan execution with mocked scan engine

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system—essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Engagement ID Uniqueness

*For any* sequence of engagement creation requests, all generated engagement identifiers SHALL be unique, and each engagement SHALL have a corresponding isolated database file on disk.

**Validates: Requirements 1.1**

### Property 2: Engagement Data Round-Trip

*For any* valid engagement metadata (name, client, type, dates, status), creating an engagement and then listing engagements from the Master Index Database SHALL return a record containing all the originally provided fields unchanged.

**Validates: Requirements 1.2, 1.10**

### Property 3: State Machine Validity

*For any* engagement in a given state and any attempted state transition, the Engagement Manager SHALL accept the transition if and only if it is in the set of valid transitions defined by the state machine, and SHALL record the transition timestamp upon success.

**Validates: Requirements 1.4**

### Property 4: Engagement Open Round-Trip

*For any* engagement that has been created with documents, contacts, RoE, and milestones, opening that engagement SHALL load all stored data such that every field matches what was originally written.

**Validates: Requirements 1.5, 1.6, 1.7, 1.8, 1.9**

### Property 5: Template Isolation from Findings

*For any* finding created from a template, subsequent modifications to the master template SHALL NOT alter any field of the previously created finding.

**Validates: Requirements 2.6**

### Property 6: Template Search Completeness

*For any* template in the library with a given title, severity, category, or CWE identifier, searching by that exact value SHALL include that template in the results.

**Validates: Requirements 2.3**

### Property 7: Template Export/Import Round-Trip

*For any* set of finding templates, exporting to JSON and then importing on a fresh instance SHALL produce templates with identical title, severity, description, impact, remediation, references, and CVSS vector fields.

**Validates: Requirements 2.8**

### Property 8: Evidence Integrity Invariant

*For any* stored evidence item, the recorded SHA-256 hash SHALL equal the SHA-256 hash computed over the stored data (after decompression if applicable).

**Validates: Requirements 3.7**

### Property 9: Evidence Non-Destructive Annotation

*For any* evidence item with annotations applied, the underlying raw image data SHALL remain byte-for-byte identical to the original data stored before annotation.

**Validates: Requirements 3.2**

### Property 10: Evidence-Finding Bidirectional Linkage

*For any* evidence-to-finding link, querying evidence for a given finding SHALL return that evidence item, AND querying findings for that evidence item SHALL return that finding.

**Validates: Requirements 3.3**

### Property 11: Evidence Survives Finding Deletion

*For any* finding with linked evidence, deleting the finding SHALL NOT delete the evidence records; the evidence SHALL remain retrievable by its ID.

**Validates: Requirements 3.8**

### Property 12: Evidence Compression Round-Trip

*For any* evidence data exceeding 10 MB, storing and then retrieving the evidence SHALL produce byte-for-byte identical content to the original input.

**Validates: Requirements 3.6**

### Property 13: Note Revision Preservation

*For any* note that is edited, the original content SHALL be preserved as a revision such that the revision history contains the pre-edit content verbatim.

**Validates: Requirements 4.6**

### Property 14: Note Scope and Chronological Order

*For any* target with notes at target, service, and vulnerability scopes, retrieving notes for that target SHALL return all scoped notes ordered by creation timestamp ascending, with pinned notes appearing before unpinned notes.

**Validates: Requirements 4.4, 4.7**

### Property 15: Note Full-Text Search Completeness

*For any* note containing a specific word or phrase, full-text searching for that word SHALL include that note in the results.

**Validates: Requirements 4.5**

### Property 16: CVSS Vector String Round-Trip

*For any* valid set of CVSS metric values (v3.1 or v4.0), generating the vector string and then parsing it back SHALL produce the original metric values.

**Validates: Requirements 7.3**

### Property 17: CVSS Severity Label Consistency

*For any* computed CVSS base score, the severity label SHALL correspond to the standard ranges: None (0.0), Low (0.1–3.9), Medium (4.0–6.9), High (7.0–8.9), Critical (9.0–10.0).

**Validates: Requirements 7.5**

### Property 18: Retest Metrics Invariant

*For any* retest cycle with a set of retest results, the metrics SHALL satisfy: total_findings = findings_retested + findings_remaining, and pass_rate = findings_fixed / findings_retested (where findings_retested > 0).

**Validates: Requirements 6.4**

### Property 19: Retest Cycle History Preservation

*For any* sequence of retest cycles created for an engagement, creating a new cycle SHALL NOT modify or delete results from any previous cycle.

**Validates: Requirements 6.7**

### Property 20: Timeline Completeness for Actions

*For any* action that triggers a timeline event (scan start, finding discovery, state transition, manual action), a corresponding timeline entry SHALL exist with the correct action_type, actor, and timestamp.

**Validates: Requirements 8.1, 8.2**

### Property 21: Timeline Filter Correctness

*For any* set of timeline entries and any filter criteria (date range, action type, target, actor), the filtered results SHALL contain only entries matching ALL specified criteria and SHALL contain all entries that match.

**Validates: Requirements 8.3**

### Property 22: Import/Export Round-Trip

*For any* set of findings exported in a given format (Nessus XML, SARIF, CSV, JSON), re-importing the exported file SHALL produce finding records with equivalent host, vulnerability name, severity, and description fields.

**Validates: Requirements 9.5**

### Property 23: Import Error Resilience

*For any* import file containing a mix of N valid and M malformed records, the import SHALL produce exactly N finding records and exactly M warning messages, with no valid records skipped.

**Validates: Requirements 9.6**

### Property 24: Collaboration Package Round-Trip

*For any* engagement with findings and evidence, exporting as an encrypted package with a passphrase and then importing with the same passphrase SHALL produce an engagement with equivalent findings, evidence, and metadata.

**Validates: Requirements 10.1, 10.3**

### Property 25: Collaboration Package Rejection on Wrong Passphrase

*For any* encrypted engagement package and any passphrase that differs from the export passphrase, attempting to import SHALL fail completely with no engagement created and no files extracted.

**Validates: Requirements 10.4**

### Property 26: Collaboration Selective Export

*For any* engagement with findings F and evidence E, and any selected subset S_f ⊆ F and S_e ⊆ E, the exported package SHALL contain exactly the items in S_f and S_e and no others.

**Validates: Requirements 10.5**

### Property 27: Collaboration Manifest Integrity

*For any* exported engagement package, the manifest file SHALL list every file in the archive, and each file's recorded checksum SHALL match the actual SHA-256 hash of the file content.

**Validates: Requirements 10.7**

### Property 28: Knowledge Base Search Completeness

*For any* article stored in the knowledge base with specific terms in its title, content, or tags, searching for those terms SHALL return that article in the results.

**Validates: Requirements 11.2**

### Property 29: Report Severity Filter Correctness

*For any* severity threshold and any set of findings, a generated report SHALL include only findings whose severity is at or above the threshold, and SHALL include all such findings.

**Validates: Requirements 12.7**

### Property 30: Report Conditional Section Presence

*For any* report template with conditional sections, a generated report SHALL include a conditional section if and only if the corresponding data exists in the engagement.

**Validates: Requirements 12.5**

### Property 31: Attack Surface Graph Node Consistency

*For any* target, service, or vulnerability added to the engagement, the attack surface graph SHALL contain a corresponding node whose properties match the entity record.

**Validates: Requirements 13.2, 13.4**

### Property 32: Scheduling Cron Next-Execution Correctness

*For any* valid cron expression and reference time, the computed next execution time SHALL be the earliest future time that satisfies the cron expression.

**Validates: Requirements 19.2**

### Property 33: Scheduling Failure Counter Increment

*For any* scheduled scan that fails, the failure counter SHALL increment by exactly one and the failure reason SHALL be recorded.

**Validates: Requirements 19.5**

### Property 34: Scheduling Disable/Enable Round-Trip

*For any* scheduled scan that is disabled and then re-enabled, the scan configuration (targets, recurrence pattern, scan config) SHALL be identical to the original configuration.

**Validates: Requirements 19.7**

### Property 35: Container K8s RBAC Misconfiguration Detection

*For any* Kubernetes RBAC configuration containing a known misconfiguration pattern (wildcard verbs on all resources, cluster-admin binding to default service account), the Container Assessment Module SHALL produce a finding identifying that misconfiguration with a CIS Benchmark reference.

**Validates: Requirements 15.4, 15.5**

### Property 36: Mobile Testing Progress Invariant

*For any* mobile testing session with total checks T, completed checks C, and pending checks P, the invariant T = C + P SHALL hold at all times.

**Validates: Requirements 16.6**

### Property 37: Physical Security Attempt Categorization

*For any* logged physical security finding, the method field SHALL be one of the defined categories (tailgating, lock_bypass, badge_cloning, dumpster_diving, social_engineering).

**Validates: Requirements 17.3**

### Property 38: GCP IAM Privilege Escalation Detection

*For any* IAM policy set containing a known privilege escalation pattern (e.g., iam.serviceAccounts.actAs + compute.instances.create on same principal), the GCP Pentest Engine SHALL identify and report the escalation path.

**Validates: Requirements 18.3**

---

## Performance Considerations

- **Lazy loading**: Engagement databases only opened when accessed; modules instantiated on first use
- **WAL mode**: All SQLite databases use Write-Ahead Logging for concurrent read/write
- **Connection pooling**: Reuse `DatabaseConnectionPool` pattern from existing codebase
- **FTS indexes**: Full-text search tables for templates, knowledge base, and notes
- **Chunked evidence**: Large evidence files processed in chunks to avoid memory pressure
- **Background workers**: All network operations (GCP enumeration, K8s scanning, imports) run in `BaseWorker`/`CommandWorker` threads via `QThreadPool`
- **Incremental graph updates**: Attack surface mapper updates incrementally rather than rebuilding on each change
