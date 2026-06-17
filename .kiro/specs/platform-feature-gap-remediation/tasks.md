# Implementation Plan: Platform Feature Gap Remediation

## Overview

This plan transforms Huginn into a complete engagement management platform by implementing 19 capabilities across three priority tiers. Tasks are sequenced by dependency: data layer first, then engine modules, then UI components. The engagement manager and database isolation form the foundation that all other modules build upon.

## Tasks

- [x] 1. Engagement Manager and Database Isolation (P1 Foundation)
  - [x] 1.1 Create the engagement database module with per-engagement schema
    - Create `app/core/engagement_database.py` implementing `EngagementDatabase` class
    - Define per-engagement SQLite schema (engagement_meta, rules_of_engagement, client_contacts, documents, milestones, findings, evidence, evidence_finding_links, notes, note_revisions, attack_mappings, retest_cycles, retest_results, timeline_entries, physical_attempts, site_annotations, physical_control_ratings)
    - Implement `create_schema()`, `connect()`, `close()` methods with WAL mode
    - Use existing `DatabaseConnectionPool` pattern from `app/core/database_pool.py`
    - _Requirements: 1.1, 1.9_

  - [x] 1.2 Create the engagement manager with lifecycle state machine
    - Create `app/core/engagement_manager.py` implementing `EngagementManager(QObject)`
    - Define `EngagementState` enum (Draft, Scoping, Active, Paused, Retest, Reporting, Closed)
    - Define `VALID_TRANSITIONS` mapping enforcing the state machine
    - Implement `create_engagement()` generating UUID, creating isolated DB file under `resources/engagements/{id}/`
    - Implement `open_engagement()` connecting to the engagement's DB
    - Implement `transition_state()` with validation against allowed transitions
    - Implement `list_engagements()` with status filter and search from master index
    - Define master index schema (engagements, engagement_state_transitions, scheduled_scans tables)
    - Emit signals: `engagement_created`, `engagement_opened`, `state_changed`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.9, 1.10_

  - [ ]* 1.3 Write property tests for engagement manager
    - **Property 1: Engagement ID Uniqueness** — verify all generated IDs are unique and DB files exist
    - **Property 2: Engagement Data Round-Trip** — create then list returns unchanged metadata
    - **Property 3: State Machine Validity** — only valid transitions succeed, invalid ones rejected
    - **Property 4: Engagement Open Round-Trip** — stored docs/contacts/RoE/milestones load correctly
    - **Validates: Requirements 1.1, 1.2, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 1.10**

  - [x] 1.4 Create the engagement setup UI component
    - Create `app/components/engagement_setup_component.py` implementing `EngagementSetupComponent(QWidget)`
    - Build engagement creation form (name, client, type, dates)
    - Build engagement list view with search/filter by status
    - Build state transition controls with visual state indicator
    - Build scoping documents upload/view panel
    - Build RoE structured input form (IP ranges, excluded systems, testing hours, contacts)
    - Build client contacts CRUD interface
    - Build timeline milestones view
    - Integrate with `EngagementManager` signals for real-time updates
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8_

- [x] 2. Checkpoint - Ensure engagement foundation tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 3. Evidence Manager (P1 - Depends on Engagement DB)
  - [x] 3.1 Create the evidence manager engine
    - Create `app/core/evidence_manager.py` implementing `EvidenceManager(QObject)`
    - Implement `store_evidence()` with SHA-256 hashing, zlib compression for files >10MB
    - Implement `retrieve_evidence()` with automatic decompression
    - Implement `add_annotation()` storing annotations as JSON without modifying original data
    - Implement `link_to_finding()` and `get_evidence_for_finding()` / `get_findings_for_evidence()`
    - Implement `on_finding_deleted()` unlinking but retaining evidence
    - Support evidence types: screenshot, text_snippet, file, http_pair, terminal_output
    - Support tagging and categorization by target
    - Emit signals: `evidence_stored`, `evidence_linked`
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8_

  - [ ]* 3.2 Write property tests for evidence manager
    - **Property 8: Evidence Integrity Invariant** — stored SHA-256 matches recomputed hash
    - **Property 9: Evidence Non-Destructive Annotation** — raw data unchanged after annotations
    - **Property 10: Evidence-Finding Bidirectional Linkage** — link queries work both directions
    - **Property 11: Evidence Survives Finding Deletion** — evidence remains after finding deleted
    - **Property 12: Evidence Compression Round-Trip** — >10MB data stored/retrieved identically
    - **Validates: Requirements 3.2, 3.3, 3.6, 3.7, 3.8**

  - [x] 3.3 Create the evidence manager UI component
    - Create `app/components/evidence_manager_component.py` implementing `EvidenceManagerComponent(QWidget)`
    - Build evidence capture panel (screenshot, paste, file drop)
    - Build annotation toolbar (rectangle, arrow, text label, redaction)
    - Build evidence-to-finding linking interface with drag-and-drop
    - Build evidence gallery view with tag filtering and chronological sorting
    - Build evidence detail view with hash display and metadata
    - Integrate as enhancement to the existing Post-Exploitation page
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [x] 4. Note-Taking System (P1 - Depends on Engagement DB)
  - [x] 4.1 Create the note system engine
    - Create `app/core/note_system.py` implementing `NoteSystem(QObject)`
    - Implement `create_note()` with scope_type (target/service/vulnerability), scope_id, content, author
    - Implement `edit_note()` preserving original as revision in note_revisions table
    - Implement `get_notes_for_scope()` returning chronological order with pinned notes first
    - Implement `search_notes()` using FTS5 full-text search
    - Implement `pin_note()` / `unpin_note()` for priority display
    - Support markdown content format
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

  - [ ]* 4.2 Write property tests for note system
    - **Property 13: Note Revision Preservation** — edited notes retain pre-edit content as revision
    - **Property 14: Note Scope and Chronological Order** — notes returned in timestamp order, pinned first
    - **Property 15: Note Full-Text Search Completeness** — notes with specific terms found by search
    - **Validates: Requirements 4.4, 4.5, 4.6, 4.7**

  - [x] 4.3 Create the notes panel UI component
    - Create `app/components/notes_panel_component.py` implementing `NotesPanelComponent(QWidget)`
    - Build floating/dockable notes panel accessible from all pages
    - Build note creation form with markdown editor and preview
    - Build note list with scope indicators (target/service/vulnerability)
    - Build revision history viewer
    - Build full-text search bar with results highlighting
    - Build pin/unpin toggle on note items
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7_

- [x] 5. Finding Templates Library (P1 - Depends on Engagement DB)
  - [x] 5.1 Create the finding template library engine
    - Create `app/core/finding_template_library.py` implementing `FindingTemplateLibrary(QObject)`
    - Define templates database schema with FTS5 virtual table
    - Implement `create_template()`, `update_template()`, `delete_template()`
    - Implement `search_templates()` using FTS5 across title, description, tags, category, cwe_id
    - Implement `create_finding_from_template()` copying fields without ongoing linkage
    - Implement `export_templates()` producing JSON and `import_templates()` consuming JSON
    - Seed 50+ pre-built templates covering OWASP Top 10, network vulns, config weaknesses
    - Support categories: Web Application, Network, Infrastructure, Cloud, Mobile, Physical
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8_

  - [ ]* 5.2 Write property tests for finding template library
    - **Property 5: Template Isolation from Findings** — template edits don't alter existing findings
    - **Property 6: Template Search Completeness** — templates found by exact title/severity/category/CWE
    - **Property 7: Template Export/Import Round-Trip** — exported JSON reimported produces identical templates
    - **Validates: Requirements 2.3, 2.6, 2.8**

  - [x] 5.3 Create the finding templates UI component
    - Create `app/components/finding_templates_component.py` implementing `FindingTemplatesComponent(QWidget)`
    - Build template library browser with category tabs and search bar
    - Build template detail/edit form (title, severity, description, impact, remediation, refs, CVSS, CWE)
    - Build "Create Finding from Template" action with per-instance customization
    - Build template import/export buttons with file dialogs
    - Integrate as new tab within the Reporting page
    - _Requirements: 2.1, 2.2, 2.3, 2.5, 2.7, 2.8_

- [x] 6. Checkpoint - Ensure P1 core modules tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. CVSS Calculator (P1)
  - [x] 7.1 Create the CVSS calculator engine
    - Create `app/core/cvss_calculator.py` implementing `CVSSCalculator`
    - Implement CVSS v3.1 base/temporal/environmental score computation per FIRST specification
    - Implement CVSS v4.0 base score computation per FIRST specification
    - Implement `generate_vector_string()` producing standard format strings
    - Implement `parse_vector_string()` parsing vectors back to version + metrics dict
    - Implement `get_severity_label()` mapping scores to None/Low/Medium/High/Critical
    - Define `CVSSVersion` enum and `SEVERITY_RANGES` constants
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

  - [ ]* 7.2 Write property tests for CVSS calculator
    - **Property 16: CVSS Vector String Round-Trip** — generate then parse returns original metrics
    - **Property 17: CVSS Severity Label Consistency** — labels match standard score ranges
    - **Validates: Requirements 7.3, 7.5**

  - [x] 7.3 Create the CVSS calculator UI component
    - Create `app/components/cvss_calculator_component.py` implementing `CVSSCalculatorComponent(QWidget)`
    - Build version toggle (v3.1 / v4.0) switching metric panels
    - Build metric selection buttons with tooltip descriptions for each value
    - Build real-time score display updating on each metric change
    - Build severity label badge with color coding
    - Build vector string display with copy button
    - Build "Apply to Finding" button integrating with findings
    - Implement as dialog/panel callable from findings views
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_

- [x] 8. Timeline Logger (P1 - Hooks into all modules)
  - [x] 8.1 Create the timeline logger engine
    - Create `app/core/timeline_logger.py` implementing `TimelineLogger(QObject)`
    - Implement `log_event()` recording action_type, actor, affected_entity, description, metadata, timestamp
    - Implement signal handlers: `log_scan_start`, `log_scan_complete`, `log_finding_discovered`, `log_state_transition`, `log_evidence_captured`
    - Implement `get_timeline()` with filtering by date range, action type, target, actor
    - Implement `add_manual_entry()` for custom user notes with timestamps
    - Implement `set_database()` accepting engagement database context
    - Connect to engagement_manager, evidence_manager, and scanner signals
    - _Requirements: 8.1, 8.2, 8.3, 8.5, 8.6_

  - [ ]* 8.2 Write property tests for timeline logger
    - **Property 20: Timeline Completeness for Actions** — every action produces a corresponding entry
    - **Property 21: Timeline Filter Correctness** — filtered results match all criteria, include all matches
    - **Validates: Requirements 8.1, 8.2, 8.3**

  - [x] 8.3 Create the timeline UI component
    - Create `app/components/timeline_component.py` implementing `TimelineComponent(QWidget)`
    - Build chronological scrollable timeline view with icons per action type
    - Build filter toolbar (date range picker, action type dropdown, target filter, actor filter)
    - Build manual entry creation form
    - Build timeline entry detail popover on click
    - Integrate as new tab within Engagement Setup page
    - _Requirements: 8.3, 8.4, 8.6_

- [x] 9. ATT&CK Mapper (P1 - Depends on Engagement DB + Findings)
  - [x] 9.1 Create the ATT&CK mapper engine
    - Create `app/core/attack_mapper.py` implementing `ATTACKMapper(QObject)`
    - Bundle MITRE ATT&CK Enterprise matrix JSON (tactics, techniques, sub-techniques)
    - Implement `map_finding_to_technique()` storing technique_id, tactic, procedure in attack_mappings table
    - Implement `get_coverage_matrix()` computing tested/successful/not_tested per technique
    - Implement `get_findings_for_technique()` returning linked findings and evidence
    - Implement `suggest_techniques()` matching finding description keywords to technique names
    - Implement `get_report_summary()` producing ATT&CK coverage stats for reports
    - Support filtering by tactic, platform, and data source
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7_

  - [x] 9.2 Create the ATT&CK matrix UI component
    - Create `app/components/attack_matrix_component.py` implementing `ATTACKMatrixComponent(QWidget)`
    - Build interactive coverage matrix grid (tactics as columns, techniques as rows)
    - Color-code cells: tested/successful (green), tested/failed (yellow), not_tested (gray)
    - Build technique detail panel showing linked findings, evidence, procedures on click
    - Build filter controls (tactic, platform, data source)
    - Build mapping interface for assigning techniques to findings
    - Build suggested mappings panel with accept/reject actions
    - Integrate as new tab within the Reporting page
    - _Requirements: 5.3, 5.4, 5.5, 5.7_

- [x] 10. Retest Workflow (P1 - Depends on Engagement DB + Findings)
  - [x] 10.1 Create the retest workflow engine
    - Create `app/core/retest_workflow.py` implementing `RetestWorkflow(QObject)`
    - Implement `create_retest_cycle()` linked to engagement with cycle_number auto-increment
    - Implement `get_findings_checklist()` returning all findings with current retest status
    - Implement `record_retest_result()` requiring status, notes, optional evidence_id
    - Implement `get_metrics()` computing total, retested, remaining, pass_rate
    - Implement `complete_cycle()` generating retest summary
    - Flag regressed findings with elevated priority
    - Support multiple cycles per engagement preserving history
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

  - [ ]* 10.2 Write property tests for retest workflow
    - **Property 18: Retest Metrics Invariant** — total = retested + remaining, pass_rate = fixed/retested
    - **Property 19: Retest Cycle History Preservation** — new cycles don't modify previous cycle results
    - **Validates: Requirements 6.4, 6.7**

  - [x] 10.3 Create the retest workflow UI component
    - Create `app/components/retest_workflow_component.py` implementing `RetestWorkflowComponent(QWidget)`
    - Build findings checklist with status indicators (Not Tested, Fixed, Partially Fixed, Not Fixed, Regressed)
    - Build retest result form (status dropdown, notes text area, evidence attachment)
    - Build metrics dashboard (total, retested, remaining, pass rate progress bar)
    - Build cycle history selector and comparison view
    - Highlight regressed findings with warning styling
    - Integrate as new tab within the Reporting page
    - _Requirements: 6.2, 6.3, 6.4, 6.5, 6.6, 6.7_

- [x] 11. Checkpoint - Ensure all P1 modules tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 12. Import/Export Engine (P2 - Depends on Engagement DB)
  - [x] 12.1 Create the import/export engine
    - Create `app/core/import_export_engine.py` implementing `ImportExportEngine(QObject)`
    - Implement `parse_nessus_xml()` extracting host, vulnerability, severity into `ImportRecord` dataclass
    - Implement `parse_burp_xml()` extracting issue detail, request/response, severity
    - Implement `parse_sarif()` extracting results, rules, locations
    - Implement `parse_csv()` with configurable column mapping parameter
    - Implement `export_findings()` supporting Nessus XML, Burp XML, SARIF, CSV, JSON formats
    - Handle malformed records: skip, log warning, continue processing
    - Emit `import_progress` and `import_warning` signals
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_

  - [ ]* 12.2 Write property tests for import/export engine
    - **Property 22: Import/Export Round-Trip** — exported findings reimported produce equivalent records
    - **Property 23: Import Error Resilience** — N valid records produce N findings, M malformed produce M warnings
    - **Validates: Requirements 9.5, 9.6**

  - [x] 12.3 Create the import/export UI component
    - Create `app/components/import_export_component.py` implementing `ImportExportComponent(QWidget)`
    - Build format selector (Nessus XML, Burp XML, SARIF, CSV)
    - Build file picker with drag-and-drop support
    - Build CSV column mapping configuration dialog
    - Build import preview table showing parsed records before commit
    - Build progress bar with warning log during import
    - Build export format selector and output path chooser
    - Integrate as Tools menu dialog
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.7_

- [x] 13. Collaboration Manager (P2 - Depends on Engagement DB + Evidence)
  - [x] 13.1 Create the collaboration manager engine
    - Create `app/core/collaboration_manager.py` implementing `CollaborationManager(QObject)`
    - Implement `export_engagement()` creating AES-256 encrypted ZIP with PBKDF2 key derivation (480k iterations)
    - Implement `import_engagement()` decrypting, validating checksums, registering new engagement
    - Implement `_derive_key()` using `cryptography` library PBKDF2HMAC
    - Implement `_create_manifest()` with file checksums and export metadata
    - Implement `_validate_manifest()` checking all checksums on import
    - Support selective export (chosen findings and evidence subsets)
    - Assign new engagement ID on import to avoid conflicts
    - Reject immediately on wrong passphrase with no partial extraction
    - Emit `export_progress` and `import_progress` signals
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_

  - [ ]* 13.2 Write property tests for collaboration manager
    - **Property 24: Collaboration Package Round-Trip** — export/import with correct passphrase produces equivalent engagement
    - **Property 25: Collaboration Package Rejection on Wrong Passphrase** — wrong passphrase fails completely
    - **Property 26: Collaboration Selective Export** — only selected items appear in package
    - **Property 27: Collaboration Manifest Integrity** — manifest checksums match actual file hashes
    - **Validates: Requirements 10.1, 10.3, 10.4, 10.5, 10.7**

  - [x] 13.3 Create the collaboration UI component
    - Create `app/components/collaboration_component.py` implementing `CollaborationComponent(QWidget)`
    - Build export dialog with passphrase input, finding/evidence selector checkboxes
    - Build import dialog with file picker and passphrase input
    - Build progress bars for export/import operations
    - Build integrity validation status display
    - Integrate as File menu dialog
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5_

- [x] 14. Knowledge Base (P2)
  - [x] 14.1 Create the knowledge base engine
    - Create `app/core/knowledge_base.py` implementing `KnowledgeBase(QObject)`
    - Define knowledge base SQLite schema with FTS5 virtual table
    - Implement `create_article()`, `update_article()`, `delete_article()`
    - Implement `search_articles()` using FTS5 across title, content, tags, category
    - Implement `get_suggestions()` matching finding category/keywords to article tags
    - Implement `toggle_bookmark()` for quick access
    - Seed 100+ pre-built articles covering common pentest commands and techniques
    - Support categories: Reconnaissance, Exploitation, Post-Exploitation, Web, Network, Cloud, Reporting
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7_

  - [ ]* 14.2 Write property tests for knowledge base
    - **Property 28: Knowledge Base Search Completeness** — articles with specific terms found by FTS search
    - **Validates: Requirements 11.2**

  - [x] 14.3 Create the knowledge base UI component
    - Create `app/components/knowledge_base_component.py` implementing `KnowledgeBaseComponent(QWidget)`
    - Build article browser with category sidebar and search bar
    - Build markdown article viewer with code block syntax highlighting
    - Build article editor with live preview
    - Build bookmark list for quick access
    - Build contextual suggestion panel connecting to findings view
    - Integrate as Tools menu entry and context-sensitive side panel
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.6, 11.7_

- [x] 15. Report Customizer (P2 - Extends advanced_reporting.py)
  - [x] 15.1 Create the report customizer engine
    - Create `app/core/report_customizer.py` implementing `ReportCustomizer(QObject)`
    - Implement report template data model (sections, order, inclusion rules, formatting)
    - Implement `create_template()`, `save_template()`, `load_template()`
    - Implement drag-and-drop section ordering (Executive Summary, Methodology, Findings, Risk Matrix, Remediation Plan, Appendices)
    - Implement branding configuration (logo, company name, colors, header/footer, cover page)
    - Implement `generate_report()` producing PDF, HTML, DOCX, and Markdown outputs
    - Implement conditional sections (appear only when data exists, e.g., ATT&CK matrix)
    - Implement severity threshold filtering for finding inclusion
    - Extend existing `advanced_reporting.py` module
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7_

  - [ ]* 15.2 Write property tests for report customizer
    - **Property 29: Report Severity Filter Correctness** — only findings at/above threshold included
    - **Property 30: Report Conditional Section Presence** — conditional sections appear iff data exists
    - **Validates: Requirements 12.5, 12.7**

  - [x] 15.3 Create the report designer UI component
    - Create `app/components/report_designer_component.py` implementing `ReportDesignerComponent(QWidget)`
    - Build drag-and-drop section list for report layout ordering
    - Build branding configuration panel (logo upload, color picker, text fields)
    - Build output format selector (PDF, HTML, DOCX, Markdown)
    - Build severity filter dropdown
    - Build template save/load interface
    - Build report preview pane
    - Integrate as enhancement to existing Reporting page
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.6_

- [x] 16. Attack Surface Mapper (P2 - Depends on Engagement DB + Scan Data)
  - [x] 16.1 Create the attack surface mapper engine
    - Create `app/core/attack_surface_mapper.py` implementing `AttackSurfaceMapper(QObject)`
    - Implement `GraphNode` and `GraphEdge` dataclasses
    - Implement `add_node()`, `add_edge()`, `remove_node()`
    - Implement `find_attack_paths()` using BFS between entry and target nodes
    - Implement `filter_graph()` by subnet, service type, severity, date range
    - Implement `export_svg()` and `export_png()` for report inclusion
    - Implement `rebuild_from_database()` constructing graph from engagement data
    - Connect to `centralized_scan_data.result_added` and `pentest_database.target_added` signals
    - Emit `graph_updated` and `path_discovered` signals
    - _Requirements: 13.1, 13.2, 13.3, 13.5, 13.6, 13.7_

  - [ ]* 16.2 Write property tests for attack surface mapper
    - **Property 31: Attack Surface Graph Node Consistency** — added entities have corresponding graph nodes with matching properties
    - **Validates: Requirements 13.2, 13.4**

  - [x] 16.3 Create the attack surface graph UI component
    - Create `app/components/attack_surface_graph_component.py` implementing `AttackSurfaceGraphComponent(QWidget)`
    - Build interactive graph canvas with zoom/pan controls
    - Implement layout options (hierarchical, force-directed, radial)
    - Build node click detail panel showing entity record
    - Build filter toolbar (subnet, service type, severity, date range)
    - Build attack path highlighting overlay
    - Build export controls (SVG, PNG)
    - Integrate as new tab within the Reporting page
    - _Requirements: 13.1, 13.3, 13.4, 13.5, 13.6, 13.7_

- [x] 17. Scheduling Engine (P2 - Depends on Engagement Manager)
  - [x] 17.1 Create the scheduling engine
    - Create `app/core/scheduling_engine.py` implementing `SchedulingEngine(QObject)`
    - Implement `create_schedule()` storing config, targets, recurrence, next_execution in master DB
    - Implement `compute_next_execution()` parsing cron expressions
    - Implement `_check_pending()` on QTimer (60s interval) triggering due scans
    - Implement `disable_schedule()` / `enable_schedule()` suspending without deleting config
    - Implement `_handle_failure()` incrementing failure counter and logging reason
    - Emit `scan_triggered`, `scan_completed`, `scan_failed` signals
    - Connect `scan_triggered` to existing scan controller for execution
    - Support recurrence: one-time, daily, weekly, monthly, custom cron
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.7_

  - [ ]* 17.2 Write property tests for scheduling engine
    - **Property 32: Scheduling Cron Next-Execution Correctness** — computed next time is earliest future time satisfying cron
    - **Property 33: Scheduling Failure Counter Increment** — failures increment counter by exactly one
    - **Property 34: Scheduling Disable/Enable Round-Trip** — disabled then enabled retains original config
    - **Validates: Requirements 19.2, 19.5, 19.7**

  - [x] 17.3 Create the scan scheduler UI component
    - Create `app/components/scan_scheduler_component.py` implementing `ScanSchedulerComponent(QWidget)`
    - Build schedule creation form (name, scan config, targets, recurrence pattern)
    - Build cron expression builder with human-readable preview
    - Build calendar view showing all scheduled scans with status indicators
    - Build schedule list with enable/disable toggles
    - Build failure log viewer per schedule
    - Integrate within Tools menu and Engagement Setup page
    - _Requirements: 19.1, 19.2, 19.6, 19.7_

- [x] 18. Checkpoint - Ensure all P2 modules tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 19. GCP Pentest Engine (P3 - Follows AWS/Azure pattern)
  - [x] 19.1 Create the GCP pentest engine
    - Create `app/core/gcp_pentest_engine.py` implementing `GCPPentestEngine(QObject)`
    - Implement `configure_session()` supporting service account keys and OAuth2 tokens
    - Implement `enumerate_iam()` discovering IAM policies and bindings
    - Implement `enumerate_storage()` discovering and assessing storage buckets
    - Implement `enumerate_compute()` discovering instances and metadata
    - Implement `check_privilege_escalation()` analyzing IAM for escalation paths
    - Implement `check_public_buckets()` testing for public access
    - Implement GCP-specific finding creation with context and remediation
    - Follow existing `aws_pentest_engine.py` patterns for worker threads
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5_

  - [ ]* 19.2 Write property tests for GCP pentest engine
    - **Property 38: GCP IAM Privilege Escalation Detection** — known escalation patterns (actAs + instances.create) detected
    - **Validates: Requirements 18.3**

  - [x] 19.3 Create the GCP pentest UI component
    - Create `app/components/gcp_pentest_component.py` implementing `GCPPentestComponent(QWidget)`
    - Build credential configuration panel (service account key upload, OAuth token input)
    - Build enumeration controls (IAM, Storage, Compute, K8s, Cloud Functions)
    - Build results tree view showing discovered resources
    - Build privilege escalation path visualization
    - Build public bucket exposure findings panel
    - Integrate within Recon & Enumeration page alongside AWS/Azure engines
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.6_

- [x] 20. API Pentest Module (P3)
  - [x] 20.1 Create the API pentest engine
    - Create `app/core/api_pentest_engine.py` implementing `APIPentestEngine(QObject)`
    - Implement OWASP API Security Top 10 2023 testing workflows (API1-API10)
    - Implement `import_api_spec()` supporting OpenAPI/Swagger and Postman Collection formats
    - Implement automated checks for BOLA, broken auth, excessive data exposure, rate limiting
    - Implement finding creation with OWASP API category mapping
    - Support REST, GraphQL, and gRPC endpoint types
    - Provide test procedures and manual verification step descriptions per category
    - _Requirements: 14.1, 14.3, 14.4, 14.5, 14.6, 14.7_

  - [x] 20.2 Create the API pentest UI component
    - Create `app/components/api_pentest_component.py` implementing `APIPentestComponent(QWidget)`
    - Build OWASP API Top 10 category navigator (API1-API10 tabs)
    - Build API spec import dialog (OpenAPI/Swagger, Postman Collection)
    - Build test procedure checklist per category with auto/manual indicators
    - Build endpoint type selector (REST, GraphQL, gRPC)
    - Build automated check execution panel with progress
    - Build discovered issues list with finding creation
    - Integrate as sub-tab within Vulnerability Analysis page
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 14.6, 14.7_

- [x] 21. Container and Kubernetes Assessment (P3)
  - [x] 21.1 Create the container assessment engine
    - Create `app/core/container_assessment_engine.py` implementing `ContainerAssessmentEngine(QObject)`
    - Define `CIS_DOCKER_CHECKS` mapping for CIS Benchmark references
    - Implement `check_docker_daemon()` detecting exposed APIs, privileged containers, host mounts
    - Implement `enumerate_kubernetes()` discovering namespaces, pods, services, roles, bindings
    - Implement `check_rbac_misconfigs()` detecting overly permissive RBAC, default service accounts, exposed dashboards
    - Implement `scan_container_image()` analyzing layers and packages
    - Implement `get_escape_guidance()` providing context-based escape technique guidance
    - Create findings with CIS Benchmark mapping
    - Emit `assessment_event` and `finding_discovered` signals
    - _Requirements: 15.2, 15.3, 15.4, 15.5, 15.6, 15.7_

  - [ ]* 21.2 Write property tests for container assessment
    - **Property 35: Container K8s RBAC Misconfiguration Detection** — known misconfig patterns produce findings with CIS references
    - **Validates: Requirements 15.4, 15.5**

  - [x] 21.3 Create the container assessment UI component
    - Create `app/components/container_assessment_component.py` implementing `ContainerAssessmentComponent(QWidget)`
    - Build Docker target configuration (daemon URL, TLS settings)
    - Build K8s cluster configuration (kubeconfig path, API server URL)
    - Build CIS Benchmark check results table with pass/fail indicators
    - Build K8s resource enumeration tree view
    - Build container image scan interface with vulnerability results
    - Build escape technique guidance panel based on container context
    - Integrate as sub-tab within Exploitation page
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.6, 15.7_

- [x] 22. Mobile Application Testing (P3)
  - [x] 22.1 Create the mobile testing engine
    - Create `app/core/mobile_testing_engine.py` implementing `MobileTestingEngine(QObject)`
    - Implement OWASP Mobile Top 10 testing category workflows
    - Implement checklist system tracking completed vs. pending checks per category
    - Support Android and iOS platform-specific checklists
    - Implement progress computation (completed / total per category)
    - Implement finding creation with OWASP Mobile category and platform tags
    - Provide checklists for cert pinning bypass, local storage, binary protections, IPC
    - _Requirements: 16.2, 16.3, 16.4, 16.5, 16.6_

  - [ ]* 22.2 Write property tests for mobile testing
    - **Property 36: Mobile Testing Progress Invariant** — T = C + P holds at all times
    - **Validates: Requirements 16.6**

  - [x] 22.3 Create the mobile testing UI component
    - Create `app/components/mobile_testing_component.py` implementing `MobileTestingComponent(QWidget)`
    - Build OWASP Mobile Top 10 category tabs
    - Build platform selector (Android / iOS / Cross-platform)
    - Build interactive checklist per category with check/uncheck
    - Build progress bars per category and overall
    - Build finding creation form with mobile-specific fields
    - Integrate as sub-tab within Exploitation page
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6_

- [x] 23. Physical Security Assessment (P3 - Depends on Engagement DB)
  - [x] 23.1 Create the physical security engine
    - Create `app/core/physical_security_engine.py` implementing `PhysicalSecurityEngine(QObject)`
    - Implement `log_attempt()` recording location, time, method, outcome, evidence
    - Validate method against defined categories (tailgating, lock_bypass, badge_cloning, dumpster_diving, social_engineering)
    - Implement `add_site_annotation()` storing annotation coordinates on floor plan evidence
    - Implement `rate_control()` storing effectiveness ratings per location/control type
    - Implement `generate_summary()` producing physical assessment report section
    - _Requirements: 17.2, 17.3, 17.4, 17.5, 17.6_

  - [ ]* 23.2 Write property tests for physical security
    - **Property 37: Physical Security Attempt Categorization** — method field always one of defined categories
    - **Validates: Requirements 17.3**

  - [x] 23.3 Create the physical security UI component
    - Create `app/components/physical_security_component.py` implementing `PhysicalSecurityComponent(QWidget)`
    - Build attempt logging form (location, time, method dropdown, outcome, evidence link)
    - Build attempt history table with filtering
    - Build floor plan viewer with annotation overlay (entry points, cameras, zones)
    - Build control effectiveness rating interface per location
    - Build physical assessment summary view for report inclusion
    - Integrate as sub-tab within Engagement Setup page
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6_

- [x] 24. Checkpoint - Ensure all P3 modules tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 25. Integration Wiring and Signal Connections
  - [x] 25.1 Wire engagement context injection across all modules
    - Implement `on_engagement_opened()` handler injecting active DB into all modules
    - Connect engagement_manager.engagement_opened to context injection
    - Wire evidence_manager, note_system, timeline_logger, retest_workflow, attack_mapper, attack_surface_mapper, import_export_engine to receive engagement DB
    - Ensure modules gracefully handle no-engagement state
    - _Requirements: 1.9, 8.1_

  - [x] 25.2 Wire timeline logger signal connections
    - Connect engagement_manager.state_changed → timeline_logger.log_state_transition
    - Connect evidence_manager.evidence_stored → timeline_logger.log_evidence_captured
    - Connect scanner signals → timeline_logger.log_scan_start / log_scan_complete
    - Connect finding creation → timeline_logger.log_finding_discovered
    - Connect scheduling_engine.scan_triggered → timeline_logger
    - _Requirements: 8.1, 8.2_

  - [x] 25.3 Wire attack surface mapper signal connections
    - Connect centralized_scan_data.result_added → attack_surface_mapper.on_scan_result
    - Connect pentest_database.target_added → attack_surface_mapper.on_target_discovered
    - Connect finding creation → attack_surface_mapper to add vulnerability nodes
    - _Requirements: 13.2_

  - [x] 25.4 Wire knowledge base contextual suggestions
    - Connect findings_component.finding_selected → knowledge_base.get_suggestions
    - Display suggestion results in knowledge base side panel
    - _Requirements: 11.7_

  - [x] 25.5 Wire scheduling engine to scan controller
    - Connect scheduling_engine.scan_triggered → scan_controller.execute_scheduled_scan
    - Connect scan completion → scheduling_engine.scan_completed
    - Connect scan failure → scheduling_engine._handle_failure
    - _Requirements: 19.3, 19.4, 19.5_

  - [x] 25.6 Register new pages, tabs, and menu entries in main application
    - Add Engagement Setup page/tab to main navigation
    - Add new Reporting page tabs (Finding Templates, ATT&CK Matrix, Retest Workflow, Attack Surface Graph)
    - Add Tools menu entries (Import/Export, Knowledge Base, Scan Scheduler)
    - Add File menu entries (Collaboration Export/Import)
    - Add sub-tabs to Vulnerability Analysis (API Pentest), Exploitation (Container, Mobile), Recon (GCP)
    - Add floating Notes panel toggle to toolbar
    - Register all new components with lazy initialization
    - _Requirements: 14.2, 15.1, 16.1, 17.1, 18.6_

- [x] 26. Final Checkpoint - Ensure all integration tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation between priority tiers
- Property tests validate the 38 universal correctness properties defined in the design document
- All engines follow existing patterns: QObject signals, CommandWorker for async, DatabaseConnectionPool for DB access
- UI components use lazy initialization matching existing application conventions
- The engagement manager (Task 1) is the critical foundation — all other modules depend on it
- Import/Export and Collaboration (Tasks 12-13) depend on a working engagement database with findings and evidence
- Timeline Logger (Task 8) should be wired early since it hooks into all other module signals

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2"] },
    { "id": 2, "tasks": ["1.3", "1.4"] },
    { "id": 3, "tasks": ["3.1", "4.1", "5.1", "7.1"] },
    { "id": 4, "tasks": ["3.2", "3.3", "4.2", "4.3", "5.2", "5.3", "7.2", "7.3"] },
    { "id": 5, "tasks": ["8.1", "9.1", "10.1"] },
    { "id": 6, "tasks": ["8.2", "8.3", "9.2", "10.2", "10.3"] },
    { "id": 7, "tasks": ["12.1", "13.1", "14.1", "15.1", "16.1", "17.1"] },
    { "id": 8, "tasks": ["12.2", "12.3", "13.2", "13.3", "14.2", "14.3", "15.2", "15.3", "16.2", "16.3", "17.2", "17.3"] },
    { "id": 9, "tasks": ["19.1", "20.1", "21.1", "22.1", "23.1"] },
    { "id": 10, "tasks": ["19.2", "19.3", "20.2", "21.2", "21.3", "22.2", "22.3", "23.2", "23.3"] },
    { "id": 11, "tasks": ["25.1", "25.2", "25.3", "25.4", "25.5", "25.6"] }
  ]
}
```
