# Requirements Document

## Introduction

Comprehensive feature-gap remediation for the Huginn penetration testing suite. This document covers 19 identified gaps across three priority tiers (P1 Critical, P2 High, P3 Medium) that transform Huginn from a scanning/exploitation tool into a complete engagement management platform. The architecture uses per-engagement SQLite database isolation, file-based team collaboration via encrypted ZIP archives, and sub-tab integration for new methodology pages.

## Glossary

- **Huginn**: The PyQt6 desktop penetration testing framework application
- **Engagement_Manager**: The core module responsible for engagement lifecycle management including creation, state transitions, and data isolation
- **Finding_Template_Library**: The system that stores, retrieves, and applies reusable vulnerability finding templates
- **Evidence_Manager**: The module handling screenshot capture, annotation, file attachment, and evidence-to-finding linkage
- **Note_System**: The inline note-taking module providing per-target, per-service, and per-vulnerability timestamped notes
- **ATT&CK_Mapper**: The module implementing full MITRE ATT&CK framework integration with TTP mapping and coverage matrices
- **Retest_Workflow**: The system managing formal retest cycles for validating vulnerability remediations
- **CVSS_Calculator**: The built-in calculator UI for CVSS v3.1 and v4.0 vector string computation
- **Timeline_Logger**: The module recording chronological activity logs for all engagement actions
- **Import_Export_Engine**: The module supporting Nessus XML, Burp XML, SARIF, and CSV format import/export
- **Collaboration_Manager**: The module handling engagement package export/import as encrypted ZIP archives
- **Knowledge_Base**: The searchable repository of techniques, commands, and cheat sheets
- **Report_Customizer**: The report template engine supporting custom branding, drag-and-drop sections, and multiple output formats
- **Attack_Surface_Mapper**: The visualization module rendering interactive attack surface graphs
- **API_Pentest_Module**: The sub-tab module implementing OWASP API Top 10 testing workflow
- **Container_Assessment_Module**: The sub-tab module for Docker and Kubernetes security assessment
- **Mobile_Testing_Module**: The sub-tab module for mobile application penetration testing workflow
- **Physical_Security_Module**: The sub-tab module for physical security assessment tracking
- **GCP_Pentest_Engine**: The exploitation engine for Google Cloud Platform penetration testing
- **Scheduling_Engine**: The module managing recurring and scheduled assessment execution
- **Engagement_Database**: A per-engagement isolated SQLite database file containing all data for one engagement
- **Master_Index_Database**: The SQLite database tracking all engagements and enabling cross-engagement queries
- **Engagement_Package**: An encrypted ZIP archive containing a complete engagement export for team sharing

## Requirements

### Requirement 1: Engagement Lifecycle Management

**User Story:** As a penetration tester, I want formal engagement lifecycle management, so that I can track scoping documents, rules of engagement, client contacts, timelines, and statements of work in a structured manner.

#### Acceptance Criteria

1. WHEN the user creates a new engagement, THE Engagement_Manager SHALL generate a unique engagement identifier and create an isolated Engagement_Database file for that engagement.
2. WHEN an engagement is created, THE Engagement_Manager SHALL record the engagement name, client name, start date, end date, engagement type, and status in the Master_Index_Database.
3. THE Engagement_Manager SHALL support the following engagement states: Draft, Scoping, Active, Paused, Retest, Reporting, and Closed.
4. WHEN the user transitions an engagement between states, THE Engagement_Manager SHALL validate that the transition follows the allowed state machine (Draft→Scoping→Active→Paused/Retest/Reporting→Closed) and record the transition timestamp.
5. WHEN the user attaches a scoping document to an engagement, THE Engagement_Manager SHALL store the document within the Engagement_Database with metadata including filename, upload date, and document type.
6. THE Engagement_Manager SHALL store rules of engagement (RoE) as structured fields including authorized IP ranges, excluded systems, testing hours, emergency contacts, and escalation procedures.
7. WHEN the user adds a client contact, THE Engagement_Manager SHALL store the contact name, role, email, phone, and availability window within the Engagement_Database.
8. THE Engagement_Manager SHALL track engagement timeline milestones including planned start, actual start, planned end, actual end, and milestone checkpoints.
9. WHEN the user opens an engagement, THE Engagement_Manager SHALL connect to the corresponding Engagement_Database file and load all engagement context.
10. THE Master_Index_Database SHALL maintain a registry of all engagement metadata enabling listing, searching, and filtering engagements without opening individual Engagement_Database files.

### Requirement 2: Finding Templates Library

**User Story:** As a penetration tester, I want a library of reusable finding templates with standardized descriptions, impacts, and remediations, so that I can produce consistent reports efficiently.

#### Acceptance Criteria

1. THE Finding_Template_Library SHALL store finding templates containing title, severity, description, impact statement, remediation guidance, references, and CVSS vector string.
2. WHEN the user creates a new finding from a template, THE Finding_Template_Library SHALL populate all template fields into the new finding while allowing per-instance customization.
3. WHEN the user searches the template library, THE Finding_Template_Library SHALL support search by title, severity, category, CWE identifier, and free-text keywords.
4. THE Finding_Template_Library SHALL provide a minimum of 50 pre-built templates covering OWASP Top 10, common network vulnerabilities, and configuration weaknesses.
5. WHEN the user creates a custom template, THE Finding_Template_Library SHALL store the template for reuse across engagements.
6. WHEN the user updates a master template, THE Finding_Template_Library SHALL not modify findings already created from that template in existing engagements.
7. THE Finding_Template_Library SHALL support template categories including Web Application, Network, Infrastructure, Cloud, Mobile, and Physical.
8. WHEN the user exports templates, THE Finding_Template_Library SHALL produce a portable JSON format importable on another Huginn installation.

### Requirement 3: Screenshot and Evidence Management

**User Story:** As a penetration tester, I want to capture, annotate, organize, and link screenshots and evidence to findings, so that my reports contain verifiable proof of vulnerabilities.

#### Acceptance Criteria

1. WHEN the user captures a screenshot, THE Evidence_Manager SHALL store the image in the active Engagement_Database with a timestamp, source context, and unique identifier.
2. THE Evidence_Manager SHALL support image annotation including rectangles, arrows, text labels, and redaction boxes applied non-destructively to stored images.
3. WHEN the user links evidence to a finding, THE Evidence_Manager SHALL create a bidirectional reference between the evidence item and the finding record.
4. THE Evidence_Manager SHALL support evidence types including screenshots, text snippets, file attachments, HTTP request/response pairs, and terminal output.
5. WHEN the user organizes evidence, THE Evidence_Manager SHALL support tagging, categorization by target, and chronological sorting.
6. IF an evidence file exceeds 10 MB, THEN THE Evidence_Manager SHALL compress the file before storage and decompress on retrieval.
7. THE Evidence_Manager SHALL generate SHA-256 hashes for all stored evidence to ensure integrity verification.
8. WHEN the user removes a finding, THE Evidence_Manager SHALL retain orphaned evidence items and flag them for manual cleanup rather than cascading deletion.

### Requirement 4: Note-Taking System

**User Story:** As a penetration tester, I want per-target, per-service, and per-vulnerability inline note-taking with timestamps, so that I can document observations in real-time during assessments.

#### Acceptance Criteria

1. THE Note_System SHALL support note attachment at three scopes: target-level, service-level, and vulnerability-level.
2. WHEN the user creates a note, THE Note_System SHALL record the note content, creation timestamp, author identifier, and parent scope reference.
3. THE Note_System SHALL support rich-text formatting including bold, italic, code blocks, and hyperlinks.
4. WHEN the user views a target, THE Note_System SHALL display all notes associated with that target, its services, and its vulnerabilities in chronological order.
5. THE Note_System SHALL support note search across all scopes within the active engagement using full-text search.
6. WHEN the user edits a note, THE Note_System SHALL preserve the original note content as a revision and record the edit timestamp.
7. THE Note_System SHALL support pinning important notes to appear at the top of note lists within each scope.

### Requirement 5: MITRE ATT&CK Full Integration

**User Story:** As a penetration tester, I want full MITRE ATT&CK framework integration with TTP mapping and coverage matrices, so that I can demonstrate attack technique coverage and map findings to the ATT&CK knowledge base.

#### Acceptance Criteria

1. THE ATT&CK_Mapper SHALL contain the complete MITRE ATT&CK Enterprise matrix with all tactics, techniques, and sub-techniques.
2. WHEN the user maps a finding to an ATT&CK technique, THE ATT&CK_Mapper SHALL store the technique ID, tactic, and procedure description within the finding record.
3. THE ATT&CK_Mapper SHALL render a visual coverage matrix showing which techniques were tested, successful, and not tested during the engagement.
4. WHEN the user views a technique in the coverage matrix, THE ATT&CK_Mapper SHALL display linked findings, evidence, and procedure examples for that technique.
5. THE ATT&CK_Mapper SHALL support filtering the coverage matrix by tactic, platform, and data source.
6. WHEN the user generates a report, THE ATT&CK_Mapper SHALL include an ATT&CK coverage summary section showing tested vs. untested techniques.
7. THE ATT&CK_Mapper SHALL provide suggested ATT&CK technique mappings based on finding type and description keywords.

### Requirement 6: Retest and Validation Workflow

**User Story:** As a penetration tester, I want a formal retest workflow to verify client remediations, so that I can document whether vulnerabilities have been properly fixed.

#### Acceptance Criteria

1. WHEN the user initiates a retest cycle, THE Retest_Workflow SHALL create a retest session linked to the original engagement with its own timeline.
2. THE Retest_Workflow SHALL present a checklist of all findings from the original assessment with current retest status (Not Tested, Fixed, Partially Fixed, Not Fixed, Regressed).
3. WHEN the user marks a finding as retested, THE Retest_Workflow SHALL require a status selection, retester notes, and optional evidence attachment.
4. THE Retest_Workflow SHALL track retest metrics including total findings, findings retested, pass rate, and remaining items.
5. WHEN the user completes a retest cycle, THE Retest_Workflow SHALL generate a retest summary report comparing original findings to retest outcomes.
6. IF a finding status changes to Regressed during retest, THEN THE Retest_Workflow SHALL flag the finding with elevated priority in the retest report.
7. THE Retest_Workflow SHALL support multiple retest cycles per engagement, maintaining history across all cycles.

### Requirement 7: CVSS Calculator

**User Story:** As a penetration tester, I want a built-in CVSS calculator UI, so that I can compute accurate severity scores without leaving the application.

#### Acceptance Criteria

1. THE CVSS_Calculator SHALL support both CVSS v3.1 and CVSS v4.0 scoring methodologies with selectable version toggle.
2. WHEN the user selects metric values, THE CVSS_Calculator SHALL compute the base score, temporal score, and environmental score in real-time.
3. THE CVSS_Calculator SHALL display the resulting vector string in standard CVSS format (e.g., CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
4. WHEN the user applies a CVSS score to a finding, THE CVSS_Calculator SHALL store both the numeric score and the full vector string in the finding record.
5. THE CVSS_Calculator SHALL display a severity rating label (None, Low, Medium, High, Critical) corresponding to the computed base score.
6. THE CVSS_Calculator SHALL provide tooltip descriptions for each metric value to guide accurate scoring.

### Requirement 8: Engagement Timeline and Activity Log

**User Story:** As a penetration tester, I want a chronological timeline of all actions taken during an assessment, so that I can reconstruct testing activities for reporting and accountability.

#### Acceptance Criteria

1. THE Timeline_Logger SHALL automatically record timestamped entries for scan starts, scan completions, finding discoveries, exploit attempts, and state transitions within the active engagement.
2. WHEN the user performs a manual action (adding a note, linking evidence, modifying a finding), THE Timeline_Logger SHALL create a timeline entry with action type, actor, and affected entity.
3. THE Timeline_Logger SHALL support timeline filtering by date range, action type, target, and actor.
4. THE Timeline_Logger SHALL render timeline entries in a chronological scrollable view within the engagement UI.
5. WHEN the user exports the engagement, THE Timeline_Logger SHALL include the complete activity log in the export package.
6. THE Timeline_Logger SHALL support manual timeline entries where the user can add custom activity notes with timestamps.

### Requirement 9: Import/Export to Common Formats

**User Story:** As a penetration tester, I want to import and export data in common industry formats, so that I can integrate Huginn with other tools in my workflow.

#### Acceptance Criteria

1. WHEN the user imports a Nessus XML file, THE Import_Export_Engine SHALL parse host, vulnerability, and severity data and create corresponding target and finding records in the active engagement.
2. WHEN the user imports a Burp XML file, THE Import_Export_Engine SHALL parse issue detail, request/response evidence, and severity into finding and evidence records.
3. WHEN the user imports a SARIF file, THE Import_Export_Engine SHALL parse results, rules, and locations into finding records with source references.
4. WHEN the user imports a CSV file, THE Import_Export_Engine SHALL support configurable column mapping to Huginn finding fields.
5. WHEN the user exports findings, THE Import_Export_Engine SHALL support output in Nessus XML, Burp XML, SARIF, CSV, and JSON formats.
6. IF an import file contains malformed or missing required fields, THEN THE Import_Export_Engine SHALL log a warning for each skipped record and continue processing valid records.
7. WHEN the user initiates an import, THE Import_Export_Engine SHALL display a preview of parsed records and request confirmation before committing to the database.

### Requirement 10: Team Collaboration via Engagement Packages

**User Story:** As a penetration tester, I want to export and import engagement packages as encrypted ZIP archives, so that I can share engagement data with teammates without requiring a server.

#### Acceptance Criteria

1. WHEN the user exports an engagement package, THE Collaboration_Manager SHALL create an encrypted ZIP archive containing the Engagement_Database, evidence files, and engagement metadata.
2. THE Collaboration_Manager SHALL encrypt the ZIP archive using AES-256 encryption with a user-provided passphrase.
3. WHEN the user imports an engagement package, THE Collaboration_Manager SHALL decrypt the archive, validate integrity via stored checksums, and register the engagement in the Master_Index_Database.
4. IF the import passphrase is incorrect, THEN THE Collaboration_Manager SHALL reject the import and display an authentication failure message without partial extraction.
5. THE Collaboration_Manager SHALL support selective export allowing the user to choose which evidence items and findings to include in the package.
6. WHEN a package is imported, THE Collaboration_Manager SHALL assign a new engagement identifier to avoid conflicts with existing engagements.
7. THE Collaboration_Manager SHALL include a manifest file within the package listing all contained files, their checksums, export timestamp, and source Huginn version.

### Requirement 11: Knowledge Base

**User Story:** As a penetration tester, I want a searchable knowledge base of techniques, commands, and cheat sheets, so that I can quickly reference methodology guidance during assessments.

#### Acceptance Criteria

1. THE Knowledge_Base SHALL store articles organized by category including Reconnaissance, Exploitation, Post-Exploitation, Web Application, Network, Cloud, and Reporting.
2. WHEN the user searches the Knowledge_Base, THE Knowledge_Base SHALL support full-text search across article titles, content, and tags.
3. THE Knowledge_Base SHALL support markdown-formatted articles with code blocks, tables, and hyperlinks.
4. WHEN the user creates a custom article, THE Knowledge_Base SHALL store the article with author, creation date, modification date, and category tags.
5. THE Knowledge_Base SHALL provide a minimum of 100 pre-built articles covering common penetration testing commands and techniques.
6. THE Knowledge_Base SHALL support article bookmarking for quick access to frequently referenced entries.
7. WHEN the user views a finding, THE Knowledge_Base SHALL suggest related articles based on finding category and technique keywords.

### Requirement 12: Report Customization

**User Story:** As a penetration tester, I want custom report templates with branding and drag-and-drop sections, so that I can produce professional client-facing deliverables matching organizational standards.

#### Acceptance Criteria

1. THE Report_Customizer SHALL support custom report templates defining section order, content inclusion rules, and formatting styles.
2. WHEN the user designs a report template, THE Report_Customizer SHALL provide drag-and-drop ordering of report sections including Executive Summary, Methodology, Findings, Risk Matrix, Remediation Plan, and Appendices.
3. THE Report_Customizer SHALL support branding elements including logo image, company name, color scheme, header/footer text, and cover page layout.
4. WHEN the user generates a report, THE Report_Customizer SHALL produce output in PDF, HTML, DOCX, and Markdown formats.
5. THE Report_Customizer SHALL support conditional sections that appear only when relevant data exists (e.g., ATT&CK matrix section appears only when mappings exist).
6. WHEN the user saves a report template, THE Report_Customizer SHALL store the template for reuse across engagements.
7. THE Report_Customizer SHALL support finding severity filtering allowing reports to include only findings above a selected severity threshold.

### Requirement 13: Attack Surface Mapping Visualization

**User Story:** As a penetration tester, I want a visual attack surface graph, so that I can see relationships between targets, services, vulnerabilities, and attack paths at a glance.

#### Acceptance Criteria

1. THE Attack_Surface_Mapper SHALL render an interactive graph displaying nodes for targets, services, and vulnerabilities with edges representing relationships.
2. WHEN the user adds or discovers a new target or finding, THE Attack_Surface_Mapper SHALL update the graph view in real-time.
3. THE Attack_Surface_Mapper SHALL support graph layout options including hierarchical, force-directed, and radial arrangements.
4. WHEN the user clicks a node in the graph, THE Attack_Surface_Mapper SHALL display a detail panel showing the full record for that entity.
5. THE Attack_Surface_Mapper SHALL support visual filtering by target subnet, service type, vulnerability severity, and discovery date range.
6. THE Attack_Surface_Mapper SHALL highlight attack paths connecting entry points through lateral movement to high-value targets.
7. WHEN the user exports the graph, THE Attack_Surface_Mapper SHALL produce SVG or PNG image output suitable for report inclusion.

### Requirement 14: API Pentest Methodology

**User Story:** As a penetration tester, I want a full OWASP API Top 10 testing workflow, so that I can systematically assess API security using industry-standard methodology.

#### Acceptance Criteria

1. THE API_Pentest_Module SHALL provide guided testing workflows for all OWASP API Security Top 10 2023 categories (API1 through API10).
2. THE API_Pentest_Module SHALL be integrated as a sub-tab within the existing Vulnerability Analysis page.
3. WHEN the user selects an API testing category, THE API_Pentest_Module SHALL display test procedures, automated checks, and manual verification steps for that category.
4. THE API_Pentest_Module SHALL support API specification import in OpenAPI/Swagger and Postman Collection formats.
5. WHEN the user runs automated API checks, THE API_Pentest_Module SHALL test for Broken Object Level Authorization, Broken Authentication, Excessive Data Exposure, and rate limiting weaknesses.
6. WHEN the API_Pentest_Module discovers an issue, THE API_Pentest_Module SHALL create a finding record with OWASP API category mapping and evidence.
7. THE API_Pentest_Module SHALL support testing against REST, GraphQL, and gRPC endpoint types.

### Requirement 15: Container and Kubernetes Assessment

**User Story:** As a penetration tester, I want Docker and Kubernetes security assessment capabilities, so that I can evaluate containerized environments for misconfigurations and vulnerabilities.

#### Acceptance Criteria

1. THE Container_Assessment_Module SHALL be integrated as a sub-tab within the existing Exploitation page.
2. THE Container_Assessment_Module SHALL support Docker daemon misconfiguration detection including exposed APIs, privileged containers, and host mount analysis.
3. WHEN the user targets a Kubernetes cluster, THE Container_Assessment_Module SHALL enumerate namespaces, pods, services, roles, and role bindings.
4. THE Container_Assessment_Module SHALL check for common Kubernetes misconfigurations including overly permissive RBAC, default service accounts, and exposed dashboards.
5. WHEN the Container_Assessment_Module discovers an issue, THE Container_Assessment_Module SHALL create a finding record with CIS Benchmark mapping where applicable.
6. THE Container_Assessment_Module SHALL support container image vulnerability scanning by analyzing image layers and installed packages.
7. THE Container_Assessment_Module SHALL provide testing guidance for container escape techniques and pod-to-pod lateral movement.

### Requirement 16: Mobile Application Testing Support

**User Story:** As a penetration tester, I want a mobile application penetration testing workflow, so that I can systematically assess mobile apps for security vulnerabilities.

#### Acceptance Criteria

1. THE Mobile_Testing_Module SHALL be integrated as a sub-tab within the existing Exploitation page.
2. THE Mobile_Testing_Module SHALL provide guided workflows for OWASP Mobile Top 10 testing categories.
3. THE Mobile_Testing_Module SHALL support static analysis checklist tracking for both Android and iOS applications.
4. WHEN the user logs a mobile finding, THE Mobile_Testing_Module SHALL categorize the finding by OWASP Mobile Top 10 category and platform (Android/iOS/Cross-platform).
5. THE Mobile_Testing_Module SHALL provide checklists for certificate pinning bypass, local data storage review, binary protections, and inter-process communication analysis.
6. THE Mobile_Testing_Module SHALL track testing progress showing completed vs. pending checks per mobile testing category.

### Requirement 17: Physical Security Assessment Tracking

**User Story:** As a penetration tester, I want to track physical security assessment activities, so that I can document physical pentest findings alongside technical assessment data.

#### Acceptance Criteria

1. THE Physical_Security_Module SHALL be integrated as a sub-tab within the existing Engagement Setup page.
2. THE Physical_Security_Module SHALL support tracking of physical access attempts including location, time, method, outcome, and evidence.
3. WHEN the user logs a physical finding, THE Physical_Security_Module SHALL categorize the entry by type including tailgating, lock bypass, badge cloning, dumpster diving, and social engineering.
4. THE Physical_Security_Module SHALL support site map annotation where users can mark entry points, camera locations, and access control zones on uploaded floor plans.
5. THE Physical_Security_Module SHALL generate a physical assessment summary section for inclusion in engagement reports.
6. THE Physical_Security_Module SHALL track physical security control effectiveness ratings for each assessed location.

### Requirement 18: GCP Pentest Engine

**User Story:** As a penetration tester, I want a Google Cloud Platform exploitation engine, so that I can assess GCP environments for security weaknesses with actual enumeration and exploitation capabilities.

#### Acceptance Criteria

1. THE GCP_Pentest_Engine SHALL support authentication using GCP service account keys and OAuth2 tokens.
2. WHEN the user initiates GCP enumeration, THE GCP_Pentest_Engine SHALL discover IAM policies, storage buckets, compute instances, Kubernetes clusters, and Cloud Functions.
3. THE GCP_Pentest_Engine SHALL check for privilege escalation paths through IAM policy analysis including overly permissive bindings and service account impersonation chains.
4. WHEN the GCP_Pentest_Engine discovers a misconfiguration, THE GCP_Pentest_Engine SHALL create a finding record with GCP-specific context and remediation guidance.
5. THE GCP_Pentest_Engine SHALL support testing for public storage bucket exposure, metadata service access, and default credential usage.
6. THE GCP_Pentest_Engine SHALL be integrated within the existing Recon & Enumeration page alongside the AWS and Azure pentest engines.

### Requirement 19: Scheduling and Recurring Scans

**User Story:** As a penetration tester, I want recurring scheduled assessment support, so that I can automate periodic security checks without manual intervention.

#### Acceptance Criteria

1. WHEN the user creates a scheduled scan, THE Scheduling_Engine SHALL store the scan configuration, target list, recurrence pattern, and next execution time.
2. THE Scheduling_Engine SHALL support recurrence patterns including one-time, daily, weekly, monthly, and custom cron expressions.
3. WHILE the application is running and a scheduled scan reaches its execution time, THE Scheduling_Engine SHALL automatically initiate the scan using the stored configuration.
4. WHEN a scheduled scan completes, THE Scheduling_Engine SHALL store results in the designated engagement and send a notification to the user.
5. IF a scheduled scan fails to execute, THEN THE Scheduling_Engine SHALL log the failure reason, increment a failure counter, and retry at the next scheduled interval.
6. THE Scheduling_Engine SHALL provide a calendar view displaying all scheduled scans with their status and next execution time.
7. WHEN the user disables a scheduled scan, THE Scheduling_Engine SHALL suspend future executions while retaining the configuration for re-enablement.
