# Design Document

## Overview

This document describes the architecture and design for a YouTube Tutorial Series Script Generator system that produces complete, production-ready video scripts for the Huginn penetration testing framework. The system covers Sections 2–10 (58 videos) building on the completed Section 1 (4 videos).

## Architecture

The YouTube Tutorial Series Script Generator is a structured content production system that transforms the Huginn codebase and documentation into complete, production-ready video scripts. The system operates as a document generation pipeline with validation layers ensuring consistency, completeness, and format compliance across all outputs.

The architecture consists of three layers:
1. **Input Layer** — Source material from the Huginn codebase (`app/core/`, `app/pages/`, `app/components/`), existing documentation (`docs/`), and the established Section 1 format
2. **Generation Layer** — Script composition following the attack chain methodology with templated structure
3. **Validation Layer** — Structural, cross-reference, and content completeness checks

## Components and Interfaces

### 1. Series Structure Manager

Manages the overall series organization, section numbering, and video sequencing.

**Responsibilities:**
- Map each video topic to one of the six attack chain phases
- Maintain sequential section numbering starting from Section 2
- Enforce one-video-per-tool/feature constraint
- Generate the series overview document

**Section-to-Phase Mapping:**

| Section | Attack Chain Phase | Video Count | Topics |
|---------|-------------------|-------------|--------|
| 2 | Recon | 12 | DNS, Port Scan, SMB, SMTP, SNMP, HTTP, API, RPC, LDAP, IKE/VPN, DB Enum, AV/FW |
| 3 | Recon (OSINT) | 7 | Subdomain, Cert Transparency, Breach Intel, People OSINT, Social Media, Threat Intel, Infra OSINT |
| 4 | Scan | 4 | Scanner Overview/Profiles, Scan Config, Results Interpretation, AI Scanning |
| 5 | Exploit (Web) | 9 | SQLi, XSS, SSTI, Command Injection, Path Traversal, SSRF, Deserialization, HTTP Interceptor |
| 6 | Exploit (Network/OS) | 5 | SSH Brute/Vuln, DB Attacks, RPC Relay, Exploit DB, Hacking Mode |
| 7 | Setup (Stealth) | 4 | Stealth Mode, ProxyChains, Tor, AWS Deployment |
| 8 | Elevate | 5 | Sessions, Credentials, Persistence, Lateral Movement, AD Enum |
| 9 | Report | 5 | Findings, Reports, Executive Summary, Compliance, Trend Analysis |
| 10 | Advanced | 7 | Guided Mode, Runecraft, Hash Cracking, Local DNS, Automation, Multi-Target, Plugins |

**Total: 58 videos across Sections 2–10** (plus 4 existing in Section 1 = 62 total)

### 2. Script Template Engine

Generates individual video scripts following the established Section 1 format.

**Script Structure Template:**

```markdown
# VIDEO {number}: {Title}
### {Subtitle}
**Suggested length:** {min}–{max} minutes
**License Tier:** {Free|Professional|Enterprise}
**Certification Relevance:** {OSCP domain|CEH domain|None}

---

## INTRO (0:00 – {end_time})

**[Screen: {description}]**

> "{narration text}"

---

## SECTION 1: {Title} ({start} – {end})

**[Screen: {description}]**

> "{narration text}"

```{language}
{terminal commands if applicable}
```

---

## OUTRO ({start} – end)

> "{narration text}"
```

**Format Rules:**
- Narration: Blockquotes (`>`) containing complete word-for-word text
- Screen directions: Bold brackets (`**[Screen: ...]**`) preceding each narration segment
- Timestamps: `(MM:SS – MM:SS)` format on every section header
- Terminal commands: Fenced code blocks with language annotation
- Cross-references: `(see Video {N}: {Title})` format

### 3. Demo Target Registry

Maintains the approved demo target list and maps targets to specific tools/features.

**Approved Targets:**

| Target | Type | Use Cases |
|--------|------|-----------|
| scanme.nmap.org | Public (authorized) | Port scanning, HTTP fingerprinting, basic enumeration |
| HTB machines | Lab platform | SMB, RPC, exploitation, post-exploitation, AD |
| THM rooms | Lab platform | Web exploits, network exploits, privilege escalation |
| DVWA | Self-hosted vulnerable app | Web application attacks (SQLi, XSS, SSTI, etc.) |
| Own cloud infrastructure | Self-owned | AWS deployment, infrastructure OSINT, stealth testing |

**Target Assignment Rules:**
- Each script must reference a specific target with configuration details
- No unauthorized or non-consenting targets permitted
- Target configuration must be reproducible (specific machine name, security level, etc.)

### 4. License Tier Annotator

Tracks and annotates license tier requirements throughout all scripts.

**Tier Mapping:**

```python
TIER_MAP = {
    "Free": [
        "DNS Enumeration", "Port Scanning", "SMB Enumeration",
        "SMTP Enumeration", "SNMP Enumeration", "HTTP Fingerprinting",
        "API Enumeration", "RPC Enumeration", "LDAP Enumeration",
        "IKE/VPN Assessment", "Database Enumeration", "AV/Firewall Detection",
        "Basic Vulnerability Scanning", "Standard Reporting (JSON/CSV/XML)",
        "Findings Management", "Scan Comparison"
    ],
    "Professional": [
        "Stealth Mode", "ProxyChains", "Tor Integration",
        "AWS Infrastructure Deployment", "Local DNS Server",
        "Basic Hacking Mode", "Advanced Reporting Templates",
        "Hash Cracking", "Automation & Scheduling"
    ],
    "Enterprise": [
        "Full Exploit Database", "Post-Exploitation Framework",
        "Advanced Hacking Mode", "Active Directory Enumeration",
        "AI-Powered Scanning (Neural Network, ML Pattern)",
        "Executive Summary Generation", "Compliance Reporting (NIST/ISO/PCI)",
        "Threat Intelligence Integration", "Breach Intelligence",
        "Custom API Integrations (Shodan, VirusTotal)",
        "Multi-Target Campaigns", "Plugin System"
    ]
}
```

### 5. Cross-Reference Resolver

Ensures all inter-video references are valid and consistent.

**Rules:**
- Any reference to a prior video must use format: `(see Video {N}: {Title})`
- Referenced video must exist in the series overview
- Video number and title must match exactly
- References should only point backward (to earlier videos), never forward

### 6. Certification Mapper

Maps video topics to OSCP and CEH certification domains.

**OSCP Domain Mapping:**
- Information Gathering → Section 2 (Recon), Section 3 (OSINT)
- Vulnerability Scanning → Section 4
- Web Application Attacks → Section 5
- Network Exploitation → Section 6
- Post-Exploitation → Section 8
- Reporting → Section 9

**CEH Domain Mapping:**
- Footprinting & Reconnaissance → Sections 2, 3
- Scanning Networks → Section 2 (Port Scan), Section 4
- Enumeration → Section 2
- System Hacking → Sections 6, 8
- Web Application Hacking → Section 5
- Cryptography → Section 10 (Hash Cracking)

### 7. Dependency Analysis Generator

Maps video topics to source code files for content creator reference.

**Source File Mapping Structure:**

```python
DEPENDENCY_MAP = {
    "video_topic": {
        "core_modules": ["app/core/{module}.py"],
        "ui_pages": ["app/pages/{page}.py"],
        "components": ["app/components/{component}.py"],
        "external_tools": ["nmap", "metasploit", etc.],
        "prerequisite_videos": [video_numbers],
        "prerequisite_config": ["API key X", "VPN connection", etc.]
    }
}
```

**Page-to-Phase Mapping:**

| Phase | UI Pages |
|-------|----------|
| Setup | `attack_chain_home.py`, `home_page.py`, `global_settings_page.py` |
| Recon | `recon_enumeration_page.py`, `dns_enumeration_page.py`, `osint_page.py`, `network_discovery_page.py` |
| Scan | `huginn_scanner_page.py`, `vuln_scanning_page.py` |
| Exploit | `web_exploits_page.py`, `os_exploits_page.py`, `db_attacks_page.py`, `owasp_api_page.py` |
| Elevate | `post_exploitation_page.py`, `shell_management_page.py`, `cracking_page.py` |
| Report | `findings_page.py`, `centralized_dashboard_page.py` |

### 8. Safety and Ethics Validator

Ensures all exploitation and post-exploitation scripts include appropriate warnings.

**Required Elements for Exploitation Scripts:**
- Lab environment confirmation statement
- Ethical testing disclaimer (authorized access only)
- Responsible disclosure reminder (for Runecraft/payload generation)
- No real-world target demonstrations

## Interfaces

### Script Generation Input

```python
@dataclass
class VideoScriptInput:
    video_number: int
    title: str
    subtitle: str
    section_number: int
    attack_chain_phase: str
    tool_name: str
    license_tier: str
    demo_target: DemoTarget
    cert_relevance: list[str]  # ["OSCP: Information Gathering", "CEH: Enumeration"]
    prerequisites: list[int]   # Prior video numbers
    core_modules: list[str]    # Source file paths
    suggested_length_min: int
    suggested_length_max: int
```

### Script Generation Output

```python
@dataclass
class VideoScript:
    header: ScriptHeader       # Title, subtitle, length, tier badge
    intro: ScriptSection       # INTRO with screen direction + narration
    sections: list[ScriptSection]  # Numbered sections with timestamps
    outro: ScriptSection       # OUTRO section
    commands: list[CodeBlock]  # Terminal commands shown in video
    cross_references: list[CrossRef]  # References to other videos
    
@dataclass
class ScriptSection:
    title: str
    timestamp_start: str       # MM:SS format
    timestamp_end: str         # MM:SS format
    screen_directions: list[str]  # Bold bracket format
    narration: list[str]       # Blockquote format
    code_blocks: list[CodeBlock]  # Optional terminal commands

@dataclass
class DemoTarget:
    platform: str              # HTB | THM | DVWA | scanme.nmap.org | own_cloud
    specific_target: str       # Machine name, room name, etc.
    configuration: str         # Security level, services, etc.
    services_required: list[str]  # Expected running services
```

### Series Overview Output

```python
@dataclass
class SeriesOverview:
    sections: list[SectionOverview]
    total_videos: int
    
@dataclass  
class SectionOverview:
    section_number: int
    title: str
    phase: str
    videos: list[VideoEntry]
    tier_reference_table: dict[str, str]  # video_title -> tier

@dataclass
class VideoEntry:
    video_number: int
    title: str
    subtitle: str
    license_tier: str
    demo_target: str
```

## Data Models

### Video Metadata Schema

```python
class VideoMetadata:
    """Tracks metadata for validation and cross-referencing."""
    video_id: int
    title: str
    section: int
    phase: str
    tier: str
    demo_target: DemoTarget
    has_intro: bool
    has_outro: bool
    timestamp_format_valid: bool
    screen_directions_count: int
    narration_blocks_count: int
    code_blocks_count: int
    cross_references: list[tuple[int, str]]  # (video_num, title)
    cert_domains: list[str]
    safety_warnings_present: bool
    api_setup_included: bool
```

### Section Document Schema

```python
class SectionDocument:
    """One markdown file per section containing all videos."""
    section_number: int
    section_title: str
    phase: str
    videos: list[VideoScript]
    tier_reference_table: dict[str, str]
    practice_machines: list[str]
```

## Error Handling

### Validation Errors

| Error Type | Description | Resolution |
|-----------|-------------|------------|
| Missing INTRO/OUTRO | Script lacks required bookend sections | Add template INTRO/OUTRO |
| Invalid timestamp format | Timestamp doesn't match `(MM:SS – MM:SS)` | Reformat to spec |
| Orphaned cross-reference | References video that doesn't exist in overview | Fix reference or add missing video |
| Missing tier annotation | Script lacks license tier at start | Add tier badge to header |
| Unauthorized target | Demo target not in approved list | Replace with approved target |
| Missing safety warning | Exploitation script lacks ethical disclaimer | Add standard safety block |
| Duplicate tool assignment | Same tool appears in multiple videos | Consolidate to single video |
| Missing API setup | API-dependent OSINT tool lacks setup steps | Add API configuration section |

### Content Completeness Warnings

| Warning | Description |
|---------|-------------|
| Thin narration section | Section has screen direction but minimal narration |
| No code blocks in technical video | Technical demo video lacks terminal commands |
| Missing sub-feature coverage | Tool with known sub-features doesn't demonstrate all |
| No certification mapping | Certification-relevant topic missing OSCP/CEH reference |

## Testing Strategy

The validation of generated scripts uses two complementary approaches:

**Property-Based Tests (100+ iterations):**
- Validate structural format compliance across randomly generated script variants
- Verify cross-reference consistency by generating reference graphs and checking validity
- Confirm demo target membership in the approved list across all generated scripts
- Test license tier annotation presence and correctness across feature permutations

**Example-Based Tests:**
- Verify specific section documents (e.g., Section 2 has exactly 12 enumeration tool videos)
- Confirm specific scripts exist for each listed topic in requirements
- Validate the series overview contains all 58 video entries
- Check individual scripts against the Section 1 established format

**Manual Review:**
- Content quality assessment (narration reads naturally, technical accuracy)
- Demo workflow feasibility (can demonstrations actually be performed as described)
- Timing accuracy (suggested lengths align with content density)

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Script Structural Validity

*For any* generated video script, it SHALL contain all required structural elements: a title, subtitle, suggested video length, license tier annotation at the start, an INTRO section, an OUTRO section, timestamped section headers in `(MM:SS – MM:SS)` format, screen directions in `**[Screen: ...]**` format preceding each narration segment, and narration formatted as blockquotes. If terminal commands are present, they SHALL be enclosed in fenced code blocks.

**Validates: Requirements 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 14.1**

### Property 2: Section Phase Assignment Validity

*For any* video in the series, the section it belongs to SHALL map to exactly one of the six valid attack chain phases (Setup, Recon, Scan, Exploit, Elevate, Report), and the section numbering SHALL be sequential starting from Section 2.

**Validates: Requirements 1.1, 1.2**

### Property 3: Video-Tool Uniqueness

*For any* section in the series, each video SHALL correspond to exactly one unique tool or distinct feature, and no tool or feature SHALL appear as the primary topic of more than one video within the series.

**Validates: Requirements 1.3**

### Property 4: Cross-Reference Consistency

*For any* cross-reference in any video script, the referenced video number and title SHALL exist in the series overview document and SHALL match exactly. All cross-references SHALL point to earlier (lower-numbered) videos only.

**Validates: Requirements 1.5**

### Property 5: Demo Target Validity

*For any* video script that includes a demonstration, the assigned demo target SHALL be from the approved target list (HTB machines, THM rooms, DVWA instances, scanme.nmap.org, or own cloud infrastructure), and target configuration details (machine name, security level, required services) SHALL be specified for reproducibility.

**Validates: Requirements 13.1, 13.2, 13.3, 13.4**

### Property 6: License Tier Annotation Completeness

*For any* video script, a license tier annotation SHALL appear at the start. For any script covering features from multiple tiers, each feature SHALL be individually annotated with its tier. For any section document, a quick reference table mapping video titles to required license tiers SHALL be present at the end.

**Validates: Requirements 3.4, 11.2, 14.1, 14.2, 14.3**

### Property 7: Enumeration Script Content Coverage

*For any* enumeration tool video script (Section 2), it SHALL contain all five required content areas: protocol explanation, tool interface walkthrough, configuration options, live demonstration against a demo target, and results interpretation.

**Validates: Requirements 3.2**

### Property 8: API Setup Inclusion

*For any* OSINT video script (Section 3) that demonstrates a feature requiring an API key (Shodan, VirusTotal, or similar), the script SHALL include API setup and configuration instructions within the demonstration steps.

**Validates: Requirements 4.3**

### Property 9: Exploitation Safety Warnings

*For any* video script in Sections 5, 6, or 8 (Web Exploitation, Network Exploitation, or Post-Exploitation), the script SHALL include explicit safety warnings confirming demonstrations use isolated lab environments only. For scripts involving credential extraction, persistence techniques, or payload generation, ethical guidelines and authorized-testing-only disclaimers SHALL be present.

**Validates: Requirements 7.4, 9.4, 11.3**

### Property 10: Certification Domain Mapping

*For any* video script covering a technique tested in OSCP or CEH examinations, the script SHALL include a note identifying the relevant certification domain or objective, and SHALL reference related HTB/THM practice machines for further study.

**Validates: Requirements 15.1, 15.3**

### Property 11: Section Tier Reference Table

*For any* section document in the series, it SHALL end with a quick reference table mapping each video title within that section to its required license tier.

**Validates: Requirements 14.3**
