# Huginn Architecture

## Overview

Huginn is a professional-grade penetration testing platform built with PyQt6. It follows a **5-layer architecture** with clear separation of concerns, event-driven communication, and component-based design patterns.

## Project Structure

```
huginn/
├── app/                        # Presentation Layer (UI + scanners)
│   ├── agent/                  # Autonomous agent (windows_agent.py)
│   ├── components/             # Feature-specific UI components (50+)
│   ├── config/                 # Application payloads/config
│   ├── core/                   # Core engines and business logic (291 modules)
│   ├── main_window/            # Main window (decomposed)
│   │   ├── main_window_refactored.py
│   │   └── components/         # menu, navigation, theme, tray managers
│   ├── pages/                  # Full-screen UI pages
│   ├── tools/                  # Scanner implementations (12-tool suite)
│   ├── ui/                     # Animations, graphics, themes, widgets
│   └── widgets/                # Reusable UI widgets (80+)
├── application/                # Application Services Layer
│   ├── handlers/               # Request/response handling
│   ├── services/               # Business orchestration
│   └── workflows/              # Complex business workflows
├── domain/                     # Domain/Business Logic Layer
│   ├── models/                 # Domain entities and value objects
│   ├── repositories/           # Data access interfaces (abstract)
│   └── services/               # Domain business logic
├── infrastructure/             # Infrastructure Layer
│   ├── data/                   # Data persistence
│   │   ├── database/           # Database infrastructure
│   │   └── repositories/       # Repository implementations (SQLite)
│   ├── external/               # External service integrations
│   └── scanners/               # New-architecture scanner implementations
│       ├── base/               # BaseScanner, ScannerFactory
│       ├── network/            # Port scanner, DNS scanner
│       └── service/            # Service-specific scanners
├── shared/                     # Shared/Cross-Cutting Components
│   ├── analytics/              # Analytics engine
│   ├── configuration/          # ConfigManager, global settings
│   ├── constants/              # Application constants
│   ├── distributed/            # Node manager, task distributor
│   ├── events/                 # EventBus, plugin/hash events
│   ├── exceptions/             # Custom exception hierarchy
│   ├── plugins/                # Plugin interfaces and registry
│   └── utilities/              # Error handling, performance monitoring
├── tools/                      # High-level exploitation utilities
│   ├── base_tool.py            # Base class for tool modules
│   ├── cracking_tools.py       # Password cracking utilities
│   ├── os_exploits.py          # OS-level exploitation
│   ├── web_exploits.py         # Web application exploits
│   └── ...                     # SMB, SMTP, SNMP, DB, API enum utilities
├── plugins/                    # User/third-party plugins
│   ├── analysis_plugins/
│   ├── evasion/
│   ├── scanner_plugins/
│   └── ui_plugins/
├── modules/                    # Standalone modules (SSH parser)
├── scripts/                    # Exploit scripts (Linux, Windows)
├── examples/                   # Demo scripts for all architecture phases
├── resources/                  # Runtime data and config
│   ├── config/                 # scanner_config.yaml, tool configs, themes
│   ├── credentials/            # Credential storage
│   ├── engagements/            # Engagement project data
│   ├── fonts/                  # UI fonts
│   ├── icons/                  # UI icons
│   ├── knowledge_base/         # Built-in knowledge base
│   ├── templates/              # Report templates
│   ├── themes/                 # UI theme files
│   ├── wordlists/              # Enumeration wordlists
│   └── *.db                    # SQLite databases (proxy, scan, assets, etc.)
├── templates/                  # Additional templates
├── profiles/                   # User/target profiles
├── exports/                    # Exported reports
├── tests/                      # Test suite
│   ├── integration/            # Integration tests
│   ├── fixtures/               # Test fixtures
│   └── test_*.py               # Unit/functional tests (~90 files)
├── docs/                       # Documentation
├── main.py                     # Application entry point
├── requirements.txt            # Python dependencies
└── manifest.json               # Application manifest
```

## Architecture Layers

### 1. Presentation Layer (`app/`)

The UI layer built on PyQt6 with component-based architecture.

**Main Window** (`app/main_window/`):
- Decomposed from a monolithic file into focused components
- `main_window_refactored.py` — Core window shell (~300 lines)
- `components/menu_manager.py` — Menu bar management
- `components/navigation_manager.py` — Page navigation and routing
- `components/theme_manager.py` — Theme integration
- `components/tray_manager.py` — System tray handling

**Pages** (`app/pages/`):
- Full-screen views: home, recon/enumeration, vulnerability scanning, exploitation, OSINT, findings, shell management, guided workflows, etc.
- `page_registry.py` — Centralized page registration and routing

**Components** (`app/components/`):
- Feature-specific UI panels: attack chains, breach analysis, cloud discovery, compliance, evidence management, HTTP interceptor, scan profiles, threat intelligence, etc.

**Widgets** (`app/widgets/`):
- Reusable UI building blocks: terminal widgets, progress indicators, scan controls, theme selectors, credential forms, analytics dashboards, etc.

**Scanner Tools** (`app/tools/`):
- The 12-tool enumeration suite (DNS, Port, RPC, SMB, SMTP, SNMP, HTTP, API, LDAP, DB, IKE, AV/Firewall)
- Each scanner has a main scanner class, utilities module, and worker classes
- Also includes: stealth scanner, evasion profiler, evidence collector, payload tools

**Note on `tools/` directories**: There are two distinct locations:
- `app/tools/` — Scanner implementations used by the UI (the 12-tool suite)
- `tools/` (root) — Higher-level exploitation utilities and enum helpers used programmatically

### 2. Application Services Layer (`application/`)

Orchestrates business operations between the domain and infrastructure layers.

- **Services**: `scan_orchestrator.py`, `enhanced_scan_orchestrator.py`, `hash_lookup_service.py`, `plugin_service.py`, `advanced_integration_service.py`
- **Handlers**: `scan_handler.py` — Request validation and processing
- **Workflows**: Complex multi-step business processes

### 3. Domain Layer (`domain/`)

Core business logic, independent of infrastructure.

- **Models**: `scan_result.py` (Target, ScanResultModel, Vulnerability, ScanStatus), `hash_record.py`
- **Repositories** (interfaces): `scan_repository.py`, `hash_repository.py` — Abstract data access contracts
- **Services**: `scanner_service.py`, `hash_lookup_manager.py` — Domain business rules

### 4. Infrastructure Layer (`infrastructure/`)

Concrete implementations of domain interfaces.

- **Scanners**: BaseScanner, ScannerFactory, PortScanner, DNSScanner — New-architecture implementations with async support and event integration
- **Repositories**: `sqlite_scan_repository.py`, `sqlite_hash_repository.py` — SQLite-backed persistence
- **External**: `hash_api_client.py`, `hash_source_updater.py` — Third-party service integrations

### 5. Shared Components (`shared/`)

Cross-cutting concerns used by all layers.

- **ConfigManager** (`configuration/config_manager.py`) — Centralized, type-safe configuration
- **EventBus** (`events/event_bus.py`) — Publish-subscribe for decoupled communication
- **Exceptions** (`exceptions/`) — Hierarchical error handling (`scanner_exceptions.py`, `plugin_exceptions.py`)
- **Analytics** (`analytics/analytics_engine.py`) — Cross-layer analytics
- **Distributed** (`distributed/`) — Node management and task distribution for multi-node scanning
- **Plugins** (`plugins/`) — Plugin interfaces, registry, and UI plugin support
- **Utilities** (`utilities/`) — Error handling, performance monitoring/profiling

## Core Engines (`app/core/`)

The `app/core/` directory contains 291 modules organized by capability:

### Scanning & Reconnaissance
- `scanner_engine.py`, `sync_scanner.py`, `adaptive_scanner.py`
- `dns_resolver.py`, `subdomain_engine.py`, `content_discovery.py`
- `port_data_collector.py`, `dns_data_collector.py`, `http_data_collector.py`
- `intelligent_scan_orchestrator.py`, `multi_target_coordinator.py`

### HTTP & Web Security
- `proxy_engine.py` — mitmproxy integration
- `proxy_database.py` — HTTP history storage
- `unified_request_handler.py` — Central HTTP coordinator
- `http_client.py` — Unified HTTP request/response objects
- `authenticated_crawler.py`, `web_crawler.py`, `crawler.py`
- `ssti_detector.py`, `ssrf_tester.py`, `command_injection_tester.py`
- `cors_detector.py`, `idor_detector.py`, `path_traversal_tester.py`

### Exploitation & Post-Exploitation
- `exploit_database.py`, `exploit_generator.py`
- `post_exploitation.py`, `shell_manager.py`, `listener_manager.py`
- `aws_exploitation.py`, `aws_pentest_engine.py`, `azure_pentest_engine.py`, `gcp_pentest_engine.py`
- `kerberos_auth.py`, `ntlm_relay_client.py`, `dcsync_client.py`
- `rpc_*` modules (protocol, transport, enumeration, relay, exploitation)

### AI & Machine Learning
- `ai_pattern_analyzer.py`, `ai_payload_engine.py`
- `ml_pattern_detection.py`, `ml_vulnerability_predictor.py`
- `neural_vulnerability_engine.py`, `quantum_fuzzer.py`
- `autonomous_agent.py`

### Reporting & Evidence
- `advanced_reporting.py`, `centralized_reporting.py`, `enhanced_reporting.py`
- `pdf_generator.py`, `pdf_report_generator.py`
- `evidence_collector.py`, `evidence_manager.py`
- `compliance_mapper.py`, `compliance_reporter.py`
- `executive_summary.py`, `report_customizer.py`

### Infrastructure & Management
- `cache_manager.py` — Singleton cache management
- `unified_theme_manager.py` — Application theming
- `session_manager.py`, `engagement_manager.py`
- `license_manager.py`, `plugin_manager.py`
- `state_manager.py`, `memory_manager.py`, `performance_monitor.py`
- `distributed_scanning.py` — Multi-node scan coordination
- `scheduling_engine.py`, `rate_limiter.py`

### Credential & Authentication
- `credential_manager.py`, `secure_credential_manager.py`
- `auth_database.py`, `auth_token_analyzer.py`
- `crack_engine.py`, `gpu_crack_engine.py`, `hashcat_engine.py`
- `auth_flow_recorder.py`, `auth_replay_engine.py`

### OSINT & Intelligence
- `osint_collector.py`, `osint_engines.py`, `osint_workers.py`
- `threat_intelligence.py`, `threat_intel_engine.py`
- `breach_database.py`, `breach_intel_engine.py`
- `social_media_engine.py`, `people_intel_engine.py`
- `cert_transparency.py`

## Key Design Patterns

- **Singleton**: ConfigManager, CacheManager, ThemeManager
- **Observer/Pub-Sub**: EventBus for cross-layer communication; Qt Signal/Slot for UI updates
- **Factory**: ScannerFactory for dynamic scanner creation and registration
- **Repository**: Abstract interfaces in `domain/`, SQLite implementations in `infrastructure/`
- **Strategy**: Multiple export formats, scan profiles, evasion strategies
- **Component-based**: Main window decomposed into single-responsibility managers

## Data Flow

```
User Input → UI Validation → Application Handler → Domain Service
    → Infrastructure (Scanner/Repository) → Results
    → EventBus notification → UI update
```

1. **Scanning**: UI → app/tools scanner → core engine → results → centralized data store → UI display
2. **HTTP Proxy**: Request → ProxyEngine intercept → proxy_database → History UI → Analysis
3. **Persistence**: Domain model → Repository interface → SQLite implementation → resources/*.db
4. **Events**: Component publishes → EventBus → Subscribers react (decoupled)

## Database Layer

All databases are SQLite, stored in `resources/`:
- `proxy.db` — HTTP intercept history
- `scan_results.db` — Scan result storage
- `asset_inventory.db` — Asset tracking
- `pentest_findings.db` — Vulnerability findings
- `hash_lookup.db` — Hash cracking results
- `huginn_master_index.db` — Cross-scan indexing
- `vulnerability_findings.db` — Vulnerability database
- Plus engagement, breach, correlation, crawl, and header databases

## Plugin System

Plugins live in `plugins/` and extend via `app/core/plugin_manager.py` (PluginBase class). The `shared/plugins/` module provides the registry and interfaces for the new architecture. See [Plugin Development Guide](PLUGINS.md).

## Related Documentation

- [Architecture Implementation History](ARCHITECTURE_IMPLEMENTATION.md) — Detailed phase-by-phase transformation
- [Development Guide](DEVELOPMENT.md) — Contributing and code standards
- [Enumeration Tools](ENUMERATION_TOOLS.md) — 12-tool reconnaissance suite
- [Unified HTTP System](UNIFIED_HTTP_SYSTEM.md) — HTTP request handling architecture
- [Distributed Scanning](DISTRIBUTED_SCANNING.md) — Multi-node operations
