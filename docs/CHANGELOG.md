# Changelog

## [Unreleased]

### Security Fixes

#### Fix: `autonomous_agent.py` Returns Random Fake Results (High)
The autonomous agent used `random.random()` for every decision — which
techniques to run, whether they "succeeded", what vulnerabilities were
"found", and whether exploits "worked".  Results were non-deterministic
fabrications.  Operators running the agent in the "Insane" scan profile
received random fake vulnerability counts that were mixed into the real
results list with no indication they were synthetic.

**Changes in `app/core/autonomous_agent.py`:**

- Added `simulation_mode` constructor parameter (default `True`).
- **Simulation mode** (default): produces clearly-labelled synthetic data.
  Every result dict carries `simulated=True` and a `SIMULATION_WARNING`
  string.  No network requests are made.  `_evaluate_mission_success()`
  always returns `False` — simulation never claims a successful compromise.
- **Live mode** (`simulation_mode=False`): dispatches to real scanner
  modules (`NmapScanner`, `HTTPFingerprinter`, `VulnerabilityScanner`,
  `CertificateTransparencyClient`, `DNSScanner`).  Falls back to a
  clearly-labelled "not-executed" result if a module is unavailable.
- Removed all `random.random()`, `random.choice()`, `random.randint()` calls.
- Fixed `_mission_complete()` — previously terminated at a random count of
  5 "vulnerabilities"; now terminates when the state machine reaches
  `REPORTING`.
- Persistence techniques are skipped entirely in simulation mode.
- Automated exploitation is not implemented in live mode either — returns a
  "not-executed" result directing operators to use dedicated tools.

**Changes in `app/tools/huginn_vuln_scanner.py`:**

- Agent is now instantiated with `simulation_mode=(profile != 'insane')` —
  live mode only when the operator explicitly selects the Insane profile.
- Result consumption filters out simulated findings (`simulated=True`) before
  adding to the vulnerability list — synthetic data can never be mixed with
  real findings.

---

#### Fix: Duplicate and Stale Files Removed

Five groups of duplicate/versioned files were identified. Each was handled
based on its actual usage:

| File | Action | Reason |
|---|---|---|
| `app/core/rpc_enum_fixed.py` | **Deleted** | Byte-for-byte identical to `rpc_enum.py`; the "original" already had `_fixed` in its header comment |
| `app/tools/rpc_scanner_fixed.py` | **Deleted** | `rpc_scanner.py` header said `# app/tools/rpc_scanner_fixed.py` — it was already the fixed version, just misnamed |
| `tools/api_enum_upgraded.py` | **Deleted** | Zero imports anywhere — dead code |
| `app/core/vulnerability_correlator.py` | **Kept + noted** | Different class from `_enhanced.py`; added deprecation note pointing to the enhanced version |
| `app/widgets/stealth_widget.py` | **Kept + noted** | Different class from `_improved.py`; added deprecation note pointing to the improved version |

Header comments in `rpc_enum.py` and `rpc_scanner.py` corrected to match
their actual file names.

---

#### Fix: Resource Management Issues (Medium)

**Connection pool — unbounded session growth:**
`ConnectionPool.get_session()` stored sessions in an unbounded dict.
A caller using a unique `pool_key` per scan target could create thousands
of open HTTP connections.  Added a `_MAX_SESSIONS = 50` cap with LRU
eviction: when the limit is reached the oldest session is closed and
removed before a new one is created.  Added a `_session_lock` so
`get_session()` is thread-safe.  Added `close_session(key)` for targeted
cleanup.

**Connection pool — not closed on shutdown:**
`connection_pool.close_all()` was never called.  Added it to
`MainWindow.closeEvent` so all HTTP connections are cleanly closed when
the application exits.

**QThreadPool — no thread count limit:**
`QThreadPool.globalInstance()` was used throughout with no `maxThreadCount`
set, defaulting to the Qt default (typically `idealThreadCount()`).
During aggressive scans this could spawn dozens of threads simultaneously.
Added `_configure_thread_pool()` in `MainWindow._initialize_components()`
that sets `maxThreadCount = max(4, min(cpu_count × 2, 32))`.

**QThreadPool — not drained on shutdown:**
Added `QThreadPool.globalInstance().waitForDone(5000)` to `closeEvent`
so in-flight scan workers have up to 5 seconds to finish before the
process exits.

**QThread leak in `azure_pentest_widget.py`:**
Starting a new scan while a previous thread was still running orphaned
the old thread.  Added `_stop_current_thread()` helper that calls
`quit()` + `wait(3000)` + `terminate()` (fallback) before creating a
new thread.  Called at the start of every scan method.  Also set
`self.thread = None` after cleanup in `on_test_finished` and
`on_test_error` to prevent double-quit.

**MemoryManager — stub implementation:**
`app/core/memory_manager.py` was a 10-line stub with empty methods.
Replaced with a real implementation that:
- Runs a daemon background thread checking RSS every 30 seconds
- Logs a warning at 500 MB
- Triggers `gc.collect()` at 750 MB and logs the freed memory
- Uses `psutil` if available, falls back to `resource` module (Unix)
- Exposes `get_memory_usage()` and `optimize_memory()` for widgets

---

#### Fix: Duplicate Singleton Instances (Medium)
Four classes were instantiated at module level in **both** `app/core/X.py`
and `resources/rpc/X.py` — creating two independent instances with split
state:

- `DNSSettingsManager` — DNS setting changes in one instance were invisible
  to the other
- `SecureCredentialManager` — credentials stored via one instance were not
  accessible from the other (separate key files and credential stores)
- `VulnerabilityDatabase` — findings written via one instance were not
  visible in the other's SQLite database

**Fix:** The `resources/rpc/` copies were exact duplicates of the `app/core/`
versions (they even had `# app/core/X.py` as their first comment).  They have
been replaced with thin re-export modules that import the canonical singleton
from `app/core/`:

```python
# resources/rpc/dns_settings.py (after)
from app.core.dns_settings import DNSSettingsManager, dns_settings
```

**Singleton protection added** to `ConfigManager` and `SecureCredentialManager`
(the two most-imported classes without it) using the double-checked locking
pattern:

```python
_instance = None
_lock = threading.Lock()

def __new__(cls, *args, **kwargs):
    if cls._instance is None:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
    return cls._instance

def __init__(self, ...):
    if hasattr(self, '_initialised'):
        return   # Guard against re-init on subsequent calls
    self._initialised = True
    ...
```

`HuginnLogger` and `ConnectionPool` already had this pattern.

---

#### Fix: Duplicate Method + Dynamic Import in `main_window_refactored.py`

**Duplicate `open_reports_dialog`:** The method was defined twice in `MainWindow`.
Python silently uses the second definition, making the first unreachable dead code.
The first (earlier) definition has been removed.

**`_cleanup_services` used `__import__`:** The method used
`__import__(f'app.core.{service_name}', ...)` with a string-interpolated module
name — a pattern that is fragile, hard to analyse statically, and a potential
module injection vector if the service list ever became user-configurable.
Replaced with direct, explicit imports for each service (`local_dns_server`,
`vpn_manager`), each in its own try/except block.

**Inconsistent page factory error handling:** `_create_recon_enumeration` and
`_create_vuln_scanning` were the only two page factories without try/except
blocks — import or init errors would propagate up and crash the main window
instead of logging and returning `None` like all other factories. Both now
follow the same pattern as the rest.

#### Fix: Bare `except: pass` Throughout Codebase (High)

547 silent exception handlers across 177 files were swallowing errors
completely — including `SystemExit`, `KeyboardInterrupt`, and
`GeneratorExit` in the case of bare `except:`.  Silent failures made
debugging nearly impossible and hid real errors from operators.

**Two changes applied to every pass-only handler:**

1. **Bare `except:` → `except Exception as _exc:`**  
   Stops accidentally catching `SystemExit`, `KeyboardInterrupt`, and
   `GeneratorExit` which should always propagate.

2. **`pass` → `pass` + `logger.debug("Suppressed exception", exc_info=True)`**  
   Every suppressed exception now appears in the debug log with a full
   stack trace.  Behaviour is unchanged (no re-raise, no crash) but
   failures are now visible when running with `--log-level DEBUG`.

**Files changed: 166** (automated fix via script, verified all parse cleanly).

**Before:**
```python
try:
    sock.close()
except:
    pass
```

**After:**
```python
try:
    sock.close()
except Exception as _exc:
    pass
    logger.debug("Suppressed exception", exc_info=True)
```

The 22 handlers in files with pre-existing syntax errors were not
modified — those files need their syntax errors fixed first.

---

#### Fix: Unescaped HTML in Output Signals (Medium)
User-controlled and network-sourced data (scan results, banners, error
messages, finding titles, vulnerability descriptions) was embedded directly
into HTML strings passed to Qt `QTextEdit`/`QTextBrowser` widgets via
`setHtml()` and `output.emit()` without escaping.  A target server returning
a banner like `<script>alert(1)</script>` would have that rendered as HTML.

**Fix:** Created `app/core/html_utils.py` with:
- `h(value)` — wraps `html.escape(str(value), quote=True)`, the single
  canonical escape function for all HTML output in the application.
- `safe_p(text, color, extra_style)` — convenience wrapper for the common
  `<p style='color: ...'>text</p><br>` pattern.

All variables embedded in HTML strings are now wrapped with `h()`.

**Files changed: 33**
- `app/core/html_utils.py` — new utility module
- `app/components/findings/findings_details_component.py`
- `app/components/owasp_api/api_risk_details_component.py`
- `app/pages/post_exploitation_page.py`
- `app/components/vuln_scanner_component.py`
- `app/components/web_exploits_component.py`
- `app/components/rpc_relay_component.py`
- `app/components/automation_component.py`
- `app/components/infrastructure_osint_component.py`
- `app/components/scripts/reverse_shells_component.py`
- 24 additional scanner/tool files (bulk fix via automated script)

---

#### Fix: Weak Attestation in `windows_agent.py` (High)
The original attestation check compared `sha256(f"{operation}:huginn_agent")`
to `sha256(attestation_data)` — meaning the check passed whenever
`attestation_data == f"{operation}:huginn_agent"`.  The "secret" was the
literal string `huginn_agent`, visible in source code.  Anyone who read the
file could forge any attestation and call `modify_firewall` or
`modify_defender` without restriction.

Additional issues fixed in the same file:
- `modify_firewall` and `modify_defender` interpolated `rule_name` and
  `exclusion_path` directly into PowerShell command strings — PS injection.
- `self_clean` parsed rule names by splitting on `:` — fragile and
  exploitable with a crafted rule name.
- `__main__` block used `sys` without importing it (would crash on startup).
- All `print()` calls replaced with `logger`.
- `pywin32` imports wrapped in `try/except` so the module loads on non-Windows
  systems (e.g. for testing).

**New attestation model (`app/agent/windows_agent.py`):**

```
Token = HMAC-SHA256(secret, "<operation>:<nonce>:<expiry_unix_ts>")
```

- **Secret** — read from `HUGINN_AGENT_SECRET` env var (hex-encoded, ≥ 32 bytes),
  or from `~/.huginn/agent.key` (auto-generated on first run, chmod 600).
  Never in source code.
- **Nonce** — 32-byte random hex per token; stored in the audit DB and
  rejected on any subsequent use (replay protection).
- **Expiry** — tokens expire after 300 seconds (configurable via
  `ATTESTATION_VALIDITY_SECONDS`).
- **Constant-time comparison** — `hmac.compare_digest()` prevents timing
  side-channels.

**Orchestrator usage:**
```python
from app.agent.windows_agent import create_attestation_token
import json

token = create_attestation_token("modify_firewall")
agent.modify_firewall(rule_name, "add", json.dumps(token))
```

**PS injection fixes:**
- `rule_name` and `exclusion_path` are now passed via `env={"RULE_NAME": ...}`
  and referenced as `$env:RULE_NAME` in the PS command — never interpolated
  into the command string.
- `self_clean` passes values the same way.
- `collect_eventlogs` passes `log_name` via `$env:LOG_NAME` and validates
  the name against an alphanumeric + safe-chars allowlist.

---

#### Fix: SQL Injection via f-string Identifiers (Critical)
Table and column names were interpolated directly into SQL strings using
f-strings, allowing a malicious SQLite database file (opened via the DB
browser) or a crafted table name to inject arbitrary SQL.

**Approach:** Added `_quote_identifier()` to `database_utils.py` — a
central helper that bracket-quotes SQLite identifiers (`[name]`) and
rejects names containing `]`, `;`, or null bytes.  All identifier
interpolation now goes through this function.  Value parameters continue
to use `?` bound parameters.  f-strings were replaced with string
concatenation so the pattern is unambiguous to code reviewers.

**Files changed:**

- `app/core/database_utils.py`
  - Added `_quote_identifier(name)` helper with allowlist-style validation.
  - `get_database_info`: `SELECT COUNT(*) FROM` and `PRAGMA table_info` now
    use `_quote_identifier()`.
  - `get_table_sample`: identifier quoted; `limit` clamped to `[1, 10_000]`.
  - `cleanup_old_data`: both table name and date column quoted; `days_old`
    passed as a bound `?` parameter instead of interpolated.
  - `export_table_csv`: table name quoted.
  - `execute_safe_query`: added optional `params` argument so callers can
    pass bound parameters without building a new query string.

- `app/pages/database_management_page.py`
  - `load_database_schema`: `PRAGMA table_info` and `SELECT COUNT(*)` now
    use `_quote_identifier()`; tables with unquotable names are skipped with
    a visible label instead of silently executing.

- `app/core/ssh_data_collector.py`
  - `get_scan_summary`: table names validated against a `frozenset` allowlist
    before bracket-quoting; f-string replaced with string concatenation.

- `app/core/query_engine.py`
  - `find_weak_credentials` / `find_exposed_databases`: f-string placeholder
    building (`f\"... IN ({placeholders})\"`) replaced with string
    concatenation — the `placeholders` variable only ever contains `?,?,?`
    but the pattern was misleading.

- `app/core/auth_database.py`
  - `export_flows`: same f-string placeholder pattern replaced with string
    concatenation.

---

#### Fix: Plaintext Credential Storage (Critical)
Credentials (passwords, NTLM hashes, Kerberos tickets, API keys) were written
to disk in plaintext JSON files under ``profiles/``.  All credential persistence
now goes through Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256) using
the key managed by ``SecureCredentialManager``.

**Key changes:**

- `app/core/secure_credential_manager.py` — rewrote `_init_encryption`:
  - Fixed broken key derivation (salt was concatenated with key but re-split
    incorrectly, making the stored key unusable after restart).
  - New v2 key-file format: `[0x02 version byte][16-byte salt][32-byte PBKDF2 key]`.
  - Legacy v1 key files (raw Fernet key) are auto-migrated on first load.
  - Added `encrypt_data()` / `decrypt_data()` public helpers for use by
    `CredentialManager`.
  - Replaced all `print()` error reporting with `logger`.
  - SSL verify now reads from config in `_test_shodan_credential` /
    `_test_virustotal_credential`.

- `app/core/credential_manager.py` — rewrote persistence layer:
  - `_save_profile_credentials()` now calls `secure_credential_manager.encrypt_data()`
    and writes `<profile>_credentials.enc` instead of plaintext JSON.
  - `_load_profile_credentials()` decrypts via `secure_credential_manager.decrypt_data()`.
  - `_migrate_plaintext_file()` — on first load, any existing
    `<profile>_credentials.json` is encrypted, the plaintext file is
    zero-overwritten, then deleted.
  - Removed `_save_to_main_profile_json()` (was writing plaintext to profile JSON).
  - Replaced all `print()` error reporting with `logger`.

- `tools/credential_manager.py` — fixed standalone tool credential manager:
  - Was encrypting passwords individually but writing the outer JSON in plaintext.
  - Now encrypts the entire credential store as a single Fernet blob in
    `credentials.enc`.
  - Added migration from legacy `credentials.json` on first load.

**Migration behaviour:** Existing plaintext credential files are automatically
encrypted on the next application start.  No manual action required.

---

#### Fix: SSL/TLS Certificate Verification Enabled by Default (Critical)
SSL verification was globally disabled (`ssl_verify: False`) in the default config, exposing
all outbound HTTPS connections to man-in-the-middle attacks. This affected API key
transmission to Shodan, VirusTotal, and other external services, as well as all scan traffic.

**Root change:** `app/core/config.py` — defaults flipped to `ssl_verify: True` and
`suppress_ssl_warnings: False`.

**Propagation:** All scanners and tools now read the setting from config rather than
hardcoding `verify=False`. Users who need to scan targets with self-signed certificates
can disable verification in **Settings → Security** — the change applies globally.

**Files changed (20):**
- `app/core/config.py` — default `ssl_verify` flipped to `True`
- `app/core/connection_pool.py` — sessions now set `verify` from config
- `app/tools/http_fingerprint.py` — reads `ssl_verify` from config (was hardcoded `False`)
- `app/tools/http_scanner.py` — `self.ssl_verify` from config; 7 inline `verify=False` replaced
- `app/tools/api_scanner.py` — `self.ssl_verify` from config; 5 inline calls replaced
- `app/tools/api_enumerator.py` — `self.ssl_verify` from config; 4 inline calls replaced
- `app/tools/enterprise_fingerprint.py` — session `verify` from config
- `app/tools/api_matcher.py` — session `verify` from config
- `app/tools/av_firewall_scanner.py` — `self.ssl_verify` from config
- `app/tools/scan_plugins/ai_ssti_plugin.py` — `self.ssl_verify` from config (was hardcoded `False`)
- `app/tools/scan_plugins/security_plugin.py` — `self.ssl_verify` from config (was hardcoded `False`)
- `app/tools/scan_plugins/waf_plugin.py` — uses `self.ssl_verify`
- `app/tools/scan_plugins/xss_plugin.py` — uses `self.ssl_verify`
- `app/tools/scan_plugins/ssrf_plugin.py` — uses `self.ssl_verify`
- `app/tools/scan_plugins/idor_plugin.py` — uses `self.ssl_verify`
- `app/core/vuln_scanner.py` — `self.ssl_verify` from config; 6 inline calls replaced
- `app/core/advanced_vuln_scanner.py` — `self.ssl_verify` from config; 11 inline calls replaced
- `app/core/advanced_dir_enum.py` — `self.ssl_verify` from config; 2 inline calls replaced
- `app/core/web_crawler.py` — session `verify` from config
- `app/core/source_map_analyzer.py` — session `verify` from config
- `tools/web_exploits.py`, `tools/db_attacks.py`, `tools/api_enum.py`,
  `tools/api_enum_upgraded.py`, `tools/nse_vuln_scanner.py`,
  `tools/advanced_nse_scanner.py` — `_ssl_verify()` helper injected; all inline calls replaced

---

#### Fix: Command Injection via `shell=True` (Critical)
Replaced all `subprocess.run(..., shell=True)` and `subprocess.Popen(..., shell=True)` calls
that incorporated user-controlled input with safe argument-list invocations (`shell=False`).
Where a legacy string command must be accepted, `shlex.split()` is used to tokenise it before
passing the list to subprocess — preventing shell metacharacter injection.

**Files changed:**
- `app/tools/ssh_scanner.py` — `_test_key_auth`: SSH key-auth command now uses an argument list
- `app/core/ad_enumeration.py` — `enumerate_domain`: `net user/view/group` commands use argument lists; username/password no longer interpolated into a shell string
- `app/tools/av_firewall_scanner.py` — `_run_nmap_scan`: nmap args split via `shlex.split`, target passed as separate list element
- `app/tools/api_scanner.py` — `run_command`: accepts list or string; strings are split via `shlex.split` instead of `shell=True`
- `app/core/rpc_shell.py` — `_shell_loop`, `_execute_beacon_command`: network-received commands split via `shlex.split`
- `app/tools/evidence_collector.py` — `collect_command_output`: command split via `shlex.split`
- `app/core/aws_exploitation.py` — reverse shell payload: network-received commands split via `shlex.split`
- `app/tools/payload_builder.py` — all four stager templates (TCP, HTTP, DNS, SMB): generated stager code now uses `shlex.split` + `shell=False`
- `app/pages/exploitation/runecraft_wizard.py` — reverse shell and bind shell templates updated
- `app/pages/exploitation/runecraft_tab.py` — reverse shell template and encoded PowerShell template updated

---

## [2.1.0] - 2024-01-03

### Added - Advanced Reporting Engine
- **Comprehensive Report Generation**: Multi-format reporting (PDF, HTML, JSON)
- **Executive Summary Reports**: High-level risk assessment for management
- **Technical Detailed Reports**: In-depth technical analysis and findings
- **Compliance Assessment Reports**: Framework compliance checking (OWASP, NIST, ISO27001)
- **Vulnerability Assessment Reports**: Security-focused analysis with risk scoring
- **Risk Assessment Engine**: Automated risk scoring and categorization (Critical/High/Medium/Low/Info)
- **Recommendations Engine**: Actionable security recommendations based on findings
- **Attack Surface Analysis**: Comprehensive attack vector identification and assessment
- **Report Templates**: Customizable report templates for different use cases
- **Report History Management**: Track and manage generated reports with metadata
- **GUI Integration**: Seamless integration with enumeration tools via export dropdown
- **Pattern Detection**: Intelligent analysis of scan results with trend identification
- **Compliance Checking**: Automated framework alignment verification

### Enhanced
- **Export Options**: Added "Advanced Report" option to enumeration page export dropdown
- **Documentation**: Added comprehensive Advanced Reporting documentation
- **Test Coverage**: Added test script for Advanced Reporting functionality

### Technical Details
- **Core Engine**: `app/core/advanced_reporting.py` - Main reporting engine
- **GUI Widget**: `app/widgets/advanced_reporting_widget.py` - User interface
- **Documentation**: `docs/ADVANCED_REPORTING.md` - Complete feature documentation
- **Test Script**: `test_advanced_reporting.py` - Validation and demonstration

### Dependencies
- **Optional**: ReportLab 4.0+ for PDF generation
- **Core**: PyQt6 for GUI integration

### Usage
1. Run a scan to generate results
2. Select "Advanced Report" from Export dropdown
3. Choose report type (Executive, Technical, Compliance, Vulnerability)
4. Select output format (PDF, HTML, JSON)
5. Configure options and generate comprehensive reports

## Previous Versions

### [2.0.0] - 2024-01-01
- Complete enumeration suite with 8 tools
- Modern PyQt6 interface
- Multi-threaded operations
- Export capabilities (JSON, CSV, XML)
- Performance optimizations
- Professional reporting features
- Advanced integrations and analysis tools

### [1.0.0] - 2023-12-01
- Initial release
- Basic enumeration tools
- Core functionality implementation