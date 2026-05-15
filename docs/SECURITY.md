# Security Policy

## Reporting a Vulnerability

If you discover a security issue in Huginn, please open a private issue or contact the
maintainers directly. Do not disclose vulnerabilities publicly until a fix has been released.

---

## Secure Coding Standards

The following rules apply to all contributions. PRs that violate them will not be merged.

### 1. No `shell=True` with External Input

Never pass user-supplied or network-received data to `subprocess` with `shell=True`.
This allows shell metacharacter injection (e.g. `; rm -rf /`).

**Wrong:**
```python
subprocess.run(f"ssh {username}@{target}", shell=True)
subprocess.run(user_command, shell=True)
```

**Correct:**
```python
# Use an argument list — shell metacharacters are never interpreted
subprocess.run(["ssh", f"{username}@{target}"])

# If you must accept a string, split it safely first
import shlex
subprocess.run(shlex.split(user_command), shell=False)
```

The only acceptable use of `shell=True` is for fully-trusted, hardcoded shell pipelines
with no user input. Even then, prefer argument lists.

### 2. Parameterised SQL Queries

Never interpolate values or identifiers directly into SQL strings.

**Wrong:**
```python
cursor.execute(f"SELECT * FROM {table_name}")
cursor.execute(f"PRAGMA table_info({name})")
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

**Correct:**
```python
# For VALUES — always use bound ? parameters
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

# For IDENTIFIERS (table/column names) — use _quote_identifier() then
# concatenate (never f-string), so the pattern is obvious to reviewers
from app.core.database_utils import _quote_identifier
quoted = _quote_identifier(table_name)          # raises ValueError if invalid
cursor.execute("SELECT COUNT(*) FROM " + quoted)
cursor.execute("PRAGMA table_info(" + quoted + ")")

# For IN-clause placeholders — build the placeholder string from length only
placeholders = ','.join('?' * len(values))
cursor.execute("SELECT * FROM t WHERE col IN (" + placeholders + ")", values)
```

### 3. SSL/TLS Verification

SSL verification must be **enabled by default**. Disabling it requires an explicit
user action with a visible warning in the UI.

**Wrong:**
```python
requests.get(url, verify=False)
session.verify = False
```

**Correct:**
```python
requests.get(url, verify=True)   # default — always verify
# Only disable when the user has explicitly opted in:
requests.get(url, verify=config.get("ssl_verify", True))
```

### 4. Credential Storage

Credentials must never be written to disk in plaintext. Use `SecureCredentialManager`
(which uses Fernet symmetric encryption) for all credential persistence.

**Wrong:**
```python
with open("credentials.json", "w") as f:
    json.dump({"password": plaintext_password}, f)
```

**Correct:**
```python
from app.core.secure_credential_manager import secure_credential_manager
secure_credential_manager.store_credential(service, username, password)
```

### 5. HTML Output Escaping

All user-supplied or scan-result data embedded in HTML output signals must be escaped.

**Wrong:**
```python
self.signals.output.emit(f"<p>{user_input}</p>")
```

**Correct:**
```python
import html
self.signals.output.emit(f"<p>{html.escape(user_input)}</p>")
```

### 6. Exception Handling

Never use bare `except:` or `except Exception: pass`. Always log the exception and
handle it specifically.

**Wrong:**
```python
try:
    do_something()
except:
    pass
```

**Correct:**
```python
from app.core.logger import logger
try:
    do_something()
except SomeSpecificError as e:
    logger.warning(f"Expected failure in do_something: {e}")
except Exception as e:
    logger.error(f"Unexpected error in do_something: {e}", exc_info=True)
    raise
```

---

## Known Issues Being Remediated

The following issues were identified in a security review and are being fixed
incrementally. Each item links to the relevant CHANGELOG entry when resolved.

| # | Issue | Severity | Status |
|---|-------|----------|--------|
| 1 | `shell=True` with user input in subprocess calls | Critical | ✅ Fixed (see CHANGELOG [Unreleased]) |
| 2 | SSL verification disabled globally by default | Critical | ✅ Fixed (see CHANGELOG [Unreleased]) |
| 3 | Credentials stored in plaintext JSON | Critical | ✅ Fixed (see CHANGELOG [Unreleased]) |
| 4 | SQL injection via f-string table names | Critical | ✅ Fixed (see CHANGELOG [Unreleased]) |
| 5 | Weak attestation in `windows_agent.py` | High | ✅ Fixed (see CHANGELOG [Unreleased]) |
| 6 | Unescaped HTML in output signals | Medium | ✅ Fixed (see CHANGELOG [Unreleased]) |
| 7 | Bare `except: pass` throughout codebase | High | ✅ Fixed (see CHANGELOG [Unreleased]) |
| 8 | `autonomous_agent.py` returns random fake results | High | ✅ Fixed (see CHANGELOG [Unreleased]) |

---

## Dependency Security

- Pin all dependencies to exact versions in `requirements.txt`
- Run `pip audit` (or `safety check`) before each release
- Do not add dependencies with known CVEs
