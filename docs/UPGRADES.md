1) Payload Builder & Installer Generator — app/tools/payload_builder.py
Purpose: produce stagers/agents and service installers that embed metadata (engagement id, expiry, allowed C2s), signable artifacts, and installer templates (MSI/MSIX wrapper).
Key features:
- Multi-transport stagers (reverse-TCP, HTTP/S, DNS, SMB, FTP) built from templates.
- Metadata embedding: engagement_id, scope JSON, expiry timestamp, fingerprint.
- Auto-service wrapper generator (native C# service or NSSM wrapper for lab builds).
- Signing pipeline hooks (CI integration to sign Pro/Enterprise builds).
- Safe defaults: lab-mode unsigned builders with ephemeral expiry; Pro builders signed.

Why: centralizes payload generation and enforces audit metadata for every artifact.
API surface (example):
- build_stager(transport, options) -> PathToArtifact
- generate_service_installer(artifact_path, service_name, options) -> PathToMSI
- embed_metadata(artifact, metadata) -> artifact

2) Listener Manager & Transport Plugin System — app/core/listener_manager.py (expand)
Purpose: single place to manage listeners, sessions, transports, auto-expiry, kill-switch, and audit logs.
Key features:
- Plugin interface for transports: start_listener(cfg), stop_listener(id), generate_payload(cfg), list_sessions().
- Session store: session metadata + encrypted data channel pointers.
- Scoped listeners: IP/range restrictions, app-scoped firewall rule IDs, port affinity.
- Auto-expiry / TTL enforcement and remote kill endpoint.
- UI hooks to show active listeners, sessions, logs and to kill/expire.
Why: makes adding new transports trivial and centralizes lifecycle + audit.

Example plugin types to ship first:
- reverse_tcp_plugin.py
- http_beacon_plugin.py (supports TLS, cert management)
- dns_oob_plugin.py (coarse, slow; for constrained lab scenarios)
- smb_listener_plugin.py (lab-mode only; simulation/relay aware)

3) Windows Agent (native service) + Agent API — app/agent/* (native component + Python client)
Purpose: a small signed native service that runs agent tasks (listener bootstrap, evidence capture, firewall & Defender changes when allowed).
Key features:
- Native service launcher (C# recommended) that starts the Python agent worker.
- RPC/control channels: local named pipe + secure REST on localhost (cert pinned) for UI to instruct agent.
- Defender & Firewall API wrapper methods (calls Set-MpPreference/Get-MpPreference and New-NetFirewallRule)—only after attestation and with full audit trail.
- Evidence endpoints: collect Event Logs, process lists, screenshots, selective PCAP (if allowed) and upload encrypted to central DB.
- Self-clean: revert firewall/exclusions on expiry/uninstall.

Security & safety:
- Agent only runs privileged tasks after a signed attestation file and local UAC elevation.
- Audit log entries for every system modification.
- Opt-out phone-home by default; enterprise can enable server upload.

4) Active Directory Enumerator + Attack Graph Engine — app/tools/ad_enum.py + app/core/graph_engine.py
Purpose: replace BloodHound-style dependency while staying license-clean — collect AD objects and produce attack-path visualizations and “shortest path to DA”.
Key features:

- Safe enumerations (LDAP/AD RPC) that gather: computers, users, groups, sessions, local-admin, ACLs, trusts.
- Graph datastore: use sqlite tables for nodes/edges and networkx (or in-house graph) for analysis.
- Attack path algorithms: shortest path weighted by risk, privilege escalation suggestions (non-exploit).
- Simulator mode: simulate chaining in sandbox VMs with printable playbooks (step-by-step safe actions for HTB/THM training).

Why: key differentiation and huge value for both newbies and pros.

5) Kerberos & Credential Assessment Tools — app/tools/kerberos_tools.py
Purpose: non-destructive Kerberos enumeration and risk assessment:

- Enumerate SPNs for Kerberoast detection (list SPNs and risk scores).
- AS-REP enumeration detection (highlight accounts with preauth disabled).
- Ticket parsing features (from provided pcap/ticket file) for evidence and report.

6) Post-Exploitation Evidence & Forensics Collector — app/tools/evidence_collector.py
Purpose: standardized POC capture modules:

- Process snapshot (basic), command output capture, Event Log slices, PowerShell transcript, screenshots, selective PCAP (or mitmproxy capture), file exfil simulation (lab).
- Attachments are encrypted and stored with finding references; include hashes for chain-of-custody.

7) Vulnerability Correlator + Attack-Chain Synthesizer — app/core/vulnerability_correlator.py (enhance)
Purpose: correlate findings across protocols (RPC, SMB, HTTP) and produce attack-chains automatically:

- Fuse results by host/user/asset.
- Generate prioritized “attack chains” that show A -> B -> C to escalate to high-value target.
- For HTB/THM, produce step-by-step playbooks to practice the chain in lab.

8) C2 / Beacon Orchestrator (in-app, optional Pro) — app/tools/c2_orchestrator.py
Purpose: lightweight, auditable beacon scheduler for lab/probe use:

- Beacon jitter, scheduled callbacks, modular transport stack (use listener manager plugins).
- Strict scoping: only allowed IP ranges, attestation required, auto-expiry.
- Session management and POC replay/export.

Medium / Nice-to-have tools
API-based Shodan/VT integrations with caching (app/core/api_integration.py) — already present; enhance with rate-limited caching and correlation to local findings.

Graphical visualizer component for PyQt using d3/webview to display attack graphs.

Plugin sandboxing via subprocesses/containers to prevent plugin crashes from harming main app.

Unit/integration test harness for labs (VM snapshots + Ansible/Packer automation).

Repo mapping & integration suggestions
Keep all new tools under app/tools/ and agent/native components under app/agent/ or app/native/.

Extend app/core/plugin_manager.py to enforce plugin interfaces and versioning.

Use scan_database.db schema extensions: listeners, sessions, payloads, evidence, attestations tables.