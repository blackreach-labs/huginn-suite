# VIDEO 3: Navigating the UI
### Efficient Navigation, Sessions & Operational Configuration
**Suggested length:** 12–15 minutes
**License Tier:** Free
**Certification Relevance:** OSCP, CEH, PNPT — full methodology coverage

---

## INTRO (0:00 – 1:00)

**[Screen: Huginn splash screen with Section 1 title card "Getting Started"]**

> "Welcome back. In this video we'll get oriented in Huginn's interface — focused on efficient navigation for operators who want to move fast. You'll learn the fastest paths to every tool across 270-plus modules, how session management handles multi-engagement tracking, and which settings matter for professional operations. Launch Huginn and follow along (see Video 2: Installation & Setup)."

**[Screen: Huginn main window — full application visible with all UI regions]**

> "Huginn's interface is built around three core regions: the navigation sidebar, the attack chain toolbar, and the central content area. Let's cover each one and how to work through them efficiently during an active engagement."

---

## SECTION 1: Interface Layout (1:00 – 2:45)

**[Screen: Huginn main window with overlay annotations highlighting three regions — sidebar (left), toolbar (top), content area (center)]**

> "Three regions. The navigation sidebar on the left lists Huginn's main pages — Home, Recon and Enumeration, Scanner, Web Exploits, OS Exploits, Post-Exploitation, and Findings. The attack chain toolbar across the top provides methodology-driven navigation through the six engagement phases. The central content area fills the majority of the screen and renders whichever module you've selected."

**[Screen: Sidebar highlighted — showing page list with icons]**

> "The sidebar is your primary navigation. Click a page to load it in the content area. Pages are organized by engagement function — enumeration tools live under Recon, exploitation tools under Web Exploits and OS Exploits, reporting under Findings. The sidebar stays visible at all times for one-click access to any section of the framework."

**[Screen: Content area highlighted — showing consistent module layout with config panel, action buttons, results]**

> "Every module follows a consistent layout pattern — configuration options at the top, action buttons in the center, results at the bottom. Learn one module's layout and you've learned them all. This consistency matters when you're moving quickly between tools mid-engagement."

**[Screen: Window title bar showing session name, active target, current phase, and license tier badge]**

> "The title bar provides operational context at a glance — current session name, active target, which attack chain phase you're working in, and your license tier. This context persists everywhere in the application so you always know which engagement you're operating in."

---

## SECTION 2: Attack Chain Toolbar (2:45 – 5:00)

**[Screen: Attack chain toolbar zoomed in — six phase buttons: Setup, Recon, Scan, Exploit, Elevate, Report]**

> "The attack chain toolbar is Huginn's signature navigation element and its methodology enforcement mechanism. Six buttons — Setup, Recon, Scan, Exploit, Elevate, Report — each representing one phase of a professional engagement. Clicking a phase filters the sidebar and content area to show only tools relevant to that phase."

**[Screen: Clicking "Recon" phase — sidebar updates to show only recon-related pages, content shows recon overview with module quick-launch]**

> "Click Recon and the sidebar narrows to enumeration modules — DNS, Port Scanning, Network Discovery, OSINT. The content area shows a phase overview with quick-launch buttons for every module in that phase. Phase-based filtering eliminates visual noise when you're focused on a specific engagement stage."

**[Screen: Clicking "Exploit" phase — sidebar shows Web Exploits, OS Exploits, Database Attacks]**

> "Click Exploit and you see Web Exploits, OS Exploits, and Database Attacks. Each phase has its own tool set. Click any phase button to return to its overview — useful for seeing all available capabilities at a glance when planning your next move on a complex target."

**[Screen: Phase progress indicators — coverage checkmarks and active phase highlighting]**

> "Progress indicators on each phase button serve as coverage assurance. As you work through a session, completed phases show checkmarks. This visual tracking ensures thorough enumeration before moving to exploitation — methodology discipline that matters on complex engagements with large scope. It's not gating you from moving forward — it's tracking what you've covered and what you haven't."

**[Screen: Toolbar context menu — right-click showing "Jump to phase", "Reset phase", "View phase summary"]**

> "Right-click any phase for additional options. 'Jump to phase' bypasses linear progression for experienced operators who know exactly where they need to be. 'Reset phase' clears phase data for the current session if you need to re-run enumeration with different parameters. 'View phase summary' shows a digest of everything collected during that phase — useful for mid-engagement status reviews and handoff documentation."

---

## SECTION 3: Session Management (5:00 – 7:30)

**[Screen: Session panel — accessible from sidebar, showing current session details with engagement metadata]**

> "Sessions are how Huginn tracks engagement state. Every action — every scan, every finding, every configuration change — is bound to a session. If you're managing multiple concurrent client engagements, sessions keep them completely isolated. Switch between engagements instantly with full state preserved."

**[Screen: New Session dialog — fields for session name, target scope, engagement type, and notes]**

> "Create a new session with Ctrl+N or the session icon in the sidebar. Name it with your engagement identifier — client name, scope reference, internal tracking number. Add target scope details and any engagement notes. For lab work, name it after the machine or room you're targeting."

```
Session Name: ClientA-External-2024Q4
Description: External penetration test — client public IP range
Target: 203.0.113.0/24
Notes: Scope: external perimeter only. Rules of engagement signed 2024-10-15.
```

**[Screen: Session list panel — showing multiple engagement sessions with timestamps and phase progress]**

> "The session list shows all your engagements sorted by last activity. Each entry displays the session name, creation date, last modified timestamp, and phase progress indicators. Solo consultants typically manage three to five concurrent engagements — switching between them is a single click with no state loss."

**[Screen: Switching sessions — clicking a different session, UI updates with that engagement's data]**

> "When you switch sessions, the entire application context updates. Target information, discovered hosts, scan results, findings, reporting progress — everything reflects the selected engagement. Work an internal assessment in the morning, switch to an external test in the afternoon, pick up either one tomorrow exactly where you left off."

**[Screen: Session actions menu — Export, Archive, Duplicate, Delete options]**

> "Right-click a session for management actions. Export produces a portable session file for backup or handoff to another team member. Archive moves completed engagements out of your active list without deleting data. Duplicate creates a copy — useful for retesting a client's environment against a new scope window without overwriting the original assessment."

---

## SECTION 4: Module Search and Rapid Access (7:30 – 9:30)

**[Screen: Recon & Enumeration page — showing the module grid with all enumeration tools]**

> "With 270-plus modules across six phases, efficient tool access is critical during active engagements. Three navigation paths: phase-based browsing through the toolbar, hierarchical navigation through the sidebar, and — the fastest option — the command palette."

**[Screen: Search bar activated — Ctrl+K shortcut shown, search popup appears with fuzzy matching]**

> "Ctrl+K opens the command palette. Type any module name — DNS, SQLi, Bloodhound, SSTI — and fuzzy matching finds it instantly. Press Enter to navigate directly to that module. This is the fastest way to reach any tool in Huginn. Learn this shortcut and you'll rarely touch the sidebar for navigation."

**[Screen: Search bar showing results for "relay" — RPC Relay, NTLM Relay, Relay Attack Chains all appear with phase indicators]**

> "The search is context-aware. Typing 'relay' surfaces RPC Relay under Network Exploits and Relay Attack Chains under Post-Exploitation. Each result shows the module name, its parent page, and which attack chain phase it belongs to. Search by technique — 'brute' shows SSH Brute-Force, DNS Brute-Force, and Directory Brute-Force across different phases."

**[Screen: Module page layout — configuration panel, action buttons, results panel with tabs]**

> "When you land on a module, layout is consistent. Configuration options at the top — target, parameters, wordlists, scan profiles. Action buttons in the center — Start, Stop, Pause, Export. Results at the bottom with tabs for table view, raw output, tree view, or graph visualization depending on the data type. Consistent across all 270 modules."

**[Screen: Favorites panel — starred modules pinned at the top of sidebar]**

> "Star your most-used modules for sidebar pinning. Click the star icon on any module and it appears in your Favorites section at the top of the sidebar. During engagements, I keep DNS Enumeration, Port Scanning, the HTTP Interceptor, and Findings pinned — adjust yours based on your typical engagement profile."

---

## SECTION 5: Guided Workflow vs Manual Mode (9:30 – 11:30)

**[Screen: Home page — two prominent buttons: "Guided Workflow" and "Manual Mode"]**

> "Huginn offers two operating modes. Manual Mode gives you unrestricted access to every tool — navigate where you want, run what you want, in any order. Guided Workflow provides structured methodology coverage assurance. Both modes use the same underlying modules with the same capabilities. The difference is operational guidance."

**[Screen: Guided Workflow page — showing methodology questionnaire tracking engagement progress]**

> "Guided Workflow tracks your engagement progress against the full attack chain methodology. It identifies what you've completed, flags coverage gaps, and recommends next steps based on what you've discovered so far. Did you enumerate SMB but skip SNMP on a host with port 161 open? Guided Workflow flags that gap."

**[Screen: Guided Workflow — showing coverage gap analysis: "DNS enumerated, Port scan complete, SMB skipped — recommend SMB enumeration based on port 445 detected"]**

> "On complex engagements with dozens of hosts and hundreds of services, methodology gaps happen under time pressure. Guided Workflow prevents those gaps from reaching your final report. It's the equivalent of a methodology checklist — automated and aware of your actual findings."

**[Screen: Manual Mode — full sidebar with all modules accessible, no guided prompts]**

> "Most experienced operators use Manual Mode for routine work and switch to Guided Workflow on large-scope engagements or assessments with strict methodology requirements. If you're new to penetration testing, Guided Workflow is an excellent way to learn professional methodology — it teaches you the right sequence and ensures you don't skip critical steps while you're still building your process."

**[Screen: Switching between modes — toggle in settings and home page]**

> "Switch between modes at any time. There's no commitment to one or the other — use Guided for the initial enumeration sweep to ensure coverage, then switch to Manual for targeted exploitation where you want full control over sequencing."

---

## SECTION 6: Operational Settings (11:30 – 13:15)

**[Screen: Settings page — accessed via gear icon, showing categories: General, Network, Scanning, Display, License]**

> "Key settings relevant to professional operations. Open Settings via the gear icon at the bottom of the sidebar."

**[Screen: General settings — workspace directory, auto-save interval, default session behavior]**

> "Under General — workspace directory controls where engagement data lives. Auto-save interval defaults to five minutes. Default launch behavior lets you resume the last session automatically or show the session picker on startup."

**[Screen: Network settings — proxy configuration, interface selection, timeout values, DNS resolver]**

> "Network settings control traffic routing. Proxy configuration for engagements requiring specific routing paths. Interface selection — which we configured in the previous video — determines the adapter Huginn binds to. Timeout values control responsiveness thresholds for scanning and enumeration. Custom DNS resolver if you need to use a specific nameserver for the engagement."

**[Screen: Scanning settings — default scan profiles, thread counts, rate limiting, stealth defaults]**

> "Scanning settings define defaults for the vulnerability scanner. Default profile, maximum thread count, rate limiting for bandwidth-constrained environments, and — on Professional tier — default stealth parameters. Configure these once for your standard engagement profile and override per-session only when needed."

**[Screen: Display settings — dark/light theme, terminal font size, result formatting]**

> "Display settings — dark and light themes, terminal font sizes, result formatting preferences. Functional choices. Set once and move on."

**[Screen: Reporting settings — default templates, company branding, output format preferences]**

> "Under Reporting — configure default report templates, company branding for client deliverables, and preferred output formats. This eliminates repetitive configuration at the start of every new engagement."

---

## OUTRO (13:15 – end)

**[Screen: End card with "Next: Video 4 — Licensing & Tiers" and UI in background]**

> "You're now oriented in Huginn's interface. Sidebar for page navigation, attack chain toolbar for methodology-driven workflow, Ctrl+K for rapid module access, sessions for multi-engagement isolation, and Guided Workflow for coverage assurance on complex scope. In the next video, we'll cover the three license tiers — what capabilities each unlocks and which tier matches your operational profile. See you in Video 4."
