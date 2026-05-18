# YouTube Playlist — Section 1: Getting Started
## Complete Video Scripts & Content Guide

---

# VIDEO 1: What is Huginn?
### Platform Overview, Use Cases & Who It's For
**Suggested length:** 8–12 minutes

---

## INTRO (0:00 – 1:00)

**[Screen: Huginn running, showing the Attack Chain home screen]**

> "Hey everyone, welcome to the Huginn tutorial series. In this first video I'm going to give you a high-level overview of what Huginn actually is, what it's designed to do, and whether it's the right tool for you. If you're already sold and just want to get it installed, feel free to skip ahead to Video 2 — but I'd recommend watching this one first so you understand the philosophy behind the tool before you start using it."

---

## SECTION 1: What is Huginn? (1:00 – 3:00)

**[Screen: Show the main Attack Chain mindmap on the home screen]**

> "Huginn is a professional-grade penetration testing platform built in Python to run on Windows. It's a desktop application — not a web app, not a CLI-only tool — it has a full graphical interface designed to guide you through the entire penetration testing lifecycle from start to finish."

> "The core idea behind Huginn is that a penetration test follows a structured methodology. You start with reconnaissance, move into vulnerability scanning, then exploitation, post-exploitation, and finally reporting. Huginn organises all of its tools around that workflow, so instead of jumping between a dozen different terminal windows and tools, everything lives in one place."

**[Point to the Attack Chain mindmap on screen]**

> "You can see that right here on the home screen — this is the Attack Chain mindmap. It shows you the six phases of a penetration test: Setup, Recon, Vulnerability Scanning, Exploitation, Post-Exploitation, and Reporting. You can click any of these phases to jump directly to the relevant tools. We'll cover this in detail in Video 3."

---

## SECTION 2: Who Is It For? (3:00 – 5:00)

**[Screen: Stay on home page]**

> "So who is Huginn actually for? There are a few different audiences."

> "First — **penetration testers and red teamers**. If you're doing professional security assessments, Huginn gives you a full suite of enumeration and exploitation tools in a single organised interface. It's designed to speed up your workflow and keep your findings organised by project."

> "Second — **security students and learners**. Huginn has a Guided Mode that walks you through a penetration testing methodology step by step. If you're studying for OSCP, CEH, or just learning ethical hacking, this is a great way to understand the process while having real tools at your fingertips."

> "Third — **security teams and consultants** who need professional reporting. Huginn can generate executive summaries, technical reports, and compliance-mapped reports for frameworks like NIST, ISO 27001, and PCI-DSS."

> "One important note — Huginn is a penetration testing tool. You should only ever use it against systems you own or have explicit written permission to test. Unauthorised use is illegal. We'll be using lab environments and intentionally vulnerable machines throughout this series."

---

## SECTION 3: Core Capabilities (5:00 – 8:00)

**[Screen: Briefly navigate to Recon/Enumeration page to show the tool list]**

> "Let me give you a quick tour of what Huginn can actually do."

> "The core of the platform is a **12-tool enumeration suite**. This covers DNS enumeration, port scanning, SMB, SMTP, SNMP, HTTP fingerprinting, API enumeration, LDAP, database enumeration, IKE/VPN assessment, RPC, and AV/firewall detection. Each of these gets its own dedicated video later in the series."

**[Navigate back to home]**

> "On top of that, there's a **vulnerability scanner** with scan profiles ranging from a quick light scan all the way up to an aggressive insane mode that includes machine learning-based pattern detection."

> "There's an **OSINT framework** for gathering intelligence from public sources, an **HTTP interceptor and proxy** for traffic analysis, and a full **post-exploitation framework** for managing sessions after you've gained access."

> "For reporting, Huginn can produce HTML reports, JSON exports, executive summaries, and compliance-mapped outputs."

> "And then there are the **Professional and Enterprise features** — things like Stealth Mode for evasion, ProxyChains and Tor integration, Active Directory enumeration, advanced analytics, and AWS infrastructure deployment for spinning up proxy servers. We'll cover all of that in later sections."

---

## OUTRO (8:00 – end)

> "That's the overview. In the next video we're going to get Huginn installed and running on your machine. After that we'll do a full UI tour so you know exactly where everything lives before we start diving into the individual tools."

> "If you have any questions drop them in the comments. Let's get into it."

---
---

# VIDEO 2: Installation & Setup
### Getting Huginn Running on Your Machine
**Suggested length:** 10–15 minutes

---

## INTRO (0:00 – 0:45)

**[Screen: Terminal / file explorer]**

> "Welcome back. In this video we're going to get Huginn installed and running. I'll walk through the full process from cloning the repository to launching the application for the first time. This should take about 10 minutes."

> "You'll need Python 3.10 or higher installed on your system. I'll be demonstrating on Windows, but the process is essentially the same on Linux and macOS."

---

## SECTION 1: Prerequisites (0:45 – 2:30)

**[Screen: Show Python version check in terminal]**

> "Before we start, let's confirm you have the right Python version. Open a terminal and run:"

```bash
python --version
```

> "You want to see Python 3.10 or higher. If you're on an older version, head to python.org and grab the latest release."
https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe

> "You'll also want Git installed. Check that with:"

```bash
git --version
```

> "If you don't have Git, grab it from git-scm.com. On Linux you can install it with your package manager — `sudo apt install git` on Debian/Ubuntu."
https://github.com/git-for-windows/git/releases/download/v2.54.0.windows.1/Git-2.54.0-64-bit.exe

> "The third prerequisite is **Npcap**. This is a Windows packet capture library that Huginn relies on for low-level network operations — things like Layer 2 discovery, ARP scanning, MAC address lookups, and any feature that needs to send or capture raw packets directly on the wire. Without it, those features will either fail silently or throw errors at runtime."

> "Download the installer from the link below and run it. The default installation options are fine — just click through and finish. You don't need to enable WinPcap compatibility mode unless another tool on your system specifically requires it."
https://npcap.com/dist/npcap-1.88.exe

> "Once Npcap is installed you don't need to do anything else — Huginn picks it up automatically through the Scapy library."

> "I'd also strongly recommend using a virtual environment to keep Huginn's dependencies isolated from your system Python. We'll set that up in a moment."

---

## SECTION 2: Cloning the Repository (2:30 – 4:00)

**[Screen: Terminal]**

> "Navigate to wherever you want to keep the project. I'm going to put mine in a `tools` folder in my home directory."

```bash
mkdir ~\tools
cd ~\tools
git clone https://github.com/whiteborr/huginn-suite.git
cd huginn-suite
```

> "Once that's done you should have the full project directory. Let's take a quick look at the structure."

**[Screen: Show the directory listing]**

> "The main application code lives in the `app/` folder. The `resources/` folder contains config files, wordlists, and assets. The `docs/` folder has all the documentation we'll be referencing throughout this series. And at the root level you'll find `requirements.txt` and the main entry point."

---

## SECTION 3: Setting Up a Virtual Environment (4:00 – 6:00)

**[Screen: Terminal]**

> "Let's create a virtual environment. This keeps all of Huginn's Python packages separate from your system."

```bash
python -m venv venv
```

> "Now activate it. On Windows:"

```bash
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
venv\Scripts\activate
```

> "On Linux or macOS:"

```bash
source venv/bin/activate
```

> "You should see `(venv)` appear at the start of your terminal prompt. That tells you the virtual environment is active."

---

## SECTION 4: Installing Dependencies (6:00 – 9:00)

**[Screen: Terminal, running pip install]**

> "Now let's install the dependencies."

```bash
pip install -r requirements.txt
```

> "This will take a minute or two depending on your connection. The main dependencies are PyQt6 for the GUI, and a collection of networking and security libraries."

> "Alternatively, if you want to install Huginn as a proper Python package so you can run it from anywhere:"

```bash
pip install -e .
```

> "The `-e` flag installs it in editable mode, which means changes to the source code take effect immediately without reinstalling."

**[Wait for install to complete on screen]**

> "Once that's done, let's verify everything installed correctly."

```bash
pip show PyQt6
```

> "You should see PyQt6 and its related packages listed."

---

## SECTION 5: First Launch (9:00 – 12:00)

**[Screen: Terminal]**

> "Now let's launch Huginn for the first time."

```bash
python main.py
```

> "Or if you installed it as a package:"

```bash
python -m huginn
```

**[Screen: Huginn launches, Mode Selection dialog appears]**

> "The first thing you'll see is the Mode Selection dialog. This asks whether you want to start in **Guided Mode** or **Advanced Mode**."

> "**Guided Mode** walks you through a structured penetration testing methodology step by step — great if you're learning or want a checklist-driven workflow."

> "**Advanced Mode** takes you straight to the full interface with the Attack Chain home screen and access to all tools immediately."

> "For this tutorial series we're going to use Advanced Mode so we can explore everything freely. Click Advanced Mode."

**[Screen: Main window opens in fullscreen]**

> "And there it is — Huginn is running. It opens in fullscreen by default. You can go to View → Navigation Style to switch between Advanced and Guided modes."

> "You'll notice the Attack Chain mindmap at the top of the screen and the main content area below it. We'll cover all of this in the next video."

---

## SECTION 6: Troubleshooting Common Issues (12:00 – 14:00)

**[Screen: Slide or text overlay]**

> "A few common issues people run into:"

> "**PyQt6 not found** — Make sure your virtual environment is activated before running pip install. If you see import errors on launch, try `pip install PyQt6` directly."

> "**Font loading warning** — You might see a warning about `neuropol.otf` not being found. This is cosmetic — the app will fall back to a system font and everything will work fine."

> "**Permission errors on Linux** — Some network scanning features require elevated privileges. You may need to run a termina or command prompt as Administrator to launch "python main.py"

> "**Missing resources directory** — If you see errors about missing config files, make sure you cloned the full repository and didn't just download a zip of the source."

---

## OUTRO (14:00 – end)

> "That's the installation done. In the next video we're going to do a full tour of the interface so you know exactly where everything is before we start using the tools. See you there."

---
---

# VIDEO 3: Navigating the UI
### Tour of the Interface, Sessions & Main Modules
**Suggested length:** 12–18 minutes

---

## INTRO (0:00 – 0:45)

**[Screen: Huginn open in Advanced Mode, Attack Chain home screen]**

> "Welcome back. Now that Huginn is installed, let's do a proper tour of the interface. By the end of this video you'll know exactly where everything lives and how to navigate between the different sections. This is the foundation for everything else in the series."

---

## SECTION 1: The Mode Selection Dialog (0:45 – 2:00)

**[Screen: Close and relaunch Huginn to show the dialog again]**

> "Every time you launch Huginn, you'll see this Mode Selection dialog. Let's talk about what each option actually means."

> "**Guided Mode** launches a step-by-step questionnaire that walks you through a penetration testing engagement. It asks about your target, scope, and objectives, then guides you through each phase in order. This is great for structured engagements or if you're still building your methodology."

> "**Advanced Mode** skips the questionnaire and takes you straight to the full interface. This is what we'll be using throughout this series."

> "you can always switch between modes from the menu under View → Navigation Style."

---

## SECTION 2: The Attack Chain Mindmap (2:00 – 5:00)

**[Screen: Focus on the mindmap at the top of the screen]**

> "The first thing you'll notice in Advanced Mode is this Attack Chain mindmap running across the top of the screen. This is the primary navigation element in Huginn."

> "It shows the six phases of a penetration test as clickable nodes:"

> "**SETUP** — This is where you configure your engagement. Target profiles, credentials, scope."

> "**RECON** — Reconnaissance and enumeration. All 12 of the enumeration tools live here — DNS, port scanning, SMB, HTTP fingerprinting, and so on."

> "**SCAN** — Vulnerability scanning. This is where you run the Huginn scanner against your targets."

> "**EXPLOIT** — Web exploits, OS exploits, database attacks. The offensive tooling."

> "**ELEVATE** — Post-exploitation & Privileged escallation. Session management, lateral movement, persistence, credential harvesting."

> "**REPORT** — Findings management and report generation."

**[Click each node to demonstrate navigation]**

> "Click any node and the main content area below switches to that section. It's designed to mirror the natural flow of an engagement — you work left to right through the phases."

---

## SECTION 3: The Menu Bar (5:00 – 9:00)

**[Screen: Click through each menu]**

> "Let's go through the menu bar. There are five menus: File, Navigate, Tools, View, and Help. The menus have been organised so that each one has a clear purpose — file operations, page navigation, utility tools, visual preferences, and help."

### File Menu

**[Open File menu]**

> "The **File menu** is focused purely on file operations."

> "**Profiles** — This is a submenu where you manage engagement profiles. You can create a new profile with `Ctrl+N`, load an existing one with `Ctrl+O`, or delete profiles you no longer need. Profiles store your target information and settings for each engagement."

> "**Export Results** — Shortcut `Ctrl+E`. Exports the results from whatever page you're currently on."

> "**Exit** — `Ctrl+Q`."

### Navigate Menu

**[Open Navigate menu]**

> "The **Navigate menu** is where all page navigation lives. This mirrors the Attack Chain mindmap phases."

> "At the top you have the six phases: **Engagement Setup**, **Recon & Enumeration**, **Vulnerability Analysis**, **Exploitation**, **Post-Exploitation**, and **Reporting**. Clicking any of these takes you directly to that section — same as clicking the mindmap nodes."

> "Below the separator you'll find standalone pages:"

> "**Inventory** — `Ctrl+Shift+I`. Shows all discovered assets across your scans."

> "**VPN Connection** — Manage VPN connections for your engagements."

> "**Running Scans** — `Ctrl+Shift+R`. Opens a dedicated page showing all currently active scans, their progress, and the ability to cancel them."

> "**Sessions** — `Ctrl+Shift+S`. Opens the Session Management and information panel. This is how you organise your work into projects. We'll cover this in detail shortly."

### Tools Menu

**[Open Tools menu]**

> "The **Tools menu** contains configuration and utility tools — things you use to set up and manage your environment."

> "**Stealth Mode** — Configure stealth and evasion settings. Four evasion levels from Normal through to Paranoid."

> "Below the separator:"

> "**Databases** — `Ctrl+D`. Opens the database management page where you can query and manage the SQLite scan history database directly."

> "**Global Settings** — `Ctrl+,`. This is where you configure API keys for integrations like Shodan and VirusTotal, and set global application preferences."

> "**License Manager** — This is where you activate a Professional or Enterprise license, or generate a trial. We'll cover this in the next video."

### View Menu

**[Open View menu]**

> "The **View menu** is now focused purely on visual and UI preferences."

> "**Navigation Style** — A submenu to switch between Advanced Mode and Guided Mode without restarting."

> "**Themes** — `Ctrl+T` opens the theme selector. There are free themes — Dark, Light, Ocean Blue — and Professional/Enterprise themes like Matrix and Cyberpunk that unlock with a license. You can also pick individual themes directly from the submenu."

> "**Minimize to Tray** — `Ctrl+M`. Minimizes the application to the system tray."

> "**Clear Output** — `Ctrl+L`. Clears the terminal output on the current page."

### Help Menu

**[Open Help menu]**

> "**Help** is straightforward — F1 opens the tool help panel, and About shows version information."

---

## SECTION 4: The Main Content Area (9:00 – 12:00)

**[Screen: Navigate through a few pages]**

> "Below the mindmap is the main content area. This is where each tool's interface loads when you navigate to it."

> "Let me click through a few pages so you can see the general layout."

**[Click RECON in mindmap]**

> "The Recon/Enumeration page shows all the enumeration tools as a tabbed or card-based interface. Each tool has its own controls, target input, and output area. We'll spend a lot of time here in Section 2 of the series."

**[Click VULN in mindmap]**

> "The Vulnerability Scanning page is where you configure and run the Huginn scanner. You set your target, choose a scan profile, and kick it off."

**[Click EXPLOIT in mindmap]**

> "The Web Exploits page gives you access to the offensive web testing tools."

**[Navigate back to home via SETUP]**

> "You can always get back to the home screen by clicking SETUP in the mindmap, or by navigating via the Navigate menu."

---

## SECTION 5: Session Management (12:00 – 16:00)

**[Screen: Open Sessions dialog via Navigate → Sessions]**

> "Let's talk about sessions, because this is how you keep your work organised."

> "Every time you launch Huginn, a new session is automatically created with a timestamp name. All scans you run and all exports you generate are automatically tracked in that session."

> "The Session Management dialog — open it with `Ctrl+Shift+S` or Navigate → Sessions — shows you all your sessions."

**[Walk through the dialog]**

> "To create a new session, click the **New Session** button. Give it a descriptive name — something like 'Client XYZ External Assessment' — add a description, and optionally list your target domains or IPs. Click OK."

> "To make a session active, select it and click **Set Current**. Once a session is active, all new scan results are automatically associated with it."

> "You can edit a session by double-clicking it, and delete sessions you no longer need."

**[Open Session Info via Navigate → Sessions or Ctrl+Shift+S]**

> "The Session Info page — `Ctrl+Shift+S` — gives you a live view of your current session. It has four tabs:"

> "**Current Session** — Overview and quick stats. How many scans you've run, how many targets."

> "**Exports** — Every file you've exported is listed here. You can open the file directly or show it in Explorer."

> "**Scans** — A history of every scan run in this session, with timestamps and results."

> "**Statistics** — Charts and analytics showing your scanning patterns."

> "This window refreshes every 5 seconds, so you can leave it open alongside your main work and it'll stay up to date."

---

## SECTION 6: The Status Bar (16:00 – 17:00)

**[Screen: Point to the status bar at the bottom]**

> "At the very bottom of the window is the status bar. It shows you what's happening — navigation events, scan status, error messages. On the right side there's a memory usage widget so you can keep an eye on resource consumption during heavy scans."

---

## OUTRO (17:00 – end)

> "That's the full UI tour. You now know how to navigate between sections, use the menu bar, manage sessions, and understand the overall layout of the application."

> "In the next video we're going to cover licensing — what's free, what's in the Professional and Enterprise tiers, and how to activate a trial so you can follow along with the Pro features in this series."

> "See you in the next one."

---
---

# VIDEO 4: Licensing & Tiers
### Free vs Professional vs Enterprise, Activating a Trial
**Suggested length:** 8–12 minutes

---

## INTRO (0:00 – 0:45)

**[Screen: Huginn open, navigate to Tools → License Manager]**

> "Welcome back. In this video we're going to cover Huginn's licensing system — what features are available for free, what's in the Professional and Enterprise tiers, and how to activate a trial license so you can follow along with the advanced features in this series."

---

## SECTION 1: The Three Tiers (0:45 – 4:00)

**[Screen: License Manager dialog open]**

> "Huginn has three tiers: Free, Professional, and Enterprise."

### Free Tier

> "The **Free tier** gives you the core enumeration suite — DNS, port scanning, SMB, SMTP, SNMP, HTTP fingerprinting, and API enumeration. You also get standard reporting in JSON, CSV, and XML formats, and basic vulnerability scanning. For a lot of use cases, this is plenty."

### Professional Tier — $99/month

> "The **Professional tier** adds:"

> "**Stealth Mode** — Advanced evasion techniques including packet fragmentation, decoy IPs, timing randomisation, and configurable scan delays. Four evasion levels from Normal through to Paranoid."

> "**ProxyChains** — Route your traffic through HTTP, SOCKS4, SOCKS5, or Tor proxies. You can chain multiple proxies together in strict, dynamic, or random order."

> "**Basic Hacking Mode** — Integration with Metasploit and Empire for automated exploit execution."

> "**Local DNS Server** — Run a local DNS server on port 5353 with custom A, AAAA, and CNAME records. Useful for simulating DNS environments in testing."

> "**AWS Infrastructure Deployment** — Automatically deploy proxy servers and OpenVPN servers on AWS using SAM templates."

> "**Advanced reporting templates** and priority support."

### Enterprise Tier — $299/month

> "The **Enterprise tier** adds everything in Professional, plus:"

> "**Full Exploit Database** — Real-time CVE feeds from the National Vulnerability Database with automated service-to-exploit matching and CVSS scoring."

> "**Post-Exploitation Framework** — Full session management for multiple compromised hosts, credential harvesting, persistence techniques, and lateral movement."

> "**Advanced Hacking Mode** — Full exploit framework integration including Cobalt Strike."

> "**Custom API Integrations** — Shodan, VirusTotal, URLVoid, and custom threat intelligence feeds."

> "**Executive reporting and compliance templates** — NIST, ISO 27001, PCI-DSS."

> "**Active Directory Enumeration** — Full AD assessment and attack capabilities."

> "**Dedicated support channel.**"

---

## SECTION 2: Opening the License Manager (4:00 – 6:00)

**[Screen: License Manager dialog]**

> "To open the License Manager, go to **Tools → License Manager**."

> "The dialog shows your current license status — what tier you're on, when it expires, and which features are active."

> "If you have a license key, paste it into the activation field and click Activate. The features will unlock immediately."

---

## SECTION 3: Activating a Trial License (6:00 – 9:00)

**[Screen: License Manager, Trial section]**

> "If you want to follow along with the Professional features in this series, you can activate a free 30-day trial. No credit card required."

> "In the License Manager, click **Generate Trial**. A trial license key is generated and automatically activated. You'll see the Professional features unlock immediately."

> "The trial gives you full access to all Professional tier features for 30 days. After that, the features revert to Free tier unless you upgrade."

> "You'll see the expiry date shown in the License Manager. The application will also remind you as the expiry approaches."

---

## SECTION 4: How Licensing Affects the UI (9:00 – 11:00)

**[Screen: View → Themes, show locked themes]**

> "A couple of places in the UI where you'll notice the licensing system in action."

> "In the Theme Selector — open it with `Ctrl+T` or View → Themes → Theme Selector — Professional and Enterprise themes show a lock icon if you're on the Free tier. Activate a trial and those themes unlock."

**[Screen: Tools menu, show Stealth Mode]**

> "In the Tools menu, Stealth Mode will show a warning dialog if you try to access it without the right license tier. With a trial or paid license active, it opens normally. The other professional features like AD Enumeration and Advanced Analytics are accessible through the mindmap navigation."

**[Screen: Show Stealth Mode opening with trial active]**

> "With the trial active, let's open Stealth Mode as an example — Tools → Stealth Mode. You can see the four evasion levels and all the configuration options. We'll cover this in detail in Section 6."

---

## OUTRO (11:00 – end)

> "That covers the licensing system. To summarise: the Free tier is fully functional for core enumeration and scanning. The Professional tier adds evasion, proxying, and infrastructure features. Enterprise adds the full exploit database, post-exploitation framework, and compliance reporting."

> "Activate a trial if you want to follow along with everything in this series — it's free and takes about 30 seconds."

> "In the next video we'll start actually using the tools. We'll kick off Section 2 with DNS enumeration. See you there."

---

## APPENDIX: Quick Reference for Section 1

### Key Keyboard Shortcuts

| Shortcut | Action |
| --- | --- |
| `Ctrl+N` | New Profile |
| `Ctrl+O` | Load Profile |
| `Ctrl+E` | Export current results |
| `Ctrl+D` | Databases |
| `Ctrl+,` | Global Settings |
| `Ctrl+T` | Theme Selector |
| `Ctrl+Shift+R` | Running Scans |
| `Ctrl+Shift+S` | Sessions |
| `Ctrl+Shift+I` | Inventory |
| `Ctrl+M` | Minimize to Tray |
| `Ctrl+L` | Clear Output |
| `F1` | Tool Help |
| `Ctrl+Q` | Exit |

### Installation Commands (Quick Reference)
```bash
# Clone
git clone https://github.com/your-org/huginn
cd huginn

# Virtual environment
python -m venv venv
source venv/bin/activate      # Linux/macOS
venv\Scripts\activate         # Windows

# Install
pip install -r requirements.txt

# Launch
python main.py
```

### Session Management Quick Reference

- New session: `Navigate → Sessions → New Session`
- Set active session: Select session → "Set Current"
- View session live: `Ctrl+Shift+S`
- Save session: Session Info → "Save Session"
- Restore session: Session Info → "Restore Session"

### License Tiers Summary
| Feature | Free | Professional | Enterprise |
|---|---|---|---|
| Core Enumeration (12 tools) | ✅ | ✅ | ✅ |
| Basic Vulnerability Scanning | ✅ | ✅ | ✅ |
| Standard Reporting | ✅ | ✅ | ✅ |
| Stealth Mode | ❌ | ✅ | ✅ |
| ProxyChains / Tor | ❌ | ✅ | ✅ |
| Local DNS Server | ❌ | ✅ | ✅ |
| AWS Deployment | ❌ | ✅ | ✅ |
| Exploit Database | ❌ | ❌ | ✅ |
| Post-Exploitation Framework | ❌ | ❌ | ✅ |
| AD Enumeration | ❌ | ❌ | ✅ |
| Compliance Reporting | ❌ | ❌ | ✅ |
| API Integrations (Shodan etc.) | ❌ | ❌ | ✅ |
