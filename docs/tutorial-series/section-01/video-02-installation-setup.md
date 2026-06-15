# VIDEO 2: Installation & Setup
### Getting Huginn Running on Your Machine
**Suggested length:** 10–13 minutes
**License Tier:** Free
**Certification Relevance:** OSCP, CEH, PNPT — full methodology coverage

---

## INTRO (0:00 – 1:00)

**[Screen: Huginn splash screen with Section 1 title card "Getting Started"]**

> "Welcome back. In this video we're getting Huginn installed and configured for engagement work. I'll cover system requirements, both installation methods — pip and source — first launch, workspace configuration, and network interface selection. This is straightforward setup — I'll keep it concise and assume you know your way around a terminal and a Python environment (see Video 1: What is Huginn?)."

**[Screen: Slide showing what we'll cover — Requirements, pip Install, Source Install, First Launch, Workspace Config, Network Setup]**

> "If you run into issues, there's a troubleshooting section at the end covering the most common failure modes. Let's get started."

---

## SECTION 1: System Requirements (1:00 – 2:15)

**[Screen: Slide titled "System Requirements" with specifications table]**

> "Requirements are minimal. Windows 10 or 11. Python 3.10 or newer — 3.11 or 3.12 recommended for best performance. Eight gigabytes of RAM minimum — you'll want more during aggressive scans with multiple concurrent threads against large scope. A few gigabytes of disk space for the installation plus session data. And network connectivity for remote enumeration and OSINT modules."

**[Screen: Requirements table — OS: Windows 10/11, Python: 3.10+, RAM: 8GB+, Disk: 2GB+, Network: Required for remote targets]**

> "Check your Python version from the terminal. If you're below 3.10, grab the latest from python.org. Make sure 'Add Python to PATH' is checked during installation — you already know this, but it's the number one support issue we see."

```powershell
python --version
# Expected: Python 3.10.x or higher
```

---

## SECTION 2: Installation via pip (2:15 – 4:30)

**[Screen: Windows Terminal (PowerShell) — clean prompt]**

> "The standard installation method is pip. Create a virtual environment to isolate Huginn's dependencies from your system Python, activate it, and install the framework package."

```powershell
# Create and activate virtual environment
python -m venv huginn-env
.\huginn-env\Scripts\Activate.ps1

# Install Huginn
pip install huginn-framework
```

**[Screen: Terminal showing pip install progress — downloading PyQt6, networking libraries, crypto modules]**

> "Pip resolves all dependencies — PyQt6 for the GUI, networking libraries, crypto modules, reporting tools. Expect two to three minutes depending on your connection speed. When you see 'Successfully installed huginn-framework' with the full dependency list, you're done."

**[Screen: Terminal showing successful installation completion]**

> "That's it for pip. No manual dependency management, no build steps. The pip method is the recommended path for most operators — clean, reproducible, and easy to update when new versions ship."

---

## SECTION 3: Installation from Source (4:30 – 6:15)

**[Screen: GitHub repository page for Huginn — main branch with README]**

> "Source installation is for operators who want to inspect the code before running it, contribute upstream, or run development builds with the latest features before they hit a pip release."

```powershell
# Clone the repository
git clone https://github.com/blackreach-labs/huginn-suite.git
cd huginn

# Create and activate virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt

# Or install in editable mode for development
pip install -e .
```

**[Screen: Terminal showing git clone and dependency installation progress]**

> "Clone the repo, set up a virtual environment, and install from requirements.txt. Editable mode with pip install dash e dot means source changes take effect immediately without reinstalling — essential if you're developing custom modules or contributing patches. Both methods produce the same functional result for day-to-day operations."

---

## SECTION 4: First Launch and Workspace Configuration (6:15 – 8:30)

**[Screen: Terminal — running the Huginn launch command]**

> "Launch Huginn from your terminal. Pip installations use the huginn command directly. Source installations use python dash m app or the run.py script."

```powershell
# Pip installation
huginn

# Source installation
python -m app
```

**[Screen: Huginn loading screen — splash with progress bar showing "Loading modules..."]**

> "First launch takes slightly longer while Huginn initializes the module registry, creates the local session database, and builds configuration files. You'll see 270-plus modules register as the splash screen loads."

**[Screen: First-run configuration dialog — workspace directory selection]**

> "On first launch, Huginn asks you to set a workspace directory. This is where all engagement data lives — session files, scan results, exported reports, and configuration. Choose a location with adequate space and — critically — one appropriate for the sensitivity of your engagement data. If you're handling client results from production assessments, that workspace belongs on an encrypted volume."

**[Screen: Workspace directory configuration with recommended structure]**

> "I structure mine with subdirectories per client or engagement. Huginn's session management handles internal organization, but your workspace path determines where that data physically lives on disk. Set this once and you're done — you can change it later in settings if your storage requirements evolve."

**[Screen: Huginn home page fully loaded — attack chain toolbar, sidebar, welcome screen]**

> "Once configuration completes, you're on the home page. The attack chain toolbar runs across the top, the navigation sidebar is on the left, and the central content area shows quick-start options. Huginn creates a default session automatically on first launch — you're ready to work."

---

## SECTION 5: Network Interface and VPN Configuration (8:30 – 10:00)

**[Screen: Settings → Network page — showing interface selection dropdown and proxy configuration]**

> "Before running any remote operations, configure your network interface. Open Settings, then Network. The interface dropdown shows all available network adapters. If you're working through a VPN — whether that's a client-provided connection for an engagement or a lab VPN for HTB or THM — select the appropriate adapter here."

**[Screen: Network interface dropdown showing Ethernet, Wi-Fi, and OpenVPN/WireGuard adapters]**

> "For client engagements, select whichever interface routes to the target network. For lab environments, connect your VPN first, then select the tun0 or equivalent adapter in Huginn. Huginn binds scanning and enumeration traffic to the selected interface — this matters for proper connectivity and for keeping engagement traffic on the correct network segment."

**[Screen: Proxy configuration panel — SOCKS5 and HTTP proxy fields]**

> "The proxy configuration panel is also here for engagements requiring traffic routing through a specific proxy. SOCKS5 and HTTP proxies are supported natively. Professional tier users get ProxyChains and Tor integration for advanced operational security — we cover those in Section 7."

---

## SECTION 6: Troubleshooting (10:00 – 11:45)

**[Screen: Slide titled "Common Issues" with numbered list]**

> "Quick troubleshooting for the most common installation issues."

**[Screen: Terminal showing "python is not recognized" error]**

> "Python not on PATH — reinstall Python with 'Add to PATH' checked, or manually add your Python installation directory to the system PATH variable."

```powershell
# Verify Python is on PATH
where python
```

**[Screen: Terminal showing pip dependency compilation error]**

> "Dependency compilation failures — if pip can't build a C extension, install the Visual Studio Build Tools. Choose the 'Desktop development with C++' workload. This resolves most compilation errors."

**[Screen: Terminal showing PyQt6 DLL load failure]**

> "PyQt6 DLL errors on launch — install the latest Visual C++ Redistributable from Microsoft. PyQt6 depends on these runtime libraries and they're not always present on fresh Windows installations."

```powershell
# VC++ Redistributable download
# https://aka.ms/vs/17/release/vc_redist.x64.exe
```

**[Screen: Terminal showing port conflict on 5353]**

> "Port 5353 conflict — the local DNS feature uses this port. If another service has it bound — common with mDNS/Bonjour — either disable that service or change Huginn's configured port in settings."

**[Screen: Terminal showing clean reinstall commands]**

> "If nothing else resolves your issue — delete the virtual environment, recreate it, upgrade pip, and reinstall fresh. This fixes the majority of package corruption and version conflict problems."

```powershell
# Clean reinstall
deactivate
Remove-Item -Recurse -Force huginn-env
python -m venv huginn-env
.\huginn-env\Scripts\Activate.ps1
pip install --upgrade pip
pip install huginn-framework
```

---

## OUTRO (11:45 – end)

**[Screen: End card with "Next: Video 3 — Navigating the UI" and Huginn running in background]**

> "Huginn should be installed and configured — workspace directory set, network interface selected, and the application launching cleanly. In the next video, we'll cover the interface — efficient navigation, session management for multi-engagement tracking, and the operational settings that matter for professional work. See you in Video 3."
