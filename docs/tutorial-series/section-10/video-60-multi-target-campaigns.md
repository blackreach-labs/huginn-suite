# VIDEO 60: Multi-Target Campaigns
### Campaign Management, Parallel Execution & Result Aggregation
**Suggested length:** 15–18 minutes
**License Tier:** Enterprise
**Certification Relevance:** OSCP: Information Gathering (Multi-scope assessments) | CEH: Scanning Networks (Large-scale enumeration)

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 10 title card "Advanced Features and Workflows"]**

> "Last video, we scheduled scans to run automatically over time (see Video 59: Automation & Scheduling). Now we're scaling across space — multiple targets, scanned simultaneously, results aggregated into a unified campaign view. This is Multi-Target Campaigns, an Enterprise tier feature that takes Huginn from single-target scanning to coordinated, parallel assessment operations. If you're testing a network with 10 servers, you don't want to scan them one at a time. You want them all running in parallel, with a single dashboard showing progress across the entire campaign. That's what we're building today."

**[Screen: Side-by-side comparison — left shows sequential scanning (target 1, then target 2, then target 3, total time: 45 minutes), right shows parallel campaign (all three simultaneously, total time: 15 minutes)]**

> "The math is simple. A Normal profile scan takes about 15 minutes per target. Three targets sequentially: 45 minutes. Three targets in a campaign running parallel: still 15 minutes. Five targets: still about 15 minutes, because the orchestrator runs up to five concurrent scans. At scale, campaigns save hours. But it's not just about speed — campaigns give you aggregate statistics, cross-target correlation, and unified reporting. One campaign, one report, covering your entire scope. Let's set one up."

---

## SECTION 1: Campaign Architecture (1:30 – 3:30)

**[Screen: Architecture diagram showing three layers — `multi_target_coordinator.py` (campaign management), `multi_target_orchestrator.py` (execution scheduling with semaphore), and `multi_target_manager.py` (worker pool with ThreadPoolExecutor)]**

> "The campaign system is built from three coordinated modules. At the top, `multi_target_coordinator.py` manages campaign lifecycle — creation, status tracking, and result collection. In the middle, `multi_target_orchestrator.py` handles execution scheduling with an asyncio semaphore limiting concurrent targets to a configurable maximum — default five. At the bottom, `multi_target_manager.py` provides the worker pool using Python's ThreadPoolExecutor to actually dispatch and manage individual scan threads. Together, they give you parallel execution with resource control."

**[Screen: Code snippet from `multi_target_orchestrator.py` showing the semaphore-based concurrency control in `execute_campaign`]**

> "The key insight is the semaphore. You might have 20 targets in a campaign, but running 20 simultaneous scans would overwhelm your network and the targets. The semaphore caps concurrency at 5 — or whatever you configure — so targets queue and execute as slots become available. Five finish, five more start. This protects both your machine's resources and the targets from excessive simultaneous load."

```python
# Campaign execution with semaphore control (multi_target_orchestrator.py)
async def execute_campaign(self, campaign_name: str) -> Dict:
    """Execute a scan campaign with controlled concurrency"""
    campaign = next((c for c in self.scan_queue if c['name'] == campaign_name), None)
    
    # Create semaphore for concurrent target limiting
    semaphore = asyncio.Semaphore(self.max_concurrent_targets)  # Default: 5
    
    # Execute scans for all targets in parallel (limited by semaphore)
    tasks = []
    for target in campaign['targets']:
        task = self._scan_target_with_semaphore(semaphore, target, campaign['profile'])
        tasks.append(task)
    
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return self._compile_results(campaign_name, results)
```

**[Screen: Resource usage panel showing active/queued/completed counts and the max concurrent targets setting]**

> "The resource usage panel shows you the current state at a glance: how many scans are active, how many are queued waiting for a slot, and how many have completed. The maximum concurrent targets setting is adjustable — if you're on a powerful machine with good bandwidth, bump it to 8 or 10. On constrained systems, drop it to 3. This gives you fine-grained control over campaign execution pressure."

---

## SECTION 2: Creating a Campaign (3:30 – 6:00)

**[Screen: Huginn UI → Running Scans → Campaigns tab — showing the campaign creation interface with fields for campaign name, target list, and scan profile]**

> "For this demonstration, we're going to run a campaign against two targets simultaneously: our DVWA localhost instance and TryHackMe's 'Vulnversity' room. This mirrors a real engagement where you're assessing multiple systems in scope — maybe a web server and an application server. Navigate to Running Scans, select the Campaigns tab, and let's configure."

**[Screen: Campaign creation form — Name: "Lab Assessment Q1", Profile: Normal, Target input showing a text area with two targets entered]**

> "Campaign name: 'Lab Assessment Q1'. Profile: Normal. Now the target list — enter both targets, one per line. DVWA at 127.0.0.1 and the THM Vulnversity machine at its assigned IP. You can also import targets from a file — same format as the scheduler import (see Video 59: Automation & Scheduling)."

```bash
# Campaign Configuration:
Campaign Name:     Lab Assessment Q1
Scan Profile:      Normal
Concurrency Limit: 5 (default)

Target List:
  127.0.0.1          # DVWA (localhost)
  10.10.10.245       # THM Vulnversity

# Alternative: Import from file
# targets.txt:
# 127.0.0.1       # DVWA web server
# 10.10.10.245    # THM Vulnversity
# 192.168.56.10   # Internal web server
# 192.168.56.11   # Mail server
```

**[Screen: Clicking "Launch Campaign" — confirmation dialog showing "2 targets, Normal profile, estimated time: 15-20 minutes"]**

> "Click Launch Campaign. Huginn shows a confirmation: two targets, Normal profile, estimated completion in 15-20 minutes since both will run in parallel. Confirm, and the coordinator creates the campaign, assigns a campaign ID, and dispatches both scans to the orchestrator. Both targets begin scanning simultaneously."

**[Screen: Campaign launched — campaign ID displayed: "campaign_1_1708012800", status: "Running", progress showing 2 active scans]**

> "Campaign launched. The coordinator assigns ID `campaign_1_1708012800` — combining a sequence number with a timestamp for uniqueness. Both targets are now being scanned in parallel. Let's watch the progress."

---

## SECTION 3: Monitoring Campaign Progress (6:00 – 8:30)

**[Screen: Campaign dashboard showing real-time progress — two target cards side by side, each with their own progress bar: DVWA at 60%, Vulnversity at 45%]**

> "The campaign dashboard gives you a bird's-eye view of all targets in the campaign. Each target has its own progress card showing scan phase, percentage complete, and findings discovered so far. You can see DVWA is ahead — localhost connections are faster — while Vulnversity over the THM VPN is slightly behind. Both are scanning simultaneously."

**[Screen: DVWA target card expanding — showing individual scan stages: Port Scan ✓, Service Detection ✓, Vulnerability Scan ▶ (in progress)]**

> "Expand any target card to see detailed stage progress. DVWA has completed port scanning and service detection, and is now in the vulnerability assessment phase. You can drill into any individual target mid-campaign — it's the same scan results interface you'd see for a standalone scan, just wrapped in the campaign context."

```bash
# Campaign progress monitor:
Campaign: Lab Assessment Q1 (campaign_1_1708012800)
Status: Running
Duration: 8m 23s

┌─────────────────────────────────────────────────────┐
│ Target: 127.0.0.1 (DVWA)                           │
│ Status: Scanning [████████████████░░░░] 78%         │
│ Phase:  Vulnerability Assessment                    │
│ Ports:  2 open (80, 3306)                          │
│ Findings so far: 9                                  │
├─────────────────────────────────────────────────────┤
│ Target: 10.10.10.245 (Vulnversity)                 │
│ Status: Scanning [██████████░░░░░░░░░░] 52%         │
│ Phase:  Service Detection                           │
│ Ports:  4 open (22, 3333, 139, 445)                │
│ Findings so far: 3                                  │
└─────────────────────────────────────────────────────┘

Total Progress: 65% | Active: 2/2 | Queued: 0 | Complete: 0/2
```

**[Screen: Live event feed showing findings appearing from both targets interspersed — finding from DVWA, then Vulnversity, then DVWA again]**

> "The live event feed shows findings as they're discovered across all targets. You get a unified stream — a finding from DVWA, then one from Vulnversity, interleaved as the parallel scans progress. Each finding is tagged with its source target so you always know which system it belongs to. This real-time visibility lets you spot critical issues immediately without waiting for the campaign to finish."

---

## SECTION 4: Campaign Completion and Result Aggregation (8:30 – 11:00)

**[Screen: Campaign completing — both targets showing 100%, status changing to "Completed", aggregate summary appearing]**

> "Both targets are done. Campaign status flips to 'Completed' and the aggregate summary generates automatically. This is where Multi-Target Campaigns truly differentiate from running two separate scans — you get unified statistics across the entire scope."

**[Screen: Campaign summary panel — showing aggregate statistics: Total Targets: 2, Total Vulnerabilities: 16, Critical: 2, High: 5, Medium: 6, Low: 3]**

> "The campaign summary aggregates findings across all targets. Sixteen total vulnerabilities across both systems — two Critical, five High, six Medium, three Low. This gives you a scope-wide risk picture in one view. Below the aggregate, each target has its own breakdown so you can compare which systems carry more risk."

```bash
# Campaign Summary: Lab Assessment Q1
Campaign ID:    campaign_1_1708012800
Duration:       14m 38s
Total Targets:  2
Status:         Completed

Aggregate Statistics:
  Total Vulnerabilities: 16
  ┌──────────┬───────┬──────────────────┐
  │ Severity │ Count │ Distribution     │
  ├──────────┼───────┼──────────────────┤
  │ Critical │ 2     │ ████░░░░░░ 12.5% │
  │ High     │ 5     │ ████████░░ 31.3% │
  │ Medium   │ 6     │ █████████░ 37.5% │
  │ Low      │ 3     │ █████░░░░░ 18.7% │
  └──────────┴───────┴──────────────────┘

Per-Target Breakdown:
  127.0.0.1 (DVWA):
    Vulnerabilities: 11 (Critical: 1, High: 3, Medium: 5, Low: 2)
    Scan Duration: 12m 15s

  10.10.10.245 (Vulnversity):
    Vulnerabilities: 5 (Critical: 1, High: 2, Medium: 1, Low: 1)
    Scan Duration: 14m 38s
```

**[Screen: Cross-target correlation view — showing a finding type "Missing Security Headers" present on both targets, highlighted as a systemic issue]**

> "The cross-target correlator identifies patterns across your scope. When the same vulnerability type appears on multiple targets — like missing security headers on both systems — it's flagged as a systemic issue rather than an isolated finding. This distinction matters in reporting: systemic issues suggest organizational process gaps, not just individual server misconfigurations. The campaign view surfaces these patterns automatically."

---

## SECTION 5: Campaign Reporting (11:00 – 13:00)

**[Screen: Campaign report generation — selecting "Generate Campaign Report" with format options: JSON, HTML, PDF]**

> "Campaigns generate unified reports covering the entire scope. Click 'Generate Campaign Report' and select your format — JSON for machine consumption, HTML for web viewing, PDF for stakeholder delivery. The report includes the aggregate summary, per-target breakdowns, cross-target correlations, and timeline showing scan execution order. One report, complete scope coverage."

**[Screen: HTML campaign report preview — showing executive summary with scope overview, aggregate findings chart, and per-target sections]**

> "The HTML report leads with a scope overview — how many targets, what profile, when it ran. Then aggregate findings with a severity chart. Then per-target detail sections, each with its own findings list. This format is ready for delivery to stakeholders who need to understand risk across the full engagement scope. For compliance-mapped reporting, integrate campaign results with the Compliance Reporting features from Video 53 (see Video 53: Compliance Reporting)."

```bash
# Campaign report structure:
Campaign Report: Lab Assessment Q1
Generated: 2024-02-15 15:12:00

1. Executive Overview
   - Scope: 2 targets assessed
   - Timeline: 2024-02-15 14:48 → 15:03 (14m 38s)
   - Overall Risk: HIGH (2 Critical, 5 High findings)

2. Aggregate Findings (16 total)
   - Cross-target patterns identified: 2
   - Unique to single target: 14

3. Target: 127.0.0.1 (DVWA)
   - 11 findings (Critical: 1, High: 3, Medium: 5, Low: 2)
   - Top finding: SQL Injection on /dvwa/vulnerabilities/sqli/

4. Target: 10.10.10.245 (Vulnversity)
   - 5 findings (Critical: 1, High: 2, Medium: 1, Low: 1)
   - Top finding: Unrestricted File Upload on port 3333

5. Cross-Target Correlations
   - Missing X-Frame-Options → Both targets (systemic)
   - Missing Content-Security-Policy → Both targets (systemic)

6. Recommendations
   - Priority 1: Remediate Critical findings on both targets
   - Priority 2: Address systemic header issues organization-wide
```

**[Screen: Findings Management showing campaign results imported — each finding tagged with campaign ID and source target]**

> "Campaign results also feed into Findings Management (see Video 50: Findings Management). Every finding is tagged with the campaign ID and source target. You can filter findings by campaign to see only what that specific assessment discovered. When you schedule recurring campaigns — combining scheduling from Video 59 with multi-target from this video — your findings accumulate campaign over campaign, building comprehensive trend data."

---

## SECTION 6: Scaling Campaigns (13:00 – 15:00)

**[Screen: Campaign configuration with 10 targets — showing the queuing behavior with max concurrency of 5]**

> "Let's talk about scaling. We demonstrated with two targets, but real campaigns might have 10, 20, or 50 targets. With the default concurrency limit of 5, a 10-target campaign queues the first 5 immediately, holds the other 5, and starts them as slots free up. A 20-target campaign does the same — four rounds of 5 concurrent scans. The orchestrator handles queuing transparently."

```bash
# Large campaign scaling example (10 targets):
Campaign: Full Network Assessment
Targets: 10 servers
Concurrency: 5 (default)

Execution timeline:
  T+0:00  — Targets 1-5 start scanning
  T+12:00 — Target 3 completes (fastest) → Target 6 starts
  T+14:00 — Targets 1, 4 complete → Targets 7, 8 start
  T+15:00 — Targets 2, 5 complete → Targets 9, 10 start
  T+26:00 — All targets complete

Total time: ~26 minutes (vs ~150 minutes sequential)
Speedup: 5.7x

# Adjusting concurrency:
Settings → Campaigns → Max Concurrent Targets: 8
# Higher concurrency = faster completion but more resource usage
```

**[Screen: Resource monitoring panel showing CPU, memory, and network usage during a 5-target concurrent campaign — showing manageable resource consumption]**

> "Resource consumption scales linearly with concurrency. Five concurrent scans use roughly five times the network bandwidth and CPU of a single scan. Monitor the resource panel and adjust concurrency to match your system's capacity. On a dedicated testing machine with good bandwidth, you can safely run 8-10 concurrent. On a shared workstation over VPN, stick with 3-5 to avoid saturation."

**[Screen: Campaign template saving — "Save as Template" to reuse the same target list and profile configuration]**

> "For recurring campaigns, save the configuration as a template. Next month's assessment uses the same target list and profile — load the template, update any target changes, and launch. Combine this with scheduling to create fully automated recurring campaign assessments. Schedule a weekly campaign every Sunday night, covering your entire scope. Monday morning, you review the aggregated results. Enterprise-grade continuous assessment with zero manual intervention."

---

## SECTION 7: Integration with Asset Inventory (15:00 – 16:30)

**[Screen: Inventory page showing discovered assets — selecting multiple assets and choosing "Launch Campaign" from the context menu]**

> "The final integration point is the Asset Inventory. As you scan targets across the series, Huginn builds an asset database — IPs, hostnames, services, and metadata. From the Inventory page, select multiple assets and launch a campaign directly against them. No manual target entry — just select the assets you want to reassess and go."

**[Screen: Inventory → Select 4 assets → Right-click → "Launch Campaign with Profile: Normal" — campaign starts immediately against selected assets]**

> "Select four assets from inventory, right-click, 'Launch Campaign with Profile: Normal'. Done. The campaign starts immediately against those assets using their stored addresses. This workflow makes reassessment trivial — after remediation, select the affected assets, launch a campaign, and verify the fixes across all of them simultaneously."

```bash
# Inventory-driven campaign workflow:
1. Select assets from inventory (DVWA, Vulnversity, Lab Web Server, Lab DB)
2. Right-click → Launch Campaign
3. Select profile: Normal
4. Campaign executes against all 4 selected assets in parallel
5. Results update the asset inventory with latest findings

# Asset inventory updated post-campaign:
┌─────────────────┬─────────────┬────────────┬──────────────────┐
│ Asset           │ Last Scan   │ Findings   │ Risk Level       │
├─────────────────┼─────────────┼────────────┼──────────────────┤
│ DVWA            │ 2 min ago   │ 11         │ HIGH             │
│ Vulnversity     │ 2 min ago   │ 5          │ HIGH             │
│ Lab Web Server  │ 2 min ago   │ 3          │ MEDIUM           │
│ Lab DB          │ 2 min ago   │ 2          │ LOW              │
└─────────────────┴─────────────┴────────────┴──────────────────┘
```

**[Screen: Asset details showing scan history — previous campaigns listed chronologically, showing risk reduction over time]**

> "Each asset's detail page shows its campaign history — every time it was included in a campaign, what was found, and how findings have changed. This is your per-asset risk timeline. Combined with the campaign-level aggregate reporting, you have both the forest and the trees."

---

## OUTRO (16:30 – end)

**[Screen: Campaign dashboard showing completed campaign with aggregate results, both targets green with checkmarks]**

> "That's Multi-Target Campaigns — Enterprise tier. Parallel execution across multiple targets, semaphore-controlled concurrency, aggregate statistics and cross-target correlation, unified campaign reporting, and asset inventory integration. You've gone from single-target manual scanning to orchestrated multi-target assessments. In our final video — Video 61 — we're opening up Huginn itself: the Plugin System. Custom plugins, the extension API, and how to build functionality that doesn't exist yet (see Video 61: Plugin System). See you there."

---

*Source files referenced: `app/core/multi_target_coordinator.py`, `app/core/multi_target_manager.py`, `app/core/multi_target_orchestrator.py`*
*Demo target: THM "Vulnversity" + DVWA (localhost) simultaneously*
*Prerequisites: Video 59 (Automation and Scheduling), Video 50 (Findings Management), Enterprise tier license*
