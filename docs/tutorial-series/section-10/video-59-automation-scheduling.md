# VIDEO 59: Automation & Scheduling
### Scheduled Scans, Batch Operations & Recurring Assessments
**Suggested length:** 15–18 minutes
**License Tier:** Professional
**Certification Relevance:** OSCP: Reporting (Continuous assessment methodology) | CEH: Scanning Networks (Scheduled monitoring)

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 10 title card "Advanced Features and Workflows"]**

> "In the last video, we set up a Local DNS Server to give our lab targets consistent hostnames (see Video 58: Local DNS Server). Now we're automating the work itself. Up until this point, every scan we've launched in this series has been manual — click a button, wait for results, review. That's fine for one-off assessments. But real-world security programs need recurring scans: daily vulnerability checks, weekly configuration audits, monthly compliance runs. Huginn's Automation and Scheduling system — Professional tier — lets you define scan profiles, attach them to schedules, and walk away. The scans run on time, results accumulate, and you review the deltas. Let's build a scheduled scanning workflow from scratch."

**[Screen: Slide showing the evolution from manual scanning to automated pipeline — Manual (Video 24–26), Profiles (Video 25), and now Scheduling (this video) — with a timeline showing daily/weekly/monthly scan cadences]**

> "Think of it this way: in Video 24 (see Video 24: Scanner Overview & Profiles), you learned scan profiles. In Video 25 (see Video 25: Scan Configuration), you configured targets and parameters. Scheduling is the third piece: when does it run? Once? Daily? Every Monday at 3 AM? You define the cadence, and Huginn handles execution. Results feed into the same Findings Management system we covered in Video 50 (see Video 50: Findings Management), and Trend Analysis from Video 54 (see Video 54: Trend Analysis) shows you the trajectory over time. Scheduling connects the dots between all of these features."

---

## SECTION 1: Scheduler Architecture (1:30 – 3:30)

**[Screen: Architecture diagram showing `scheduler.py` at center, connected to the scan engine, the settings persistence layer (`schedules.json`), and the Running Scans UI page]**

> "The scheduler runs as a background daemon thread within Huginn. The core module is `scheduler.py` — a `ScanScheduler` class that maintains a dictionary of scheduled scans, each with a target, scan type, execution time, and optional repeat interval. Every 30 seconds, the scheduler loop checks whether any scheduled scans are due for execution. When one fires, it triggers the scan engine exactly as if you'd clicked 'Start Scan' manually. Results land in the same results pipeline."

**[Screen: Code snippet showing the `ScanScheduler` class initialization and the `schedule_scan` method signature]**

> "Each scheduled scan is an entry with a scan ID, target, scan type, execution time as an ISO timestamp, an optional template with scan parameters, and a repeat interval in hours — zero means one-shot, 24 means daily, 168 means weekly. The scheduler persists everything to `schedules.json` so your schedules survive application restarts."

```python
# Scheduler core (app/core/scheduler.py)
class ScanScheduler:
    def schedule_scan(self, scan_id: str, target: str, scan_type: str,
                     schedule_time: datetime, template: Dict = None,
                     repeat_interval: int = 0) -> bool:
        """
        Schedule a scan to run at specific time.
        
        Args:
            scan_id: Unique identifier for this schedule
            target: Target IP/hostname
            scan_type: Scan profile (light/normal/aggressive/insane)
            schedule_time: When to execute
            template: Additional scan parameters
            repeat_interval: Hours between repeats (0 = one-shot)
        """
```

**[Screen: Diagram showing the scheduler loop — checking every 30 seconds, comparing current time against `schedule_time` for each entry, executing when due]**

> "The scheduler loop is intentionally simple — poll-based at 30-second intervals. This keeps resource usage minimal and avoids complex timer management. When a one-shot scan completes, it's removed from the schedule. When a recurring scan completes, its next execution time is calculated and the status resets to 'scheduled'. Failed scans are marked but not automatically retried — you'll see the failure in the Running Scans page and can re-queue manually."

---

## SECTION 2: Creating a One-Shot Scheduled Scan (3:30 – 6:00)

**[Screen: DVWA running in browser at localhost — confirming our lab target is operational]**

> "Let's start with a one-shot scheduled scan. Our target is DVWA on localhost — same target we've used throughout the series. I want to schedule a Normal profile scan to run in 5 minutes from now. This simulates the use case where you want a scan to start at a specific time — maybe during a maintenance window, or when you know network traffic will be lower."

**[Screen: Huginn UI → Running Scans page → Schedule tab — showing the scheduling form with fields: Target, Scan Profile, Schedule Time, and Repeat Interval]**

> "Navigate to the Running Scans page and select the Schedule tab. Fill in the target — `127.0.0.1` or `dvwa.lab` if you set up LocalDNS in the last video. Select scan profile: Normal. Set the schedule time: five minutes from now. And leave repeat interval at zero — this is a one-shot. Click 'Schedule Scan'."

```bash
# Creating a one-shot scheduled scan:
Target:           127.0.0.1 (DVWA localhost)
Scan Profile:     Normal
Schedule Time:    2024-02-15 14:30:00 (5 minutes from now)
Repeat Interval:  0 (one-shot — execute once)
Scan ID:          dvwa_onetime_scan

# Confirmation:
[14:25:01] Scan scheduled: dvwa_onetime_scan
[14:25:01] Target: 127.0.0.1
[14:25:01] Profile: Normal
[14:25:01] Execution: 2024-02-15 14:30:00
[14:25:01] Repeat: None (one-shot)
```

**[Screen: Schedule confirmed — entry appears in the Scheduled Scans list with countdown: "4 minutes 59 seconds until execution"]**

> "The scan appears in the scheduled list with a live countdown. The scheduler background thread is tracking it. When the countdown hits zero, the scan launches automatically. Let's set up a recurring scan while we wait."

---

## SECTION 3: Setting Up Recurring Assessments (6:00 – 9:00)

**[Screen: Schedule form again — this time configuring a recurring daily scan]**

> "Recurring scans are where automation truly pays off. Let's schedule a daily Light profile scan of DVWA at 2 AM every night. The Light profile is fast — minimal impact, catches obvious issues — perfect for daily monitoring. You'll see drift immediately: if someone deploys a new feature or misconfiguration, tomorrow's scan catches it."

**[Screen: Filling form — Target: 127.0.0.1, Profile: Light, Time: 02:00 tomorrow, Repeat: 24 hours]**

> "Target: 127.0.0.1. Profile: Light. Schedule time: 02:00 tomorrow. Repeat interval: 24 — that's hours, so this fires every 24 hours. Click Schedule. Now we have a daily recurring assessment."

```bash
# Creating a recurring daily scan:
Target:           127.0.0.1 (DVWA localhost)
Scan Profile:     Light
Schedule Time:    2024-02-16 02:00:00 (tomorrow at 2 AM)
Repeat Interval:  24 hours (daily)
Scan ID:          dvwa_daily_light

# Creating a weekly aggressive scan:
Target:           127.0.0.1 (DVWA localhost)
Scan Profile:     Aggressive
Schedule Time:    2024-02-19 03:00:00 (next Monday at 3 AM)
Repeat Interval:  168 hours (weekly — 7 × 24)
Scan ID:          dvwa_weekly_aggressive

# Scheduled scans list:
┌─────────────────────────┬────────────┬────────────┬──────────────┬───────────┐
│ Scan ID                 │ Target     │ Profile    │ Next Run     │ Repeat    │
├─────────────────────────┼────────────┼────────────┼──────────────┼───────────┤
│ dvwa_onetime_scan       │ 127.0.0.1  │ Normal     │ 3 min        │ One-shot  │
│ dvwa_daily_light        │ 127.0.0.1  │ Light      │ 11 hours     │ Daily     │
│ dvwa_weekly_aggressive  │ 127.0.0.1  │ Aggressive │ 4 days       │ Weekly    │
└─────────────────────────┴────────────┴────────────┴──────────────┴───────────┘
```

**[Screen: Adding a second recurring scan — weekly Aggressive profile on Mondays at 3 AM, repeat interval 168 hours]**

> "Let's add one more: a weekly Aggressive scan every Monday at 3 AM. The Aggressive profile digs deeper — more payloads, more checks, longer runtime. You wouldn't want this daily, but weekly gives you thorough coverage without overwhelming the target. Now we have three schedules: an imminent one-shot, a daily Light, and a weekly Aggressive. This mirrors real-world security programs — light daily checks to catch regressions, deep weekly scans for thorough coverage."

**[Screen: Scheduled Scans list showing all three entries with their countdown timers and status indicators]**

> "The schedule list now shows three entries. Each has a countdown to next execution and a status indicator. When a recurring scan fires, it executes, stores results, then recalculates its next run time — next night at 2 AM, next Monday at 3 AM. The cycle continues indefinitely until you cancel it."

---

## SECTION 4: Monitoring Execution and Results (9:00 – 11:30)

**[Screen: Time-lapse — countdown reaching zero on the one-shot scan — status flipping from "Scheduled" to "Running"]**

> "Our one-shot scan just triggered. Watch the status change — 'Scheduled' flips to 'Running'. The scan engine is now active against DVWA, executing the Normal profile we configured. The Running Scans page shows it alongside any manually triggered scans — there's no visual distinction. Same scan engine, same results format."

**[Screen: Running Scans page showing the automated scan in progress — port scan completing, vulnerability scan running, progress bar at 45%]**

> "The automated scan runs identically to a manual one. Port scan, service detection, vulnerability assessment — the full Normal profile pipeline. You'll see it progressing in the Running Scans page in real-time, or you can ignore it entirely and review results later. That's the point of automation — it works while you don't."

```bash
# Automated scan execution log:
[14:30:00] Scheduler: Executing dvwa_onetime_scan
[14:30:00] Target: 127.0.0.1 | Profile: Normal
[14:30:01] Port scan started: 1-65535 (Normal range)
[14:30:12] Port scan complete: 2 ports open (80, 3306)
[14:30:13] Service detection: Apache/2.4.54, MySQL 5.7.40
[14:30:14] Vulnerability scan started (Normal profile)
[14:32:45] Vulnerability scan complete: 11 findings
[14:32:46] Results stored: scan_results/dvwa_onetime_scan_20240215.json
[14:32:46] Scheduler: dvwa_onetime_scan completed — removing (one-shot)
```

**[Screen: Scan completing — 11 findings discovered — results automatically stored and one-shot entry removed from schedule list]**

> "Eleven findings. Results stored automatically. And since this was a one-shot, the schedule entry is removed — it ran once, produced results, and cleaned itself up. The recurring scans stay in the list, counting down to their next execution. Tomorrow at 2 AM, the Light scan fires. Monday at 3 AM, the Aggressive scan runs. Results accumulate scan after scan."

**[Screen: Findings Management page showing accumulated results from multiple automated scans — sorted by date, showing scan source as "Scheduled: dvwa_daily_light"]**

> "Results from scheduled scans integrate seamlessly with Findings Management. Each finding carries metadata indicating it came from a scheduled execution — you can filter by source to see only automated results. Over time, this builds the historical dataset that powers Trend Analysis (see Video 54: Trend Analysis) — comparing automated scan results across days, weeks, and months to show your security posture trajectory."

---

## SECTION 5: Batch Operations and Template Management (11:30 – 13:30)

**[Screen: Schedule template creation interface — defining a reusable scan template with pre-configured parameters]**

> "When you're scheduling the same type of scan across multiple targets, templates save repetition. A scan template captures all parameters — profile, port range, authentication credentials, timing — as a reusable configuration. Create once, attach to multiple schedules."

```bash
# Scan template example:
Template Name: "DVWA Weekly Full Assessment"
Profile:       Aggressive
Port Range:    1-65535
Authentication:
  Type: Cookie-based
  Cookie: security=medium; PHPSESSID=abc123
Modules:       Web Exploits, SQL Injection, XSS, Path Traversal
Timing:        Default (no throttle)
Output:        JSON + HTML report

# Applying template to schedule:
Scan ID:          dvwa_weekly_full
Target:           127.0.0.1
Template:         "DVWA Weekly Full Assessment"
Schedule Time:    2024-02-19 03:00:00
Repeat Interval:  168 hours
```

**[Screen: Batch scheduling interface — entering multiple targets with the same template and schedule applied to all]**

> "Batch operations extend this further. Enter multiple targets — or import a target list from a file — apply the same template and schedule, and Huginn creates individual scheduled entries for each. Ten targets, same template, same cadence. This connects directly to the multi-target capabilities we'll explore in Video 60 (see Video 60: Multi-Target Campaigns), but at the scheduling layer — each target gets its own schedule entry and runs independently."

**[Screen: Target list file import — loading a text file with 5 lab IPs, applying the Light daily template to all]**

> "Import from file is particularly useful. Your target list lives in a text file — one IP per line, comments with hash marks. Import it, apply a schedule, and five new recurring scans appear in your schedule list. When the target list changes — new server deployed, old one decommissioned — update the file and reimport. Schedule management stays maintainable even across large environments."

---

## SECTION 6: Managing and Canceling Schedules (13:30 – 15:30)

**[Screen: Scheduled Scans list — selecting a recurring entry and clicking "Cancel"]**

> "Managing schedules is straightforward. Each entry has Cancel and Edit actions. Cancel removes the schedule immediately — the scan won't fire again. This is non-destructive: any results from previous executions remain in your findings database. You're only stopping future runs."

**[Screen: Editing a schedule — changing the repeat interval from 24 hours to 12 hours]**

> "Edit lets you modify parameters on a running schedule. Change the repeat interval from daily to twice-daily, adjust the profile, update the target. Changes take effect at the next execution — the current countdown resets to reflect the new schedule time."

```bash
# Schedule management operations:

# View all schedules with status:
Scheduled Scans:
  dvwa_daily_light       → Next: 11h 23m | Status: Scheduled | Repeat: 24h
  dvwa_weekly_aggressive → Next: 4d 13h  | Status: Scheduled | Repeat: 168h

# Cancel a schedule:
[Action] Cancel dvwa_daily_light
[Result] Schedule cancelled. Previous results retained.

# Edit a schedule:
[Action] Edit dvwa_weekly_aggressive → Change repeat to 72h (every 3 days)
[Result] Schedule updated. Next execution recalculated.

# View schedule history:
dvwa_daily_light — Execution History:
  2024-02-16 02:00 — Completed (8 findings)
  2024-02-17 02:00 — Completed (8 findings)
  2024-02-18 02:00 — Completed (7 findings) ← improvement!
  2024-02-19 02:00 — Failed (target unreachable)
  2024-02-20 02:00 — Completed (7 findings)
```

**[Screen: Schedule history view — showing execution log for a recurring scan over 5 days, including one failure when target was unreachable]**

> "The schedule history shows every execution — when it ran, how many findings it produced, and whether it succeeded or failed. Failures are logged but don't break the recurring schedule. If DVWA was down on February 19th, the scan fails that night, but the next night at 2 AM it tries again. This resilience is important for unattended operation — transient outages don't require manual intervention."

---

## SECTION 7: Integration with Notifications and Reports (15:30 – 17:00)

**[Screen: Settings → Notifications panel — configuring email alerts for scheduled scan completions]**

> "Automation is only useful if you actually review the results. Huginn's notification integration alerts you when scheduled scans complete — or more importantly, when they find something new. Configure email notifications for scan completion, or set severity-based alerts: only notify me when a Critical or High finding appears that wasn't in the previous scan. This pairs with Trend Analysis to give you change-detection alerting."

**[Screen: Alert configuration — "Notify on: New Critical/High findings" with email delivery configured]**

> "The configuration is threshold-based. 'Notify on any completion' sends an email every time a scheduled scan finishes. 'Notify on new findings' only alerts when the scan discovers something that wasn't in the previous run. 'Notify on Critical/High only' filters further — you only get pinged for urgent issues. Set it and forget it. Your inbox tells you when something needs attention."

```bash
# Notification configuration for scheduled scans:
Trigger:        New findings not in previous scan
Severity Filter: Critical, High
Delivery:       Email (admin@lab.local)
Include:        Finding title, severity, target, timestamp
Attach:         JSON summary of new findings

# Example notification:
Subject: [Huginn] New High-severity finding on 127.0.0.1
Body:
  Scheduled scan: dvwa_daily_light
  Execution: 2024-02-21 02:00:00
  New finding: SQL Injection (regression)
  Severity: High
  Target: 127.0.0.1 /dvwa/vulnerabilities/sqli/
  Note: This finding was previously remediated (last seen 2024-02-10)
```

**[Screen: Dashboard showing automated scan results feeding into the trend analysis graph — daily data points accumulating over two weeks]**

> "Over time, your automated scans build the dataset that powers everything in Section 9 — findings accumulate, trends emerge, reports generate from real data. This is the operational flywheel: schedule once, let it run, review the delta. Professional penetration testing programs run exactly this way."

---

## OUTRO (17:00 – end)

**[Screen: Scheduled Scans list showing active recurring schedules with green status indicators, next execution countdowns visible]**

> "That's Automation and Scheduling — Professional tier. You can now define one-shot scans for specific timing, recurring daily or weekly assessments, batch operations across target lists, and alert-based notifications. Your scans run on time, results accumulate, and you only intervene when something changes. Next up in Video 60, we scale this concept across multiple targets simultaneously — Multi-Target Campaigns at the Enterprise tier (see Video 60: Multi-Target Campaigns). See you there."

---

*Source files referenced: `app/core/scheduler.py`, `app/core/multi_target_manager.py`, `app/core/distributed_scanning.py`*
*Demo target: DVWA (localhost) — scheduled scan profiles*
*Prerequisites: Video 24 (Scanner Overview), Video 25 (Scan Configuration), Professional tier license*
