# VIDEO 51: Standard Report Generation
### JSON, CSV, XML, PDF & HTML Report Formats
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Reporting | CEH: Scanning Networks (Reporting phase)

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 9 title card "Reporting and Documentation"]**

> "In the last video (see Video 50: Findings Management), we built a complete findings database — 15 categorized, scored, and organized vulnerability findings from our DVWA engagement. Today we turn that structured data into deliverable reports. We'll generate reports in every format Huginn supports: JSON for automation and API integration, CSV for spreadsheet analysis, XML for tool interoperability, HTML for browser-based sharing, and PDF for the professional pentest report you hand to a client. By the end of this video, you'll have a polished PDF report ready for delivery."

**[Screen: Slide showing the report generation pipeline — Findings Database → Format Selection → Template Application → Generation → Output File]**

> "The report generation pipeline takes your findings database and transforms it through a template engine into formatted output. The pipeline is the same regardless of format — findings go in, a formatted report comes out. The difference is in the template and renderer. JSON and CSV produce machine-readable data. XML provides structured interchange. HTML gives you a shareable web page. And PDF produces the print-ready professional document that clients expect. Let's start with the data formats and build up to the full PDF."

---

## SECTION 1: Accessing Report Generation (1:30 – 3:00)

**[Screen: Huginn Findings Manager — clicking the "Generate Report" button in the top toolbar]**

> "From the Findings Manager, click 'Generate Report' in the toolbar. This opens the Report Generation dialog where you select your format, configure options, and kick off generation. You can also access this from the centralized dashboard page under Report → Generate, but the Findings Manager path is the most common workflow because you've just finished organizing your findings."

**[Screen: Report Generation dialog — showing format tabs: JSON, CSV, XML, HTML, PDF. Each tab shows format-specific options]**

> "The dialog presents five format tabs. Each tab has format-specific options — column selection for CSV, schema version for XML, template selection for PDF. The common options across all formats include: which findings to include (all, filtered by severity, or a custom selection), whether to include evidence artifacts, and the output file path. Let's walk through each format."

**[Screen: The common options panel — showing "Include Findings" dropdown (All / High+ / Custom), "Include Evidence" checkbox, "Output Directory" path field]**

> "Before we pick a format, note the common options. 'Include Findings' controls scope — 'All' exports everything, 'High+' exports only High and Critical findings for executive audiences, and 'Custom' lets you pick specific findings. 'Include Evidence' attaches the raw request/response data and screenshots. And 'Output Directory' determines where files land. I'll use our project's exports folder for all demonstrations."

```bash
# Common report options:
Include Findings: All (15 findings)
Include Evidence: ✓ (for PDF/HTML, optional for data formats)
Output Directory: ./exports/dvwa-engagement/
Session: DVWA Penetration Test
Generated: 2024-01-15 14:30:00
```

---

## SECTION 2: JSON Export — Machine-Readable Data (3:00 – 5:00)

**[Screen: Selecting the JSON tab — showing options: "Pretty Print", "Include Metadata", "JSON Schema Version" (v1/v2)]**

> "JSON is your go-to for automation, CI/CD integration, and feeding findings into other tools. Select the JSON tab. Options are minimal — 'Pretty Print' for human readability versus compact output, 'Include Metadata' to add session context and generation timestamps, and 'Schema Version' which controls the output structure. Version 2 includes the CVSS vector string and evidence hashes."

**[Screen: Clicking "Generate" — a progress spinner followed by a success message showing the output path]**

> "Click Generate. JSON export is nearly instant since it's just serializing your findings database. The output lands at your configured path. Let's look at what was produced."

**[Screen: Opening the generated JSON file in a code viewer — showing the structure with findings array, metadata, and session info]**

> "The JSON output is a structured document with three top-level keys: 'metadata' containing session details and generation info, 'summary' with finding counts by severity, and 'findings' — an array of finding objects each containing the full detail: title, description, severity, CVSS score and vector, category, affected URL, evidence references, and remediation guidance."

```json
{
  "metadata": {
    "report_id": "rpt-dvwa-20240115-001",
    "session": "DVWA Penetration Test",
    "target": "http://localhost/dvwa/",
    "generated_at": "2024-01-15T14:30:00Z",
    "tool_version": "Huginn 2.0",
    "schema_version": "2.0"
  },
  "summary": {
    "total_findings": 15,
    "critical": 1,
    "high": 3,
    "medium": 4,
    "low": 5,
    "info": 2,
    "risk_score": 76
  },
  "findings": [
    {
      "id": "FIND-001",
      "title": "SQL Injection",
      "severity": "Critical",
      "cvss_score": 9.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
      "category": "Injection",
      "affected_url": "http://localhost/dvwa/vulnerabilities/sqli/",
      "description": "The id parameter is vulnerable to SQL injection...",
      "evidence": ["ev-req-001", "ev-resp-001", "ev-payload-001"],
      "remediation": "Use parameterized queries...",
      "status": "Exploited",
      "discovered_at": "2024-01-15T09:45:00Z"
    }
  ]
}
```

**[Screen: Terminal showing a curl command using the JSON report to push findings to a tracking API]**

> "The JSON format integrates directly into your workflow. Feed it into Jira for ticket creation, push it to DefectDojo for centralized vulnerability management, or parse it in your own scripts for custom analysis. The structured schema means any tool that understands JSON can consume your findings without manual reformatting."

---

## SECTION 3: CSV Export — Spreadsheet Analysis (5:00 – 6:30)

**[Screen: Selecting the CSV tab — showing column selection checkboxes: Title, Severity, CVSS, Category, URL, Status, Description, Remediation]**

> "CSV is for spreadsheet users — project managers who want to sort and filter findings in Excel, or analysts building pivot tables for trend analysis. The CSV tab shows column selection — you choose which fields appear in the output. For most uses, you want Title, Severity, CVSS Score, Category, Affected URL, and Remediation. Description can be included but makes the CSV harder to read in narrow columns."

**[Screen: Clicking "Generate" — success message showing the .csv file path]**

> "Generate the CSV. The output is a standard comma-separated file that opens directly in Excel, Google Sheets, or LibreOffice Calc."

**[Screen: Opening the CSV in a spreadsheet view — showing sorted findings with severity color-coding applied via conditional formatting]**

> "Here's the CSV opened in a spreadsheet. Each row is one finding, each column is a field. From here you can sort by severity, filter by category, create pivot tables showing finding distribution, or share with team members who prefer tabular data. The CSV format is also useful for importing into project management tools that accept CSV uploads."

```csv
Title,Severity,CVSS Score,Category,Affected URL,Status,Remediation
SQL Injection,Critical,9.1,Injection,http://localhost/dvwa/vulnerabilities/sqli/,Exploited,Use parameterized queries for all database interactions
Command Injection,High,8.6,Injection,http://localhost/dvwa/vulnerabilities/exec/,Exploited,Validate and sanitize all user input before passing to OS commands
Stored XSS,High,8.1,Input Validation,http://localhost/dvwa/vulnerabilities/xss_s/,Exploited,Implement output encoding and Content Security Policy
Weak Default Credentials,High,8.1,Authentication,http://localhost/dvwa/login.php,Confirmed,Enforce password change on first login
Reflected XSS,Medium,6.1,Input Validation,http://localhost/dvwa/vulnerabilities/xss_r/,Confirmed,Implement context-aware output encoding
CSRF,Medium,5.4,Session Management,http://localhost/dvwa/vulnerabilities/csrf/,Confirmed,Implement anti-CSRF tokens on all state-changing requests
Missing CSP Header,Medium,5.0,Configuration,http://localhost/dvwa/,Confirmed,Deploy Content-Security-Policy header
Missing HSTS,Medium,5.0,Configuration,http://localhost/dvwa/,Confirmed,Deploy Strict-Transport-Security header
```

---

## SECTION 4: XML Export — Tool Interoperability (6:30 – 8:00)

**[Screen: Selecting the XML tab — showing options: "Schema" (Huginn Native / OpenVAS Compatible / OWASP ZAP Compatible), "Include DTD"]**

> "XML export is designed for tool interoperability — feeding Huginn findings into other security platforms or compliance systems that expect XML input. The key option here is Schema selection. 'Huginn Native' produces our full-featured XML format. 'OpenVAS Compatible' generates XML that OpenVAS/Greenbone can import. 'OWASP ZAP Compatible' outputs in ZAP's report format. The schema choice determines which fields are included and how they're structured."

**[Screen: Selecting "Huginn Native" schema and clicking Generate — showing the output XML file path]**

> "I'll generate with the Huginn Native schema to show you the full output. For integration with specific tools, you'd select the compatible schema — but the native format preserves all Huginn-specific data like correlation amplifiers and engagement risk scores."

**[Screen: Opening the XML file showing the document structure with proper element nesting]**

> "The XML output uses proper element nesting with a root 'huginn-report' element containing 'metadata,' 'summary,' and 'findings' sections. Each finding is a 'vulnerability' element with child elements for all attributes. The XML is well-formed and valid against our published DTD, so XML parsers and XSLT transforms can process it reliably."

```xml
<?xml version="1.0" encoding="UTF-8"?>
<huginn-report version="2.0">
  <metadata>
    <report-id>rpt-dvwa-20240115-001</report-id>
    <session>DVWA Penetration Test</session>
    <target>http://localhost/dvwa/</target>
    <generated>2024-01-15T14:30:00Z</generated>
  </metadata>
  <summary>
    <total-findings>15</total-findings>
    <risk-score>76</risk-score>
    <severity-breakdown>
      <critical count="1"/>
      <high count="3"/>
      <medium count="4"/>
      <low count="5"/>
      <informational count="2"/>
    </severity-breakdown>
  </summary>
  <findings>
    <vulnerability id="FIND-001" severity="critical" cvss="9.1">
      <title>SQL Injection</title>
      <category>Injection</category>
      <affected-url>http://localhost/dvwa/vulnerabilities/sqli/</affected-url>
      <cvss-vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L</cvss-vector>
      <description>The id parameter is vulnerable to SQL injection allowing
        unauthorized database access and data extraction.</description>
      <remediation>Use parameterized queries for all database interactions.
        Implement input validation with whitelist approach.</remediation>
      <evidence count="3">
        <artifact type="request" ref="ev-req-001"/>
        <artifact type="response" ref="ev-resp-001"/>
        <artifact type="payload" ref="ev-payload-001"/>
      </evidence>
    </vulnerability>
  </findings>
</huginn-report>
```

---

## SECTION 5: HTML Report — Browser-Based Sharing (8:00 – 10:00)

**[Screen: Selecting the HTML tab — showing template options: "Standard", "Dark Theme", "Minimal", and a "Include Interactive Charts" checkbox]**

> "HTML reports produce self-contained web pages that anyone can open in a browser — no special software required. This makes them ideal for sharing with team members who don't have PDF readers configured or for embedding in internal wikis. The template options control the visual style — Standard is a clean professional theme, Dark Theme for those who prefer it, and Minimal strips all decoration for maximum content density. The 'Interactive Charts' option embeds JavaScript-powered severity distribution and risk visualization charts."

**[Screen: Selecting "Standard" template with Interactive Charts enabled, clicking Generate]**

> "Let's generate with the Standard template and interactive charts. This produces a single HTML file — all CSS, JavaScript, and image assets are inlined so the file is completely self-contained and portable."

**[Screen: Opening the generated HTML report in a browser — showing a professional header with engagement metadata, followed by an interactive severity pie chart and finding cards]**

> "The HTML report opens directly in any browser. The header shows engagement metadata — target, date, tester, and risk score. Below that, an interactive severity chart visualizes your finding distribution. Hover over chart segments to see counts. Then the findings appear as expandable cards — click any finding to expand its full detail including description, evidence, and remediation."

```bash
# Generated HTML report structure:
dvwa-engagement-report.html (single file, 847 KB)

Contents:
├── Header: Engagement metadata + risk score badge
├── Executive Summary: Auto-generated 3-sentence overview
├── Severity Chart: Interactive pie/bar chart (Chart.js embedded)
├── Findings Table: Sortable, filterable table with expand/collapse
│   ├── Finding Card: Title, severity badge, CVSS score
│   │   ├── Description (expandable)
│   │   ├── Evidence (expandable, base64-encoded inline)
│   │   └── Remediation (expandable)
├── Remediation Summary: Prioritized action items
└── Footer: Generation timestamp + tool version
```

**[Screen: Demonstrating the HTML report interactivity — clicking a finding to expand it, using the severity filter dropdown to show only Critical/High, then clicking "Print" which produces clean output]**

> "The interactivity makes this format great for walkthrough meetings. Filter to show only Critical and High findings for an executive audience, expand specific findings to show evidence during technical discussions, and use the browser's print function for a quick paper copy. The CSS includes print-specific styles that hide the interactive elements and produce a clean printable layout."

---

## SECTION 6: PDF Report — Professional Pentest Deliverable (10:00 – 14:30)

**[Screen: Selecting the PDF tab — showing comprehensive options: Template (Technical / Executive / Combined), Page Size (A4/Letter), Include Cover Page, Include Table of Contents, Include Evidence Screenshots, Branding options]**

> "PDF is the gold standard for professional pentest deliverables. This is what you email to a client, attach to a compliance submission, or archive for the engagement record. The PDF generator has the most options because it needs to produce a document that looks like it came from a professional security consultancy."

**[Screen: PDF options in detail — Template: "Technical" selected, Page Size: A4, all checkboxes enabled: Cover Page, Table of Contents, Evidence, Executive Summary, Remediation Roadmap]**

> "Template selection drives the overall structure. 'Technical' produces a full pentest report with methodology, findings, evidence, and remediation — this is your OSCP-style report. 'Executive' produces a shorter document focused on business risk without technical detail. 'Combined' gives you both — executive summary up front, full technical detail in the body. For this demonstration, we'll generate a Technical report with all sections enabled."

```bash
# PDF Generation Configuration:
Template: Technical (Full pentest report)
Page Size: A4
Include Cover Page: ✓
Include Table of Contents: ✓
Include Executive Summary: ✓
Include Methodology Section: ✓
Include Findings Detail: ✓ (all 15 findings)
Include Evidence Artifacts: ✓ (requests, responses, screenshots)
Include Remediation Roadmap: ✓
Include Risk Score Visualization: ✓
Company Name: "Security Assessment Team"
Report Title: "DVWA Penetration Test Report"
Classification: "CONFIDENTIAL"
```

**[Screen: Clicking "Generate PDF" — showing a progress bar with stages: "Building cover page... Rendering findings... Embedding evidence... Generating charts... Finalizing document..."]**

> "Click Generate PDF. The progress bar shows five stages — building the cover page with your branding, rendering each finding section with formatted descriptions, embedding evidence artifacts as inline images and formatted text blocks, generating severity charts as vector graphics, and finalizing the document with page numbers and table of contents links. For 15 findings with evidence, this takes about 10 seconds."

**[Screen: PDF opened in a viewer — showing the cover page with "DVWA Penetration Test Report", "CONFIDENTIAL" classification, date, and assessor details]**

> "The cover page immediately establishes professionalism. Report title, classification marking, target identification, assessment dates, and assessor details. This is what a client sees first when they open your deliverable. The classification marking — CONFIDENTIAL in this case — reminds everyone handling the document about its sensitivity."

**[Screen: Table of Contents page — showing clickable section links: Executive Summary, Methodology, Findings Summary, Detailed Findings (each finding listed), Remediation Roadmap, Appendix: Evidence]**

> "The table of contents is auto-generated with clickable links. Every section, every individual finding, and every appendix entry is linked — click to jump directly. This matters for long reports. A 50-finding engagement might produce a 100-page PDF, and stakeholders need to navigate directly to what they care about."

**[Screen: Executive Summary section of the PDF — showing risk score, finding count summary, and three-sentence narrative]**

> "The executive summary section — even in a Technical template — gives non-technical readers a quick overview. It shows the engagement risk score, finding count by severity, and an auto-generated narrative summarizing the overall security posture. 'The assessment identified 15 vulnerabilities including 1 Critical and 3 High severity findings. The target demonstrates significant exploitable risk in injection handling and authentication mechanisms. Immediate remediation is recommended for 4 findings to reduce the attack surface.'"

**[Screen: Individual finding in the PDF — showing the formatted finding card with title, severity badge, CVSS score, description, evidence screenshots, and remediation]**

> "Each finding gets a full page — or more for complex findings with extensive evidence. The layout shows severity badge, CVSS score with vector string, affected URL, detailed description, evidence artifacts rendered inline, and specific remediation steps. Evidence from the scanner — request/response pairs — is formatted in monospace blocks. Screenshots are embedded at readable resolution. This is the level of detail OSCP examiners expect in your exam report."

```bash
# PDF Finding Layout:
┌──────────────────────────────────────────────────────────────┐
│ FINDING #1: SQL Injection                    [CRITICAL 9.1]  │
├──────────────────────────────────────────────────────────────┤
│ Category: Injection                                          │
│ Affected: http://localhost/dvwa/vulnerabilities/sqli/        │
│ CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L       │
│ Status: Exploited                                            │
├──────────────────────────────────────────────────────────────┤
│ DESCRIPTION                                                  │
│ The 'id' parameter in the SQL Injection module is            │
│ vulnerable to injection attacks. An attacker can extract     │
│ the entire database contents including user credentials      │
│ without requiring valid authentication due to known          │
│ default credentials.                                         │
├──────────────────────────────────────────────────────────────┤
│ EVIDENCE                                                     │
│ Request:                                                     │
│   GET /dvwa/vulnerabilities/sqli/?id=1'+OR+'1'='1'--        │
│   Host: localhost                                            │
│   Cookie: PHPSESSID=abc123; security=medium                  │
│                                                              │
│ Response (excerpt):                                          │
│   First name: admin / Surname: admin                         │
│   First name: Gordon / Surname: Brown                        │
│   First name: Hack / Surname: Me                             │
│   [5 total rows returned — confirms injection]               │
├──────────────────────────────────────────────────────────────┤
│ REMEDIATION                                                  │
│ 1. Replace string concatenation with parameterized queries   │
│ 2. Implement input validation (whitelist numeric IDs)        │
│ 3. Apply least-privilege database permissions                │
│ 4. Deploy WAF rules for SQL injection patterns               │
│ Priority: IMMEDIATE                                          │
└──────────────────────────────────────────────────────────────┘
```

**[Screen: Remediation Roadmap section — showing a prioritized timeline: Immediate (Week 1), Short-term (Weeks 2-4), Long-term (Months 2-3)]**

> "The remediation roadmap at the end organizes all recommendations into a prioritized timeline. Immediate items — fix within one week — include the Critical SQL injection and High severity findings. Short-term items — within a month — cover the Medium findings like missing security headers and CSRF protections. Long-term items — within a quarter — address the Low and Informational findings. This gives the client actionable next steps rather than just a list of problems."

**[Screen: Final PDF file properties — showing page count: 34 pages, file size: 2.4 MB, embedded evidence: 15 artifacts]**

> "Our final PDF is 34 pages covering 15 findings with full evidence — a complete professional pentest report generated in about 10 seconds from the structured findings database we built in Video 50. In a real engagement with 50+ findings, you'd get a 100+ page report, but the generation time scales linearly — about 30 seconds for a large report."

---

## SECTION 7: Complete Workflow — Raw Scan to Finished PDF (14:30 – 16:30)

**[Screen: Split-screen showing the complete pipeline: left side shows the Huginn scanner with DVWA results, right side shows the final PDF report]**

> "Let's zoom out and trace the complete workflow from raw scan to finished deliverable. This is the workflow you'll repeat for every engagement — and the one you'll demonstrate in your OSCP exam report."

**[Screen: Step-by-step workflow diagram with arrows — Scan Target → Review Results → Triage & Validate → Import to Findings → Categorize & Score → Generate Report]**

> "Step one: scan the target with an appropriate profile — Normal or Aggressive for thorough coverage. Step two: review results in the results panel, check evidence, and verify confidence scores (see Video 26: Results Interpretation). Step three: triage false positives and confirm true vulnerabilities through manual validation. Step four: import confirmed findings into the Findings Manager. Step five: categorize by vulnerability class, score with contextual CVSS, add manual findings from your testing. Step six: generate the report in your required format — PDF for client delivery, JSON for tracking systems."

```bash
# Complete engagement reporting workflow:
1. Scan Execution
   huginn scan --target http://localhost/dvwa/ --profile normal

2. Results Review (Video 26)
   → 16 raw findings produced
   → Evidence review for each finding
   → 2 false positives identified

3. Findings Import (Video 50)
   → 13 scanner findings imported (deduplicated)
   → 2 manual findings added
   → Total: 15 validated findings

4. Categorization & Scoring (Video 50)
   → Findings grouped by category (6 categories)
   → CVSS scores reviewed and adjusted
   → Engagement risk score: 76/100

5. Report Generation (This video)
   → JSON export for tracking systems
   → CSV export for spreadsheet analysis
   → PDF report for client delivery (34 pages)

Total time from scan completion to deliverable PDF: ~25 minutes
```

**[Screen: The exports folder showing all generated files — .json, .csv, .xml, .html, .pdf — with file sizes]**

> "Our exports folder now contains the complete set of deliverables. The JSON at 45KB for automation. CSV at 8KB for spreadsheets. XML at 52KB for tool integration. HTML at 847KB with embedded interactivity. And the PDF at 2.4MB — your professional report. In practice, you'd generate whichever formats your engagement requires — most clients want just the PDF, but internal teams often want the JSON or CSV for their vulnerability management platforms."

```bash
# Generated report files:
./exports/dvwa-engagement/
├── dvwa-report-2024-01-15.json    (45 KB)
├── dvwa-report-2024-01-15.csv     (8 KB)
├── dvwa-report-2024-01-15.xml     (52 KB)
├── dvwa-report-2024-01-15.html    (847 KB)
└── dvwa-report-2024-01-15.pdf     (2.4 MB, 34 pages)
```

---

## SECTION 8: Certification Tips (16:30 – 17:30)

**[Screen: Slide showing OSCP reporting tip — "Your exam report must include: methodology, findings with proof, and remediation for each vulnerability"]**

> "For OSCP — the exam report structure maps directly to what we just generated. OSCP expects methodology (how you approached each target), findings with proof (screenshots and commands showing exploitation), and remediation for each finding. Practice this exact workflow against HTB machines — scan, validate, document, generate PDF — so it's automatic during your 24-hour exam window. Huginn's PDF template follows OSCP reporting expectations out of the box."

**[Screen: CEH tip — "Understand report formats and when to use each — JSON for automation, PDF for management, CSV for compliance tracking"]**

> "For CEH — the exam tests your knowledge of reporting methodology and format selection. Know when to use each format: JSON for DevSecOps pipeline integration, CSV for compliance tracking and audit evidence, XML for enterprise tool interoperability, HTML for internal sharing, and PDF for formal deliverables. Understanding the audience for each format demonstrates reporting maturity."

**[Screen: Practice recommendation — "Generate reports from your HTB/THM engagements. Build a portfolio of professional PDF reports."]**

> "Best practice recommendation: generate a PDF report for every HTB or THM machine you complete. This builds your portfolio, reinforces the workflow, and gives you material for job interviews. A candidate who can show three or four professional pentest reports during an interview demonstrates practical capability beyond just holding a certification."

---

## OUTRO (17:30 – end)

**[Screen: Summary slide — Report Generation: JSON (automation) + CSV (analysis) + XML (interop) + HTML (sharing) + PDF (delivery) | Complete workflow: 25 minutes from scan to deliverable | Next: Video 52 — Executive Summary]**

> "That's standard report generation — five formats covering every use case from machine-readable automation to professional client delivery. The complete workflow from scan completion to finished PDF takes about 25 minutes of active work, and Huginn handles the heavy lifting of formatting, pagination, evidence embedding, and professional layout. Your findings database does the real work — organize it well in Video 50's process and the reports practically write themselves. In the next video, we'll explore Enterprise-tier Executive Summary generation — automated business-risk narratives and C-suite-ready reports that translate technical findings into business language. See you in Video 52."

