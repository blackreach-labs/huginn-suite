# VIDEO 53: Compliance Reporting
### NIST, ISO 27001, PCI-DSS Templates & Mapping
**Suggested length:** 15–18 minutes
**License Tier:** Enterprise
**Certification Relevance:** OSCP: Reporting | CEH: Scanning Networks (Compliance documentation)

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 9 title card "Reporting and Documentation"]**

> "In Video 51 (see Video 51: Standard Report Generation), we produced technical reports. In Video 52 (see Video 52: Executive Summary), we produced business-facing narratives. Today we add the third pillar of professional reporting: compliance mapping. Compliance reports take your findings and map them directly to regulatory framework controls — showing exactly which NIST categories, ISO 27001 clauses, or PCI-DSS requirements are violated by each vulnerability. This is an Enterprise tier feature that turns a pentest into an audit artifact."

**[Screen: Slide showing three compliance frameworks side by side — NIST Cybersecurity Framework (5 functions), ISO 27001 (14 domains), PCI-DSS v4.0 (12 requirements) — with arrows from "Your Findings" pointing to controls in each]**

> "Why does this matter? Because most organizations don't just want to know 'you have SQL injection.' They need to know 'SQL injection violates PCI-DSS Requirement 6.2.4, which means your compliance certification is at risk and you have 90 days to remediate before your next QSA audit.' That's the difference between a vulnerability report and a compliance finding. Huginn maps your technical discoveries to the exact control language auditors look for. Let's set it up."

---

## SECTION 1: Compliance Framework Selection (1:30 – 3:30)

**[Screen: Report phase menu → Compliance Reporting — opening the Compliance Mapper interface with framework selection]**

> "Navigate to Report → Compliance Reporting. The Compliance Mapper interface presents available frameworks. Huginn ships with templates for NIST Cybersecurity Framework, ISO 27001:2022, PCI-DSS version 4.0, OWASP Top 10 2021, HIPAA, SOX, and GDPR. Each template maps vulnerability categories to specific controls within that framework. You can activate multiple frameworks simultaneously — which is common for organizations subject to multiple regulatory requirements."

**[Screen: Framework selection panel showing checkboxes for each framework — NIST CSF ✓, ISO 27001 ✓, PCI-DSS v4.0 ✓ selected, others unchecked]**

> "For this demonstration, I'll select the three frameworks most commonly requested in penetration test reports: NIST CSF for US government and critical infrastructure clients, ISO 27001 for international organizations with ISMS certification, and PCI-DSS for anyone handling payment card data. In practice, your client tells you which frameworks apply to their environment — you select those and Huginn handles the mapping."

```bash
# Framework selection:
Compliance Reporting → Select Frameworks
  ✓ NIST Cybersecurity Framework (CSF) v1.1
    Functions: Identify, Protect, Detect, Respond, Recover
    Categories: 23
    Subcategories: 108
  ✓ ISO 27001:2022
    Domains: 4 themes (Organizational, People, Physical, Technological)
    Controls: 93
  ✓ PCI-DSS v4.0
    Requirements: 12 principal requirements
    Sub-requirements: 264 defined testing procedures
  ☐ OWASP Top 10 2021
  ☐ HIPAA Security Rule
  ☐ SOX IT Controls
  ☐ GDPR Article 32
```

**[Screen: After selecting frameworks — the interface shows a "Map Findings" button and a preview showing "18 findings ready for compliance mapping"]**

> "With frameworks selected, Huginn shows your findings count ready for mapping. Our DVWA engagement has 18 unique findings from Video 50 (see Video 50: Findings Management). Click 'Map Findings' to let the compliance mapper engine analyze each finding and assign it to the appropriate controls. This uses the mapping logic in `compliance_mapper.py` — keyword matching on vulnerability type, CVSS vector components, and CWE identifiers to determine which controls are impacted."

---

## SECTION 2: NIST Cybersecurity Framework Mapping (3:30 – 6:30)

**[Screen: NIST CSF mapping results — showing the five functions (Identify, Protect, Detect, Respond, Recover) as columns with findings distributed across them]**

> "The NIST mapping distributes your findings across the five core functions. Identify covers asset management and risk assessment — our enumeration findings land here. Protect covers access control, data security, and protective technology — injection vulnerabilities, authentication weaknesses, and configuration issues map here. Detect covers security monitoring — our missing logging findings go here. Respond and Recover are typically not populated by vulnerability findings unless you've identified incident response gaps."

**[Screen: Expanding the "Protect" function — showing sub-categories PR.AC (Access Control), PR.DS (Data Security), PR.IP (Protective Technology) with specific findings mapped to each]**

> "Let's drill into the Protect function where most of our findings landed. Under PR.AC — Access Control — Huginn mapped our weak default credentials and missing account lockout findings. Under PR.DS — Data Security — the SQL injection finding maps here because it threatens data confidentiality. Under PR.IP — Protective Technology — missing security headers and the lack of input validation map to protective controls. Each mapping includes the specific NIST subcategory identifier."

```bash
# NIST CSF Mapping Results:
┌─────────────────────────────────────────────────────────┐
│ IDENTIFY (ID)                        │ 3 findings       │
│   ID.AM-2 (Software inventory)       │ PHP version leak │
│   ID.AM-5 (Resource classification)  │ MySQL exposed    │
│   ID.RA-1 (Vulnerability identified) │ Dir listing      │
├─────────────────────────────────────────────────────────┤
│ PROTECT (PR)                         │ 12 findings      │
│   PR.AC-1 (Identity management)      │ Weak credentials │
│   PR.AC-4 (Access permissions)       │ No lockout       │
│   PR.AC-7 (Authentication)           │ Default creds    │
│   PR.DS-1 (Data-at-rest protection)  │ SQLi extraction  │
│   PR.DS-2 (Data-in-transit)          │ Missing HSTS     │
│   PR.DS-5 (Data leak protections)    │ XSS, CSRF        │
│   PR.IP-1 (Security config baseline) │ Missing CSP      │
│   PR.IP-3 (Configuration change)     │ Debug mode       │
│   PR.PT-3 (Least functionality)      │ Cmd injection    │
├─────────────────────────────────────────────────────────┤
│ DETECT (DE)                          │ 2 findings       │
│   DE.CM-4 (Malicious code detection) │ No WAF           │
│   DE.CM-7 (Unauthorized monitoring)  │ No logging       │
├─────────────────────────────────────────────────────────┤
│ RESPOND (RS)                         │ 1 finding        │
│   RS.MI-2 (Incident mitigation)      │ No rate limiting │
├─────────────────────────────────────────────────────────┤
│ RECOVER (RC)                         │ 0 findings       │
└─────────────────────────────────────────────────────────┘
```

**[Screen: A compliance coverage heatmap — NIST functions as rows, colored green (covered), yellow (partial), red (gaps) based on findings mapped vs. controls assessed]**

> "The compliance coverage heatmap shows where your assessment has coverage and where gaps exist. Green means you assessed controls in that area and found issues — which counterintuitively is good because it means you tested there. Yellow means partial coverage. Red means your assessment didn't evaluate that area at all. For a penetration test, Respond and Recover are typically red because those are process controls, not technical vulnerabilities. The heatmap helps scope future assessments."

---

## SECTION 3: ISO 27001 Control Mapping (6:30 – 9:00)

**[Screen: Switching to ISO 27001 tab — showing the four themes: Organizational (37 controls), People (8 controls), Physical (14 controls), Technological (34 controls)]**

> "ISO 27001:2022 organizes controls into four themes. For a penetration test, the Technological theme carries most of our findings, but several map to Organizational controls around access management policies. Let's look at how Huginn distributes our 18 findings across the ISO control structure."

**[Screen: ISO 27001 Technological controls expanded — showing A.8.x controls with findings mapped: A.8.5 (Secure authentication), A.8.7 (Malware protection), A.8.9 (Configuration management)]**

> "Under Technological controls, Huginn mapped our authentication findings to A.8.5 — Secure Authentication. The missing security headers map to A.8.9 — Configuration Management. SQL injection maps to both A.8.25 — Secure Development Life Cycle — indicating the application wasn't built securely, and A.8.26 — Application Security Requirements — indicating security requirements weren't defined. Each mapping references the ISO control number, title, and the specific finding that violates it."

```bash
# ISO 27001:2022 Mapping (Technological theme - A.8):
A.8.5  Secure authentication          → Weak credentials, No lockout
A.8.7  Protection against malware     → No WAF, No input validation
A.8.9  Configuration management       → Missing headers, Debug mode, Dir listing
A.8.12 Data classification            → MySQL version exposed
A.8.24 Use of cryptography            → Missing HSTS (no forced TLS)
A.8.25 Secure development lifecycle   → SQLi, XSS, Cmd injection, CSRF
A.8.26 Application security reqs      → All injection findings
A.8.28 Secure coding                  → SQLi, XSS, SSTI, Path traversal

# Organizational controls (A.5):
A.5.15 Access control                 → Default credentials, No lockout
A.5.17 Authentication information     → Weak password policy

# Coverage summary:
Controls assessed: 10 of 93 (11%)
Controls with findings: 10 (100% of assessed)
Controls not assessed: 83 (out of scope for pentest)
```

**[Screen: ISO 27001 Statement of Applicability (SoA) integration — showing how findings populate the SoA document with "Non-Conformant" status]**

> "For organizations maintaining ISO 27001 certification, the compliance report integrates with the Statement of Applicability. Each finding that maps to a control updates that control's status to 'Non-Conformant' with evidence reference. This is exactly the format internal auditors and certification bodies need to see. If your client is preparing for a surveillance audit, this report tells them which controls will fail and what evidence the auditor will find."

---

## SECTION 4: PCI-DSS Mapping (9:00 – 11:30)

**[Screen: PCI-DSS v4.0 tab — showing the 12 principal requirements as an accordion list. Requirements 2, 6, 7, and 8 are highlighted indicating findings mapped]**

> "PCI-DSS is the most prescriptive of our three frameworks — it has specific technical requirements rather than broad control objectives. Huginn maps findings to PCI-DSS requirements with testing procedure granularity. Our findings triggered four of the twelve principal requirements: Requirement 2 on secure configurations, Requirement 6 on secure software development, Requirement 7 on restricting access, and Requirement 8 on identifying and authenticating users."

**[Screen: Expanding Requirement 6 — showing sub-requirements 6.2.4 (software engineering), 6.3.1 (vulnerability identification), 6.4.1 (public-facing web protections)]**

> "Requirement 6 is where most web application findings land. Sub-requirement 6.2.4 states that software must be developed in accordance with PCI-DSS secure coding guidelines — our SQL injection, XSS, and command injection findings directly violate this. Requirement 6.3.1 requires identification of security vulnerabilities — which is what we've done through our scan, but the presence of these vulnerabilities means the development process failed to catch them. And 6.4.1 requires protection of public-facing web applications through mechanisms like a WAF — which our target lacks."

```bash
# PCI-DSS v4.0 Mapping Results:
Requirement 2: Apply secure configurations to all system components
  2.2.2 Vendor default accounts managed         → Default credentials (FAIL)
  2.2.7 Non-console admin access encrypted      → Missing HSTS (FAIL)

Requirement 6: Develop and maintain secure systems and software
  6.2.4 Software developed securely             → SQLi, XSS, CmdInj (FAIL)
  6.3.1 Security vulnerabilities identified     → 18 vulns found (FINDING)
  6.3.2 Inventory of custom software            → PHP version leak (PARTIAL)
  6.4.1 Public-facing web app protection (WAF)  → No WAF detected (FAIL)
  6.5.1 Injection flaws addressed               → SQLi, CmdInj active (FAIL)

Requirement 7: Restrict access to system components
  7.2.2 Access assigned based on job function   → Dir listing enabled (FAIL)

Requirement 8: Identify users and authenticate access
  8.3.4 Invalid auth attempts limited           → No lockout (FAIL)
  8.3.6 Password complexity enforced            → admin/password (FAIL)
  8.6.1 System/app accounts managed             → Default credentials (FAIL)

Compliance Status: NON-COMPLIANT (9 FAIL, 1 PARTIAL, 2 FINDING)
```

**[Screen: PCI-DSS compliance score panel — showing 22% compliant for assessed requirements, with a red "NON-COMPLIANT" badge]**

> "The PCI-DSS compliance score for our assessed requirements shows 22% — heavily non-compliant. The important caveat: we only assessed requirements addressable through a penetration test. A full PCI-DSS assessment covers physical security, policies, and processes that are out of scope for our test. The report clearly states which requirements were assessed and which are marked 'not assessed — out of scope' so the QSA understands the coverage boundaries."

**[Screen: PCI-DSS remediation timeline showing SAQ-required deadlines — "Defined vulnerability" must be remediated per PCI risk ranking]**

> "PCI-DSS has specific remediation timelines. Critical and high-risk vulnerabilities must be remediated according to the entity's vulnerability management process — typically within 30 days for critical, 90 days for high. Huginn's compliance report includes these timelines mapped to your finding severities, giving your client a PCI-specific remediation schedule they can present to their acquiring bank."

---

## SECTION 5: Cross-Framework Correlation (11:30 – 13:30)

**[Screen: Cross-framework view — showing a matrix where rows are findings and columns are frameworks, with cells showing the control reference for each]**

> "One of the most powerful features is cross-framework correlation. A single finding often violates controls across multiple frameworks simultaneously. SQL injection violates NIST PR.DS-5, ISO A.8.25, PCI-DSS 6.5.1, and OWASP A03:2021. The cross-framework matrix shows this at a glance — one remediation action satisfies multiple compliance obligations."

**[Screen: Highlighting the SQL Injection row — showing it maps to controls in all three selected frameworks plus OWASP]**

> "Take our SQL injection finding. Remediating it addresses NIST Protect function data leak prevention, ISO 27001 secure development lifecycle, PCI-DSS injection flaw requirements, and OWASP Injection category. That's four compliance wins from a single fix. This cross-mapping helps prioritize remediation by compliance impact — fixes that satisfy the most frameworks get higher priority."

```bash
# Cross-Framework Correlation Matrix (sample):
┌──────────────────────┬───────────┬───────────────┬─────────────┐
│ Finding              │ NIST CSF  │ ISO 27001     │ PCI-DSS 4.0 │
├──────────────────────┼───────────┼───────────────┼─────────────┤
│ SQL Injection        │ PR.DS-5   │ A.8.25, A.8.28│ 6.2.4, 6.5.1│
│ Weak Credentials     │ PR.AC-1   │ A.5.17, A.8.5 │ 8.3.6, 8.6.1│
│ Missing HSTS         │ PR.DS-2   │ A.8.24        │ 2.2.7       │
│ XSS (Stored)        │ PR.DS-5   │ A.8.25, A.8.28│ 6.2.4       │
│ Command Injection    │ PR.PT-3   │ A.8.25, A.8.26│ 6.2.4, 6.5.1│
│ No Account Lockout   │ PR.AC-4   │ A.5.15        │ 8.3.4       │
│ Missing CSP         │ PR.IP-1   │ A.8.9         │ 6.4.1       │
│ Directory Listing    │ ID.RA-1   │ A.8.9         │ 7.2.2       │
└──────────────────────┴───────────┴───────────────┴─────────────┘

Compliance Impact Score (findings that hit all 3 frameworks):
  SQL Injection: 3/3 frameworks → Priority: CRITICAL
  Weak Credentials: 3/3 frameworks → Priority: HIGH
  Command Injection: 3/3 frameworks → Priority: CRITICAL
```

**[Screen: A "Compliance Impact Priority" list — findings sorted by how many framework controls they violate, with SQL injection and command injection at the top]**

> "The Compliance Impact Priority list reorders your findings not by CVSS severity but by compliance breadth — how many framework controls each finding violates. This gives compliance-focused organizations a different prioritization lens. A finding might be Medium severity technically but violate controls across four frameworks — making it a compliance priority even if it's not an exploitation priority."

---

## SECTION 6: Generating the Compliance Report (13:30 – 15:30)

**[Screen: Compliance Report generation dialog — output format: PDF, sections: all three frameworks, appendix: cross-framework matrix]**

> "Time to generate the full compliance report. Select your output format — PDF for formal delivery. Choose which framework sections to include — all three in our case. Enable the cross-framework appendix. And set the output path alongside your other engagement deliverables."

**[Screen: Clicking "Generate Compliance Report" — progress bar showing framework mapping stages]**

> "Click Generate. The compliance reporter processes each framework sequentially — NIST mapping, ISO mapping, PCI-DSS mapping — then builds the cross-framework correlation matrix and renders the final document. For three frameworks and 18 findings, this takes about 10 seconds."

```bash
# Compliance Report generation:
Format: PDF
Frameworks: NIST CSF, ISO 27001:2022, PCI-DSS v4.0
Sections:
  ✓ Framework Overview (scope, version, assessment date)
  ✓ NIST CSF Mapping (5 functions, subcategory detail)
  ✓ ISO 27001 Control Mapping (4 themes, control references)
  ✓ PCI-DSS Requirement Mapping (12 requirements, testing procedures)
  ✓ Cross-Framework Correlation Matrix
  ✓ Compliance Gap Analysis
  ✓ Remediation-to-Compliance Mapping
  ✓ Assessment Scope Limitations
Output: ./exports/dvwa-engagement/compliance-report.pdf
```

**[Screen: Generated PDF preview — showing NIST section with professional formatting, control tables, and compliance status badges]**

> "The generated report is structured by framework with consistent formatting. Each section opens with the framework name, version, and assessment scope. Then control-by-control findings are listed with status badges: PASS, FAIL, PARTIAL, or NOT ASSESSED. Evidence references point back to the technical report for detailed proof. The assessment scope limitations section is critical — it tells the reader exactly what was tested and what wasn't, preventing misinterpretation of compliance status."

**[Screen: The exports directory showing three deliverables: technical-report.pdf, executive-summary.pdf, compliance-report.pdf]**

> "You now have a complete three-document engagement deliverable set. The technical report for the security team. The executive summary for leadership. And the compliance report for auditors and GRC teams. Together, these three documents satisfy every stakeholder in a professional penetration test engagement."

---

## SECTION 7: Custom Framework Templates (15:30 – 16:30)

**[Screen: Settings → Compliance Templates — showing "Create Custom Framework" option alongside the built-in templates]**

> "Enterprise customers can create custom compliance templates for internal frameworks, industry-specific standards, or emerging regulations not yet built into Huginn. The template editor lets you define framework categories, map vulnerability types to controls, and set control descriptions. This is useful for organizations with internal security policies that go beyond public standards — you can map findings to your own control catalog."

**[Screen: Custom template editor — showing a simplified template being built with categories, control IDs, and mapping rules]**

> "The template editor accepts framework metadata — name, version, and description — then lets you define categories and controls within each. Mapping rules use the same keyword and CWE-based matching that powers the built-in templates. Once created, your custom framework appears alongside NIST and ISO in the framework selection panel. This means you can include internal policy compliance in the same report as regulatory compliance."

```bash
# Custom framework template structure:
Settings → Compliance Templates → Create Custom
  Framework Name: "Internal Security Policy v3.0"
  Version: 3.0
  Categories:
    - AUTH: Authentication Controls
      - AUTH-01: Multi-factor authentication required
      - AUTH-02: Account lockout after 5 attempts
      - AUTH-03: Password complexity enforced
    - INP: Input Validation Controls
      - INP-01: All user input sanitized
      - INP-02: Parameterized queries required
      - INP-03: Output encoding applied
  Mapping Rules:
    - "auth*|credential*|password*" → AUTH category
    - "injection*|xss*|input*" → INP category
```

---

## OUTRO (16:30 – end)

**[Screen: Recap slide showing: Findings → Framework Selection → Control Mapping → Cross-Correlation → Professional Compliance Report]**

> "To recap — Compliance Reporting maps your penetration test findings to specific regulatory framework controls, producing audit-ready documentation that tells organizations exactly which compliance obligations are violated and what to fix. It supports NIST CSF, ISO 27001, PCI-DSS, OWASP Top 10, and custom frameworks. The cross-framework correlation identifies findings with the broadest compliance impact. This is an Enterprise tier feature that bridges the gap between security testing and governance, risk, and compliance. Next up: Trend Analysis — comparing scans over time to track remediation progress and identify emerging risks. See you in Video 54."

**[Screen: End card with Video 53 title, Section 9 progress bar showing 4/5 complete, and "Next: Video 54 — Trend Analysis"]**

---

## CERTIFICATION NOTES

| Certification | Relevance |
|---|---|
| OSCP | Reporting domain — While OSCP doesn't require compliance mapping, understanding how findings map to frameworks demonstrates professional maturity expected of senior pentesters. |
| CEH | Documentation phase — CEH covers regulatory compliance awareness. Demonstrating automated compliance mapping shows efficiency in documentation workflows. |

**Practice:** Map your DVWA findings to NIST CSF manually, then compare with Huginn's automated mapping. Identify any findings where you'd map to a different control than the tool selected — this builds compliance mapping intuition.

---

## TIER REFERENCE

| Feature | Tier |
|---|---|
| NIST CSF Compliance Mapping | Enterprise |
| ISO 27001 Control Mapping | Enterprise |
| PCI-DSS Requirement Mapping | Enterprise |
| OWASP Top 10 Mapping | Enterprise |
| HIPAA / SOX / GDPR Templates | Enterprise |
| Cross-Framework Correlation | Enterprise |
| Custom Framework Templates | Enterprise |
| Compliance Report Generation (PDF) | Enterprise |
| Standard Report Generation (PDF/HTML/JSON/CSV/XML) | Free |
