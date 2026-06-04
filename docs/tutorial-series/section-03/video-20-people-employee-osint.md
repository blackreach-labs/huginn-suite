# VIDEO 20: People/Employee OSINT
### Employee Discovery, Role Mapping & Organizational Charts
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Footprinting & Reconnaissance

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 3 title card "OSINT and Intelligence Gathering"]**

> "Welcome back to the Huginn tutorial series. In this video we're covering People and Employee OSINT — the art of gathering intelligence about an organization's personnel without ever touching their infrastructure directly. In a real engagement, understanding who works at a company, what roles they hold, and how they're structured tells you who has access to what, who's likely to be a phishing target, and what email patterns the organization uses."

**[Screen: Slide showing attack chain with "Recon (OSINT)" phase highlighted — people silhouettes with organizational connections]**

> "This is purely passive reconnaissance. We're querying public data sources, analyzing publicly available profiles, and correlating information — all without sending a single packet to the target. We'll use a fictional company hosted on our own infrastructure for this demonstration, so no real individuals are involved. If you haven't watched Video 17 on Subdomain Discovery, that provides useful context on how we identify target domains before people searches (see Video 17: Subdomain Discovery)."

---

## SECTION 1: Why People OSINT Matters (1:30 – 3:30)

**[Screen: Slide titled "The Human Attack Surface" — showing interconnections between employees, email, social media, and organizational access]**

> "People are the most exploitable attack surface in any organization. Technical controls can be hardened, but humans make mistakes — they reuse passwords, click phishing links, and leak information on social media. Understanding the people behind a target organization gives you several tactical advantages."

**[Screen: Bullet list appearing one by one — "Email pattern discovery", "Phishing target identification", "Organizational structure mapping", "Role-based access inference", "Social engineering pretexting"]**

> "First, email pattern discovery. If you know that John Smith's email is j.smith@company.com, you can predict every employee's email address. Second, phishing target identification — executives, IT administrators, and finance staff are high-value targets. Third, organizational structure mapping reveals reporting chains and who has authority to approve actions. Fourth, role-based access inference — a database administrator likely has production database credentials. Fifth, all of this feeds social engineering pretexts for authorized engagements."

**[Screen: Diagram showing the flow: "Public Sources → Name Collection → Email Pattern → Org Chart → Attack Planning"]**

> "The workflow is straightforward. We collect names from public sources, identify the email naming convention, build an organizational chart, and use all of this to inform our attack planning. Huginn's People Intel Engine automates much of this process using multiple OSINT data sources."

---

## SECTION 2: Huginn People Intel Interface (3:30 – 5:30)

**[Screen: Huginn application — navigating from Home → OSINT & Intelligence → People/Employee search tab]**

> "Open Huginn and navigate to the OSINT and Intelligence page from the sidebar. You'll see tabs across the top for different OSINT modules. Click the People/Employee tab to open the people intelligence interface."

**[Screen: People search page — highlighting the target input field, domain field, and search type dropdown]**

> "The interface has three key inputs. The Target field accepts a person's name, a username, or a company name depending on your search type. The Domain field is optional — enter the target organization's domain if known, and Huginn will use it for email pattern generation. The Search Type dropdown lets you choose between Full Person Intel, Username Search, Email Enumeration, Social Profiles, Professional Networks, or Contact Discovery."

**[Screen: People search page — showing the module selection checkboxes and the results panel below]**

> "Below the inputs, you'll see module toggles. These control which intelligence sources Huginn queries — social platforms, professional networks, public records, email validation services. You can enable or disable individual modules depending on what intelligence you need. The results panel below shows findings organized by category as they come in."

**[Screen: Showing the "Full Person Intel" option selected — all sub-modules visible]**

> "For a comprehensive assessment, select Full Person Intel. This runs all available modules in parallel — social profiles, professional networks, username correlation, email enumeration, and contact discovery. It's the broadest search option and gives you the most complete picture."

---

## SECTION 3: Setting Up the Demo Environment (5:30 – 7:30)

**[Screen: Browser showing a fictional company website "Meridian Technologies" on own infrastructure — staff directory page visible]**

> "For this demonstration, we've set up a fictional company called Meridian Technologies on our own infrastructure. This company website includes a staff directory, an about page with leadership bios, and a careers page. None of these are real people — they're test profiles created specifically for this demo."

**[Screen: The fictional staff directory showing names, titles, and departments]**

> "The staff directory lists employees with names, job titles, and department affiliations. In the real world, many companies expose similar information through their websites, LinkedIn company pages, or press releases. Our demo mirrors this real-world exposure pattern."

```
Demo Infrastructure:
  Domain: meridian-tech-demo.own-infra.local
  Staff Directory: /about/team
  Company Size: 25 fictional employees
  Departments: Engineering, Finance, Operations, Executive
```

**[Screen: Huginn People Intel interface — entering company name and domain]**

> "In Huginn, set the target to 'Meridian Technologies' and enter our demo domain in the Domain field. We'll start with Email Enumeration to discover the naming convention, then run a Full Person Intel search on specific individuals."

---

## SECTION 4: Email Pattern Discovery (7:30 – 9:30)

**[Screen: Selecting "Email Enumeration" search type — entering the demo domain]**

> "Select Email Enumeration as the search type and enter the demo domain. This module attempts to determine the email naming convention used by the organization. It queries certificate transparency logs, search engine caches, and public data aggregators — all passive sources."

**[Screen: Clicking "Start Search" — progress indicator showing modules being queried]**

> "Click Start Search. Watch the progress indicators — Huginn is querying multiple sources in parallel. The email enumeration module checks for common patterns like first.last, f.last, first_last, and flast against known data."

```bash
[OSINT] Email Enumeration starting for meridian-tech-demo.own-infra.local
[OSINT] Querying certificate transparency logs...
[OSINT] Checking public data aggregators...
[OSINT] Generating email pattern candidates...

[OSINT] Discovered email pattern: {first}.{last}@meridian-tech-demo.own-infra.local
[OSINT] Confidence: High (4 confirmed matches)
[OSINT] Confirmed addresses:
  → sarah.chen@meridian-tech-demo.own-infra.local
  → michael.torres@meridian-tech-demo.own-infra.local
  → david.patel@meridian-tech-demo.own-infra.local
  → jennifer.kowalski@meridian-tech-demo.own-infra.local

[OSINT] Alternative patterns detected:
  → s.chen (initial.last) — 1 match found
  → No firstname-only pattern detected

[OSINT] Email enumeration complete: 4 addresses confirmed, pattern identified
```

**[Screen: Results panel showing the identified email pattern and confirmed addresses]**

> "Huginn identified the first.last pattern with high confidence — it found four confirmed matches from public sources. This is the most common corporate email format. Now that we have the pattern, we can generate probable email addresses for any employee whose name we discover from other sources."

**[Screen: Showing the "Generate Email Dorks" sub-results — Google dork queries for finding more emails]**

> "Notice the Generate Email Dorks section in the results. Huginn produces ready-to-use search engine queries that help find additional email addresses exposed in public documents, mailing lists, or cached web pages. These are passive queries against search engines — not against the target directly."

---

## SECTION 5: Full Person Intelligence Gathering (9:30 – 12:00)

**[Screen: Switching search type to "Full Person Intel" — entering a fictional employee name "Sarah Chen"]**

> "Now let's run a full person intelligence search on one of our discovered employees. Switch to Full Person Intel and enter 'Sarah Chen' with the company domain still set. This runs all OSINT modules simultaneously."

**[Screen: Clicking Start — progress bars for each module advancing: Social Profiles, Professional Networks, Username Search, Contact Discovery]**

> "Watch the parallel execution. Social Profiles checks dozens of platforms for accounts matching the name. Professional Networks queries LinkedIn-style platforms. Username Search tries common username derivations across hundreds of sites. Contact Discovery correlates contact information from public data."

```bash
[OSINT] Full Person Intel: Sarah Chen @ meridian-tech-demo.own-infra.local
[OSINT] Running 5 modules in parallel...

[SOCIAL] Checking 40+ platforms for 'sarah.chen' variants...
[SOCIAL] Found: GitHub profile (sarah-chen-dev)
[SOCIAL] Found: Twitter/X profile (@sarahchen_tech)
[SOCIAL] Found: Personal blog (sarahchen.dev)

[PROFESSIONAL] Checking professional networks...
[PROFESSIONAL] Found: LinkedIn-style profile — "Senior DevOps Engineer at Meridian Technologies"
[PROFESSIONAL] Title: Senior DevOps Engineer
[PROFESSIONAL] Location: Portland, OR
[PROFESSIONAL] Previous: Cloud Engineer at TechCorp (2019-2022)

[USERNAME] Generating variants: sarah.chen, sarahchen, s.chen, sarah_chen...
[USERNAME] Checking 200+ platforms...
[USERNAME] Matches: 6 platforms confirmed

[CONTACT] Contact discovery for sarah.chen...
[CONTACT] Email confirmed: sarah.chen@meridian-tech-demo.own-infra.local
[CONTACT] Pattern match: first.last

[OSINT] Full Person Intel complete — 4/5 modules returned results
```

**[Screen: Results organized by category — Social Profiles tab, Professional Networks tab, Username Correlation tab]**

> "The results are organized into tabs by category. The Social Profiles tab shows where this person has accounts — GitHub, Twitter, a personal blog. Professional Networks reveals their job title, location, and employment history. The Username Correlation tab maps which platforms share the same username variant."

**[Screen: Highlighting the "Role & Access Inference" section showing DevOps role implications]**

> "Notice the Role and Access Inference section. Based on the job title 'Senior DevOps Engineer', Huginn flags likely access patterns — cloud platform credentials, CI/CD pipeline access, container orchestration, infrastructure-as-code repositories. This intelligence directly informs attack path planning for authorized engagements."

---

## SECTION 6: Building an Organizational Chart (12:00 – 14:30)

**[Screen: Running multiple Full Person Intel searches — results accumulating for different fictional employees]**

> "To build an organizational chart, we repeat this process for multiple employees. Let's run searches for several people from our fictional staff directory — the CTO, a finance manager, and an IT administrator. In a real engagement, you'd iterate through every name you discover."

```bash
[OSINT] Full Person Intel: James Morrison
[PROFESSIONAL] Title: Chief Technology Officer at Meridian Technologies
[PROFESSIONAL] Reports: Board of Directors
[PROFESSIONAL] Direct Reports: Engineering, DevOps, Security

[OSINT] Full Person Intel: Amanda Rivers  
[PROFESSIONAL] Title: Finance Manager at Meridian Technologies
[PROFESSIONAL] Department: Finance & Operations
[PROFESSIONAL] Certifications: CPA, CISA

[OSINT] Full Person Intel: Robert Kim
[PROFESSIONAL] Title: IT Systems Administrator at Meridian Technologies
[PROFESSIONAL] Skills: Active Directory, Azure, VMware, Networking
[PROFESSIONAL] Certifications: MCSE, Azure Administrator
```

**[Screen: Huginn's organizational chart visualization — tree structure showing hierarchy with role-based color coding]**

> "Huginn can visualize the collected intelligence as an organizational chart. The tree structure shows reporting relationships — CTO at the top of the technology branch, with engineers and IT staff below. Color coding indicates inferred access levels — red for high-privilege roles like administrators, orange for management, green for standard users."

**[Screen: Showing the "Export Org Chart" button — JSON and visual formats available]**

> "Export the organizational chart in JSON format for integration with other tools, or as a visual diagram for your engagement report. This mapping identifies key targets — the IT administrator with Active Directory access, the CTO with broad system access, finance staff who can authorize wire transfers."

**[Screen: Slide showing "High-Value Targets" summary with roles and why they matter]**

> "From just passive OSINT, we've identified that Robert Kim manages Active Directory and Azure infrastructure — making him a prime target for credential phishing. Sarah Chen has DevOps access to production infrastructure. Amanda Rivers handles financial systems and has compliance certifications. Each person represents a potential attack vector in an authorized engagement."

---

## SECTION 7: Certification Mapping and Practice (14:30 – 16:00)

**[Screen: Slide showing certification mapping — OSCP: Information Gathering, CEH: Footprinting & Reconnaissance (Module 2)]**

> "People OSINT maps to the OSCP Information Gathering domain — specifically the passive reconnaissance objectives. For CEH, this falls under Module 2: Footprinting and Reconnaissance, covering company employee enumeration, email harvesting, and organizational intelligence gathering."

**[Screen: Bullet list of exam-relevant techniques — "Email pattern identification", "Organizational mapping", "Passive information sources"]**

> "For exam preparation, practice identifying email patterns from minimal information, mapping organizational structures from public profiles, and using passive sources to build target intelligence without alerting the target. The key distinction tested in both certifications is passive versus active — everything we did today generated zero network traffic to the target."

**[Screen: Slide listing practice resources — "THM OSINT rooms", "Own test infrastructure practice"]**

> "For hands-on practice, TryHackMe has several OSINT-focused rooms that test people enumeration skills. You can also set up your own fictional company profiles as we did here and practice correlation techniques. The skill transfers directly to real engagements."

---

## OUTRO (16:00 – end)

**[Screen: Summary slide — "People/Employee OSINT: Email Discovery, Profile Correlation, Org Chart Construction | Next: Video 21 — Social Media Intelligence"]**

> "That's People and Employee OSINT in Huginn. We covered email pattern discovery to predict corporate addresses, full person intelligence searches that correlate profiles across platforms, and organizational chart construction to map the human attack surface. All of it passive — no direct target interaction. In the next video, we'll go deeper into Social Media Intelligence — analyzing activity patterns, metadata extraction, and platform correlation for individual targets. See you there."
