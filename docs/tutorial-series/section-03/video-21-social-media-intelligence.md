# VIDEO 21: Social Media Intelligence
### Platform Correlation, Activity Analysis & Digital Footprint
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Footprinting & Reconnaissance

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 3 title card "OSINT and Intelligence Gathering"]**

> "Welcome back to the Huginn tutorial series. In this video we're covering Social Media Intelligence — SOCMINT — the discipline of extracting actionable intelligence from social media platforms. People share enormous amounts of information online — location check-ins, workplace photos showing monitor screens, technology stack mentions, and personal details that feed social engineering. Huginn's Social Media Engine automates the collection and correlation of this public data."

**[Screen: Slide showing interconnected social platform icons — Twitter/X, LinkedIn, GitHub, Facebook, Instagram — with data flowing between them]**

> "The key challenge in social media intelligence isn't finding one profile — it's correlating identities across platforms and extracting patterns from public activity. A username on Twitter might link to a GitHub account that reveals code repositories, which links to a LinkedIn profile confirming their employer. Huginn handles this correlation automatically. We'll use our own test accounts for this demonstration — no real individuals are targeted (see Video 20: People/Employee OSINT for how we identify targets)."

---

## SECTION 1: Social Media Intelligence Methodology (1:30 – 3:30)

**[Screen: Slide titled "SOCMINT Collection Framework" — showing five phases: Discovery → Correlation → Content Analysis → Timeline Recon → Metadata Extraction]**

> "Social media intelligence follows a structured methodology. First, Account Discovery — finding which platforms a target uses. Second, Platform Correlation — linking accounts across different services. Third, Content Analysis — examining what they post, comment on, and share. Fourth, Timeline Reconnaissance — identifying activity patterns, working hours, and travel schedules. Fifth, Metadata Extraction — pulling technical details from images, documents, and profile data."

**[Screen: Diagram showing data categories: "Identity Data", "Location Data", "Technical Data", "Behavioral Data", "Network Data"]**

> "Each platform leaks different intelligence categories. Professional networks expose career data and organizational connections. Code repositories reveal technology stacks and sometimes hardcoded credentials. Photo-sharing platforms leak GPS coordinates in EXIF data. Microblogging platforms expose opinions, schedules, and real-time location. Huginn's engine categorizes all findings into these five intelligence types automatically."

**[Screen: Slide with important note: "All passive — public data only — no login required — no direct interaction with target accounts"]**

> "Critical point — all of this is passive. We're accessing publicly available information. We don't log into any platform, we don't send messages or follow requests, and we don't interact with the target's accounts in any way. This is observation of public data, not unauthorized access."

---

## SECTION 2: Huginn Social Media Interface (3:30 – 5:30)

**[Screen: Huginn application — navigating to OSINT & Intelligence → Social Media Intelligence tab]**

> "Navigate to the OSINT and Intelligence page and select the Social Media Intelligence tab. The interface presents five analysis modes matching our methodology: Account Discovery, Content Analysis, Network Mapping, Timeline Recon, and Metadata Extraction. There's also a Full Social Intel option that runs all five."

**[Screen: Social Media Intelligence page — highlighting the target input, platform selection toggles, and analysis mode dropdown]**

> "The target input accepts a username, full name, or URL to a specific profile. Below that, platform toggles let you enable or disable specific platforms — Twitter/X, LinkedIn, GitHub, Facebook, Instagram, Reddit, and others. The analysis mode dropdown selects which intelligence module to run."

**[Screen: Showing the "Account Discovery" mode selected — platform checkboxes all enabled, depth slider set to "Standard"]**

> "Account Discovery is usually your first step. It takes a username or name and searches across all enabled platforms for matching accounts. The depth slider controls how many username variations Huginn generates and tests — Standard checks common variants, Deep generates dozens of permutations including initials, numbers, and platform-specific patterns."

**[Screen: Showing the results layout — tabs for each finding category with count badges]**

> "Results organize into tabs with count badges showing how many findings each category returned. You can drill into individual results for full details or use the unified view to see everything in a timeline format."

---

## SECTION 3: Account Discovery Demo (5:30 – 8:00)

**[Screen: Entering the test account username "alex_meridian_test" into the target field — selecting Account Discovery mode]**

> "Let's run Account Discovery against one of our test accounts. We've created a test persona called 'alex_meridian_test' across several platforms specifically for this demonstration. Enter the username and select Account Discovery. All platforms are enabled."

**[Screen: Clicking Start — progress showing platforms being checked in parallel]**

> "Click Start. Huginn checks each platform in parallel — you can see the progress indicators for each. It's looking for exact matches first, then trying common variations of the username."

```bash
[SOCMINT] Account Discovery starting for: alex_meridian_test
[SOCMINT] Checking 45 platforms in parallel...
[SOCMINT] Generating username variants: alex_meridian_test, alexmeridiantest, 
          alex.meridian.test, alex-meridian-test, meridian_alex...

[SOCMINT] FOUND: Twitter/X — @alex_meridian_test (exact match)
         → Bio: "DevOps & Cloud | Portland | Tech enthusiast"
         → Followers: 47 | Following: 112 | Tweets: 234
         → Account created: 2023-06-15

[SOCMINT] FOUND: GitHub — alex-meridian-test (variant match)
         → Bio: "Infrastructure automation"
         → Public repos: 8 | Contributions last year: 156
         → Primary languages: Python, Terraform, YAML

[SOCMINT] FOUND: Reddit — alex_meridian_test (exact match)
         → Karma: 1,247
         → Active subreddits: r/devops, r/aws, r/kubernetes, r/homelab

[SOCMINT] FOUND: LinkedIn — alexmeridiantest (variant match)
         → Title: "DevOps Engineer at Meridian Technologies"
         → Location: Portland, OR

[SOCMINT] FOUND: Instagram — alex.meridian.test (variant match)
         → Posts: 89 | Followers: 156
         → Bio: "Pacific NW | Coffee & Code"

[SOCMINT] NOT FOUND: Facebook (no public profile)
[SOCMINT] NOT FOUND: TikTok (no match)

[SOCMINT] Account Discovery complete: 5 platforms confirmed, 2 not found
[SOCMINT] Username correlation confidence: HIGH (same bio elements across platforms)
```

**[Screen: Results showing 5 confirmed accounts with platform icons, profile snippets, and correlation indicators]**

> "Five confirmed accounts across Twitter, GitHub, Reddit, LinkedIn, and Instagram. Notice the correlation confidence rating — Huginn detected matching bio elements and consistent identity markers across platforms, giving us high confidence these all belong to the same person. The GitHub account uses a hyphenated variant, Instagram uses dots — Huginn's variant generation caught both patterns."

---

## SECTION 4: Content Analysis and Network Mapping (8:00 – 10:30)

**[Screen: Switching to "Content Analysis" mode — selecting the discovered Twitter account]**

> "Now let's analyze the content from these accounts. Switch to Content Analysis mode. Huginn pulls publicly available posts, comments, and shared content to extract intelligence. We'll focus on the Twitter account first."

```bash
[SOCMINT] Content Analysis: @alex_meridian_test (Twitter/X)
[SOCMINT] Analyzing 234 public tweets...

[SOCMINT] Technology mentions extracted:
  → AWS (mentioned 34 times) — EC2, S3, Lambda, EKS
  → Kubernetes (22 mentions) — specifically EKS and Helm charts
  → Terraform (18 mentions) — infrastructure-as-code
  → Jenkins (8 mentions) — CI/CD pipeline
  → Python (12 mentions) — automation scripts

[SOCMINT] Keyword clusters:
  → "deployment" + "production" — suggests production access
  → "on-call" + "incident" — indicates operational responsibilities
  → "migrating" + "aws" — current infrastructure project

[SOCMINT] Sentiment indicators:
  → Frustration with "legacy systems" — possible technical debt
  → Positive mentions of "new monitoring stack"

[SOCMINT] Content Analysis complete: 94 unique technology/tool references extracted
```

**[Screen: Results showing a word cloud of mentioned technologies and a categorized list of extracted intelligence]**

> "The content analysis extracted 94 unique technology references from public tweets. We now know this person works heavily with AWS — specifically EKS for Kubernetes, uses Terraform for infrastructure management, and runs Jenkins for CI/CD. They've mentioned production deployments and on-call responsibilities, confirming operational access to live systems."

**[Screen: Switching to "Network Mapping" mode — showing connection analysis]**

> "Network Mapping analyzes public connections and interactions. It identifies who the target communicates with most frequently, what organizations those contacts belong to, and maps the professional network."

```bash
[SOCMINT] Network Mapping: alex_meridian_test
[SOCMINT] Analyzing public interactions across 5 platforms...

[SOCMINT] Top interactions (public):
  → @meridian_devops_team (colleague — same organization)
  → @sarah_chen_dev (colleague — frequent code review interactions on GitHub)
  → @cloudnative_portland (local meetup group)

[SOCMINT] Organizational connections:
  → 4 accounts identified as likely Meridian Technologies colleagues
  → Active in Portland tech community groups
  → Attends CloudNative Portland meetups (public RSVPs)

[SOCMINT] Network Mapping complete: 4 organizational links, 12 community connections
```

**[Screen: Network graph visualization showing connections between discovered profiles and organizational links]**

> "The network graph visualizes these relationships. Our test persona is connected to four other accounts at the same organization — confirming team structure. Public meetup RSVPs reveal physical presence in Portland, which could inform physical social engineering in an authorized engagement."

---

## SECTION 5: Timeline Reconnaissance (10:30 – 12:30)

**[Screen: Selecting "Timeline Recon" mode — date range selector visible]**

> "Timeline Reconnaissance analyzes when the target is active to establish behavioral patterns. This reveals working hours, time zones, travel schedules, and break periods. Select Timeline Recon mode."

```bash
[SOCMINT] Timeline Recon: alex_meridian_test
[SOCMINT] Analyzing activity timestamps across 5 platforms (90 days)...

[SOCMINT] Activity patterns:
  → Peak activity: Mon-Fri, 09:00-17:00 PST (working hours)
  → Secondary peak: Mon-Thu, 20:00-22:00 PST (personal browsing)
  → Minimal activity: Sat-Sun (occasional posts)
  → Time zone: PST/PDT (consistent across all platforms)

[SOCMINT] Notable patterns:
  → GitHub commits cluster: 10:00-12:00 and 14:00-16:00 weekdays
  → No activity: Dec 23 – Jan 2 (holiday break)
  → Reduced activity: Every other Friday (possible flex schedule)
  → 3-day gap in March (possible travel/conference — Instagram post from Denver)

[SOCMINT] Behavioral summary:
  → Standard business hours (Pacific Time)
  → Consistent daily routine
  → Flex Fridays (biweekly)
  → Annual conference attendance

[SOCMINT] Timeline Recon complete
```

**[Screen: Heat map visualization showing activity by hour and day of week — darker cells indicating higher activity]**

> "The heat map shows clear patterns. Heavy weekday activity during business hours, with a secondary evening spike. Almost no weekend activity. This tells us phishing emails sent during working hours are most likely to be seen quickly. The three-day gap with a Denver Instagram post suggests conference travel — a period when the target might be using unfamiliar networks or be distracted."

**[Screen: Calendar view showing the activity gaps and their potential explanations]**

> "The calendar view highlights anomalies — the holiday break, the flex Fridays, the travel period. Every gap and pattern is potentially useful intelligence. For an authorized phishing engagement, you'd time your campaign to coincide with return-from-vacation periods when people have full inboxes and reduced attention."

---

## SECTION 6: Metadata Extraction (12:30 – 14:30)

**[Screen: Selecting "Metadata Extraction" mode — showing what data sources it analyzes]**

> "The final module is Metadata Extraction. This pulls technical metadata from publicly shared images, documents, and profile information. It's looking for EXIF data in photos, document properties, and machine-identifiable information embedded in shared content."

```bash
[SOCMINT] Metadata Extraction: alex_meridian_test
[SOCMINT] Analyzing metadata from public content...

[SOCMINT] Profile metadata:
  → Account creation dates mapped (earliest: GitHub 2019, latest: Instagram 2023)
  → Email patterns: consistent use of alex.meridian format
  → Profile photo: same image across 3 platforms (identity confirmation)

[SOCMINT] Image EXIF analysis (Instagram public posts):
  → 12 of 89 posts contain GPS coordinates
  → Location cluster: Portland, OR metro area (home/office)
  → 3 images from Denver, CO (conference trip — correlates with timeline gap)
  → Camera: iPhone 14 Pro (device identification)

[SOCMINT] Document metadata (GitHub repos):
  → Git author email: alex.chen@meridian-tech-demo.own-infra.local
  → Commit signatures: GPG key ID 0xABCD1234
  → Common IDE: VS Code (identified from .vscode configs in repos)
  → OS: macOS (identified from .DS_Store files and path separators)

[SOCMINT] Technical fingerprint:
  → Primary device: macOS + iPhone 14 Pro
  → Primary IDE: VS Code
  → Git email reveals corporate email address
  → GPG key usage indicates security awareness

[SOCMINT] Metadata Extraction complete: 23 metadata artifacts collected
```

**[Screen: Results showing extracted metadata organized by type — Device Info, Location Data, Technical Fingerprint, Identity Markers]**

> "The metadata extraction reveals significant intelligence. EXIF data from Instagram photos pinpoints locations and identifies the device — an iPhone 14 Pro. GitHub commits leaked the corporate email address in the git author field, confirmed the naming pattern we identified earlier, and revealed they use macOS with VS Code. The GPG key usage actually indicates some security awareness — useful for calibrating social engineering difficulty."

**[Screen: Map visualization showing location clusters from EXIF data]**

> "The location map plots GPS coordinates extracted from public images. We see a tight cluster in Portland — likely home and office locations — plus the Denver conference trip. All from publicly shared photos with EXIF data intact. This is why security-conscious individuals strip metadata before posting, and why checking for it is valuable reconnaissance."

---

## SECTION 7: Certification Mapping and Practice (14:30 – 16:00)

**[Screen: Slide showing certification mapping — OSCP: Information Gathering (Passive Recon), CEH: Module 2 Footprinting & Reconnaissance]**

> "Social Media Intelligence maps to OSCP's Information Gathering domain — specifically passive reconnaissance techniques. For CEH, this is Module 2: Footprinting and Reconnaissance, covering social media footprinting, username enumeration, and digital footprint analysis. Both certifications test your ability to extract intelligence without alerting the target."

**[Screen: Bullet list of exam-relevant skills — "Username correlation", "EXIF metadata analysis", "Activity pattern identification", "Passive vs Active distinction"]**

> "For exam preparation, focus on the distinction between passive and active techniques. Everything we demonstrated today is passive — querying public data without authentication or direct interaction. Practice correlating usernames across platforms, extracting metadata from shared files, and identifying behavioral patterns from public timelines."

**[Screen: Practice resources — "THM OSINT rooms", "Own test account practice", "Trace Labs OSINT CTFs"]**

> "For hands-on practice, set up your own test accounts across platforms as we did here. TryHackMe has OSINT-focused rooms that test these skills. Trace Labs runs OSINT CTF events that develop real-world intelligence gathering abilities in a competitive format."

---

## OUTRO (16:00 – end)

**[Screen: Summary slide — "Social Media Intelligence: Account Discovery, Content Analysis, Network Mapping, Timeline Recon, Metadata Extraction | Next: Video 22 — Threat Intelligence"]**

> "That's Social Media Intelligence in Huginn. We covered account discovery and cross-platform correlation, content analysis to extract technology and organizational intelligence, network mapping to identify colleagues and communities, timeline reconnaissance to establish behavioral patterns, and metadata extraction to fingerprint devices and locations. All completely passive against public data. In the next video, we'll shift to Threat Intelligence — using Shodan and VirusTotal APIs to assess the threat landscape around target infrastructure. That's an Enterprise tier feature requiring API keys, so we'll walk through the full setup. See you there."
