# VIDEO 8: SMTP Enumeration
### User Verification, Relay Testing & Banner Grabbing
**Suggested length:** 12–16 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 0:45)

**[Screen: Huginn main dashboard with the Recon & Enumeration page open. Section 2 playlist sidebar visible.]**

> "Welcome back to the Huginn tutorial series. In this video we're covering SMTP enumeration — one of the most overlooked reconnaissance techniques that can reveal valid usernames on a target mail server. If you've done your port scan and spotted port 25 or 587 open, this is your next move. We'll connect to an SMTP server, grab its banner, and use three different techniques — VRFY, EXPN, and RCPT TO — to enumerate valid users. All of this is built right into Huginn's recon module, so let's get started."

---

## SECTION 1: Understanding SMTP and Why It Matters (0:45 – 2:30)

**[Screen: Slide showing SMTP protocol diagram — MUA → MTA → MDA flow with port numbers 25, 465, 587 labeled.]**

> "SMTP — Simple Mail Transfer Protocol — is the standard protocol for sending email between servers. It typically runs on port 25 for server-to-server communication, port 587 for authenticated client submission, and historically port 465 for SMTPS. From a pentester's perspective, SMTP is interesting because many mail servers still respond to user verification commands. If the server confirms whether an email address exists, we can build a list of valid usernames — and usernames are half the battle when it comes to brute-forcing credentials or crafting phishing campaigns."

**[Screen: Terminal showing a basic telnet connection to port 25 with a 220 banner response.]**

> "When you connect to an SMTP server, it greets you with a banner — usually a 220 response code followed by the server hostname and software version. That banner alone can tell you what mail server software is running, which helps with version-specific vulnerability lookups. But the real value comes from the enumeration commands: VRFY asks the server to verify a username exists, EXPN asks it to expand a mailing list, and RCPT TO tests whether the server will accept mail for a given address. Not every server responds to all three, so Huginn tries each method automatically."

---

## SECTION 2: Huginn SMTP Scanner Interface (2:30 – 4:30)

**[Screen: Huginn Recon & Enumeration page → Service Scanners tab → SMTP selected from the protocol dropdown.]**

> "In Huginn, navigate to the Recon and Enumeration page — you'll find it in the left sidebar under the Recon phase. Click into Service Scanners and select SMTP from the protocol dropdown. You'll see the SMTP enumeration panel with fields for your target configuration."

**[Screen: Close-up of the SMTP configuration panel showing Target IP, Port, Domain, HELO Name, and Wordlist fields.]**

> "The interface gives you five configuration options. Target is the IP or hostname of the mail server. Port defaults to 25 but you can change it to 587 if that's what your port scan revealed. The Domain field is used for RCPT TO testing — it's the domain portion of the email addresses you're testing. HELO Name is the identity Huginn announces when connecting — 'test.local' works fine for lab environments. And finally, the Wordlist field lets you point to a username list. Huginn ships with a default list of common usernames like admin, root, postmaster, and test, but you can load your own."

**[Screen: Wordlist file browser dialog showing `/usr/share/wordlists/` directory.]**

> "For a real engagement you'd use a targeted wordlist — maybe names gathered from LinkedIn OSINT or a company directory. For this demo we'll use the built-in defaults first, then swap in a custom list."

---

## SECTION 3: Configuration Options (4:30 – 6:00)

**[Screen: SMTP panel with all fields filled in — Target: 10.10.10.7, Port: 25, Domain: beep.localdomain, HELO: test.local, Wordlist: default.]**

> "Let's configure our scan against today's target — HTB Beep at 10.10.10.7. We know from our earlier port scan that port 25 is open and running Postfix. I'll set the domain to beep.localdomain based on what the banner told us, and we'll start with the default wordlist."

**[Screen: Advanced options expanded showing Timeout, Max connections, and Enumeration method dropdowns (VRFY, EXPN, RCPT TO, All).]**

> "Under advanced options you can set the connection timeout — important for slow or rate-limited servers — the maximum concurrent connections, and most importantly, the enumeration method. VRFY is the most direct approach but many modern servers disable it. EXPN is even less commonly available. RCPT TO is the most reliable because servers have to accept or reject recipient addresses to function — so even hardened servers typically respond to this. The 'All' option tries each method in sequence and reports which ones worked. For this demo we'll use All to see the full picture."

---

## SECTION 4: Live Demonstration — SMTP Enumeration (6:00 – 10:30)

**[Screen: Huginn SMTP scanner ready to run with Start Scan button highlighted. Target: HTB "Beep" (10.10.10.7).]**

> "Everything's configured. Let's hit Start Scan and watch Huginn work through the enumeration."

```bash
# Huginn connects to SMTP server
HELO test.local
250 beep.localdomain

# VRFY technique - verifying individual users
VRFY root
252 2.0.0 root
VRFY admin
550 5.1.1 <admin>: Recipient address rejected
VRFY postmaster
252 2.0.0 postmaster

# EXPN technique - expanding distribution lists
EXPN root
502 5.5.2 Error: command not recognized

# RCPT TO technique - testing recipient acceptance
MAIL FROM:<test@test.local>
250 2.1.0 Ok
RCPT TO:<root@beep.localdomain>
250 2.1.5 Ok
RCPT TO:<admin@beep.localdomain>
550 5.1.1 <admin@beep.localdomain>: Recipient address rejected
RCPT TO:<asterisk@beep.localdomain>
250 2.1.5 Ok
```

**[Screen: Huginn output panel showing real-time results with green "Valid user" entries and amber "Rejected" entries.]**

> "Watch the output panel. Huginn starts by connecting and sending the HELO command. Then it works through each enumeration method. With VRFY, we get 252 responses for valid users — that's the server saying 'I'll attempt delivery' without fully confirming. A 550 means the address is rejected. You can see EXPN returns a 502 — command not recognized — which is common on hardened servers. But RCPT TO works beautifully here. A 250 response means the server accepts that recipient, confirming the user exists. A 550 rejection means no such mailbox."

**[Screen: Results summary panel showing discovered users: root, postmaster, asterisk, fanis, cyrus.]**

> "After running through the wordlist, Huginn found five valid users: root, postmaster, asterisk, fanis, and cyrus. The 'asterisk' user is particularly interesting — that tells us this machine is likely running Asterisk PBX, which is consistent with the 'Beep' machine's Elastix installation. These usernames are now attack surface — we can try them against SSH, the web login, or any other authenticated service on this box."

**[Screen: Huginn running a second scan with a custom wordlist loaded from a file.]**

> "Now let's swap in a custom wordlist. I've got one with Elastix-specific usernames. Click the wordlist browse button, select your file, and run again. This time Huginn finds additional service accounts tied to the PBX system. The takeaway: your wordlist quality directly determines your enumeration coverage."

---

## SECTION 5: Results Interpretation (10:30 – 13:00)

**[Screen: Huginn results panel showing categorized output — Valid Users section, Server Info section, and Method Availability section.]**

> "Let's break down the results. Huginn organizes SMTP findings into three categories. First, Valid Users — this is your gold. Each confirmed username is a potential credential to test elsewhere. Second, Server Information — the banner, supported commands, and any version strings. Third, Method Availability — which enumeration techniques the server actually responded to. On this target, VRFY and RCPT TO worked but EXPN was disabled."

**[Screen: Side-by-side comparison of SMTP response codes — 250, 251, 252, 450, 451, 550, 553 with explanations.]**

> "Understanding response codes is critical. A 250 is a definitive yes — the mailbox exists and the server will deliver. A 252 means the server can't verify locally but will attempt delivery — it's still a positive indicator. A 550 is a hard no — the mailbox doesn't exist. And 450 or 451 are temporary failures that might warrant a retry. Huginn handles this interpretation automatically, but knowing the codes helps you validate findings manually if needed."

**[Screen: Export dialog showing options to save results as JSON, CSV, or copy to clipboard.]**

> "You can export these results for use in other tools. Copy the valid username list to feed into a brute-force attack against SSH, or export the full results as JSON to include in your engagement notes. These findings also feed directly into Huginn's Findings module if you want to document them formally."

---

## SECTION 6: OSCP Exam Tips and Practice (13:00 – 14:30)

**[Screen: Slide showing "OSCP Relevance: Information Gathering — Active Reconnaissance" with bullet points.]**

> "For OSCP preparation, SMTP enumeration falls under Active Information Gathering. On the exam, when you see port 25 open, always attempt user enumeration — the valid usernames you discover often lead to password reuse on other services. Time-saving tip: start with RCPT TO since it's the most reliable method, and use a focused wordlist rather than a massive one. Five minutes of targeted SMTP enumeration can save you an hour of blind brute-forcing."

**[Screen: HTB machine recommendations — "Beep" for SMTP + web stack, "Sneaky" for SMTP + IPv6.]**

> "For additional practice, HTB Beep — which we used today — combines SMTP enumeration with a complex web application stack. It's excellent for chaining enumeration findings into exploitation. Also check out the smtp-user-enum standalone tool documentation to understand what Huginn automates under the hood (see Video 6: Port Scanning for how to identify these services initially)."

---

## OUTRO (14:30 – end)

> "That's SMTP enumeration in Huginn. We covered the protocol basics, walked through all three enumeration techniques — VRFY, EXPN, and RCPT TO — and demonstrated how valid usernames become the starting point for further attacks. In the next video, we'll look at SNMP enumeration, which can reveal even more information about a target including running processes, installed software, and network configuration. See you there."
