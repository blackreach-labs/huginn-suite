# VIDEO 57: Hash Cracking
### Dictionary Attacks, Rule-Based Cracking & Rainbow Tables
**Suggested length:** 14–18 minutes
**License Tier:** Professional
**Certification Relevance:** OSCP: Post-Exploitation (credential cracking) | CEH: Cryptography (hash algorithms, cracking techniques)

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 10 title card "Advanced Features and Workflows" — Hash Cracking module icon (a cracked padlock) fading in]**

> "Welcome back to Section 10. In Video 46 (see Video 46: Credential Harvesting), we extracted password hashes from the Bastion machine — SAM database dumps containing NTLM hashes. Those hashes are useless as-is — you can't log in with a hash alone in most scenarios. You need the plaintext password. That's what hash cracking does: it takes extracted hashes and recovers the original passwords through computational brute force. Today we cover Huginn's integrated hash cracking tools — dictionary attacks, rule-based mutations, mask attacks, and GPU acceleration."

**[Screen: Slide showing the hash cracking workflow: "Extract Hashes → Identify Type → Select Attack Mode → Configure Wordlist/Rules → Crack → Recover Credentials"]**

> "Hash cracking sits in the Elevate phase of the attack chain — you've already gained access, you've harvested hashes, and now you need credentials for lateral movement or privilege escalation. Huginn integrates two cracking backends: its own native Python engine for quick attacks and portability, and hashcat integration for GPU-accelerated performance on larger hash sets. We'll use both today against the NTLM hashes we extracted from HTB Bastion."

---

## SECTION 1: Accessing the Cracking Module (1:30 – 3:00)

**[Screen: Huginn navigation — clicking the Elevate phase icon, then selecting "Cracking" from the submenu]**

> "The hash cracking module lives in the Elevate phase. Click the Elevate icon — the shield with an upward arrow — and select 'Cracking' from the dropdown. This opens the cracking dashboard with five main tabs: Hash Analysis, Attack Configuration, Live Attacks, Results Management, and SSH Key Parser."

**[Screen: Cracking dashboard — showing the five tabs, Hash Analysis tab active with an empty hash input field and "Paste Hashes" / "Import from File" buttons]**

> "The dashboard starts on Hash Analysis. This is where you feed in your hashes. You can paste them directly, import from a file, or — and this is the seamless workflow — import directly from credential harvesting results. If you ran the SAM dump in Video 46, those hashes are already in Huginn's database, ready to load."

**[Screen: "Import from Session" button — showing a dialog listing previous sessions with extracted hashes: "Bastion — 4 NTLM hashes (2024-01-20)"]**

> "Click 'Import from Session' and you'll see previous engagements where hashes were extracted. Our Bastion session has four NTLM hashes from the SAM dump. Select it and the hashes load directly into the cracking module — no manual copy-paste, no file juggling. This is the Professional tier workflow that connects post-exploitation directly to credential recovery."

```bash
# Imported hashes from Bastion SAM dump:
Administrator:500:aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

---

## SECTION 2: Hash Identification and Analysis (3:00 – 5:00)

**[Screen: Hash Analysis tab — showing the auto-detection results for each imported hash with type identification and metadata]**

> "Once hashes are loaded, Huginn's hash analysis engine identifies the type automatically. It examines the hash length, character set, and format to determine the algorithm. Our SAM dump uses the standard format: username, RID, LM hash, NTLM hash. The NTLM hashes are 32 hex characters — MD4-based. Huginn identifies these instantly."

**[Screen: Hash analysis results panel — showing each hash with: identified type (NTLM), length (32 chars), charset (hex), hashcat mode (1000), known-empty indicator]**

> "The analysis shows four hashes. Notice two of them — Guest and DefaultAccount — have the value 31d6cfe0d16ae931b73c59d7e0c089c0. That's the NTLM hash of an empty string. Huginn flags these immediately as 'empty password' — no cracking needed. That leaves two hashes we actually need to crack: Administrator and L4mpje."

```bash
# Hash Analysis Results:
┌───────────────┬──────────┬──────────┬──────────────┬───────────────┐
│ Username      │ Hash Type│ Length   │ Hashcat Mode │ Status        │
├───────────────┼──────────┼──────────┼──────────────┼───────────────┤
│ Administrator │ NTLM     │ 32 chars │ 1000         │ Pending       │
│ Guest         │ NTLM     │ 32 chars │ 1000         │ EMPTY (known) │
│ L4mpje        │ NTLM     │ 32 chars │ 1000         │ Pending       │
│ DefaultAccount│ NTLM     │ 32 chars │ 1000         │ EMPTY (known) │
└───────────────┴──────────┴──────────┴──────────────┴───────────────┘

[*] 2 of 4 hashes identified as empty password (31d6cfe0d16ae931b73c59d7e0c089c0)
[*] 2 hashes remaining for cracking: Administrator, L4mpje
```

**[Screen: Hash lookup tab — checking hashes against known databases (rainbow tables, online lookups)]**

> "Before burning compute cycles on cracking, Huginn checks the hashes against known databases. This 'hash lookup' feature compares your hashes against pre-computed rainbow tables and known-password databases. If someone else has already cracked the same hash, you get the result instantly. For our L4mpje hash — let's see if it's a common password."

```bash
# Hash Lookup Results:
[*] Checking 26112010952d963c8dc4217daec986d9 against known databases...
[+] MATCH FOUND: 26112010952d963c8dc4217daec986d9 → bureaulampje
    Source: Pre-computed NTLM rainbow table
[*] Checking 7a21990fcd3d759941e45c490f143d5f...
[-] No match found — requires active cracking

# Summary: 1 hash cracked via lookup, 1 requires active cracking
```

**[Screen: Results updating — L4mpje now showing "Cracked: bureaulampje" with the Administrator hash still pending]**

> "The L4mpje hash resolved instantly — 'bureaulampje' which is Dutch for 'desk lamp.' It was in the rainbow table because it's a dictionary word. The Administrator hash didn't match any known database, so we'll need to crack it actively. This two-step approach — lookup first, crack second — saves significant time on real engagements where you might have dozens or hundreds of hashes."

---

## SECTION 3: Dictionary Attack (5:00 – 7:30)

**[Screen: Attack Configuration tab — selecting "Dictionary" attack mode, with wordlist selection dropdown showing available lists]**

> "The dictionary attack is your first active cracking approach. It tries every word in a wordlist against the target hash. If the password is a common word, a name, or appears in any breach database, a dictionary attack finds it fast. The key is choosing the right wordlist — too small and you miss the password, too large and it takes forever."

**[Screen: Wordlist selection — showing categories: "Common Passwords" (rockyou.txt — 14M entries), "SecLists/Passwords" (various), "Custom" (user-created), with file size and entry count for each]**

> "Huginn's wordlist manager organizes available wordlists by category and size. The gold standard for NTLM cracking is rockyou.txt — 14 million passwords from a real breach. For faster attempts, you might start with the top 1000 or top 10000 most common passwords. For our Administrator hash, let's start with rockyou.txt — if the admin used any common password, this will find it."

```bash
# Attack Configuration — Dictionary Mode:
Attack Mode: Dictionary (Straight)
Target Hash: 7a21990fcd3d759941e45c490f143d5f (Administrator NTLM)
Wordlist: rockyou.txt (14,344,392 entries)
Engine: Native Python (CPU)
```

**[Screen: Clicking "Start Attack" — live progress showing candidates tested, speed (hashes/second), estimated time remaining]**

> "Click 'Start Attack' and the cracking engine begins. The live attacks panel shows real-time progress — candidates tested, cracking speed, and estimated time remaining. With the native Python engine on CPU, we're getting around 2 million hashes per second for NTLM. That means rockyou.txt completes in about 7 seconds. For stronger hash types like bcrypt, the speed drops dramatically."

```bash
# Live Attack Progress — Dictionary:
[*] Starting dictionary attack on Administrator NTLM hash
[*] Wordlist: rockyou.txt (14,344,392 candidates)
[*] Engine: Native Python (CPU)
[*] Speed: ~2,100,000 H/s

Progress: [████████████████████░░░░] 78%
Tested: 11,188,625 / 14,344,392
Elapsed: 5.3s
ETA: 1.5s

[*] Status: Exhausted — password not found in rockyou.txt
```

**[Screen: Attack completed — "Exhausted" status — password not found in wordlist]**

> "The dictionary attack exhausted the entire wordlist without finding the Administrator password. This means the password isn't in rockyou.txt — it's either a custom password, contains numbers or special characters in an unusual pattern, or it's a longer passphrase. Time to escalate our approach with rule-based attacks."

---

## SECTION 4: Rule-Based Cracking (7:30 – 10:00)

**[Screen: Attack Configuration — switching to "Dictionary + Rules" mode, showing rule file selection: "best64.rule", "d3ad0ne.rule", "dive.rule", "toggles.rule"]**

> "Rule-based cracking takes each word in your dictionary and applies transformations — capitalizing letters, appending numbers, replacing characters with leetspeak, reversing the word, and thousands of other mutations. This dramatically expands your candidate space without needing a larger wordlist. A 14-million word list with best64.rule becomes over 900 million candidates."

**[Screen: Rule examples displayed — showing transformations applied to the word "password": "Password", "password1", "p@ssword", "PASSWORD", "drowssap", "password123!"]**

> "Here's what rules do to a single word like 'password' — capitalize the first letter, append numbers, substitute characters with symbols, uppercase everything, reverse it, append common suffixes. The best64 rule file contains the 64 most statistically effective transformations based on real password analysis. Dive.rule is more aggressive with over 100,000 rules, but takes proportionally longer."

```bash
# Rule-based attack demonstration:
Base word: "summer"
Rules applied (best64.rule sample):
  :        → summer       (no change)
  c        → Summer       (capitalize first)
  $1       → summer1      (append 1)
  $!       → summer!      (append !)
  $1$2$3   → summer123    (append 123)
  sa@      → summer       (replace a→@, no 'a' present)
  ^1       → 1summer      (prepend 1)
  r        → remmus       (reverse)
  d        → summersummer (duplicate)
  C        → sUMMER       (toggle case)
```

**[Screen: Starting rule-based attack — rockyou.txt + best64.rule, showing expanded candidate count and adjusted ETA]**

> "Let's run rockyou.txt with best64.rule. The candidate space jumps from 14 million to over 900 million — every word gets 64 mutations. Speed remains the same per candidate, but the total time increases proportionally. For NTLM at 2 million hashes per second, this takes about 7-8 minutes on CPU."

```bash
# Attack Configuration — Dictionary + Rules:
Attack Mode: Dictionary + Rules
Target Hash: 7a21990fcd3d759941e45c490f143d5f (Administrator)
Wordlist: rockyou.txt (14,344,392 entries)
Rules: best64.rule (64 rules)
Total Candidates: ~918,041,088
Engine: Native Python (CPU)
Speed: ~2,100,000 H/s
Estimated Time: ~7 min 17 sec

[*] Progress: [████░░░░░░░░░░░░░░░░] 22%
[*] Current candidate: "Summer2019!" (rule: c$2$0$1$9$!)
[*] Elapsed: 1m 36s | ETA: 5m 41s
```

**[Screen: Attack progress reaching 45% — a match found notification pops up in green]**

> "And there it is — at 45% through the candidates, we have a hit. The Administrator password was in rockyou.txt but with a transformation applied — a rule mutated the base word to match. Let me show you the result."

```bash
# CRACKED!
[+] Hash cracked: 7a21990fcd3d759941e45c490f143d5f
[+] Password: Secret1234!
[+] Source: rockyou.txt + best64.rule
[+] Base word: "secret" → Rule: c$1$2$3$4$! (capitalize + append "1234!")
[+] Time elapsed: 3m 18s
[+] Candidates tested: 416,220,847

# All hashes resolved:
┌───────────────┬─────────────────┬─────────────────┐
│ Username      │ Password        │ Method          │
├───────────────┼─────────────────┼─────────────────┤
│ Administrator │ Secret1234!     │ Rules (best64)  │
│ L4mpje        │ bureaulampje    │ Hash Lookup     │
│ Guest         │ [empty]         │ Known Empty     │
│ DefaultAccount│ [empty]         │ Known Empty     │
└───────────────┴─────────────────┴─────────────────┘
```

---

## SECTION 5: Mask Attacks and Brute Force (10:00 – 12:00)

**[Screen: Attack Configuration — selecting "Mask / Brute-Force" mode, showing mask syntax explanation and preset masks]**

> "When dictionary and rules fail, mask attacks let you define the password structure and brute-force within that pattern. If you know the password policy requires 8 characters with uppercase, lowercase, and a digit, you can define a mask that only tries combinations matching that pattern. This is far more efficient than pure brute-force because you're not wasting time on impossible candidates."

**[Screen: Mask syntax reference — showing placeholders: ?l (lowercase), ?u (uppercase), ?d (digit), ?s (special), ?a (all), with example masks]**

> "The mask syntax uses placeholders: question-mark-l for lowercase, question-mark-u for uppercase, question-mark-d for digit, question-mark-s for special characters, and question-mark-a for any character. A mask like capital-U followed by seven lowercase characters targets passwords like 'Password' — one uppercase followed by seven lowercase. You can combine these in any order to match expected patterns."

```bash
# Mask Attack Syntax:
?l = lowercase (a-z)         26 chars
?u = uppercase (A-Z)         26 chars
?d = digit (0-9)             10 chars
?s = special (!@#$%...)      33 chars
?a = all printable           95 chars

# Example masks:
?u?l?l?l?l?l?d?d     = "Abcdef12" pattern (8 chars)
?u?l?l?l?l?l?l?d?s   = "Passwor1!" pattern (9 chars)
?d?d?d?d?d?d          = PIN codes (6 digits)

# Mask keyspace calculation:
?u?l?l?l?l?l?d?d = 26 × 26^5 × 10^2 = 30,891,577,600 candidates
```

**[Screen: Configuring a mask attack with ?u?l?l?l?l?l?d?d?s pattern — showing estimated keyspace and time]**

> "If our Administrator password hadn't cracked with rules, we'd try common masks next. For Windows environments, passwords often follow the pattern: capital letter, several lowercase letters, digits, maybe a special character. The mask ?u?l?l?l?l?l?d?d?s covers that pattern — about 8 billion candidates. At GPU speeds that's feasible; at CPU speeds it would take hours."

---

## SECTION 6: GPU Acceleration and Hashcat Integration (12:00 – 14:30)

**[Screen: Settings panel — showing "Cracking Engine" toggle between "Native (CPU)" and "Hashcat (GPU)" with device detection below]**

> "For serious cracking workloads, CPU speed isn't enough. Huginn integrates with hashcat for GPU-accelerated cracking. If you have an NVIDIA or AMD GPU, hashcat can crack NTLM hashes at billions per second — a thousand times faster than CPU. Let's look at the GPU integration."

**[Screen: GPU device detection — showing detected GPU (e.g., "NVIDIA RTX 3080 — 10GB VRAM"), estimated speeds per hash type, and OpenCL status]**

> "Huginn auto-detects available GPUs through the gpu_crack_engine module. It shows your GPU model, available VRAM, and estimated cracking speed per hash type. NTLM is the fastest — modern GPUs achieve 50-100 billion hashes per second. Bcrypt is the slowest — maybe 30,000 per second — because it's specifically designed to resist GPU cracking. This is why password storage algorithms matter."

```bash
# GPU Device Detection:
┌──────────────────────────────────────────────────────────┐
│ GPU Cracking Engine Status                                │
├──────────────────────────────────────────────────────────┤
│ Device: NVIDIA GeForce RTX 3080                          │
│ VRAM: 10 GB                                              │
│ OpenCL: Available (v3.0)                                 │
│ Driver: 535.104.05                                       │
├──────────────────────────────────────────────────────────┤
│ Estimated Speeds:                                        │
│   NTLM:      ~65,000 MH/s (65 billion/sec)             │
│   MD5:       ~55,000 MH/s                               │
│   SHA-256:   ~8,500 MH/s                                │
│   bcrypt:    ~28 kH/s (28,000/sec)                      │
│   SHA-512:   ~2,200 MH/s                                │
│   NetNTLMv2: ~4,000 MH/s                                │
└──────────────────────────────────────────────────────────┘
```

**[Screen: Hashcat integration panel — showing hashcat binary location, rules directory, and available charsets detected automatically]**

> "Hashcat integration is configured in the cracking settings. Huginn looks for hashcat in your tools directory first, then checks the system PATH. Once found, it detects available rule files, charset files, and the potfile location. All hashcat attacks launched from Huginn use the same friendly interface — you don't need to remember hashcat command-line syntax."

```bash
# Hashcat Integration Configuration:
Binary: tools/hashcat-7.1.2/hashcat.exe
Rules directory: tools/hashcat-7.1.2/rules/ (22 rule files)
Charsets: tools/hashcat-7.1.2/charsets/ (8 charset files)
Potfile: tools/hashcat-7.1.2/hashcat.potfile
Workload Profile: 2 (Default)
Optimized Kernels: Enabled

# Available rules:
  best64.rule, combinator.rule, d3ad0ne.rule, dive.rule,
  generated.rule, generated2.rule, hybrid/ (directory),
  Incisive-leetspeak.rule, InsidePro-HashManager.rule,
  InsidePro-PasswordsPro.rule, leetspeak.rule, oscommerce.rule,
  rockyou-30000.rule, specific.rule, T0XlC-insert_00-99_1950-2050.rule,
  T0XlC.rule, T0XlC_3_rule.rule, toggles1.rule, toggles2.rule,
  toggles3.rule, toggles4.rule, toggles5.rule
```

**[Screen: Running the same dictionary+rules attack via hashcat — showing dramatically higher speed and near-instant completion]**

> "Let's replay our earlier attack — rockyou.txt with best64.rule — but through hashcat with GPU. Watch the speed difference. On CPU, this took over 3 minutes. On GPU..."

```bash
# Hashcat GPU attack (same parameters):
hashcat -m 1000 -a 0 -w 3 hash.txt rockyou.txt -r best64.rule

[*] Speed.#1: 65382.7 MH/s (65 billion/sec)
[*] Progress: 918041088/918041088 (100.00%)
[*] Recovered: 1/1 (100.00%)
[*] Time.Started: Mon Jan 22 14:33:01 2024
[*] Time.Elapsed: 0 secs (INSTANT)

7a21990fcd3d759941e45c490f143d5f:Secret1234!

# Result: 918 million candidates tested in under 1 second
# CPU took 3 minutes 18 seconds for the same work
```

**[Screen: Speed comparison visualization — bar chart showing CPU (2.1 MH/s) vs GPU (65,382 MH/s) — a 31,000x speedup]**

> "Under one second for 918 million candidates. The GPU is 31,000 times faster than CPU for NTLM cracking. This is why password length and algorithm choice matter so much — if your organization stores passwords as NTLM hashes, every password under 12 characters can be brute-forced in minutes on consumer hardware. With bcrypt at 28,000 hashes per second, the same 8-character brute-force takes centuries."

---

## SECTION 7: Certification Tips and Practice (14:30 – 16:30)

**[Screen: OSCP tip — "For OSCP: always try 'hashcat -m 1000 hash.txt rockyou.txt' first. If that fails, add rules. Document cracked credentials in your report methodology section."]**

> "For OSCP — hash cracking is a common step after gaining initial access. The exam machines often have SAM dumps or Linux shadow files accessible. Your workflow should be: identify the hash type, try rockyou.txt straight, add best64 rules if that fails, then try mask attacks based on any password policy hints. Always document cracked credentials in your report — they're part of your proof of impact."

**[Screen: CEH tip — "CEH tests hash algorithm identification. Know: MD5 (32 hex), SHA-1 (40 hex), SHA-256 (64 hex), NTLM (32 hex), bcrypt ($2a$...). Understand why bcrypt resists GPU cracking."]**

> "For CEH — the exam tests hash identification directly. Memorize the lengths: MD5 is 32 hex characters, SHA-1 is 40, SHA-256 is 64, NTLM is 32 but in a different context than MD5. Understand why bcrypt resists cracking — it's designed with a work factor that makes each hash computation intentionally slow, defeating the parallelism advantage of GPUs. This is the fundamental difference between fast hashes (MD5, SHA-1, NTLM) and slow hashes (bcrypt, scrypt, Argon2)."

**[Screen: Practice targets — "Extract and crack hashes from these HTB machines: Bastion (NTLM SAM), Lame (Linux shadow), Active (Kerberos TGS)"]**

> "Practice targets: Bastion for Windows SAM hashes — which we just demonstrated. HTB Lame for Linux shadow file cracking — those are SHA-512 hashes with salt. And HTB Active for Kerberos TGS hashes — Kerberoasting produces hashes that crack with standard wordlists if the service account has a weak password. Each of these exercises different hash types and attack strategies."

**[Screen: SSH key cracking note — "Huginn also cracks passphrase-protected SSH keys. Use the SSH Key Parser tab to convert keys to crackable format."]**

> "One more feature worth noting — Huginn's SSH Key Parser tab handles passphrase-protected SSH keys. If you find a private key during an engagement but it's passphrase-protected, the parser converts it to a hash format that the cracking engine can attack. This is the same concept as ssh2john in John the Ripper, but integrated directly into Huginn's workflow."

```bash
# SSH Key cracking workflow:
1. Import passphrase-protected SSH key (id_rsa)
2. SSH Key Parser extracts the cipher parameters
3. Converts to crackable hash format ($sshng$...)
4. Attack with dictionary/rules (hashcat mode 22921)
5. Recovered passphrase unlocks the private key

# Supported key formats:
- RSA (PKCS#1, PKCS#8)
- ED25519
- ECDSA
- DSA
```

---

## OUTRO (16:30 – end)

**[Screen: Summary slide — Hash Cracking: Identify → Lookup → Dictionary → Rules → Mask → GPU Accelerate | Professional Tier | Next: Video 58 — Local DNS Server]**

> "That's hash cracking in Huginn — from hash identification and rainbow table lookups through dictionary attacks, rule-based mutations, mask-based brute force, and GPU acceleration via hashcat integration. We cracked the Bastion Administrator hash using rules in 3 minutes on CPU and under one second on GPU — demonstrating why hash algorithm selection is a critical security decision. All of this runs on the Professional tier. In the next video, we set up Huginn's Local DNS Server for managing custom lab environments — mapping hostnames to target IPs without modifying your system's DNS configuration. See you in Video 58."
