# VIDEO 35: HTTP Interceptor
### Request Interception, Modification, Replay & Traffic Analysis
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Web Application Attacks | CEH: Web Application Hacking

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn splash screen with Section 5 title card "Web Application Exploitation"]**

> "Welcome back to the Huginn tutorial series. This video covers the HTTP Interceptor — Huginn's built-in proxy system for capturing, modifying, and replaying HTTP requests. If you've used Burp Suite's Proxy or OWASP ZAP's interceptor, this is Huginn's equivalent — fully integrated into the exploitation workflow with additional automation for authentication testing."

**[Screen: Diagram showing HTTP Interceptor architecture — Browser → Huginn Proxy → Target Server, with intercept/modify/forward arrows]**

> "The HTTP Interceptor sits between your browser and the target application. It captures every request and response, lets you pause requests for modification before they reach the server, replay requests with different parameters, and record authentication flows for automated security testing. It's the foundation for understanding how web applications communicate and where you can inject your payloads."

**[Screen: Safety warning banner — red border, lock icon]**

> "As always — lab environment only. We're demonstrating against DVWA running locally. Intercepting and modifying traffic to systems you don't own is unauthorized access. These techniques are for authorized penetration testing engagements and personal lab practice only."

---

## SECTION 1: HTTP Interceptor Architecture (1:30 – 3:00)

**[Screen: Component diagram — CurlInterceptor, UnifiedHttpClient, AuthFlowRecorder, AuthReplayEngine connected with arrows]**

> "Huginn's interceptor is built on four core components. The CurlInterceptor handles request capture and pausing — it can intercept requests, hold them for modification, then forward or drop them. The UnifiedHttpClient manages the actual HTTP communication with support for all methods, custom headers, and SSL handling."

**[Screen: Highlighting AuthFlowRecorder and AuthReplayEngine components]**

> "The AuthFlowRecorder captures multi-step authentication sequences — login flows, OAuth handshakes, token exchanges — and stores them as replayable sessions. The AuthReplayEngine takes those recorded flows and replays them with mutations — removing tokens, swapping user contexts, testing CSRF bypasses — to identify authentication vulnerabilities automatically."

**[Screen: Feature list — Intercept, Modify Headers/Parameters, Replay, Repeat, Auth Flow Recording, Security Mutations]**

> "Together these give you: request interception with pause/forward/drop, header and parameter modification, single and multi-request replay, repeated sending for timing attacks or brute-force, authentication flow recording, and automated security mutation testing. All Free tier — no license upgrade required."

---

## SECTION 2: Huginn HTTP Interceptor Interface (3:00 – 5:00)

**[Screen: Huginn application — navigating from Home to Web Exploits → HTTP Interceptor tab]**

> "Open Huginn and navigate to Web Exploits, then select the HTTP Interceptor tab. The interface has four main areas: the request builder on the left, the intercept controls in the center toolbar, the request/response viewer on the right, and the history log at the bottom."

**[Screen: HTTP Interceptor interface — highlighting the request builder panel with method dropdown, URL field, headers, and body sections]**

> "The request builder lets you craft requests manually. The method dropdown supports GET, POST, PUT, DELETE, PATCH, OPTIONS, and HEAD. Below that you have the URL field, a headers section where you add key-value pairs, and the body section for POST data. You can also paste a raw curl command and Huginn will parse it automatically into its component parts."

**[Screen: Highlighting the Intercept toggle button and the history panel showing captured requests]**

> "The Intercept toggle in the toolbar enables or disables request capture. When enabled, outgoing requests pause before sending — you'll see them appear in the intercept queue where you can modify and forward them, or drop them entirely. The history panel at the bottom logs every request and response with timestamps, status codes, and response times."

**[Screen: Showing the curl import feature — pasting a curl command and watching it populate the fields]**

> "A powerful workflow shortcut — copy a request as curl from your browser's DevTools, paste it into the command field, and Huginn parses the method, URL, headers, cookies, and body automatically. This bridges browser-observed traffic directly into Huginn's testing interface."

```bash
# Paste from browser DevTools "Copy as cURL":
curl -X POST 'http://localhost/dvwa/login.php' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: PHPSESSID=abc123; security=medium' \
  --data 'username=admin&password=password&Login=Login'
```

---

## SECTION 3: Lab Setup — DVWA Brute Force Module (5:00 – 6:30)

**[Screen: DVWA login page — logging in with admin/password, navigating to Security settings]**

> "For our demonstration, we're using DVWA's Brute Force module at Security Level Medium. Log into DVWA with the default credentials — admin, password. Navigate to DVWA Security and set the level to Medium. This adds a two-second delay on failed login attempts — making it a realistic target for interceptor-based testing."

```bash
Target: http://localhost/dvwa
Credentials: admin / password
Security Level: Medium
Module: Brute Force
```

**[Screen: Navigating to Brute Force module — showing the login form with username and password fields]**

> "Navigate to the Brute Force module. You'll see a simple login form with username and password fields. At Medium security, the application adds a sleep(2) on failed attempts. Our goal is to intercept the login request, understand its structure, modify parameters, and replay it with different credentials — demonstrating how the interceptor enables manual parameter manipulation."

**[Screen: Opening browser DevTools Network tab alongside Huginn's interceptor]**

> "I'll keep the browser's DevTools Network tab open so you can compare what the browser sees with what Huginn captures. This helps you understand exactly where the interceptor sits in the request flow."

---

## SECTION 4: Intercepting a Login Request (6:30 – 9:00)

**[Screen: Enabling intercept mode in Huginn — clicking the Intercept toggle to ON]**

> "Enable intercept mode by clicking the toggle. The indicator turns red, showing that outgoing requests will now pause before sending. Submit the DVWA Brute Force form with a test username and password — let's use 'admin' and 'test123'."

**[Screen: Submitting the DVWA form — request appears in Huginn's intercept queue]**

> "The request is caught. Look at the intercept queue — we can see the full GET request with all parameters visible in the URL. DVWA's Brute Force at Medium uses GET parameters for the credentials."

```bash
[INTERCEPT] Request paused:
  Method: GET
  URL: http://localhost/dvwa/vulnerabilities/brute/
  Parameters:
    username=admin
    password=test123
    Login=Login
  Headers:
    Cookie: PHPSESSID=r4nd0m5e5s10n; security=medium
    Referer: http://localhost/dvwa/vulnerabilities/brute/
    User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...
```

**[Screen: Intercept queue showing the paused request — highlighting the editable parameter fields]**

> "Every part of this request is now editable. The URL, parameters, headers, and cookies are all exposed. You can change the username, swap the password, modify the session cookie, add headers, or completely rewrite the request before it reaches the server. This is the core power of interception — you control what the server receives."

**[Screen: Modifying the password parameter from 'test123' to 'password' in the intercept editor]**

> "Let's modify the password from 'test123' to 'password' — the correct credential — and forward the request. This demonstrates how an interceptor lets you bypass client-side logic entirely."

```bash
[INTERCEPT] Modified parameter: password = "test123" → "password"
[INTERCEPT] Forwarding request to server...
[RESPONSE] HTTP 200 OK (142ms)
  Body contains: "Welcome to the password protected area admin"
```

**[Screen: Response showing successful login — "Welcome to the password protected area"]**

> "The server accepted our modified request and we're logged in. The original form submitted 'test123' but the server received 'password' because we intercepted and changed it in transit. Client-side validation, JavaScript restrictions, disabled form fields — none of that matters when you control the request at the proxy level."

---

## SECTION 5: Header and Cookie Modification (9:00 – 11:00)

**[Screen: Crafting a new request in the request builder — targeting the DVWA Brute Force endpoint]**

> "Let's explore header modification. Create a new request in the builder targeting the same Brute Force endpoint. We'll manipulate headers to test how the application handles different request contexts."

**[Screen: Adding and modifying headers — changing User-Agent, adding X-Forwarded-For, modifying Cookie]**

> "First, let's change the User-Agent to impersonate a different browser. Then add an X-Forwarded-For header — some applications use this to identify the client's IP, and if they trust it without validation, we can spoof our source address. Finally, let's modify the security cookie from 'medium' to 'low' and see if DVWA downgrades its protections."

```bash
[REQUEST] Building modified request:
  Method: GET
  URL: http://localhost/dvwa/vulnerabilities/brute/?username=admin&password=password&Login=Login
  Modified Headers:
    User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_0)
    X-Forwarded-For: 192.168.1.100
    Cookie: PHPSESSID=r4nd0m5e5s10n; security=low
  
[SEND] Sending request...
[RESPONSE] HTTP 200 OK (45ms)
  Note: Response time 45ms (vs 2000ms+ for failed attempts at Medium)
  Security context: low (no sleep delay applied)
```

**[Screen: Response panel showing faster response time — confirming the security level downgrade worked]**

> "Look at the response time — 45 milliseconds. At Medium security, failed attempts take over 2 seconds because of the sleep delay. By changing the security cookie to 'low', we bypassed the brute-force protection entirely. The application trusts the client-supplied cookie to determine its security posture — a real vulnerability pattern where server-side security depends on client-controlled values."

**[Screen: History panel showing both requests — the original and the modified version side by side]**

> "The history panel now shows both requests. You can compare them side by side — same endpoint, different headers, dramatically different server behavior. This kind of differential testing is exactly what the interceptor enables."

---

## SECTION 6: Request Replay and Repeated Sending (11:00 – 13:30)

**[Screen: Selecting a request from history — clicking the Replay button]**

> "Request replay is where the interceptor becomes a testing engine. Select any request from history and click Replay to send it again with identical parameters, or click Repeat to send it multiple times. This is critical for testing rate limiting, session fixation, and brute-force scenarios."

**[Screen: Configuring repeated send — setting count to 5, showing the modified password parameter for each iteration]**

> "Let's demonstrate repeated sending. We'll replay the login request five times with different passwords to simulate a brute-force attempt. Huginn's send_repeated function handles this natively."

```bash
[REPLAY] Sending request 5 times with password variations:
  Attempt 1: password=admin     → HTTP 200 (2134ms) — "Username and/or password incorrect"
  Attempt 2: password=password1 → HTTP 200 (2089ms) — "Username and/or password incorrect"
  Attempt 3: password=letmein   → HTTP 200 (2102ms) — "Username and/or password incorrect"
  Attempt 4: password=password  → HTTP 200 (47ms)   — "Welcome to the password protected area"
  Attempt 5: password=admin123  → HTTP 200 (2095ms) — "Username and/or password incorrect"
```

**[Screen: Results table showing all five attempts — highlighting the successful one with different response time and content]**

> "The results tell a clear story. Failed attempts take over 2 seconds — that's the Medium security sleep delay. The successful attempt returns in 47 milliseconds with different response content. In a real engagement, this differential timing is a side-channel that reveals correct credentials even without parsing the response body."

**[Screen: Showing the history entries with status codes, response times, and response size columns]**

> "The history log captures everything — timestamps, response times, and response sizes. Filtering by response time or content length quickly identifies anomalous responses. A request that returns faster or with a different content length is likely hitting a different code path — successful authentication, valid parameter, or bypassed check."

---

## SECTION 7: Auth Flow Recording and Integration (13:30 – 15:30)

**[Screen: Auth Flow Recorder panel — clicking "Start Recording" to begin capturing an authentication sequence]**

> "The Auth Flow Recorder captures multi-step authentication sequences for replay testing. Click Start Recording, then perform a complete login flow in the browser. Huginn captures each request and identifies authentication-related traffic — login forms, token exchanges, redirects, and session establishment."

```bash
[AUTH RECORDER] Recording started: session_dvwa_bruteforce
[AUTH RECORDER] Captured: GET /dvwa/login.php (auth-related: login form)
[AUTH RECORDER] Captured: POST /dvwa/login.php (auth-related: credential submission)
[AUTH RECORDER] Token extracted: PHPSESSID=new_session_value
[AUTH RECORDER] Cookie captured: security=medium
[AUTH RECORDER] Captured: GET /dvwa/vulnerabilities/brute/ (authenticated request)
[AUTH RECORDER] Recording stopped: 3 requests captured, 1 token, 2 cookies
```

**[Screen: Recorded flow displayed — showing the sequence of requests with extracted tokens and cookies highlighted]**

> "Stop recording and you'll see the captured flow — three requests showing the complete authentication sequence. Huginn automatically identified the PHPSESSID token and security cookie. These extracted values are marked as dynamic — they'll be updated during replay to maintain a valid session."

**[Screen: Auth Replay Engine — showing mutation test options: Remove Token, Expired Token, Swap User, Remove CSRF]**

> "The Replay Engine can now test this flow with security mutations. Remove Token sends the requests without authentication. Expired Token uses an old session. Swap User tests horizontal privilege escalation. Remove CSRF drops anti-forgery tokens. Each mutation tests a specific authentication weakness automatically."

```bash
[AUTH REPLAY] Running security mutations on session_dvwa_bruteforce:
  Test 1: Remove Token       → HTTP 302 Redirect to /login.php (PASS — requires auth)
  Test 2: Expired Token      → HTTP 302 Redirect to /login.php (PASS — rejects expired)
  Test 3: Swap User Context  → HTTP 200 — accessing other user data (FAIL — no isolation)
  Test 4: Remove CSRF Token  → HTTP 200 — action still processed (FAIL — CSRF not enforced)
[AUTH REPLAY] Results: 2 PASSED, 2 FAILED — vulnerabilities detected
```

**[Screen: Replay results showing two failures — Swap User and CSRF removal both succeeded when they shouldn't have]**

> "Two mutations revealed vulnerabilities. The application properly requires authentication and rejects expired sessions, but it doesn't enforce user isolation — we accessed another user's data by swapping context. And it doesn't validate CSRF tokens on the brute-force form — actions process without the anti-forgery token. These are real findings you'd report."

---

## SECTION 8: Integration with Other Huginn Tools (15:30 – 16:30)

**[Screen: Showing how intercepted requests feed into other modules — SQL Injection, XSS, Command Injection]**

> "The interceptor integrates directly with Huginn's other exploitation tools. Right-click any captured request and you can send it to the SQL Injection tester, XSS tester, or Command Injection module with one click. The request parameters, headers, and cookies transfer automatically — you don't need to reconfigure the target."

**[Screen: Sending an intercepted request to the SQLi module — parameters pre-populated]**

> "For example, sending our DVWA request to the SQL Injection module pre-populates the target URL, the username and password parameters as injection points, and the session cookies needed for authentication. This workflow — intercept, understand, then exploit — is how professional testers work (see Video 28: SQL Injection)."

**[Screen: Export options — exporting history as JSON, showing curl command generation]**

> "You can also export your entire intercept history as JSON for documentation, or generate curl commands for any captured request to reproduce testing outside of Huginn. The auth flow exports are importable — share them with team members or save them for regression testing on future engagements."

---

## SECTION 9: Certification Mapping and Practice (16:30 – 17:30)

**[Screen: Slide showing certification mapping — OSCP: Web Application Attacks, CEH: Web Application Hacking]**

> "HTTP interception is foundational for OSCP. Every web application attack on the exam requires understanding request structure — parameters, cookies, headers. You'll use proxy tools constantly during the exam to identify injection points and craft payloads. For CEH, this covers Module 14 — session hijacking, parameter tampering, and authentication testing."

**[Screen: Practice recommendations — DVWA all modules with interceptor, THM "Burp Suite" rooms for proxy methodology]**

> "For practice, run through every DVWA module with the interceptor enabled. Watch how forms submit data, how sessions are maintained, and how security levels change request behavior. The TryHackMe Burp Suite rooms teach proxy methodology that translates directly to Huginn's interceptor. On HTB, any web-focused machine benefits from interceptor-first reconnaissance."

---

## OUTRO (17:30 – end)

**[Screen: Summary slide — HTTP Interceptor: Request Capture, Header/Parameter Modification, Replay, Auth Flow Testing | Next: Video 36 — SSH Brute-Force & Vulnerability Scanning]**

> "That's the HTTP Interceptor in Huginn. We captured and modified requests in flight, manipulated headers and cookies to bypass security controls, replayed requests for brute-force testing, and recorded authentication flows for automated security mutation testing. This tool is your foundation for every web exploitation technique we've covered in Section 5. In the next video, we move to Section 6 — Network and OS Exploitation — starting with SSH Brute-Force and Vulnerability Scanning. See you there."
