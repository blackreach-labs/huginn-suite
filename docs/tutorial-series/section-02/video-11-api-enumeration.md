# VIDEO 11: API Enumeration
### Endpoint Discovery, Method Testing & Schema Extraction
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 0:45)

**[Screen: Huginn splash screen with Section 2 badge, transitioning to OWASP API Security page]**

> "Welcome back to the Huginn tutorial series. In this video we're covering API enumeration — discovering REST endpoints, testing which HTTP methods are accepted, and extracting schema documentation from web services. APIs are everywhere in modern applications, and knowing how to map them out is an essential recon skill. If you haven't already, make sure you've watched our HTTP/S Fingerprinting video first (see Video 10: HTTP/S Fingerprinting), since API enumeration builds directly on that foundation. Let's jump in."

---

## SECTION 1: Understanding API Enumeration (0:45 – 2:30)

**[Screen: Slide — "What is API Enumeration?" with diagram showing client requests flowing to API endpoints]**

> "Before we touch any tools, let's talk about what API enumeration actually means. Modern web applications expose functionality through RESTful APIs — structured HTTP endpoints that accept and return data in formats like JSON or XML. API enumeration is the process of discovering these endpoints, determining which HTTP methods each one accepts, identifying authentication requirements, and extracting any available schema documentation like OpenAPI or Swagger specifications."

**[Screen: Slide — "Why API Enumeration Matters" with bullet points: hidden endpoints, method misconfigurations, IDOR vulnerabilities, rate limiting gaps]**

> "Why does this matter for penetration testing? Applications often expose more API endpoints than the frontend actually uses. Developers might leave debug endpoints accessible, forget to restrict dangerous HTTP methods, or expose internal documentation. Finding these is how you uncover attack surface that traditional web scanning misses. The OWASP API Security Top 10 specifically calls out issues like broken authentication, excessive data exposure, and lack of resource-level authorization — all things we can start identifying during enumeration."

---

## SECTION 2: Huginn's API Enumeration Interface (2:30 – 5:00)

**[Screen: Huginn UI — navigating to Recon & Enumeration page, then OWASP API page]**

> "Huginn provides API enumeration through two interfaces. The first is the Recon and Enumeration page, where API scanning sits alongside other service scanners. The second is the dedicated OWASP API Security page, which gives you a structured view of API risks mapped to the OWASP Top 10. Let me show you both."

**[Screen: Huginn UI — OWASP API Security page with two-panel layout: risk list on left, risk details on right]**

> "The OWASP API page uses a two-panel layout. On the left you have the risk list component showing each OWASP API risk category. When you select one, the right panel shows detailed findings, test results, and recommendations. This is where your API enumeration results get organized by risk category."

**[Screen: Huginn UI — Target input field, showing configuration options]**

> "Now let's look at the configuration options. You'll need to provide a target URL — this is the base URL of the API you want to enumerate. Huginn supports several discovery methods."

**[Screen: Huginn UI — Configuration panel showing endpoint discovery options]**

> "First, there's automatic endpoint discovery. Huginn crawls the target looking for common API documentation paths — things like /swagger.json, /openapi.yaml, /api-docs, /v1/docs, and similar well-known locations. It also parses HTML and JavaScript files looking for API endpoint references in client-side code. Second, you can provide a known OpenAPI or Swagger specification URL directly if you already have it. Third, there's wordlist-based endpoint brute-forcing for when documentation isn't publicly available."

---

## SECTION 3: Lab Setup — THM OWASP API Security (5:00 – 6:15)

**[Screen: TryHackMe platform — "OWASP API Security Top 10" room page]**

> "For today's demonstration we're using the TryHackMe room called OWASP API Security Top 10. This room deploys a vulnerable API application specifically designed for practicing API security testing. Go ahead and deploy the target machine — it takes about a minute to spin up."

**[Screen: Terminal — VPN connection to THM and machine IP confirmation]**

```bash
# Connect to TryHackMe VPN (if not already connected)
sudo openvpn ~/thm-vpn.ovpn

# Confirm target is reachable
ping -c 3 MACHINE_IP
```

> "Once the machine is deployed, confirm you can reach it. The target exposes a REST API on the standard HTTP port. We'll use the machine IP provided by TryHackMe throughout this demo."

---

## SECTION 4: Endpoint Discovery (6:15 – 9:00)

**[Screen: Huginn UI — Starting API enumeration scan against THM target]**

> "Let's start our API enumeration. I'll enter the target URL and kick off the endpoint discovery scan. Huginn's API security tester begins by looking for documentation endpoints — it checks for Swagger and OpenAPI specs first since those give you the complete endpoint map without any guessing."

**[Screen: Huginn UI — Results populating as endpoints are discovered, showing /api/v1/, /api/v2/, /users, /products, /admin paths]**

> "Look at that — Huginn found an OpenAPI specification and is now parsing it to extract all documented endpoints. You can see it's discovering paths like /api/users, /api/products, /api/admin, and several others. Each endpoint gets cataloged with its supported methods and expected parameters."

**[Screen: Terminal — equivalent curl commands for manual verification]**

```bash
# Manual check for common API documentation paths
curl -s http://MACHINE_IP/swagger.json | head -50
curl -s http://MACHINE_IP/api-docs
curl -s http://MACHINE_IP/openapi.yaml

# Check for API versioning
curl -s http://MACHINE_IP/api/v1/ -o /dev/null -w "%{http_code}\n"
curl -s http://MACHINE_IP/api/v2/ -o /dev/null -w "%{http_code}\n"
```

> "Behind the scenes, Huginn is making requests similar to these curl commands. It checks well-known documentation paths, probes for API version prefixes, and parses any specs it finds. The advantage of using Huginn is that it does all of this automatically and organizes the results for you."

**[Screen: Huginn UI — Endpoint list fully populated with discovered paths]**

> "We've now got a complete endpoint map. Huginn discovered endpoints for user management, product catalog, authentication, and what looks like an admin interface. Each entry shows the path, the HTTP methods it responded to, and whether authentication appears to be required. This gives us a solid picture of the API's attack surface."

---

## SECTION 5: HTTP Method Testing (9:00 – 11:30)

**[Screen: Huginn UI — HTTP Methods Enumerator results panel]**

> "Next up is HTTP method testing. Huginn's HTTP Methods Enumerator goes beyond a simple OPTIONS request. It tests each endpoint against a comprehensive list of methods — the standard ones like GET, POST, PUT, DELETE, and PATCH, but also less common ones like TRACE, CONNECT, and the WebDAV methods: PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, and UNLOCK."

**[Screen: Huginn UI — Method test results showing allowed methods per endpoint, with severity indicators for dangerous methods]**

> "Here's what we found. The /api/users endpoint accepts GET and POST as expected, but it also responds to PUT and DELETE — those are flagged as high severity because they could allow unauthorized data modification or deletion if access controls are weak. The /api/admin endpoint has TRACE enabled, which is flagged as medium severity because it can leak session tokens through cross-site tracing attacks."

**[Screen: Terminal — demonstrating method testing manually]**

```bash
# Test which HTTP methods are allowed on an endpoint
curl -X OPTIONS http://MACHINE_IP/api/users -i

# Test for dangerous methods
curl -X PUT http://MACHINE_IP/api/users/1 -d '{"name":"test"}' -H "Content-Type: application/json" -o /dev/null -w "%{http_code}\n"
curl -X DELETE http://MACHINE_IP/api/users/1 -o /dev/null -w "%{http_code}\n"
curl -X TRACE http://MACHINE_IP/api/admin -i

# Test for method override headers
curl -X POST http://MACHINE_IP/api/users/1 -H "X-HTTP-Method-Override: DELETE" -o /dev/null -w "%{http_code}\n"
```

> "Huginn also tests for HTTP method override vulnerabilities. Some frameworks allow you to override the HTTP method using headers like X-HTTP-Method-Override, X-HTTP-Method, or X-Method-Override. If the server processes these, an attacker could bypass method-based access controls by sending a POST request with an override header set to DELETE. Huginn found that the X-HTTP-Method-Override header is being processed here — that's a medium-severity finding."

**[Screen: Huginn UI — WebDAV method detection results]**

> "And look at this — WebDAV methods are enabled on one of the endpoints. PROPFIND is responding, which means there might be WebDAV functionality exposed that could allow file listing or manipulation. This is the kind of finding you'd miss with basic scanning."

---

## SECTION 6: Schema Extraction and Analysis (11:30 – 13:45)

**[Screen: Huginn UI — Schema extraction results showing parsed OpenAPI spec]**

> "The third component of API enumeration is schema extraction. When Huginn finds API documentation — whether it's OpenAPI, Swagger, or even a GraphQL introspection endpoint — it parses the schema to understand the data models, parameter types, and authentication flows."

**[Screen: Huginn UI — Detailed schema view showing endpoint parameters, request bodies, and response formats]**

> "Here we can see the parsed schema. Each endpoint has its parameters documented — required versus optional, data types, validation constraints. This information is gold for planning further testing. If an endpoint expects an integer ID parameter with no apparent bounds checking documented, that's a candidate for IDOR testing. If a parameter accepts free-form strings without noted sanitization, that's a potential injection point."

**[Screen: Huginn UI — OWASP API risk categorization of findings]**

> "Huginn maps everything it finds back to the OWASP API Security Top 10 categories. Our findings so far touch on API1 — Broken Object Level Authorization, since we found endpoints accepting PUT and DELETE without clear auth requirements. We've also got findings under API7 — Security Misconfiguration, with the TRACE method enabled and WebDAV exposed. The OWASP API page makes it easy to see how your findings map to these well-known risk categories."

**[Screen: Terminal — GraphQL introspection query example]**

```bash
# Check for GraphQL endpoint and introspection
curl -s http://MACHINE_IP/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name,fields{name}}}}"}'

# Check for JWT usage on authenticated endpoints
curl -s http://MACHINE_IP/api/users -H "Authorization: Bearer invalid_token" -i
```

> "Huginn also checks for GraphQL endpoints and attempts introspection queries when found. GraphQL introspection exposes the entire schema — every type, every field, every query and mutation. Additionally, it probes for JWT-based authentication to understand the auth model in use."

---

## SECTION 7: Results Interpretation (13:45 – 16:00)

**[Screen: Huginn UI — Complete API enumeration results summary with severity breakdown]**

> "Let's review our complete results. We've mapped out the entire API surface of this application. Here's what we found: multiple undocumented endpoints not referenced in the frontend, dangerous HTTP methods enabled on sensitive resources, method override headers being processed, and WebDAV functionality exposed unnecessarily."

**[Screen: Huginn UI — Findings detail view with recommendations]**

> "Each finding comes with a severity rating and a recommendation. The high-severity items — unrestricted PUT and DELETE on user resources — should be investigated further with authenticated testing. The medium-severity items like TRACE and method override need attention but are lower priority. And the informational items give us the complete method map for planning our next steps."

**[Screen: Huginn UI — Export options for API enumeration results]**

> "You can export these results in multiple formats for your notes or reporting. The key takeaway is that API enumeration gave us a comprehensive view of the application's attack surface before we've even attempted any exploitation. Every endpoint we discovered is now a candidate for further testing — authentication bypass, injection attacks, rate limiting checks, and access control validation."

---

## SECTION 8: Certification Context (16:00 – 16:45)

**[Screen: Slide — OSCP and CEH relevance for API testing]**

> "For those studying for OSCP, API enumeration falls under the Information Gathering domain. The exam frequently presents web applications with API backends — knowing how to discover and map those endpoints can reveal paths to initial access that aren't visible from the browser alone. For CEH candidates, this maps to the Enumeration phase where you're cataloging services and their capabilities. Practice this technique on TryHackMe's OWASP API rooms and HTB machines with web services to build speed and confidence."

---

## OUTRO (16:45 – end)

> "That's API enumeration in Huginn. We covered endpoint discovery using documentation parsing and wordlist probing, HTTP method testing to find dangerous configurations, and schema extraction to understand the data model. In our next video, we'll move to RPC enumeration (see Video 12: RPC Enumeration) — a completely different protocol with its own enumeration techniques. See you there."

---
