# VIDEO 14: IKE/VPN Assessment
### IKE Mode Detection, Transform Enumeration & PSK Testing
**Suggested length:** 14–18 minutes
**License Tier:** Free
**Certification Relevance:** OSCP: Information Gathering | CEH: Enumeration

---

## INTRO (0:00 – 1:30)

**[Screen: Huginn dashboard with Recon & Enumeration page open, IKE/VPN section highlighted in the service scanner panel]**

> "Welcome back to the Huginn tutorial series. In this video we are covering IKE and VPN assessment — a critical but often overlooked part of reconnaissance. IKE, or Internet Key Exchange, is the protocol used to set up IPsec VPN tunnels. When you find UDP port 500 or 4500 open on a target, it usually means there is a VPN gateway waiting to negotiate a tunnel. If we can enumerate the supported transforms, detect the IKE version, and test for weak pre-shared keys, we may find a path directly into the internal network. Today we will use Huginn's IKE scanner module against HTB Conceal to do exactly that."

**[Screen: Brief slide showing IKE protocol overview — Phase 1 (SA negotiation) and Phase 2 (IPsec tunnel setup)]**

> "If you have not already identified open UDP ports on your target, go back and review the UDP scanning techniques we covered earlier (see Video 6: Port Scanning). Port 500 for IKE and port 4500 for NAT Traversal are what we are looking for. Let's get started."

---

## SECTION 1: Understanding the IKE Protocol (1:30 – 4:00)

**[Screen: Diagram showing IKEv1 Main Mode vs Aggressive Mode handshake flow — six packets for Main Mode, three for Aggressive Mode]**

> "Before we touch the tool, let's understand what IKE actually does. IKE operates in two versions — IKEv1 and IKEv2. IKEv1 has two exchange modes: Main Mode and Aggressive Mode. Main Mode uses six messages and protects the identity of both peers. Aggressive Mode uses only three messages and sends the identity in the clear, which makes it easier to enumerate but also exposes the pre-shared key hash to offline cracking."

**[Screen: Table comparing IKEv1 Main Mode, IKEv1 Aggressive Mode, and IKEv2]**

> "A transform set defines the cryptographic parameters both sides must agree on — the encryption algorithm like 3DES or AES, the hash algorithm like MD5 or SHA, the authentication method such as pre-shared key or RSA signatures, and the Diffie-Hellman group for key exchange. When we enumerate transforms, we are essentially asking the VPN gateway: which combinations do you accept?"

**[Screen: Transform set diagram showing Encryption + Hash + Auth + DH Group = Transform Proposal]**

> "This is directly relevant to the OSCP exam. VPN misconfigurations, especially weak pre-shared keys in Aggressive Mode, are a documented attack vector. The CEH exam also covers IKE enumeration under its Enumeration domain."

---

## SECTION 2: Huginn IKE Scanner Interface (4:00 – 6:30)

**[Screen: Huginn UI — Recon & Enumeration page, clicking into the IKE/VPN service scanner tab]**

> "In Huginn, the IKE scanner lives under the Recon and Enumeration module. Navigate to the service scanners section and select IKE/VPN Assessment. You will see the familiar target input field at the top."

**[Screen: IKE scanner panel showing target field, port selection (500/4500), and scan type dropdown with options: Basic, Detailed, Transforms, Full]**

> "The scan type dropdown gives us four options. Basic performs simple service detection — it confirms IKE is listening and reports whether it responds to initiator packets. Detailed runs ike-scan with multiline output parsing to extract vendor IDs, handshake types, and supported transforms. Transforms mode specifically enumerates all accepted transform combinations. Full combines everything into a single comprehensive scan."

```bash
# Huginn IKE scan types map to these ike-scan operations:
# Basic:     ike-scan <target>
# Detailed:  ike-scan -M <target>
# Transforms: ike-scan --trans=1,2,3,4 <target>
# Full:      All of the above combined
```

**[Screen: Configuration options panel showing timeout setting, port selection, and aggressive mode toggle]**

> "Below the scan type you will find configuration options. The port defaults to 500 but you can change it to 4500 for NAT Traversal testing. The timeout is set to 30 seconds by default, which is generous — IKE responses are usually fast when the service is alive. The aggressive mode toggle is important — enabling it switches from Main Mode probes to Aggressive Mode probes, which reveals more information but is also noisier."

---

## SECTION 3: Live Demo — Scanning HTB Conceal (6:30 – 11:00)

**[Screen: Terminal showing HTB VPN connection established, target IP 10.10.10.116 confirmed reachable]**

> "Our target today is HTB Conceal at 10.10.10.116. This is a Hard-difficulty box that specifically requires IKE interaction to progress. Let's confirm connectivity first."

```bash
# Verify target is reachable
ping -c 3 10.10.10.116

# Confirm IKE port is open (from our earlier port scan)
sudo nmap -sU -p 500,4500,161 10.10.10.116
```

**[Screen: Nmap output showing UDP 500 open, UDP 4500 open, UDP 161 open (SNMP)]**

> "We can see UDP 500 and 4500 are both open, confirming an IKE/IPsec endpoint. Port 161 is also open — SNMP — which we covered in Video 9. On Conceal, SNMP actually gives us information we need later, but today we are focused on IKE."

**[Screen: Huginn UI — entering 10.10.10.116 in the target field, selecting "Full" scan type, clicking Start Scan]**

> "Let's run a Full scan in Huginn. I will enter the target IP, select Full as the scan type, keep port 500, and click Start."

**[Screen: Scan progress indicator, then results populating in the IKE results panel]**

> "The scan completes in a few seconds. Let's look at what we found."

```bash
# Behind the scenes, Huginn runs:
ike-scan 10.10.10.116
ike-scan -M 10.10.10.116
ike-scan --trans=1,2,3,4 10.10.10.116

# Aggressive mode probe:
ike-scan -M --aggressive --id=vpnuser 10.10.10.116
```

**[Screen: Results panel showing — IKE Version: v1, Handshake: Main Mode, Transforms detected: 3DES/SHA1/PSK/DH Group 2, Vendor IDs: Microsoft Windows]**

> "The results tell us several things. First, this is IKEv1 responding in Main Mode. The accepted transform is 3DES encryption with SHA1 hashing, Pre-Shared Key authentication, and Diffie-Hellman Group 2. The vendor ID decodes to Microsoft Windows — so this is likely a Windows Server running the built-in IPsec/IKE implementation."

**[Screen: Expanding the Vendor ID section showing hex value and decoded name]**

> "The vendor ID is a fingerprinting goldmine. Different VPN implementations — Cisco, Checkpoint, strongSwan, Windows — each send a unique vendor ID. Huginn automatically decodes common vendor IDs including RFC 3947 NAT-T, Dead Peer Detection, and IKE Fragmentation markers."

**[Screen: Huginn UI — switching to Aggressive Mode toggle, re-running scan]**

> "Now let's try Aggressive Mode. This is where things get interesting for penetration testing. In Aggressive Mode, the responder sends the hash of the pre-shared key in the clear."

```bash
# Aggressive Mode with group name:
ike-scan -M --aggressive --id=GroupVPN 10.10.10.116
```

**[Screen: Aggressive Mode results showing PSK hash captured]**

> "If we get a response in Aggressive Mode with a PSK hash, we can take that hash offline and attempt to crack it. On Conceal, the pre-shared key is actually obtainable through SNMP enumeration, but this demonstrates the attack path. A weak PSK in Aggressive Mode is a critical finding."

---

## SECTION 4: Interpreting Results and Next Steps (11:00 – 14:00)

**[Screen: Huginn results summary panel with all findings organized — version, transforms, vendor IDs, mode support]**

> "Let's interpret what we have gathered. We know the target runs IKEv1 on Windows with 3DES-SHA1-PSK-Group2. This gives us everything we need to configure a matching IPsec policy on our attack machine to establish a tunnel. The transform set tells us exactly which cryptographic parameters to use."

**[Screen: Terminal showing strongSwan or Windows IPsec policy configuration using the discovered parameters]**

> "For Conceal specifically, once we have the pre-shared key — obtained via SNMP in this case — we configure our local IPsec policy to match these transforms and establish the tunnel. After the tunnel is up, previously filtered TCP ports become accessible."

```bash
# Example: Configure IPsec connection with discovered parameters
# /etc/ipsec.conf (strongSwan)
conn conceal
    type=transport
    keyexchange=ikev1
    left=%defaultroute
    right=10.10.10.116
    authby=psk
    ike=3des-sha1-modp1024
    esp=3des-sha1

# Set pre-shared key in /etc/ipsec.secrets
10.10.10.116 : PSK "discovered_key_here"
```

**[Screen: Huginn findings export showing severity rating and recommendation]**

> "From a reporting perspective, finding IKEv1 with Aggressive Mode support is typically rated Medium severity. Finding a weak or default pre-shared key escalates that to High or Critical. Huginn automatically generates the finding with the appropriate CVSS score and remediation guidance — upgrade to IKEv2, disable Aggressive Mode, and use strong pre-shared keys or certificate-based authentication."

**[Screen: Table showing common IKE findings and their severity ratings]**

> "Related practice machines for further study include HTB Conceal for the full IKE-to-shell path, and any environment running strongSwan or Cisco ASA with pre-shared key authentication. For OSCP preparation, understand that VPN enumeration can reveal an entirely hidden attack surface behind the tunnel."

---

## SECTION 5: Configuration Deep Dive (14:00 – 16:00)

**[Screen: Huginn IKE scanner advanced configuration panel showing all adjustable parameters]**

> "Before we wrap up, let's look at the advanced configuration options. The IKE scanner supports custom transform proposals — you can specify exactly which encryption, hash, auth, and DH group combinations to test. This is useful when you want to check if a gateway accepts weak transforms like DES or MD5."

```bash
# Testing specific weak transforms:
ike-scan --trans=1,1,1,1 10.10.10.116    # DES-MD5-PSK-Group1
ike-scan --trans=5,2,1,2 10.10.10.116    # 3DES-SHA1-PSK-Group2
ike-scan --trans=7,2,1,14 10.10.10.116   # AES-128-SHA1-PSK-Group14
```

**[Screen: Results showing which transforms are accepted vs rejected]**

> "If a gateway accepts DES or MD5, that is an immediate finding — those algorithms are cryptographically weak. Huginn flags these automatically in the results with appropriate severity ratings. You can also configure the scan to test NAT-T on port 4500 and Dead Peer Detection support, both of which provide additional fingerprinting data."

---

## OUTRO (16:00 – end)

> "That covers IKE and VPN assessment in Huginn. We learned how IKE negotiation works, used Huginn's scanner to identify the IKE version, enumerate supported transforms, detect vendor IDs, and test Aggressive Mode for PSK exposure. In the next video, we will move on to Database Enumeration where we use Huginn's database scanner to discover and fingerprint database services like MSSQL, MySQL, and PostgreSQL (see Video 15: Database Enumeration). Thanks for watching, and I will see you in the next one."
