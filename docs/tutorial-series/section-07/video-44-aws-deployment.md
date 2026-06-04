# VIDEO 44: AWS Infrastructure Deployment
### Proxy/VPN Server Deployment, SAM Templates & Cloud Pivoting
**Suggested length:** 16–18 minutes
**License Tier:** Professional
**Certification Relevance:** CEH: Evading IDS/Firewalls

---

## INTRO (0:00 – 1:45)

**[Screen: Huginn splash screen with Section 7 title card "Stealth and Evasion"]**

> "Welcome to the final video in Section 7 — AWS Infrastructure Deployment. In the previous video, we integrated Tor for anonymization — routing scan traffic through onion relays so our real IP never reaches the target (see Video 43: Tor Integration). But Tor has limitations. Many targets block known Tor exit nodes, TCP connect scans are the only option, and latency is significant. Today we solve those problems by deploying our own proxy and VPN infrastructure on AWS. You get clean cloud IPs that no blocklist flags, full protocol support including raw packets, and the ability to distribute traffic across multiple regions. When you're done, you tear everything down — no lingering resources, no surprise bills."

**[Screen: License tier badge — "Professional Tier Required" prominently displayed]**

> "AWS Infrastructure Deployment is a Professional tier feature. You'll need an active Professional or Enterprise license in Huginn, plus your own AWS account with configured credentials. This video uses real AWS resources that incur costs — I'll show you exactly what gets deployed, what it costs, and how to tear it all down cleanly."

**[Screen: Prerequisites checklist — AWS account, AWS CLI configured, IAM credentials with required permissions, Professional license, Videos 41-43 completed]**

> "Prerequisites. You need an AWS account with billing enabled, the AWS CLI installed and configured with credentials that have EC2, VPC, CloudFormation, and IAM permissions. You should have completed Videos 41 through 43 so you understand stealth mode, ProxyChains, and Tor — this video builds on all of them. I'm using my own AWS account for this demonstration, and I'll deploy real infrastructure that you'll see me tear down at the end."

---

## SECTION 1: AWS CLI Setup and Credential Configuration (1:45 – 3:45)

**[Screen: Terminal showing AWS CLI installation verification]**

> "First, let's verify AWS CLI is installed and configured. The CLI is how Huginn communicates with AWS to deploy and manage infrastructure."

```bash
# Verify AWS CLI installation
aws --version
# aws-cli/2.15.10 Python/3.11.6 Linux/6.1.0-kali9-amd64

# Check current identity
aws sts get-caller-identity
# {
#     "UserId": "AIDACKCEVSQ6C2EXAMPLE",
#     "Account": "123456789012",
#     "Arn": "arn:aws:iam::123456789012:user/huginn-deployer"
# }

# Verify required permissions (IAM)
aws iam list-attached-user-policies --user-name huginn-deployer
# {
#     "AttachedPolicies": [
#         {
#             "PolicyName": "HuginnDeployerPolicy",
#             "PolicyArn": "arn:aws:iam::123456789012:policy/HuginnDeployerPolicy"
#         }
#     ]
# }
```

**[Screen: Huginn Global Settings → AWS Configuration panel with credential fields]**

> "In Huginn, navigate to Global Settings → AWS Configuration. Enter your AWS Access Key ID and Secret Access Key. Huginn stores these encrypted in your local configuration. You can also specify a default region — I'm using us-east-1 for the primary deployment, but we'll deploy to multiple regions shortly."

```bash
# Huginn AWS Configuration
# ═══════════════════════════════════════
#
# SAMDeploymentManager.configure_aws()
#
# AWS Configuration:
# ┌────────────────────────┬───────────────────────────────────┐
# │ Access Key ID          │ AKIA...EXAMPLE                    │
# │ Secret Access Key      │ ****************************      │
# │ Default Region         │ us-east-1                         │
# │ Deployment Template    │ SAM proxy/VPN template            │
# └────────────────────────┴───────────────────────────────────┘
#
# [*] AWS credentials configured
# [*] Testing connectivity...
# [+] AWS connection verified — Account: 123456789012
# [+] Region: us-east-1
```

**[Screen: IAM policy document showing minimum required permissions]**

> "For security, use a dedicated IAM user with only the permissions Huginn needs — not your root account or an admin user. Here's the minimum policy. EC2 full access for launching instances, VPC permissions for networking, CloudFormation for template-based deployment, and IAM PassRole for the instance profiles. This follows least-privilege principles."

```bash
# Minimum IAM Policy for Huginn Deployment (HuginnDeployerPolicy)
# ═══════════════════════════════════════════════════════════════
#
# {
#   "Version": "2012-10-17",
#   "Statement": [
#     {
#       "Effect": "Allow",
#       "Action": [
#         "ec2:RunInstances", "ec2:TerminateInstances",
#         "ec2:DescribeInstances", "ec2:CreateSecurityGroup",
#         "ec2:AuthorizeSecurityGroupIngress",
#         "ec2:DeleteSecurityGroup", "ec2:DescribeSecurityGroups",
#         "ec2:CreateKeyPair", "ec2:DeleteKeyPair",
#         "ec2:DescribeVpcs", "ec2:DescribeSubnets",
#         "ec2:DescribeRegions"
#       ],
#       "Resource": "*"
#     },
#     {
#       "Effect": "Allow",
#       "Action": [
#         "cloudformation:CreateStack", "cloudformation:DeleteStack",
#         "cloudformation:DescribeStacks", "cloudformation:DescribeStackEvents"
#       ],
#       "Resource": "arn:aws:cloudformation:*:123456789012:stack/huginn-*"
#     },
#     {
#       "Effect": "Allow",
#       "Action": "iam:PassRole",
#       "Resource": "arn:aws:iam::123456789012:role/huginn-*"
#     }
#   ]
# }
```

---

## SECTION 2: SAM Template Overview — What Gets Deployed (3:45 – 6:00)

**[Screen: Architecture diagram — Huginn SAM Template deploying EC2 instances as proxy/VPN servers across regions]**

> "Huginn uses SAM — Serverless Application Model — templates to define the infrastructure as code. When you click Deploy, Huginn submits a CloudFormation stack that provisions everything automatically. Let me walk you through what gets created."

**[Screen: Diagram showing deployment components — VPC, Security Group, EC2 instance, Elastic IP, user-data script]**

> "A single proxy deployment creates: one EC2 instance running a SOCKS5 proxy daemon, a security group allowing inbound connections from your IP only, and optionally an Elastic IP for a persistent address. The instance runs Amazon Linux 2 with Dante SOCKS server pre-configured via user-data scripts. Total cost: roughly two to three cents per hour for a t3.micro instance."

```bash
# SAM Deployment Architecture
# ═══════════════════════════════════════
#
# What Huginn deploys per region:
#
# ┌─────────────────────────────────────────────────┐
# │  VPC (default or specified)                     │
# │  ┌───────────────────────────────────────────┐  │
# │  │  Security Group: huginn-proxy-sg          │  │
# │  │  - Inbound: TCP 1080 from YOUR_IP/32     │  │
# │  │  - Inbound: TCP 22 from YOUR_IP/32       │  │
# │  │  - Outbound: All traffic (0.0.0.0/0)     │  │
# │  │                                           │  │
# │  │  EC2 Instance: t3.micro (Amazon Linux 2) │  │
# │  │  - Dante SOCKS5 server on port 1080      │  │
# │  │  - SSH access for management             │  │
# │  │  - Auto-configured via user-data         │  │
# │  └───────────────────────────────────────────┘  │
# │                                                 │
# │  Elastic IP (optional): persistent address      │
# └─────────────────────────────────────────────────┘
#
# VPN deployment variant adds:
# - OpenVPN Access Server or WireGuard
# - UDP port 1194 (OpenVPN) or 51820 (WireGuard)
# - Certificate generation for VPN authentication
```

**[Screen: Huginn deployment options panel — Proxy Server vs VPN Server selection, region picker, instance size]**

> "Huginn offers two deployment types. Proxy Server deploys a SOCKS5 proxy — lightweight, fast to provision, works with ProxyChains directly. VPN Server deploys OpenVPN or WireGuard — full tunnel that routes all system traffic, not just proxychains-wrapped commands. For penetration testing, proxy servers are more flexible because you can selectively route specific tools through them while keeping other traffic direct."

```bash
# Deployment configuration options in Huginn
# ═══════════════════════════════════════════
#
# SAMDeploymentManager.deploy_proxy_servers(config)
#
# Configuration options:
# {
#   "deployment_type": "proxy",        # "proxy" or "vpn"
#   "regions": ["us-east-1"],          # Target regions
#   "instance_type": "t3.micro",       # Instance size
#   "proxy_port": 1080,                # SOCKS5 listen port
#   "restrict_to_ip": "203.0.113.45",  # Your IP (security group)
#   "auto_terminate_hours": 4,         # Auto-cleanup timer
#   "elastic_ip": false                # Persistent IP (adds cost)
# }
```

---

## SECTION 3: Deploying a Single-Region Proxy (6:00 – 9:00)

**[Screen: Huginn AWS Deployment panel — "Deploy Proxy Server" button with region set to us-east-1]**

> "Let's deploy our first proxy server. I'm starting with a single instance in us-east-1. In Huginn, select Deploy Proxy Server, confirm the region, and click Deploy. Huginn submits the CloudFormation stack and monitors progress."

**[Screen: Huginn showing deployment progress — CloudFormation events streaming in real-time]**

```bash
# Deploying proxy server to us-east-1
# ═══════════════════════════════════════
#
# [*] Initiating deployment...
# [*] Creating CloudFormation stack: huginn-proxy-us-east-1-20240115
# [*] Stack creation in progress...
#
# CloudFormation Events:
# ┌──────────┬───────────────────────────────┬─────────────────────┐
# │ Time     │ Resource                      │ Status              │
# ├──────────┼───────────────────────────────┼─────────────────────┤
# │ 14:45:01 │ huginn-proxy-sg               │ CREATE_IN_PROGRESS  │
# │ 14:45:03 │ huginn-proxy-sg               │ CREATE_COMPLETE     │
# │ 14:45:05 │ huginn-proxy-keypair          │ CREATE_IN_PROGRESS  │
# │ 14:45:06 │ huginn-proxy-keypair          │ CREATE_COMPLETE     │
# │ 14:45:08 │ huginn-proxy-instance         │ CREATE_IN_PROGRESS  │
# │ 14:45:45 │ huginn-proxy-instance         │ CREATE_COMPLETE     │
# │ 14:45:47 │ huginn-proxy-us-east-1-stack  │ CREATE_COMPLETE     │
# └──────────┴───────────────────────────────┴─────────────────────┘
#
# [+] Stack created successfully
# [+] Instance ID: i-0f1e2d3c4b5a69870
# [+] Public IP: 3.87.142.56
# [+] Proxy endpoint: socks5://3.87.142.56:1080
# [*] Waiting for SOCKS5 service to initialize (user-data script)...
# [+] Proxy service verified — accepting connections
```

**[Screen: Huginn showing deployment complete — green status with proxy endpoint details]**

> "Deployed in about 45 seconds. The instance is running, the security group restricts access to our IP only, and the SOCKS5 proxy is accepting connections on port 1080. Let's verify it works by testing the proxy chain."

```bash
# Verify the deployed proxy
# ═══════════════════════════════════════
#
# ProxyChainsManager chain configuration updated:
# [ProxyList]
# socks5 3.87.142.56 1080
#
# Testing connectivity through deployed proxy:
# [*] Executing: curl -s http://httpbin.org/ip
# [+] Response: {"origin": "3.87.142.56"}
#
# Verification:
# ┌───────────────┬──────────────────┐
# │ Your real IP  │ 203.0.113.45     │
# │ Proxy IP      │ 3.87.142.56      │  (AWS us-east-1)
# │ Seen by dest  │ 3.87.142.56      │  ← clean cloud IP
# └───────────────┴──────────────────┘
#
# Key advantage over Tor:
# - 3.87.142.56 is an AWS IP — NOT on any Tor blocklist
# - Full TCP/UDP support — SYN scans work
# - Low latency (~20ms vs Tor's 500-2000ms)
```

**[Screen: Huginn showing IP verification — target sees AWS IP, not real IP or Tor exit]**

> "The target sees 3.87.142.56 — a clean AWS IP address in the us-east-1 range. This IP is not on any Tor exit node list. It looks like normal cloud traffic. WAFs, IDS systems, and firewalls that block Tor exits will allow this through. And because it's a direct proxy — not three relay hops — latency is only about 20 milliseconds. We can run SYN scans, UDP scans, anything we need."

---

## SECTION 4: Multi-Region Deployment (9:00 – 11:30)

**[Screen: Huginn multi-region deployment panel — showing region selector with us-east-1, eu-west-1, and ap-southeast-1 selected]**

> "For longer engagements, distributing your traffic across multiple regions makes pattern detection harder. If all your scans come from one IP, it's trivial to block. With proxies in three or more regions, you can rotate between them — each probe appearing to come from a different continent. Let's deploy to two additional regions."

```bash
# Multi-region deployment
# ═══════════════════════════════════════
#
# Deploying to additional regions:
# - eu-west-1 (Ireland)
# - ap-southeast-1 (Singapore)
#
# [*] Deploying to eu-west-1...
# [+] Stack: huginn-proxy-eu-west-1-20240115 — CREATE_COMPLETE
# [+] Instance: i-0a2b4c6d8e0f13579
# [+] Proxy: socks5://52.214.89.201:1080
#
# [*] Deploying to ap-southeast-1...
# [+] Stack: huginn-proxy-ap-southeast-1-20240115 — CREATE_COMPLETE
# [+] Instance: i-0b3c5d7e9f1a24680
# [+] Proxy: socks5://13.229.67.143:1080
#
# ═══════════════════════════════════════
# Active Proxy Infrastructure:
# ┌──────────────────┬─────────────────┬────────────┐
# │ Region           │ Proxy IP        │ Status     │
# ├──────────────────┼─────────────────┼────────────┤
# │ us-east-1        │ 3.87.142.56     │ ● Active   │
# │ eu-west-1        │ 52.214.89.201   │ ● Active   │
# │ ap-southeast-1   │ 13.229.67.143   │ ● Active   │
# └──────────────────┴─────────────────┴────────────┘
#
# Combined cost: ~$0.09/hour (3x t3.micro instances)
```

**[Screen: Huginn ProxyChains configuration updated with all three proxy endpoints in random chain mode]**

> "With three proxies deployed, let's configure Huginn's ProxyChainsManager in random chain mode. Random mode selects a random proxy from the list for each connection. Each scan packet potentially exits from a different region — making traffic correlation extremely difficult for the target."

```bash
# Multi-region random chain configuration
# ═══════════════════════════════════════
#
# ProxyChainsManager.set_chain_type("random")
# Chain type set to: random
#
# ProxyChains config generated:
# ─────────────────────────────
# random_chain
# chain_len = 1
# proxy_dns
# quiet_mode
#
# [ProxyList]
# socks5 3.87.142.56 1080      # US East
# socks5 52.214.89.201 1080    # EU Ireland
# socks5 13.229.67.143 1080    # Asia Singapore
#
# Each connection randomly selects one proxy
# Target sees traffic from 3 different geographic regions
```

**[Screen: Huginn running scan with multi-region proxies — showing different source IPs for different probes]**

> "Let's run a scan and observe the IP distribution. Each connection request uses a random proxy from our pool."

```bash
# Scan with multi-region proxy rotation
# ═══════════════════════════════════════
#
# Scanning own EC2 (54.210.167.89) with random proxy chain:
#
# [*] Port 22 probe → via 3.87.142.56 (us-east-1)
# [*] Port 80 probe → via 13.229.67.143 (ap-southeast-1)
# [*] Port 443 probe → via 52.214.89.201 (eu-west-1)
# [*] Port 8080 probe → via 3.87.142.56 (us-east-1)
# [*] Port 3306 probe → via 52.214.89.201 (eu-west-1)
#
# Target sees connections from 3 different IPs across 3 continents
# No single IP sends enough traffic to trigger rate limiting
#
# EC2 access logs:
# 3.87.142.56 → port 22 probe (Virginia, US)
# 13.229.67.143 → port 80 probe (Singapore)
# 52.214.89.201 → port 443 probe (Ireland)
# Pattern: appears as unrelated traffic from different sources
```

**[Screen: Huginn infrastructure status panel — all three regions green, cost accumulator showing]**

> "From the target's perspective, it received probes from three unrelated IP addresses in three different countries. There's no obvious pattern connecting them. This dramatically reduces the chance of detection and IP-based blocking compared to scanning from a single source."

---

## SECTION 5: Cost Awareness and Resource Monitoring (11:30 – 13:30)

**[Screen: Huginn cost awareness panel — showing running costs, hourly rates, and projected daily cost]**

> "Real money is involved here. Let's talk costs. A t3.micro instance costs roughly $0.0116 per hour in us-east-1 — about 1.2 cents per hour. Three instances across regions runs around 9 cents per hour, or roughly $2.16 per day. That's manageable for an active engagement. But if you forget to tear down your infrastructure, it adds up fast — $65 per month for three idle instances you're not using."

```bash
# Cost breakdown for deployed infrastructure
# ═══════════════════════════════════════════
#
# Current deployment costs:
# ┌──────────────────┬──────────────┬───────────────┐
# │ Region           │ Instance     │ Cost/Hour     │
# ├──────────────────┼──────────────┼───────────────┤
# │ us-east-1        │ t3.micro     │ $0.0116       │
# │ eu-west-1        │ t3.micro     │ $0.0126       │
# │ ap-southeast-1   │ t3.micro     │ $0.0132       │
# ├──────────────────┼──────────────┼───────────────┤
# │ TOTAL            │ 3 instances  │ ~$0.037/hour  │
# └──────────────────┴──────────────┴───────────────┘
#
# Projected costs:
# - 4 hour engagement:  ~$0.15
# - 8 hour day:         ~$0.30
# - Left running 24h:   ~$0.89
# - Forgotten for 30d:  ~$26.70
#
# ⚠️  ALWAYS tear down when done!
```

**[Screen: Huginn auto-terminate setting — countdown timer visible, 4 hours remaining]**

> "Huginn includes an auto-terminate safety net. When you deploy, you can set an auto-terminate timer — I set mine to 4 hours. If you don't explicitly extend or tear down, Huginn automatically terminates the instances after the timer expires. This prevents forgotten infrastructure from running indefinitely. You'll see a countdown in the deployment status panel."

```bash
# Auto-terminate configuration
# ═══════════════════════════════════════
#
# Auto-terminate: ENABLED
# Timeout: 4 hours from deployment
# Countdown: 3h 14m remaining
#
# Behavior on timeout:
# [*] Timer expired for huginn-proxy-us-east-1-20240115
# [*] Initiating auto-termination...
# [*] Terminating i-0f1e2d3c4b5a69870 (us-east-1)
# [*] Terminating i-0a2b4c6d8e0f13579 (eu-west-1)
# [*] Terminating i-0b3c5d7e9f1a24680 (ap-southeast-1)
# [*] Deleting security groups...
# [*] Deleting CloudFormation stacks...
# [+] All resources terminated — no ongoing costs
#
# You can extend the timer or manually tear down earlier
```

**[Screen: Huginn showing AWS billing warning — "Resources are consuming costs" indicator in orange]**

> "While infrastructure is running, Huginn shows a persistent orange indicator reminding you that billable resources are active. This stays visible across all panels so you don't lose track. Good practice is to deploy at the start of your assessment window and tear down immediately when you're done for the day."

---

## SECTION 6: Teardown and Cleanup (13:30 – 15:30)

**[Screen: Huginn deployment panel — "Tear Down All" button prominently displayed with confirmation dialog]**

> "When your assessment window closes, tear everything down. Huginn's teardown process is comprehensive — it deletes the CloudFormation stacks, which cascade-deletes all associated resources: instances, security groups, key pairs, and Elastic IPs. Nothing is left behind."

```bash
# Infrastructure teardown
# ═══════════════════════════════════════
#
# [*] Initiating teardown of all deployed infrastructure...
#
# Tearing down us-east-1:
# [*] Deleting stack: huginn-proxy-us-east-1-20240115
# [*] Terminating instance: i-0f1e2d3c4b5a69870
# [*] Deleting security group: huginn-proxy-sg
# [*] Deleting key pair: huginn-proxy-key-us-east-1
# [+] us-east-1 — all resources deleted
#
# Tearing down eu-west-1:
# [*] Deleting stack: huginn-proxy-eu-west-1-20240115
# [*] Terminating instance: i-0a2b4c6d8e0f13579
# [*] Deleting security group: huginn-proxy-sg
# [*] Deleting key pair: huginn-proxy-key-eu-west-1
# [+] eu-west-1 — all resources deleted
#
# Tearing down ap-southeast-1:
# [*] Deleting stack: huginn-proxy-ap-southeast-1-20240115
# [*] Terminating instance: i-0b3c5d7e9f1a24680
# [*] Deleting security group: huginn-proxy-sg
# [*] Deleting key pair: huginn-proxy-key-ap-southeast-1
# [+] ap-southeast-1 — all resources deleted
#
# ═══════════════════════════════════════
# [+] TEARDOWN COMPLETE
# [+] All 3 stacks deleted
# [+] All 3 instances terminated
# [+] All security groups removed
# [+] All key pairs deleted
# [+] No remaining billable resources
# ═══════════════════════════════════════
```

**[Screen: Huginn deployment panel showing empty state — "No Active Infrastructure" with green checkmark]**

> "Clean slate. All three stacks are deleted, all instances terminated, all security groups and key pairs removed. The deployment panel shows 'No Active Infrastructure' with a green checkmark. Let me verify in the AWS console."

```bash
# Verification via AWS CLI
# ═══════════════════════════════════════
#
aws ec2 describe-instances --filters "Name=tag:Project,Values=huginn-proxy" \
  --query "Reservations[].Instances[?State.Name!='terminated']"
# []  ← No running instances with huginn-proxy tag

aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE
# {
#     "StackSummaries": []   ← No active stacks
# }

# Double-check: any huginn-related security groups?
aws ec2 describe-security-groups --filters "Name=group-name,Values=huginn-*"
# {
#     "SecurityGroups": []   ← All cleaned up
# }
#
# [+] Verified: zero Huginn resources remain in AWS
```

**[Screen: AWS Billing console showing minimal charges — $0.04 for the session]**

> "Checking the billing console — total cost for today's demonstration was about four cents. Three instances running for roughly one hour across three regions. That's the beauty of on-demand cloud infrastructure for penetration testing. Deploy when you need it, tear down when you don't. No monthly server costs, no maintenance, no ongoing exposure."

---

## SECTION 7: Combining AWS Proxies with Tor and Stealth Mode (15:30 – 17:15)

**[Screen: Huginn showing combined configuration — Stealth Mode + Tor + AWS Proxy layered setup]**

> "The real power comes from combining everything we've learned in Section 7. Stealth Mode controls your traffic patterns and timing (see Video 41: Stealth Mode). Tor provides onion-routed anonymity (see Video 43: Tor Integration). AWS proxies give you clean cloud IPs with full protocol support. Layer them together for maximum operational security."

```bash
# Maximum anonymity configuration
# ═══════════════════════════════════════
#
# Stealth Mode: Paranoid
# Chain Mode: strict
#
# [ProxyList]
# socks5 127.0.0.1 9050            # Tor (anonymize from proxy)
# socks5 3.87.142.56 1080          # AWS proxy (clean exit IP)
#
# Traffic flow:
# You → Tor Guard → Middle → Exit → AWS Proxy → Target
#
# - Your ISP sees: Tor traffic (if not using VPN pre-Tor)
# - Tor exit sees: Connection to AWS IP
# - AWS proxy sees: Tor exit IP (not your real IP)
# - Target sees: AWS proxy IP (clean, not Tor, not you)
#
# Result: 5 hops of separation, clean exit IP,
# Tor-level anonymity, no Tor blocklist issues
```

**[Screen: Slide showing the complete Section 7 evasion toolkit — Stealth Mode + ProxyChains + Tor + AWS combined]**

> "This layered approach gives you the best of every technique. Stealth Mode shapes your traffic to avoid IDS triggers. Tor provides cryptographic anonymity across three relays. The AWS proxy provides a clean exit IP that bypasses Tor blocklists. Together, you have five or more hops of separation between your real IP and the target, with traffic patterns that look like normal cloud activity rather than automated scanning."

**[Screen: Slide showing CEH domain mapping — Module 12: Evading IDS, Firewalls, and Honeypots]**

> "AWS-based proxy infrastructure maps to CEH Module 12 — Evading IDS, Firewalls, and Honeypots. The exam covers cloud-based evasion techniques, proxy pivoting, and traffic distribution. Understanding how to deploy disposable infrastructure, rotate source IPs, and clean up after assessments are all relevant skills. For OSCP, while cloud deployment isn't directly tested, the ability to tunnel and proxy traffic is essential for the pivoting scenarios in the exam."

**[Screen: Practice recommendations]**

> "For practice, create a minimal IAM policy and deploy a single proxy to one region. Verify your IP changes, run a scan through it, and tear it down. Time yourself — practice getting infrastructure up and operational in under two minutes. In real engagements, speed of deployment matters when you need to rotate IPs mid-assessment."

---

## OUTRO (17:15 – end)

**[Screen: Summary slide — AWS Deployment: CLI Setup | SAM Templates | Single-Region Deploy | Multi-Region Distribution | Cost Management | Teardown | Combined Evasion | Section 7 Complete → Next: Section 8 — Post-Exploitation]**

> "That's AWS Infrastructure Deployment, and that completes Section 7 — Stealth and Evasion. Across these four videos, we covered Stealth Mode for traffic pattern control, ProxyChains for multi-proxy routing, Tor for onion-routed anonymity, and now AWS deployment for clean, disposable cloud infrastructure. Together, these give you a comprehensive evasion toolkit for authorized penetration testing — Professional tier features that let you conduct assessments without triggering detection systems. Next up is Section 8 — Post-Exploitation and Privilege Escalation — where we'll use established sessions to harvest credentials, maintain persistence, and move laterally through networks. See you there."
