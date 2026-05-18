# Requirements Document

## Introduction

The Tool Help System provides comprehensive, in-application documentation for all currently implemented tools in Huginn. Accessed via Help → Tool Help (F1), the panel displays a navigable list of tools on the left and tabbed help content on the right (Overview, Tool Help, Shortcuts, Tips & Tricks). This feature ensures every tool in the application has complete, accurate help content covering features, usage instructions, and tips.

## Glossary

- **Help_Panel**: The standalone window (`EnhancedHelpPanel`) opened via Help → Tool Help (F1) that displays tool documentation
- **Help_Data**: The Python dictionary within the Help_Panel that stores structured help content for each tool
- **Tool_List**: The left-side panel of buttons in the Help_Panel that allows users to select a tool for viewing its documentation
- **Tool_Help_Tab**: The right-side tab that displays the selected tool's features, usage, and tips
- **Overview_Tab**: The right-side tab that displays a summary of all Huginn capabilities
- **Tool_Config**: The JSON configuration file (`tool_configs.json`) that defines the UI controls for each enumeration tool

## Requirements

### Requirement 1: Complete Help Data for Missing Enumeration Tools

**User Story:** As a penetration tester, I want help content for SMTP, SNMP, HTTP, API, RPC, LDAP, and Database enumeration tools, so that I can understand how to use each tool without leaving the application.

#### Acceptance Criteria

1. WHEN a user clicks the "SMTP Enumeration" button in the Tool_List, THE Help_Panel SHALL display help content for the SMTP enumeration tool containing a description (minimum 1 sentence), a features list (minimum 3 items), usage steps (minimum 3 numbered steps), and tips (minimum 3 items), and SHALL switch to the "Tool Help" tab
2. WHEN a user clicks the "SNMP Enumeration" button in the Tool_List, THE Help_Panel SHALL display help content for the SNMP enumeration tool containing a description (minimum 1 sentence), a features list (minimum 3 items), usage steps (minimum 3 numbered steps), and tips (minimum 3 items), and SHALL switch to the "Tool Help" tab
3. WHEN a user clicks the "HTTP Enumeration" button in the Tool_List, THE Help_Panel SHALL display help content for the HTTP enumeration tool containing a description (minimum 1 sentence), a features list (minimum 3 items), usage steps (minimum 3 numbered steps), and tips (minimum 3 items), and SHALL switch to the "Tool Help" tab
4. WHEN a user clicks the "API Enumeration" button in the Tool_List, THE Help_Panel SHALL display help content for the API enumeration tool containing a description (minimum 1 sentence), a features list (minimum 3 items), usage steps (minimum 3 numbered steps), and tips (minimum 3 items), and SHALL switch to the "Tool Help" tab
5. WHEN a user clicks the "RPC Enumeration" button in the Tool_List, THE Help_Panel SHALL display help content for the RPC enumeration tool containing a description (minimum 1 sentence), a features list (minimum 3 items), usage steps (minimum 3 numbered steps), and tips (minimum 3 items), and SHALL switch to the "Tool Help" tab
6. WHEN a user clicks the "LDAP Enumeration" button in the Tool_List, THE Help_Panel SHALL display help content for the LDAP enumeration tool containing a description (minimum 1 sentence), a features list (minimum 3 items), usage steps (minimum 3 numbered steps), and tips (minimum 3 items), and SHALL switch to the "Tool Help" tab
7. WHEN a user clicks the "Database Enumeration" button in the Tool_List, THE Help_Panel SHALL display help content for the Database enumeration tool containing a description (minimum 1 sentence), a features list (minimum 3 items), usage steps (minimum 3 numbered steps), and tips (minimum 3 items), and SHALL switch to the "Tool Help" tab
8. THE Help_Panel SHALL render each tool's help content within 2 seconds of the user clicking the corresponding Tool_List button
9. THE Help_Panel SHALL display help content for each of the seven enumeration tools (SMTP, SNMP, HTTP, API, RPC, LDAP, Database) using the same HTML structure as existing tool help entries: a title heading, a description paragraph, a "Features" section with a bulleted list, a "Usage" section with a numbered list, and a "Tips" section with a bulleted list

### Requirement 2: Add Missing Tools to the Tool List

**User Story:** As a penetration tester, I want the Tool_List to include IKE/VPN Assessment, AV/Firewall Detection, SSH Enumeration, and Azure Toolkit, so that I can access help for all implemented tools from the Help_Panel.

#### Acceptance Criteria

1. THE Tool_List SHALL include a button labeled "IKE/VPN Assessment" that maps to a unique tool identifier for the IKE tool help content
2. THE Tool_List SHALL include a button labeled "AV/Firewall Detection" that maps to a unique tool identifier for the AV/Firewall tool help content
3. THE Tool_List SHALL include a button labeled "SSH Enumeration" that maps to a unique tool identifier for the SSH tool help content
4. THE Tool_List SHALL include a button labeled "Azure Toolkit" that maps to a unique tool identifier for the Azure Toolkit help content
5. WHEN a user clicks any of the newly added tool buttons, THE Help_Panel SHALL switch to the Tool Help tab and display help content containing a description (minimum 1 sentence), a features list (minimum 3 items), usage steps (minimum 3 steps), and tips (minimum 2 items) specific to that tool
6. WHEN a user clicks any of the newly added tool buttons, THE Help_Panel SHALL display the help content within 1 second of the click event
7. IF help content for a clicked tool button is not found in the help data, THEN THE Help_Panel SHALL remain on the current tab without displaying blank or error content

### Requirement 3: Help Content Accuracy

**User Story:** As a penetration tester, I want the help content to accurately reflect the current tool configurations and capabilities, so that I can rely on the documentation when using the tools.

#### Acceptance Criteria

1. THE Help_Data for each tool SHALL list every scan type defined in that tool's Tool_Config combobox as a feature, using the exact label text from the configuration
2. THE Help_Data for each tool SHALL include usage steps that mention each user-facing UI control (combo boxes, input fields, checkboxes, buttons) defined in the Tool_Config by its visible label or placeholder text
3. THE Help_Data for the SMTP tool SHALL reference the VRFY, EXPN, and RCPT TO enumeration methods, the port field (default 25), domain field, HELO name field (default "test.local"), and wordlist selector
4. THE Help_Data for the SNMP tool SHALL reference SNMP versions 1, 2c, and 3, scan types (Basic Info, Users, Processes, Software, Network, Full Enumeration), community string configuration (default "public,private,community"), and the Quick preset buttons (Default, Extended)
5. THE Help_Data for the HTTP tool SHALL reference scan types (Fingerprinting, Source Code, Crawler, Directory Enum, Enterprise Scripts, Full Scan), file extension selection checkboxes grouped by category (PHP, ASP, JSP, HTML, JS, Config, Backup), presets (Manual, PHP Apps, API-focused, Login Pages, Backup Files, CMS Common), wordlist selector, Enable Listener checkbox, and authentication options (None, Basic Auth)
6. THE Help_Data for the API tool SHALL reference scan types (Basic Discovery, Gobuster Enum, HTTP Methods, Auth Bypass, Vulnerability Test, Full Scan), presets (None, API-focused, Login Pages, Backup Files), wordlist size options (Small, Medium, Large), wordlist selector, and endpoint patterns (/api, /api/v1, /rest, /graphql, /swagger)
7. THE Help_Data for the RPC tool SHALL reference scan types (Basic Info, Full Enumeration, Vulnerability Scan, Complete Assessment) and authentication methods (Anonymous, Credentials, Pass-the-Hash, Kerberos Ticket, Kerberos Password), including domain, username, password, NTLM hash, and ticket file fields
8. THE Help_Data for the LDAP tool SHALL reference port configuration (default 389), SSL/TLS checkbox (port 636), scan types (Basic Info, Anonymous Enum, Authenticated Enum, Full Scan), Base DN field with auto-detection when left empty, and username/password fields for authenticated enumeration
9. THE Help_Data for the Database tool SHALL reference supported database types (MSSQL, MySQL, MariaDB, Oracle, PostgreSQL), scan types (Basic Info, Scripts, Full Scan), port field with database-specific defaults, Oracle SID field, and authentication options including username, password, and credential manager integration
10. THE Help_Data for the IKE tool SHALL reference port field (default 500), scan types (Basic Info, Detailed Scan, Transform Enum, Full Scan), aggressive mode checkbox (enabled by default), and ike-scan tool requirement
11. THE Help_Data for the AV/Firewall tool SHALL reference detection types (WAF Detection, Firewall Detection, Evasion Test, AV Payload Gen, Full Detection), port field (default 80), payload type selector (msfvenom, shellter), and tool requirements (nmap for firewall detection, msfvenom for payload generation)
12. THE Help_Data for the SSH tool SHALL reference port field (default 22), scan types (Enumeration, Banner Grab, Key Exchange, Cipher Analysis, Full Scan), auth types (Anonymous, Password, Key File, Bruteforce), and associated fields (username, password, key file path with browse button, wordlist selector)
13. THE Help_Data for the Azure Toolkit SHALL reference modules (DNS Enumeration, Azure AD, ARM Resources, Storage, Comprehensive), domain field, subscription ID field, and auth methods (Default Credential, Interactive Browser, Client Secret) with associated fields (Tenant ID, Client ID, Client Secret)
14. IF a scan type or UI control is added to or removed from the Tool_Config, THEN THE Help_Data for the affected tool SHALL be updated to reflect the change before the next application release

### Requirement 4: Overview Tab Completeness

**User Story:** As a new user, I want the Overview tab to list all available tools in Huginn, so that I can quickly understand the full scope of the application.

#### Acceptance Criteria

1. THE Overview_Tab SHALL list every tool present in the Tool_List, including DNS Enumeration, Port Scanning, SMB Enumeration, SMTP Enumeration, SNMP Enumeration, HTTP Enumeration, API Enumeration, RPC Enumeration, LDAP Enumeration, Database Enumeration, IKE/VPN Assessment, AV/Firewall Detection, SSH Enumeration, Azure Toolkit, Runecraft, and Huginn Scanner
2. THE Overview_Tab SHALL include a one-line description of no more than 120 characters for each listed tool that states the tool's primary function
3. WHEN a new tool is added to the Tool_List, THE Overview_Tab SHALL include a corresponding entry with the tool name and one-line description before the next application release
4. IF a tool listed in the Tool_List does not have a corresponding entry in the Overview_Tab, THEN THE Overview_Tab SHALL be considered incomplete and failing this requirement

### Requirement 5: Consistent Help Content Structure

**User Story:** As a user, I want all tool help entries to follow the same structure, so that I can quickly find the information I need regardless of which tool I select.

#### Acceptance Criteria

1. THE Help_Data for each tool SHALL contain a "title" field with the tool display name as a non-empty string of no more than 80 characters
2. THE Help_Data for each tool SHALL contain a "description" field with a single-sentence summary of the tool purpose, not exceeding 200 characters
3. THE Help_Data for each tool SHALL contain a "features" field with a list of at least 4 feature descriptions, each as a non-empty string
4. THE Help_Data for each tool SHALL contain a "usage" field with at least 3 numbered step-by-step instructions presented in sequential order
5. THE Help_Data for each tool SHALL contain a "tips" field with a list of at least 3 practical tips for effective use, each as a non-empty string
6. IF any tool entry in Help_Data is missing one or more of the required fields (title, description, features, usage, tips), THEN THE System SHALL reject the entry and display an error message indicating which fields are missing
