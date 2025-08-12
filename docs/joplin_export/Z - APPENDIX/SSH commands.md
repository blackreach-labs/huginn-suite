---
title: SSH commands
updated: 2025-04-19 03:41:30Z
created: 2025-04-19 03:23:39Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## Important Files
**~/.ssh/** | User’s SSH config and key storage directory
**~/.ssh/id_rsa** | Default private key (RSA)
**~/.ssh/id_rsa.pub** | Default public key
**~/.ssh/id_ed25519** | Private key (ed25519, more secure/faster)
**~/.ssh/id_ed25519.pub** | Public key (ed25519)
**~/.ssh/authorized_keys** | List of public keys allowed to log into the user account via SSH
**~/.ssh/known_hosts** | Tracks host keys of previously connected SSH servers

**/etc/ssh/sshd_config** | Server-side SSH configuration
**/etc/ssh/ssh_config** | Client-side default SSH configuration
**/etc/ssh/ssh_host_*** | Host keys used to identify the server to clients
* * *
Clear local 

Check SSL/TLS certificate details:
`openssl s_client -connect <target>:443`

Retrieve just the certificate:
`echo | openssl s_client -connect <target>:443 | openssl x509 -noout -text`

Identify supported SSL/TLS versions & cipher suites:
`nmap --script ssl-enum-ciphers -p 443 <target>`
