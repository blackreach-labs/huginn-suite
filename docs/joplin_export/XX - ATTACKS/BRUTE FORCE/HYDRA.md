---
title: HYDRA
updated: 2023-11-27 11:11:34Z
created: 2023-10-02 10:34:13Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# HYDRA
You will need:
1. Login or Wordlist for Usernames
2. Password or Wordlist for Passwords
3. IP address or Hostname
4. HTTP Method (POST/GET)
5. Directory/Path to the Login Page
6. Request Body for Username/Password
7. A Way to Identify Failed Attempts

Follow steps [here](https://infinitelogins.com/2020/02/22/how-to-brute-force-websites-using-hydra/)

### Brute force LDAP
hydra -l {Username} -P {Big_Passwordlist} {IP} ldap2 -V -f