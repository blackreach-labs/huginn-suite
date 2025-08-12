---
title: FFUF
updated: 2023-10-02 11:09:28Z
created: 2023-10-02 10:33:51Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

# FFUF

1. Grab a copy of the payload sent to authentication and add to file **payload.txt**
![5d48d3d1de3f21925e251dd3dbe241e8.png](../../_resources/5d48d3d1de3f21925e251dd3dbe241e8.png)

2. Change the username and password values to respective keywords **FUZZUSER** and **FUZZPASS**
3. `ffuf -request payload.txt -request-proto http -mode clusterbomb -w <password_list>:FUZZPASS -w <username_list>:FUZZUSER -fs <content-length to filter>`
