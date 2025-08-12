---
title: Burpsuite
updated: 2023-11-02 10:29:06Z
created: 2023-11-02 10:05:54Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

### Burpsuite
1. Go to **Target** , **Scope Settings** , **Target Scope** and enable **Use advanced scope control**
2. **Add** > **Protocol=Any** and **Host/IP** range as target domain.
![7af1e22dbec010a0a84a7514418abcf7.png](../../_resources/7af1e22dbec010a0a84a7514418abcf7.png)
3. Go to **Proxy** , **Proxy Settings** , **Tools** , **Proxy** and under **Request interception rules** & **Response interception rules** Enable **And | URL | Is in target scope**
4. Turn **Proxy** **Intercept** to **On**
5. Capture a Login payload and Send to **Repeater** and **Intruder**, **Forward** the original login payload and find a value to match for a grep filter
6. Go to **Intruder** , **Settings** , **Grep Match**, clear the list and Add Error value to filter with.
7. Configure a Sniper attack on the password payload
8. 