---
title: Conditional Time Delays
updated: 2023-11-06 11:10:20Z
created: 2023-11-06 11:09:39Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

## Time Based Conditional

`SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 'a'||dbms_pipe.receive_message(('a'),10) ELSE NULL END FROM dual`