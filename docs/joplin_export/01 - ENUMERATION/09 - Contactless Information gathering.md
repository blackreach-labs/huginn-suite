---
title: 09 - Contactless Information gathering
updated: 2025-04-22 13:08:00Z
created: 2025-04-22 12:55:03Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## Inspect **metadata tags**
Inspect **metadata tags** of publicly available documents associated with the target organization. These tags can include a information about a document including:
**Author**, 
**creation date**, 
**name** & **version of software** used to create the document, 
**OS** of the client, etc

1. Download files from the web application.
2. Check files for metadata using **exiftool** with **-a** to display duplicated tags, and **-u** to display unknow tags
`exiftool -a -u <file>`