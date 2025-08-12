---
title: MongoDB
updated: 2023-11-01 00:47:16Z
created: 2023-10-28 06:43:22Z
latitude: -33.86881970
longitude: 151.20929550
altitude: 0.0000
---

`mongosh` # connects to mongodb://127.0.0.1:27017 by default  
`mongosh --host <host> --port <port> --authenticationDatabase admin -u <user> -p <pwd>` # omit the password if you want a prompt  
`mongosh "mongodb://<user>:<password>@192.168.1.1:27017"`  
`mongosh "mongodb://192.168.1.1:27017"`  
`mongosh "mongodb+srv://cluster-name.abcde.mongodb.net/<dbname>" --apiVersion 1 --username <username>` # MongoDB Atlas

List MongoDB databases  
`show dbs`

Switch to database  
`use <database>`

Show collections  
`show collections`

Show users  
`db.admin.find().pretty()`

Run Javascrip  
`load("myScript.js")`

Replace hash of account  
mkpasswd -m SHA512 pa55w0rd  
db.changeUserPassword("administrator@unified.htb", "$6$xGb1mYh1ULA5BMZS$fQRsAF/PepOwuHcUO2vbeqLEI6/IF2OvEfvFdl.a5TdG6EhXnVVoEzFuKYp0Sj7cBCY/AtvuVVNNp3tHTkMvx1")

```
    "_id" : ObjectId("61ce278f46e0fb0012d47ee4"),
    "name" : "administrator",
    "email" : "administrator@unified.htb",
    "x_shadow" : "$6$Ry6Vdbse$8enMR5Znxoo.WfCMd/Xk65GwuQEPx1M.QP8/qHiQV0PvUc3uHuonK4WcTQFN1CRk3GwQaquyVwCVq8iQgPTt4.",
```

&nbsp;

db.admin.update()

mongo --port 27117 ace --eval 'db.admin.update({"\_id": ObjectId("61ce278f46e0fb0012d47ee4")},{$set:{"x\_shadow":"$6$xGb1mYh1ULA5BMZS$fQRsAF/PepOwuHcUO2vbeqLEI6/IF2OvEfvFdl.a5TdG6EhXnVVoEzFuKYp0Sj7cBCY/AtvuVVNNp3tHTkMvx1"}})'

$6$xGb1mYh1ULA5BMZS$fQRsAF/PepOwuHcUO2vbeqLEI6/IF2OvEfvFdl.a5TdG6EhXnVVoEzFuKYp0Sj7cBCY/AtvuVVNNp3tHTkMvx1