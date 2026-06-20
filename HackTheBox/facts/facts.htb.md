I start by scanning the target machine with nmap

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-08 22:03 -03
Nmap scan report for 10.129.19.111
Host is up (0.37s latency).

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp    open  http    nginx 1.26.3 (Ubuntu)
|_http-title: Did not follow redirect to http://facts.htb/
|_http-server-header: nginx/1.26.3 (Ubuntu)
54321/tcp open  http?   Golang net/http server
|_http-title: Did not follow redirect to http://10.129.19.111:9001
| fingerprint-strings:.......
```

i can see 3 ports open, ssh, the web page and some weird port by the numbre 54321
