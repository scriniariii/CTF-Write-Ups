
<pre><code>> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.20 | tee nmap1.txt
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-02 18:52 -03
Initiating SYN Stealth Scan at 18:52
Scanning 10.10.11.20 [65535 ports]
Discovered open port 80/tcp on 10.10.11.20
Discovered open port 22/tcp on 10.10.11.20
Completed SYN Stealth Scan at 18:52, 26.92s elapsed (65535 total ports)
Nmap scan report for 10.10.11.20
Host is up, received user-set (0.81s latency).
Scanned at 2024-10-02 18:52:18 -03 for 27s
Not shown: 55051 filtered tcp ports (no-response), 10482 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27.04 seconds
           Raw packets sent: 127768 (5.622MB) | Rcvd: 10542 (421.704KB)</code></pre>

<pre><code>> sudo nmap -p22,80 -sCV -Pn 10.10.11.20 | tee nmap2.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-02 18:57 -03
Nmap scan report for 10.10.11.20
Host is up (0.26s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.38 seconds</code></pre>

<pre><code>sudo nano /etc/hosts</code></pre>

<pre><code>
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: /etc/hosts
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ # Static table lookup for hostnames.
   2   │ # See hosts(5) for details.
   3   │ 
   4   │ 127.0.0.1   localhost
   5   │ ::1         localhost
   6   │ 127.0.1.1   maxi-notebook.localdomain maxi-notebook
   7   │ 
   8   │ 10.10.11.20 editorial.htb
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────
</code></pre>

<pre><code>> gobuster dir -u http://editorial.htb/ -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 | tee gobuster.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://editorial.htb/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/about                (Status: 200) [Size: 2939]
/upload               (Status: 200) [Size: 7140]</code></pre>

![2024-10-02_19-13](https://github.com/user-attachments/assets/ef83909c-7c75-4cd1-ac65-ae829ae07455)

![2024-10-02_19-40](https://github.com/user-attachments/assets/be978427-6ed3-4ca9-820b-c5081227cd22)

<pre><code>> nc -nlvp 1234
Connection from 10.10.11.20:40722
GET / HTTP/1.1
Host: 10.10.14.160:1234
User-Agent: python-requests/2.25.1
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
</code></pre>

<pre><code>> curl -v http://editorial.htb/static/uploads/a8698fc0-6b65-4a4c-a1a4-f68d9ae048bf</code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>
