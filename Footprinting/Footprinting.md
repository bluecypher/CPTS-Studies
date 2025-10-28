# Footprinting

Comprehensive notes and commands for network and service footprinting and enumeration, organized by topic. Use responsibly and only on systems you have permission to test.

## Table of Contents
- Enumeration Principles
- Infrastructure Enumeration (Hosts, Ports, Services)
- FTP
- SMB
- NFS
- DNS
- SMTP
- IMAP/POP3
- SNMP
- MySQL
- MSSQL
- Oracle TNS
- IPMI
- Linux Remote Management Protocols (SSH)
- Windows Remote Management Protocols (RDP, WinRM, WMI, SMB/IPC$)
- Labs and Practical Workflow

---

## Enumeration Principles
Key concepts:
- Always start passive (OSINT, DNS records, certificates, public repos, Shodan/Censys) before active scanning.
- Enumerate systematically: scope -> discover -> fingerprint -> enumerate -> validate -> document.
- Safe scanning: set proper timing, exclude production ranges if required, throttle when needed.
- Correlate across tools; validate false-positives; capture versions/banners for CVE mapping.

Common commands:
- Ping sweep:
  - fping -aqg 10.10.11.0 10.10.11.255
  - nmap -sn 10.10.11.0/24
- Port discovery and service/version detection:
  - nmap -p- -T4 -v 10.10.11.10
  - nmap -sC -sV -p <ports> 10.10.11.10
  - rustscan -a 10.10.11.10 --ulimit 5000 -g -- -sV -sC
- UDP discovery:
  - nmap -sU --top-ports 200 -v 10.10.11.10
- Banner grabbing:
  - nc -nv 10.10.11.10 80
  - curl -I http://10.10.11.10
- Screenshotting:
  - eyewitness -x nmap.xml -d ./eyewitness

---

## Infrastructure Enumeration
Key concepts:
- Identify hosts, open TCP/UDP ports, OS, and services. Parse outputs to build a service matrix.
- Prefer saving outputs (grepable or XML) for post-processing.

Commands:
- nmap full + scripts:
  - nmap -p- -sC -sV -oA scans/full 10.10.11.10
  - nmap -A -oA scans/aggr 10.10.11.10
- UDP targeted:
  - nmap -sU -p 53,67,68,69,123,137,161,500,514,5353 -sV -oA scans/udp 10.10.11.10
- NSE scripts per service later in each section.
- Masscan first, nmap confirm:
  - masscan 10.10.11.0/24 -p1-65535 --rate 5000 -e tun0 -oL masscan.lst
  - nmap -sV -sC -p $(awk '{print $4}' masscan.lst | tr '\n' ',' | sed 's/,$//') 10.10.11.10

---

## FTP (21/tcp)
Key concepts:
- Check anonymous login; list, download, and inspect for credentials; active vs passive mode.

Commands:
- nmap --script ftp-anon,ftp-syst,ftp-banner -p21 10.10.11.10
- ftp 10.10.11.10 (user: anonymous, pass: anonymous)
- lftp -u anonymous,anonymous 10.10.11.10
- wget -m --no-passive-ftp ftp://anonymous:anonymous@10.10.11.10/
- Hydra brute (if permitted): hydra -l user -P passwords.txt -f -s 21 ftp://10.10.11.10

---

## SMB (139,445/tcp)
Key concepts:
- Enumerate shares, null/guest sessions, SMB signing, and OS/domain info.

Commands:
- nmap --script smb-os-discovery,smb-enum-shares,smb-enum-users -p445 10.10.11.10
- smbclient -L //10.10.11.10/ -N
- smbclient //10.10.11.10/SHARE -N -c "ls; get file.txt"
- crackmapexec smb 10.10.11.10 -u '' -p '' --shares
- enum4linux-ng -A 10.10.11.10
- rpcclient -U '' -N 10.10.11.10 -c "enumdomusers; enumdomgroups; querydominfo"
- impacket-smbclient -no-pass 10.10.11.10
- Check signing: nmap --script smb2-security-mode -p445 10.10.11.10

---

## NFS (2049/udp,tcp)
Key concepts:
- Discover exported directories, permissions (no_root_squash), and mount for read/write.

Commands:
- nmap --script nfs-ls,nfs-showmount,nfs-statfs -p111,2049 10.10.11.10
- showmount -e 10.10.11.10
- mkdir -p /mnt/nfs; sudo mount -t nfs 10.10.11.10:/share /mnt/nfs -o nolock
- ls -al /mnt/nfs; cat /mnt/nfs/*; sudo umount /mnt/nfs

---

## DNS (53/udp,tcp)
Key concepts:
- Zone transfer attempts, record enumeration, subdomain brute, misconfigurations.

Commands:
- nmap -sU -p53 --script dns-recursion,dns-nsid,dns-zone-transfer 10.10.11.10
- dig @10.10.11.10 example.com any +noedns
- dig @10.10.11.10 example.com AXFR
- nslookup -type=any example.com 10.10.11.10
- Subdomain brute:
  - gobuster dns -d example.com -w subdomains.txt -t 50 -o subs.txt
  - amass enum -passive -d example.com -o amass.txt
- Reverse lookup sweep:
  - for i in {1..254}; do dig -x 10.10.11.$i +short; done

---

## SMTP (25/tcp)
Key concepts:
- VRFY/EXPN user enumeration, open relay checks, banner versioning.

Commands:
- nmap -p25 --script smtp-open-relay,smtp-enum-users,smtp-commands 10.10.11.10
- nc -nv 10.10.11.10 25
  - HELO attacker.com
  - VRFY user
  - EXPN list
- swaks --to test@target.com --server 10.10.11.10 --data @mail.txt

---

## IMAP/POP3 (143,993 / 110,995)
Key concepts:
- STARTTLS support, clear-text creds on POP3/IMAP if misconfigured, capability enumeration.

Commands:
- nmap --script imap-capabilities,imap-ntlm-info -p143,993 10.10.11.10
- nmap --script pop3-capabilities -p110,995 10.10.11.10
- openssl s_client -connect 10.10.11.10:993 -crlf -quiet
  - a login user pass
  - a list "" "*"
- openssl s_client -connect 10.10.11.10:995 -quiet
- Hydra (if authorized): hydra -L users.txt -P pass.txt -S -s 993 imap://10.10.11.10

---

## SNMP (161/udp)
Key concepts:
- Community strings (public/private), walk MIBs for creds, network maps, process lists.

Commands:
- onesixtyone 10.10.11.10 -c community.txt
- snmpwalk -v2c -c public 10.10.11.10 1.3.6.1.2.1.1
- snmpbulkwalk -v2c -c public 10.10.11.10 1.3.6.1.2.1
- snmp-check 10.10.11.10 -c public
- nmap -sU -p161 --script snmp-info,snmp-processes,snmp-netstat 10.10.11.10

---

## MySQL (3306/tcp)
Key concepts:
- Default/weak creds, file read via FILE, UDFs, version disclosure, local file read with secure_file_priv.

Commands:
- nmap --script mysql-info,mysql-empty-password,mysql-users -p3306 10.10.11.10
- mysql -h 10.10.11.10 -u root -p
- MySQL enum queries:
  - SELECT VERSION();
  - SHOW DATABASES; USE db; SHOW TABLES; DESCRIBE users;
  - SELECT LOAD_FILE('/etc/passwd');
- Hydra: hydra -L users.txt -P pass.txt mysql://10.10.11.10

---

## MSSQL (1433/tcp)
Key concepts:
- SQL Browser (UDP/1434), Windows auth, xp_cmdshell, impacket tooling.

Commands:
- nmap -sU -p1434 --script ms-sql-info 10.10.11.10
- nmap -p1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-dump-hashes 10.10.11.10
- impacket-mssqlclient user:pass@10.10.11.10 -windows-auth -db msdb
- sqsh -S 10.10.11.10 -U user -P pass
- Enumeration queries:
  - SELECT @@version; SELECT name FROM sys.databases; SELECT SUSER_SNAME();

---

## Oracle TNS (1521/tcp)
Key concepts:
- TNS listener versioning, SID/service discovery, default creds.

Commands:
- nmap -p1521 --script oracle-tns-version,oracle-sid-brute 10.10.11.10
- odat sidguesser -s 10.10.11.10 -p 1521
- odat all -s 10.10.11.10 -p 1521 -d ORCL -U user -P pass

---

## IPMI (623/udp)
Key concepts:
- IPMI v2 authentication weaknesses, hash disclosure, default creds, BMC access.

Commands:
- nmap -sU -p623 --script ipmi-version,ipmi-cipher-zero 10.10.11.10
- impacket-impacket/examples/ipmiHMAC (varies) or ipmitool -I lanplus -H 10.10.11.10 -U admin -P password chassis status
- ipmitool lan print

---

## Linux Remote Management (SSH, 22/tcp)
Key concepts:
- Auth methods (password, key, keyboard-interactive), banners, cipher/KEX, weak creds.

Commands:
- nmap -p22 --script ssh2-enum-algos,ssh-hostkey 10.10.11.10
- ssh -v user@10.10.11.10
- ssh-audit 10.10.11.10
- Hydra (authorized): hydra -l user -P pass.txt ssh://10.10.11.10

---

## Windows Remote Management
### RDP (3389/tcp)
- nmap -p3389 --script rdp-enum-encryption,rdp-ntlm-info 10.10.11.10
- xfreerdp /u:user /p:pass /v:10.10.11.10 /cert:ignore

### WinRM (5985/5986)
- nmap -p5985,5986 --script http-auth,ssl-cert 10.10.11.10
- evil-winrm -i 10.10.11.10 -u user -p pass

### WMI / DCOM
- crackmapexec smb 10.10.11.10 -u user -p pass -x "whoami"
- wmiexec.py user:pass@10.10.11.10 "whoami"

### SMB/IPC$ for management
- smbmap -H 10.10.11.10 -u user -p pass
- psexec.py user:pass@10.10.11.10 cmd.exe

---

## Labs and Practical Workflow
- Create scans directory and capture all outputs:
  - mkdir -p scans; nmap -p- -sC -sV -oA scans/full 10.10.11.10
- Build a service matrix (host -> port -> version -> vulns/CVEs).
- Try anonymous/null first, then creds, then wordlists if in scope.
- Use NSE scripts per service once identified; pivot to specialized tools (e.g., odat, impacket, enum4linux-ng).
- Keep notes, exact commands, and findings under each service heading.

References quick list (for further reading):
- nmap NSE docs, Impacket, crackmapexec, enum4linux-ng, odat, ipmitool, ssh-audit, gobuster, amass.
