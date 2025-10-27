# CPTS-Studies

## Penetration Testing Process - HTB CPTS Exam Preparation

This repository contains comprehensive notes on the Penetration Testing Process for HackTheBox Certified Penetration Testing Specialist (CPTS) exam preparation.

---

## Table of Contents

1. [Pre-Engagement](#pre-engagement)
2. [Information Gathering](#information-gathering)
3. [Vulnerability Assessment](#vulnerability-assessment)
4. [Exploitation](#exploitation)
5. [Post-Exploitation](#post-exploitation)
6. [Lateral Movement](#lateral-movement)
7. [Proof of Concept](#proof-of-concept)
8. [Post-Engagement](#post-engagement)

---

## Pre-Engagement

### Overview
Pre-engagement is the initial phase where scope, rules of engagement, and legal documents are established.

### Key Activities
- **Scope Definition**: Define target systems, IP ranges, and domains
- **Rules of Engagement (RoE)**: Establish testing boundaries and limitations
- **Legal Documentation**: Sign NDAs, contracts, and authorization letters
- **Communication Plan**: Set up reporting channels and emergency contacts
- **Timeline**: Establish testing windows and deliverable dates

### Important Documents
- Master Service Agreement (MSA)
- Statement of Work (SoW)
- Non-Disclosure Agreement (NDA)
- Authorization Letter

---

## Information Gathering

### Passive Reconnaissance
- **OSINT**: Open-source intelligence gathering
- **DNS Enumeration**: Subdomain discovery, DNS records
- **Search Engine Discovery**: Google dorking, cached pages
- **Social Media**: Employee information, organizational structure
- **WHOIS Lookup**: Domain registration details

### Active Reconnaissance
- **Port Scanning**: Nmap, Masscan
- **Service Enumeration**: Version detection, service fingerprinting
- **Web Application Mapping**: Directory brute-forcing, sitemap analysis
- **Network Mapping**: Topology discovery, routing information

### Tools
```bash
# Nmap
nmap -sC -sV -oA initial_scan <target>

# Subdomain enumeration
subfinder -d <domain>
ffuf -u https://FUZZ.<domain> -w wordlist.txt

# DNS enumeration
dig <domain> ANY
dnsenum <domain>
```

---

## Vulnerability Assessment

### Vulnerability Identification
- **Automated Scanning**: Nessus, OpenVAS, Nuclei
- **Manual Testing**: Code review, configuration analysis
- **Web Application Testing**: OWASP Top 10 vulnerabilities
- **Credential Testing**: Default credentials, weak passwords

### Common Vulnerabilities
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Remote Code Execution (RCE)
- Local File Inclusion (LFI)
- Server-Side Request Forgery (SSRF)
- Authentication Bypass
- Privilege Escalation

### Prioritization
- **Critical**: Remote code execution, authentication bypass
- **High**: Privilege escalation, sensitive data exposure
- **Medium**: Information disclosure, DoS vulnerabilities
- **Low**: Minor configuration issues

---

## Exploitation

### Initial Access
- **Exploit Development**: Custom exploits for identified vulnerabilities
- **Public Exploits**: SearchSploit, Exploit-DB
- **Password Attacks**: Brute force, password spraying
- **Phishing**: Social engineering (if in scope)
- **Web Shell Upload**: File upload vulnerabilities

### Tools and Frameworks
```bash
# Metasploit
msfconsole
use exploit/...

# Manual exploitation
searchsploit <service>
python3 exploit.py <target>

# Web shells
webshell.php, cmd.aspx
```

### Maintaining Access
- Establish persistent backdoors (ethical boundaries)
- Document all access methods
- Take screenshots and logs

---

## Post-Exploitation

### Enumeration
- **System Information**: OS version, architecture, patches
- **User Enumeration**: Current user privileges, other users
- **Network Information**: Network interfaces, routing tables
- **Installed Software**: Application versions, services
- **Sensitive Files**: Configuration files, credential stores

### Windows Post-Exploitation
```powershell
# System enumeration
systeminfo
whoami /all
net user
net localgroup administrators

# Network enumeration
ipconfig /all
route print
arp -a
netstat -ano
```

### Linux Post-Exploitation
```bash
# System enumeration
uname -a
id
sudo -l
cat /etc/passwd

# Network enumeration
ifconfig
ip route
netstat -tulpn
```

### Privilege Escalation
- **Linux**: SUID binaries, sudo misconfigurations, kernel exploits
- **Windows**: Service misconfigurations, unquoted service paths, token manipulation
- **Tools**: LinPEAS, WinPEAS, PowerUp, linux-exploit-suggester

---

## Lateral Movement

### Techniques
- **Pass-the-Hash (PtH)**: Using NTLM hashes
- **Pass-the-Ticket (PtT)**: Kerberos ticket manipulation
- **Remote Service Exploitation**: PSExec, WinRM, SSH
- **Credential Dumping**: Mimikatz, secretsdump.py

### Tools
```bash
# Credential dumping
mimikatz.exe
secretsdump.py <domain>/<user>@<target>

# Lateral movement
psexec.py <domain>/<user>@<target>
evil-winrm -i <target> -u <user> -p <password>

# Pivoting
ssh -L 8080:internal_host:80 user@pivot_host
chisel, proxychains
```

### Active Directory
- **Domain Enumeration**: BloodHound, PowerView
- **Kerberoasting**: Service account attacks
- **AS-REP Roasting**: Accounts without pre-authentication
- **DCSync**: Domain Controller replication

---

## Proof of Concept

### Documentation Requirements
- **Vulnerability Description**: Clear explanation of the issue
- **Impact Assessment**: Business impact and risk level
- **Steps to Reproduce**: Detailed reproduction steps
- **Screenshots**: Visual evidence of exploitation
- **Proof**: Captured flags, sensitive data (sanitized)

### Best Practices
- Take detailed notes throughout testing
- Capture all commands executed
- Screenshot every successful exploit
- Document timestamps for all activities
- Maintain a finding tracker

---

## Post-Engagement

### Reporting
- **Executive Summary**: High-level overview for management
- **Technical Findings**: Detailed vulnerability descriptions
- **Risk Ratings**: CVSS scores, business impact
- **Remediation Recommendations**: Prioritized fix guidance
- **Appendices**: Raw scan data, screenshots, logs

### Report Structure
```
1. Executive Summary
2. Methodology
3. Scope
4. Findings Summary
5. Detailed Findings
   - Vulnerability Name
   - Severity
   - Description
   - Impact
   - Affected Systems
   - Proof of Concept
   - Remediation
6. Conclusion
7. Appendices
```

### Deliverables
- Comprehensive penetration test report
- Remediation recommendations document
- Raw scan data and logs
- Debriefing meeting with client

### Cleanup
- Remove all backdoors and tools
- Restore any modified files
- Delete uploaded shells and exploits
- Document all cleanup activities

---

## Additional Resources

### HTB CPTS Modules
- Penetration Testing Process
- Information Gathering
- Footprinting
- Enumeration
- Vulnerability Assessment
- Exploitation
- Post-Exploitation
- Lateral Movement
- Web Application Attacks
- Active Directory Attacks

### Recommended Tools
- **Reconnaissance**: nmap, masscan, gobuster, ffuf
- **Exploitation**: Metasploit, searchsploit, custom scripts
- **Post-Exploitation**: LinPEAS, WinPEAS, Mimikatz
- **AD Attacks**: BloodHound, Impacket, Rubeus
- **Web Testing**: Burp Suite, OWASP ZAP, SQLMap

### Study Tips
- Practice on HTB boxes and Pro Labs
- Document everything in your methodology
- Create cheat sheets for common commands
- Understand the 'why' behind each technique
- Focus on manual exploitation over automated tools

---

## Notes

This repository is for educational purposes and CPTS exam preparation. Always obtain proper authorization before conducting any penetration testing activities.

**Last Updated**: October 2025
**Status**: Active Study Material
**Exam Target**: HTB CPTS Certification
