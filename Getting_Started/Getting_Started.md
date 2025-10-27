# Getting Started

This chapter provides comprehensive notes on fundamental cybersecurity concepts and practical commands for penetration testing.

## 1. Introduction to Cybersecurity

### What is Cybersecurity?
Cybersecurity is the practice of protecting systems, networks, and programs from digital attacks. These cyberattacks are usually aimed at accessing, changing, or destroying sensitive information.

### Key Concepts:
- **Confidentiality**: Ensuring information is accessible only to authorized users
- **Integrity**: Maintaining accuracy and completeness of data
- **Availability**: Ensuring authorized users have access to information when needed

### Common Security Threats:
- Malware (viruses, worms, trojans)
- Phishing attacks
- Social engineering
- DDoS attacks
- Man-in-the-middle attacks

---

## 2. Penetration Testing Fundamentals

### What is Penetration Testing?
Penetration testing (pen testing) is a simulated cyberattack against your computer system to check for exploitable vulnerabilities.

### Types of Penetration Testing:
1. **Black Box Testing**: No prior knowledge of the system
2. **White Box Testing**: Full knowledge of the system
3. **Gray Box Testing**: Limited knowledge of the system

### Penetration Testing Phases:
1. **Planning and Reconnaissance**: Gathering intelligence
2. **Scanning**: Identifying live systems and services
3. **Gaining Access**: Exploiting vulnerabilities
4. **Maintaining Access**: Persistence techniques
5. **Analysis and Reporting**: Documenting findings

---

## 3. Linux Command Line Basics

### Essential Commands:

#### File and Directory Operations:
```bash
# List directory contents
ls -la

# Change directory
cd /path/to/directory

# Create directory
mkdir directory_name

# Remove files/directories
rm filename
rm -rf directory_name

# Copy files
cp source destination

# Move/rename files
mv old_name new_name

# Find files
find /path -name "filename"

# View file contents
cat filename
less filename
head filename
tail filename
```

#### System Information:
```bash
# System information
uname -a

# Current user
whoami

# Process list
ps aux

# Network connections
netstat -tulpn

# Disk usage
df -h

# Memory usage
free -h

# System uptime
uptime
```

#### Text Processing:
```bash
# Search text in files
grep "pattern" filename
grep -r "pattern" /directory

# Count lines, words, characters
wc filename

# Sort file contents
sort filename

# Remove duplicates
uniq filename

# Stream editor
sed 's/old/new/g' filename

# Text processing
awk '{print $1}' filename
```

---

## 4. Network Fundamentals

### OSI Model Layers:
1. **Physical Layer**: Hardware transmission
2. **Data Link Layer**: Error detection and correction
3. **Network Layer**: Routing (IP)
4. **Transport Layer**: Reliable delivery (TCP/UDP)
5. **Session Layer**: Session management
6. **Presentation Layer**: Data encryption/compression
7. **Application Layer**: Network services (HTTP, FTP, SSH)

### TCP vs UDP:
- **TCP**: Connection-oriented, reliable, slower
- **UDP**: Connectionless, unreliable, faster

### Common Ports:
```
21 - FTP
22 - SSH
23 - Telnet
25 - SMTP
53 - DNS
80 - HTTP
110 - POP3
143 - IMAP
443 - HTTPS
993 - IMAPS
995 - POP3S
```

### Network Commands:
```bash
# Ping host
ping google.com

# Trace route
traceroute google.com

# DNS lookup
nslookup google.com
dig google.com

# Network configuration
ifconfig
ip addr show

# Network statistics
netstat -i
ss -tuln

# ARP table
arp -a

# Route table
route -n
ip route show
```

---

## 5. Basic Reconnaissance Techniques

### Passive Information Gathering:

#### WHOIS Lookup:
```bash
# Domain information
whois example.com

# IP information
whois 8.8.8.8
```

#### DNS Enumeration:
```bash
# DNS records
nslookup example.com
dig example.com ANY

# Reverse DNS
nslookup 8.8.8.8

# DNS zone transfer
dig @dns-server example.com AXFR
```

#### Search Engine Intelligence:
- Google Dorking
- Shodan searches
- Social media reconnaissance

### Active Information Gathering:

#### Network Scanning:
```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Port scanning
nmap -sS -p 1-1000 target
nmap -sT target
nmap -sU target

# Service detection
nmap -sV target

# OS detection
nmap -O target

# Aggressive scan
nmap -A target

# Stealth scan
nmap -sS -f target
```

---

## 6. Web Application Security Basics

### Common Web Vulnerabilities:

#### OWASP Top 10:
1. **Injection**: SQL, NoSQL, OS, LDAP injection
2. **Broken Authentication**: Session management flaws
3. **Sensitive Data Exposure**: Inadequate protection
4. **XML External Entities (XXE)**: XML parser vulnerabilities
5. **Broken Access Control**: Authorization failures
6. **Security Misconfiguration**: Default configurations
7. **Cross-Site Scripting (XSS)**: Client-side injection
8. **Insecure Deserialization**: Object manipulation
9. **Using Components with Known Vulnerabilities**: Outdated software
10. **Insufficient Logging & Monitoring**: Detection gaps

### Web Reconnaissance Tools:
```bash
# HTTP methods enumeration
curl -X OPTIONS http://example.com

# HTTP headers
curl -I http://example.com

# Directory enumeration
dirb http://example.com
gobuster dir -u http://example.com -w wordlist.txt

# Web server fingerprinting
whatweb example.com
nmap --script http-methods example.com

# SSL/TLS testing
sslscan example.com
testssl.sh example.com
```

---

## 7. Basic Scripting and Automation

### Bash Scripting Basics:
```bash
#!/bin/bash

# Variables
name="John"
echo "Hello $name"

# Conditionals
if [ condition ]; then
    echo "True"
else
    echo "False"
fi

# Loops
for i in {1..10}; do
    echo "Number: $i"
done

while [ condition ]; do
    # commands
done

# Functions
function my_function() {
    echo "This is a function"
}
```

### Python for Security:
```python
#!/usr/bin/env python3

import socket
import requests
import subprocess

# Simple port scanner
def port_scan(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False

# HTTP requests
response = requests.get('http://example.com')
print(response.status_code)
print(response.headers)
```

---

## 8. Essential Security Tools

### Network Analysis:
```bash
# Wireshark (GUI)
wireshark

# tcpdump (command line)
tcpdump -i eth0 host 192.168.1.1
tcpdump -i eth0 port 80
tcpdump -i eth0 -w capture.pcap

# Netcat
nc -l -p 4444  # Listen mode
nc target 80   # Connect mode
```

### Vulnerability Scanners:
```bash
# Nessus (commercial)
# OpenVAS (open source)
# Nikto (web vulnerability scanner)
nikto -h http://example.com

# Nuclei
nuclei -u http://example.com
```

### Password Tools:
```bash
# Hydra (brute force)
hydra -l admin -P passwords.txt ssh://target

# John the Ripper
john --wordlist=rockyou.txt hashes.txt

# Hashcat
hashcat -m 0 -a 0 hashes.txt wordlist.txt
```

---

## 9. Legal and Ethical Considerations

### Legal Framework:
- Only test systems you own or have explicit permission to test
- Understand local and international laws
- Maintain proper documentation
- Follow responsible disclosure practices

### Ethical Guidelines:
- Minimize impact on systems and users
- Protect confidentiality of discovered vulnerabilities
- Report findings to appropriate parties
- Respect privacy and data protection laws

### Certifications and Compliance:
- **Professional Certifications**: CEH, OSCP, CISSP, CISM
- **Compliance Standards**: PCI DSS, HIPAA, SOX, GDPR

---

## 10. Setting Up a Lab Environment

### Virtual Machines:
```bash
# Download and install VirtualBox/VMware
# Create isolated network
# Install Kali Linux (attacker machine)
# Install vulnerable VMs (Metasploitable, DVWA, etc.)
```

### Kali Linux Essential Tools:
```bash
# Update system
sudo apt update && sudo apt upgrade

# Essential tools check
which nmap
which burpsuite
which metasploit
which sqlmap
which aircrack-ng
```

### Practice Platforms:
- **TryHackMe**: Guided learning paths
- **Hack The Box**: Realistic challenges
- **VulnHub**: Downloadable VMs
- **PentesterLab**: Web application security
- **OverTheWire**: Wargames

---

## 11. Documentation and Reporting

### Note-Taking Best Practices:
```bash
# Use tools like:
# - CherryTree
# - Obsidian
# - Notion
# - OneNote

# Command history
history > commands.txt

# Screenshot tools
scrot -s screenshot.png
gnome-screenshot -a
```

### Report Structure:
1. **Executive Summary**
2. **Methodology**
3. **Findings**
4. **Risk Assessment**
5. **Recommendations**
6. **Technical Details**
7. **Appendices**

---

## 12. Study Resources and Next Steps

### Books:
- "The Web Application Hacker's Handbook" by Dafydd Stuttard
- "Penetration Testing: A Hands-On Introduction to Hacking" by Georgia Weidman
- "The Hacker Playbook" series by Peter Kim

### Online Resources:
- OWASP (Open Web Application Security Project)
- SANS Institute
- Cybrary
- Professor Messer

### Practice Labs:
- Set up home lab
- Join CTF competitions
- Participate in bug bounty programs
- Contribute to open source security tools

---

## Quick Reference Commands

### System Reconnaissance:
```bash
# Basic system info
uname -a && whoami && id

# Network info
ifconfig && route -n && cat /etc/resolv.conf

# Running processes
ps aux | head -20

# Listening ports
netstat -tulpn | grep LISTEN
```

### File Operations:
```bash
# Find interesting files
find / -name "*.conf" 2>/dev/null
find / -perm -4000 2>/dev/null  # SUID files
find / -type f -name "*.log" 2>/dev/null
```

### Network Testing:
```bash
# Quick port scan
nmap -sS -O target

# Web enumeration
curl -I http://target
gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt
```

This comprehensive guide covers the fundamental concepts and practical commands needed to get started with cybersecurity and penetration testing. Practice these commands in a safe, legal environment and always follow ethical guidelines.
