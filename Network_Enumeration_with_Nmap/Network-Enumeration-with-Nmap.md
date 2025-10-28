# Network Enumeration with Nmap

## Introduction to Nmap
- Theory: Nmap (Network Mapper) is an open-source tool for network discovery, host identification, service and version detection, OS fingerprinting, firewall/IDS evasion, and scripting-based enumeration via NSE. It supports multiple scan techniques (TCP SYN, Connect, UDP, ACK, FIN, Xmas, Null), output formats, timing options, and powerful scripting categories.
- Key binaries: nmap, nping, ncat, ndiff, zenmap (GUI).
- Basic syntax: nmap [scan-type/options] [targets]
- Target forms: single IP/host, CIDR (10.10.10.0/24), ranges (10.10.10.1-50), lists (-iL list.txt), exclude (-exclude file or --exclude 10.10.10.5)
- Privileges: Some scans (SYN, OS detection) require root/administrator privileges on most OSes.

Examples:
- nmap 10.10.10.10
- sudo nmap -sS -p- 10.10.10.10
- nmap -iL targets.txt --exclude 10.10.10.5,10.10.10.6

## Host Discovery
- Theory: Before port scanning, discover live hosts using ARP (local L2), ICMP, TCP/UDP probes. Firewalls may block ICMP; combine methods for accuracy.
- Common discovery flags: -sn (ping scan, no port scan), -PR (ARP on local net), -PE/PP/PM (ICMP echo/timestamp/netmask), -PS/PA/PU/PO (TCP SYN/ACK, UDP, IP proto), --traceroute, --dns-servers, -R (always resolve), -n (no DNS), -Pn (treat all as up; skip discovery).

Commands:
- sudo nmap -sn 10.10.10.0/24            # ARP on local; ICMP/TCP on non-local
- sudo nmap -sn -PR 192.168.1.0/24        # Force ARP discovery
- nmap -sn -PE -PM 10.10.11.0/24          # ICMP echo + netmask
- nmap -sn -PS80,443 -PA22,3389 10.10.12.0/24   # TCP SYN/ACK pings
- nmap -sn -PU53,161 10.10.13.0/24        # UDP pings (DNS/SNMP)
- nmap -sn --traceroute 10.10.14.0/24     # Discovery with path info
- nmap -Pn 10.10.10.10                    # Skip discovery (assume up)

## Host and Port Scanning
- Theory: Scans send probes to determine port states (open, closed, filtered, unfiltered, open|filtered, closed|filtered). TCP scans: SYN (-sS), Connect (-sT), ACK (-sA), FIN (-sF), Xmas (-sX), Null (-sN), Maimon (-sM). UDP: -sU (slower, needs retries). Combine TCP/UDP for coverage. Privileged raw scans are faster/stealthier than connect.
- Port selection: default top 1000; -p 1-65535 or -p- for all; -F for fast top 100; --top-ports N; --exclude-ports; -r (no randomize).
- Service/version and OS: -sV for service/version; -O for OS; --osscan-guess/--fuzzy; --version-intensity [0-9].
- Timing and reliability: -T0..5 controls aggressiveness; set retries, host-timeout.

Commands:
- sudo nmap -sS -p- 10.10.10.10
- nmap -sT -p 1-1000 10.10.10.10
- sudo nmap -sU --top-ports 50 10.10.10.10
- sudo nmap -sS -sU -p T:1-1000,U:1-200 10.10.10.10
- sudo nmap -sS -p 22,80,443 --reason 10.10.10.10
- sudo nmap -sS -sV -O --version-intensity 7 10.10.10.10
- sudo nmap -sA -p- 10.10.10.10            # Map firewall rules (filtered/unfiltered)
- sudo nmap -sF -sX -sN -p 1-1024 10.10.10.10  # IDS evasion scans (low-noise)

## Saving the Results
- Theory: Always save outputs for reporting/diffing. Nmap supports normal (-oN), grepable (-oG), XML (-oX), and all at once (-oA base) outputs. Use ndiff for diffing two XML runs.

Commands:
- nmap -oN scan.txt 10.10.10.10
- nmap -oG scan.gnmap 10.10.10.10
- nmap -oX scan.xml 10.10.10.10
- nmap -oA nmap/full_tcp -sS -p- 10.10.10.10
- ndiff old.xml new.xml

## Service Enumeration
- Theory: After finding open ports, enumerate services, banner grab, detect versions and scripts. Use -sV with probes; adjust intensity; add --version-all for thorough probes. Follow-up with targeted NSE categories (default,safe,version,vuln,auth,brute). Use -A for convenience (OS, -sV, --traceroute, and scripts). Validate false positives.

Commands:
- sudo nmap -sV -p 21,22,80,139,445,3389 10.10.10.10
- sudo nmap -A -p- 10.10.10.10
- sudo nmap --version-all -sV -p 80,443 10.10.10.10
- sudo nmap -sV --script banner 10.10.10.10
- sudo nmap -sV --script "default or (safe and version)" -p 1-1000 10.10.10.10

## Nmap Scripting Engine (NSE)
- Theory: NSE runs Lua scripts for discovery, brute force, vuln checks, and exploitation. Script categories: auth, broadcast, brute, default, discovery, dos, exploit, external, fuzzer, intrusive, malware, safe, version, vuln. Use --script to select by name, path, or category; --script-args to pass params; --script-updatedb to refresh db.

Useful script examples:
- sudo nmap --script default -sV 10.10.10.10
- sudo nmap --script vuln -p 80,443 10.10.10.10
- sudo nmap --script smb-enum-shares,smb-enum-users -p445 10.10.10.10
- sudo nmap --script http-enum,http-title -p80,443 10.10.10.10
- sudo nmap --script ssl-enum-ciphers -p 443 10.10.10.10
- sudo nmap --script dns-brute --script-args dns-brute.domain=example.com
- sudo nmap --script ftp-anon -p21 10.10.10.10
- sudo nmap --script ssh2-enum-algos -p22 10.10.10.10
- sudo nmap --script mysql-info -p3306 10.10.10.10
- sudo nmap --script http-vuln-cve2017-5638 -p 8080 10.10.10.10
- sudo nmap --script-updatedb

## Performance
- Theory: Balance speed and accuracy. Timing templates: -T0 (paranoid) to -T5 (insane). Increase parallelism and rate while handling host/network limits. Control retries and timeouts. Use exclude/hostgrouping and top-ports for quick wins; run deep scans later.
- Key flags: --min-rate/--max-rate, --min-parallelism/--max-parallelism, --min-hostgroup/--max-hostgroup, --defeat-rst-ratelimit, --max-retries, --host-timeout, --scan-delay/--max-scan-delay, --dns-servers, -n, -R.

Commands:
- sudo nmap -sS -p- --min-rate 2000 -T4 10.10.10.10
- sudo nmap -sU --top-ports 100 --max-retries 2 --host-timeout 30m 10.10.10.10
- sudo nmap -sS -p- --min-parallelism 10 --max-retries 1 --defeat-rst-ratelimit 10.10.10.10
- sudo nmap -sS -p- --scan-delay 5ms 10.10.10.10
- nmap -F --top-ports 1000 10.10.10.10

## Firewall and IDS/IPS Evasion
- Theory: Evasion techniques attempt to bypass filtering/IDS or reduce noise. Effectiveness varies and may be detected. Use ethically and with authorization.
- Options: -f (fragment packets), --mtu 8/16/32, -D decoys, -S spoof source, -e iface, -g/--source-port, --data-length, --ttl, --spoof-mac, --badsum, --scanflags, -sA sA/-sW, idle scan (-sI), --randomize-hosts, --max-retries, --defeat-rst-ratelimit.

Commands:
- sudo nmap -sS -p 80,443 -f --mtu 8 10.10.10.10
- sudo nmap -sS -p- -D RND:10 10.10.10.10
- sudo nmap -sS -p 80 --source-port 53 10.10.10.10
- sudo nmap -sS -p 22 --data-length 200 10.10.10.10
- sudo nmap -sI 10.10.10.50 10.10.10.10
- sudo nmap -sA -p- 10.10.10.10
- sudo nmap -sW -p- 10.10.10.10
- sudo nmap -sS --scanflags FIN,URG,PSH -p 1-1024 10.10.10.10
- sudo nmap -sS --ttl 65 --spoof-mac 0 10.10.10.10

### Easy Lab
Goal: Discover alive hosts and common services on a small subnet.
- sudo nmap -sn 10.10.10.0/24
- sudo nmap -sS -F 10.10.10.0/24 -oA nmap/easy_fast
- sudo nmap -sV -O --top-ports 50 10.10.10.10 -oA nmap/easy_targeted

### Medium Lab
Goal: Enumerate TCP+UDP services with performance tuning and save results.
- sudo nmap -sS -p- --min-rate 1500 -T4 10.10.10.10 -oA nmap/medium_tcp_full
- sudo nmap -sU --top-ports 200 --max-retries 1 10.10.10.10 -oA nmap/medium_udp_top
- sudo nmap -sV -sC -p T:1-65535,U:53,123,161 10.10.10.10 -oA nmap/medium_enum

### Hard Lab
Goal: Bypass filtering and identify services behind a firewall/IDS.
- sudo nmap -Pn -sS -p- -f -D RND:5 --source-port 53 --data-length 50 --scan-delay 5ms 10.10.10.10 -oA nmap/hard_stealth
- sudo nmap -sA -p- 10.10.10.10 -oA nmap/hard_firewall_map
- sudo nmap -sI 10.10.10.50 -p 1-1024 10.10.10.10 -oA nmap/hard_idle

## Notes and Best Practices
- Always have authorization; respect scope and rate limits.
- Start broad and fast, then go deep and focused.
- Save outputs (-oA) and maintain a consistent directory structure for scans.
- Correlate Nmap findings with service-specific tools (e.g., smbclient, enum4linux, nikto, gobuster).
- Validate NSE vuln results manually before reporting.
- Use ndiff to track environment changes over time.
