# Information Gathering - Web Edition

A comprehensive, screenshot-aligned study guide for reconnaissance and information gathering on web targets. Includes detailed sections and subsections with concepts, practical commands, and best practices from the Information Gathering - Web Edition module.

---

## 1. Scope, Rules, and Target Baseline

### 1.1 Define Scope and Authorization
- In-scope: domains, subdomains, IP ranges, web apps, APIs, cloud assets, mobile backends
- Out-of-scope: explicitly excluded hosts/services, production constraints, third-party vendors if not permitted
- Time windows, DoS bans, credential-stuffing restrictions, rate limits, traffic ceilings
- Data handling: PII, secrets, exports, retention, redaction requirements
- Obtain test accounts or demo tenants if allowed

Checklist:
- [ ] Written authorization captured and stored securely
- [ ] Target roots and environment (prod/stage/dev) recorded
- [ ] SLAs for notification and contact escalation noted

Best practices:
- Maintain a scope.md with UUID, signatures of authorizers, and change log
- Tag all collected data by sensitivity and retention window

---

## 2. DNS and Host Discovery

### 2.1 DNS Resolution and Records
Commands:
- dig A/AAAA/CNAME/MX/TXT/NS target.tld
- dig ANY target.tld
- dig +short target.tld
- nslookup -type=ANY target.tld
- host -a target.tld

### 2.2 Zone Transfer (Authorized Only)
- dig AXFR @ns1.target.tld target.tld

### 2.3 Reverse Lookups and PTR Sweeps
- dig -x 1.2.3.4

### 2.4 Wordlist DNS Bruteforce
- gobuster dns -d target.tld -w wordlist.txt --wildcard
- amass enum -d target.tld -brute -src -ip
- subfinder -d target.tld -all -recursive

### 2.5 Certificate Transparency for Subdomains
- Use crt.sh, Censys, Chaos, amass intel -d target.tld

Key concepts:
- Detect CDN (Cloudflare/Akamai/Fastly) vs origin IP; watch for anycast
- Split-horizon/internal vs external DNS views; geo-DNS
- Monitor TTL changes for blue/green or canary rollouts

---

## 3. Subdomain and Asset Enumeration

### 3.1 Passive and Active Enumeration
- amass enum -passive -d target.tld -o subpassive.txt
- amass enum -active -d target.tld -brute -o subactive.txt
- subfinder -d target.tld -all -o subfinder.txt
- assetfinder --subs-only target.tld
- github-subdomains -d target.tld (needs tokens)
- gau, waybackurls, hakrawler for historical paths

### 3.2 Deduplication and Live Host Discovery
- sort -u sub*.txt > subs_all.txt
- dnsx -silent -a -aaaa -cname -retries 2 -l subs_all.txt -o subs_resolved.txt
- httpx -l subs_resolved.txt -follow-redirects -status-code -title -tech-detect -ip -o httpx.txt

Best practices:
- Tag service fingerprints (httpx tech-detect) and group by product/version
- Note wildcard responses; use dnsx -wd to weed them out

---

## 4. IP Space and Service Mapping

### 4.1 Netblocks and ASN
- amass intel -org "Target Corp"
- amass intel -asn <ASN>
- whois target.tld | grep -i "OrgName\|CIDR"

### 4.2 Port Scanning (Ethical/Scoped)
- naabu -top-ports 1000 -host target.tld -rate 2000 -o naabu.txt
- naabu -l subs_resolved.txt -p 1-65535 -o naabu_full.txt
- nmap -sV -sC -p <ports> -iL targets.txt -oA nmap

Best practices:
- Respect rate limits; coordinate with blue teams
- Prefer connect scans for accuracy behind CDNs/WAFs on allowed IPs

---

## 5. Web Fingerprinting and Technology Identification

### 5.1 HTTP Probing and Fingerprinting
- httpx -l hosts.txt -status-code -title -tech-detect -server -cdn -cname -ip -o httpx_finger.txt
- curl -I https://host | tee headers.txt
- whatweb https://host -v
- wappalyzer-cli https://host

### 5.2 CDN/WAF Identification
- zdns or httpx -cdn flags
- wafw00f https://host

Best practices:
- Record server, x-powered-by, set-cookie flags, CSP, HSTS
- Identify auth endpoints, tenant hints, locale, feature flags

---

## 6. Content Discovery and Crawling

### 6.1 Automated Crawlers
- katana -u https://host -jc -jsl -aff -fx -o katana.txt
- hakrawler -url https://host -depth 3 -plain | tee crawl.txt

### 6.2 Wordlist and Fuzzing
- ffuf -u https://host/FUZZ -w raft-small-words.txt -recursion -rate 500 -t 50 -mc all -fc 404 -o ffuf_paths.json
- gobuster dir -u https://host -w directory-list-2.3-medium.txt -x php,asp,aspx,js,txt,bak

### 6.3 Parameter Discovery
- arjun -u https://host -o arjun.json
- ffuf -u 'https://host/path?FUZZ=test' -w params.txt -fs 0

Best practices:
- Normalize paths; dedupe with anew/sponge
- Respect robots.txt but consider security impact of disallowed paths

---

## 7. Historical, OSINT, and Metadata

### 7.1 Historical URLs and Snapshots
- gau -subs target.tld | tee gau.txt
- waybackurls target.tld | tee wayback.txt
- urlhunter -d target.tld -o urlhunter.txt

### 7.2 Public Code/Repo Leaks
- trufflehog github --org target --include-paths 'src|config'
- gitleaks detect -s . --no-git
- GitHub code search: org:target filename:.env

### 7.3 Document Metadata
- exiftool *.pdf | tee exif.txt
- strings binaries for secrets; check embedded endpoints

Best practices:
- Validate findings before reporting; avoid mass downloading sensitive data

---

## 8. API Reconnaissance

### 8.1 API Documentation and Discovery
- Scrape swagger/openapi: /swagger, /swagger.json, /openapi.json
- ffuf -u https://host/FUZZ -w api-common.txt -mc 200,401,403

### 8.2 Endpoint Enumeration
- kiterunner scan -u https://api.host -w routes-large.kite -x 10
- httpx -paths apipaths.txt -status-code -websocket -follow-redirects

### 8.3 Versioning, Auth, and Rate Limits
- Identify x-ratelimit-* headers, JWT issuer/aud, scopes
- Test OPTIONS/HEAD for CORS hints

Best practices:
- Keep a per-endpoint sheet: method, auth, content-type, rate limits, responses

---

## 9. Virtual Host, Tenant, and Environment Discovery

### 9.1 VHost Enumeration
- ffuf -u https://IP/ -H 'Host: FUZZ.target.tld' -w subs_resolved.txt -fs 0
- vhostscan -t https://IP -w vhosts.txt

### 9.2 Multi-tenant Hints
- Look for X-Tenant, orgId, accountId in headers/cookies
- Try ?tenant=foo, subdomain patterns, and custom domains (CNAMEs)

### 9.3 Environment Leaks
- /.env, /config.json, debug flags, verbose error pages

---

## 10. Authentication Surface Recon

### 10.1 IdP and Flows
- OIDC/SAML: detect /.well-known/openid-configuration
- Enumerate auth routes: /login, /auth/*, /oauth2/*, /sso/*

### 10.2 Password, MFA, and Account Policies
- Enumerate username formats (emails, UPN)
- Check rate limits, lockouts, MFA prompts

### 10.3 Session Management
- Cookie flags: HttpOnly, Secure, SameSite
- JWT alg, kid, expiry; session rotation on auth

Best practices:
- Never brute-force beyond scope; coordinate tests

---

## 11. Storage, CDN, and Cloud Asset Discovery

### 11.1 Cloud Buckets and Endpoints
- s3scanner, aws s3 ls s3://public-bucket --no-sign-request
- gcp: gsutil ls gs://bucket
- Azure: az storage blob list --container-name

### 11.2 CDN/Edge Config
- Enumerate edge rules, caching, bypass params

Best practices:
- Respect ToS; avoid data exfiltration beyond proof

---

## 12. WebSockets, SSE, and Real-time

### 12.1 Discovery and Fingerprinting
- httpx -websocket -u https://host
- Observe upgrade headers, Sec-WebSocket-Protocol

### 12.2 Subscription and Event Patterns
- Test channels, auth, topic naming for multi-tenant leaks

---

## 13. TLS, Certificates, and Security Headers

### 13.1 TLS
- sslscan host:443; testssl.sh -U --sneaky host

### 13.2 Security Headers
- curl -I | grep -i 'strict-transport-security\|content-security-policy\|x-frame-options\|referrer-policy\|permissions-policy'

Best practices:
- Record deviations per host; report risk and fix guidance

---

## 14. Screenshotting and Evidence

### 14.1 Automated Screenshots
- gowitness file -f httpx.txt --delay 1 --threads 10 -P shots
- eyewitness -f urls.txt --web

### 14.2 Notes and Change Tracking
- Keep timestamps, response hashes (shasum), and diffs

---

## 15. Data Management and Reporting

### 15.1 Normalization and Storage
- Use CSV/JSONL for hosts, services, issues
- Tag: asset_type, env, severity, reproducibility

### 15.2 De-duplication and Correlation
- anew, uro, unfurl to normalize URLs
- Merge signals: DNS -> HTTP -> Tech -> Vuln

### 15.3 Deliverables
- Recon report with prioritized findings, PoC, remediation guidance, and evidence pack

---

## 16. Safe Automation and Rate Control

### 16.1 Throttling
- Use --rate, --delay, concurrency caps; respect robots and scope

### 16.2 Fail-safes
- Kill-switch scripts, IP allowlists, and logging

---

## 17. Quick Start Playbooks

### 17.1 Subdomain to Live Host
- subfinder; amass; dnsx; httpx; naabu; httpx -tech-detect

### 17.2 Content and Params
- katana/hakrawler; ffuf; arjun; waybackurls; validate with curl

### 17.3 API Recon
- Find openapi; kiterunner; httpx; rate-limit profiling

---

## 18. Appendices

- Recommended wordlists: SecLists (Discovery/DNS, Web-Content, API)
- Tools to install: amass, subfinder, naabu, nmap, httpx, ffuf, gobuster, katana, hakrawler, gau, waybackurls, arjun, kiterunner, wafw00f, whatweb, wappalyzer-cli, sslscan, testssl.sh, gowitness, eyewitness
- Environment tips: use containers, isolated VPN egress, and logging
