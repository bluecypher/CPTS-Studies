# Information Gathering - Web Edition

A comprehensive study guide for reconnaissance and information gathering focused on web targets. Modeled after other modules in this repository and intended as a practical checklist with commands, examples, and key concepts.

---

## 1. Scope, Rules, and Target Baseline
- Define scope: in-scope domains, subdomains, IP ranges, web apps, APIs, clouds, mobile backends
- Time windows, DoS bans, credential stuffing restrictions, rate limits
- Data handling: PII, secrets, exports, retention
- Obtain test account(s) if allowed

Checklist:
- [ ] Confirm legal permissions and written authorization
- [ ] Record target root(s) and environment (prod/stage/dev)
- [ ] Note SLAs for notifications and contact escalation

---

## 2. DNS and Host Discovery

Common commands:
- DNS resolution and records:
  - dig A/AAAA/CNAME/MX/TXT/NS target.tld
  - dig ANY target.tld
  - dig +short target.tld
  - nslookup -type=ANY target.tld
  - host -a target.tld
- Zone transfer attempts (only if authorized):
  - dig AXFR @ns1.target.tld target.tld
- Reverse lookups and PTR sweeps:
  - dig -x 1.2.3.4
- Wordlist DNS bruteforce:
  - gobuster dns -d target.tld -w wordlist.txt --wildcard
  - amass enum -d target.tld -brute -src -ip
  - subfinder -d target.tld -all -recursive
- Certificate transparency (subdomains):
  - crt.sh, censys, chaos, amass intel -d target.tld

Key concepts:
- Identify CDN in front (Cloudflare/Akamai/Fastly) vs origin IP
- Track multiple DNS views (internal vs external), geo-DNS, split-horizon
- Monitor TTLs for blue/green or canary deployments

---

## 3. Subdomain and Asset Enumeration

Tools/commands:
- amass enum -passive -d target.tld -o subpassive.txt
- amass enum -active -d target.tld -brute -o subactive.txt
- subfinder -d target.tld -all -o subfinder.txt
- assetfinder --subs-only target.tld
- github-subdomains -d target.tld (tokens required)
- gau, waybackurls, hakrawler for historical paths
- httpx -l subs.txt -probe -title -status-code -ip -tech-detect -o live.txt
- dnsx -a -resp -l subs.txt -o dns_resolved.txt

Notes:
- De-duplicate subdomains; map to IPs and ASN
- Detect dev, staging, old, beta, qa, preview, backup
- Enumerate wildcard subdomains vs real assets

---

## 4. IP, ASN, and Cloud Footprint

- whois target.tld | grep -i 'Registrar\|Registrant\|Name Server'
- whois 1.2.3.4
- ipinfo.io, bgp.he.net, ASN mapping
- cloud provider fingerprinting via DNS, TLS, headers
- Shodan/Censys/ZoomEye queries by org, ASN, SSL cert, favicon hash
- masscan or naabu (respect rate limits):
  - naabu -l ips.txt -p - -rate 1000 -o naabu.txt
  - masscan -p0-65535 1.2.3.0/24 --rate 1000 -oX masscan.xml

---

## 5. Web Service Discovery and Fingerprinting

- httpx -l hosts.txt -p 80,443,8080,8443,8000,9000,3000,5000 -tech-detect -title -status-code -web-server -cdn -o webscan.txt
- whatweb, wappalyzer, nuclei -tags tech
- Nginx/Apache headers, X-Powered-By, Server, set-cookie, CSP, CORS
- TLS info:
  - openssl s_client -connect target.tld:443 -servername target.tld
  - sslscan target.tld

Key artifacts:
- Frameworks (WordPress, Django, Rails, Laravel, Express, Spring)
- CMS/admin panels, default creds likelihood
- Login endpoints, SSO, OAuth providers

---

## 6. Content Discovery and Crawling

Automated:
- feroxbuster -u https://target.tld -w wordlist.txt -x php,aspx,jsp,html,js,json -t 50 -C 404,403 -o ferox.txt
- gobuster dir -u https://target.tld -w raft-medium-directories.txt -x php,txt,conf,bak,zip,tar,gz -o gobuster.txt
- dirsearch -u https://target.tld -e * -t 50 -o dirsearch.txt
- katana -u https://target.tld -jc -fx -aff -o katana.txt

Historical and backups:
- waybackurls target.tld | tee wayback.txt
- gau --subs target.tld | tee gau.txt
- gitleaks detect -s . (for local clones)
- Check /.git/, .env, backup.zip, db.sql, config.old, .DS_Store

Robots and sitemaps:
- curl -s https://target.tld/robots.txt
- curl -s https://target.tld/sitemap.xml

---

## 7. JavaScript Recon and Endpoints

- Link/endpoint extraction:
  - getJS, linkfinder, hakrawler, subjs
  - katana -u https://target.tld -jc
- Secrets scanning:
  - trufflehog filesystem/git, gitleaks, ripgrep patterns
- Analyze JS for:
  - Hidden endpoints, API base URLs, feature flags
  - Third-party services, analytics IDs, S3/GCS buckets
  - Hardcoded keys/tokens (report responsibly)

Commands:
- subjs https://target.tld | httpx -mc 200 -o js.txt
- cat js.txt | xargs -I@ python3 linkfinder.py -i @ -o cli | tee endpoints.txt

---

## 8. API Recon (REST/GraphQL)

- Swagger/OpenAPI discovery: /swagger, /swagger-ui, /v2/api-docs, /openapi.json
- Postman collections, Insomnia exports
- GraphQL:
  - Check /graphql, introspection, GraphiQL
  - nuclei -t graphql templates
- Enumerate methods, rate limits, auth mechanisms (JWT, OAuth2, HMAC)

Commands:
- nuclei -u https://api.target.tld -t http/exposures -severity low,medium,high,critical -rl 10 -o nuclei-exposures.txt
- graphql-voyager if schema available

---

## 9. Authentication and Session Observations

- Login flows: username enum, password reset tokens, MFA bypass opportunities
- Cookie attributes: HttpOnly, Secure, SameSite
- Session fixation/rotation on login/logout
- JWT: alg, kid header, expiration, audience, signature checks
- OAuth misconfig: open redirect, scope escalation, PKCE absence

Quick checks:
- curl -I https://target.tld | grep -i set-cookie
- jwt-tool -t eyJ... -d

---

## 10. Input Handling and Common Vuln Leads (Recon Angle)

- Parameters discovery: common params via waybackurls/gau/katana
- File upload endpoints and accepted types
- Debug endpoints: /debug, /actuator, /health, /metrics
- Error behavior differences for booleans, integers, arrays, JSON bodies

---

## 11. Virtual Hosts and Host Header Tricks

- vhost enumeration:
  - ffuf -u https://target.tld/ -H "Host: FUZZ.target.tld" -w subdomains.txt -fc 301,302,404
- Host header injection trails: X-Forwarded-Host, X-Original-Host

---

## 12. CORS and CSP Observations

- curl -I https://target.tld | egrep -i "access-control-allow-origin|content-security-policy"
- Test permissive CORS on auth endpoints vs public
- CSP too-permissive script-src, object-src none, frame-ancestors

---

## 13. CDN, WAF, and Rate Limiting

- Identify WAF fingerprints (Cloudflare, ModSecurity, AWS WAF)
- Observe challenge pages, 403 patterns
- Measure rate limits with incremental concurrency; back off

---

## 14. Screenshotting and Reporting Artifacts

- httpx -l live.txt -screenshot -o shots/
- aquatone -scan-timeout 30000 -ports xlarge -out aquatone
- Eyewitness for HTML reports

---

## 15. WordPress/CMS Specific Recon

- wpscan --url https://target.tld --enumerate ap,at,tt,cb,dbe
- Identify xmlrpc.php, /wp-json/ endpoints
- Themes/plugins versions vs known CVEs

---

## 16. Email, SPF/DMARC/DKIM Records

- dig TXT target.tld | grep -i spf
- dig TXT _dmarc.target.tld
- dig TXT selector._domainkey.target.tld
- Verify mail provider (GSuite, O365) and phishing exposure

---

## 17. S3/GCS/Azure Buckets and Cloud Storage

- Identify from JS, error messages, CT logs
- s3scanner, s3recon, gcpbucketbrute, microburst
- Test list/get/put if within scope and permitted

---

## 18. Technologies and Versions Mapping

- whatweb -a 3 https://target.tld
- nuclei -tags tech,cnvd,cve -severity medium,high,critical
- wappalyzer driver or CLI

---

## 19. Passive OSINT for Web Targets

- Search engines: site:target.tld, inurl:, intitle:
- GitHub, GitLab, Bitbucket code search for secrets and endpoints
- Social and job postings for tech stack, environments
- Breach data sources (reporting strictly per rules)

---

## 20. Automation Pipelines

- Runbook script example:
  - subfinder + amass -> dnsx -> httpx -> nuclei -> feroxbuster
  - Dedup and tag outputs by severity and component
- Use makefiles or simple shell wrappers to keep reproducible

---

## 21. Data Management

- Keep CSV/JSON outputs per stage with timestamps
- Note scope and permissions beside each artifact
- Separate sensitive findings; encrypt at rest

---

## 22. Ethics and Safety

- No exploitation beyond agreed recon
- Respect rate limits; avoid service degradation
- Notify stakeholders promptly upon sensitive data exposure

---

## Appendix A: Handy One-liners

- waybackurls target.tld | anew | uro | httpx -silent -status-code -title
- gau --subs target.tld | anew | gf xss | tee xss_params.txt
- cat subs.txt | httpx -path /.git/config -mc 200 -o exposed_git.txt
- ffuf -w params.txt -u https://target.tld/index.php?FUZZ=test -fs 0

## Appendix B: Wordlists and Resources
- Seclists: Discovery/DNS, Discovery/Web-Content, quickhits, raft, raft-large-extensions.txt
- ProjectDiscovery: nuclei-templates
- PayloadsAllTheThings
- hackerone/bugcrowd disclosed reports for patterns

End of notes.
