# Information Gathering - Web Edition

This document mirrors the HTB module structure and aligns section-by-section with the module’s table of contents. Each section lists core concepts and concrete commands/workflows.

---

## 1. Introduction and Methodology
- Objectives: define scope, collect OSINT, enumerate DNS/subdomains, fingerprint tech stack, map attack surface.
- Rules of engagement: rate limits, no-DoS, data handling, proof-of-concept only.
- Workflow overview: passive → active → verification → documentation.

## 2. Scoping, Target Baseline, and Legal Considerations
- Define targets: root domains, subdomains, IP ranges, web apps, APIs, mobile backends, cloud assets.
- Out of scope: explicitly excluded hosts, third-party vendors, production safety constraints.
- Timing: authorized windows, throttling, automation caps.
- Data policy: PII minimization, encrypted storage, redaction.

## 3. WHOIS and Registration Intelligence
- Concepts: registrars, registrants, contact privacy, nameservers, creation/expiry, ASN.
- Passive:
  - whois example.com
  - whois -H example.com (suppress legal banner)
  - whois 203.0.113.10
- Notes: pivot on NS, email, org to linked assets; watch GDPR-redacted data.

## 4. DNS Enumeration Fundamentals
- Record types: A/AAAA, CNAME, NS, MX, TXT/SPF/DMARC, SRV.
- Commands:
  - dig +short NS example.com
  - dig ANY example.com @8.8.8.8
  - dig TXT example.com; dig MX example.com
  - nslookup -type=TXT example.com
- Zone transfer check:
  - dig AXFR example.com @ns1.example.com
- Brute assumptions: internal patterns like dev, staging, api, intranet.

## 5. Passive Subdomain Discovery
- Sources: Certificate Transparency (crt.sh, Censys, Shodan certs), search engines, threat intel, GitHub code, DNSDB.
- Tools/queries:
  - curl "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
  - assetfinder --subs-only example.com
  - amass enum -passive -d example.com
  - subfinder -d example.com -silent
  - waybackurls example.com | unfurl -u domains | sort -u
- Notes: de-duplicate, resolve, and filter wildcard noise.

## 6. Active Subdomain Discovery and DNS Brute Forcing
- Wordlists: SecLists (Discovery/DNS), custom permutations.
- DNS resolution at scale:
  - puredns bruteforce subdomains.txt example.com -r resolvers.txt -w found.txt
  - dnsx -d example.com -w subdomains.txt -resp -o alive.txt
  - amass enum -active -brute -d example.com
- Permutation/enrichment:
  - gotator -sub subdomains.txt -perm perms.txt -depth 1 -adv -md -silent | dnsx -a -resp
- Wildcard handling: test known-random labels, compare CNAME/answers.

## 7. Virtual Host and VHost Enumeration
- Concepts: multiple vhosts on single IP, name-based routing.
- Techniques:
  - ffuf -w hosts.txt -u http://TARGET/ -H "Host: FUZZ.example.com" -fw 0 -fc 400,404
  - gobuster vhost -u http://TARGET -w hosts.txt -t 50 --append-domain
  - dnsx -ptr -resp -a -r 1.1.1.1 -silent
- SSL SNI probing:
  - tls-scan or curl --resolve vhost.example.com:443:IP https://vhost.example.com -I

## 8. Certificate Transparency and PKI Intel
- Review SANs and historical certs for subdomains and retired assets.
- Tools:
  - ctfr -d example.com
  - censys search 'parsed.names: example.com and tags.raw: trusted'
  - shodan ssl.cert.subject.CN:"example.com"
- Extract issuers, validity windows, and staging/test hosts.

## 9. Web Crawling and Content Discovery
- Robots/sitemaps and archive sources:
  - curl -s https://example.com/robots.txt
  - curl -s https://example.com/sitemap.xml
  - waybackurls example.com | httpx -mc 200 -o alive-urls.txt
- Forced browsing/content brute-force:
  - ffuf -u https://example.com/FUZZ -w raft-medium-directories.txt -e .php,.aspx,.bak,.old -fc 404
  - gobuster dir -u https://example.com -w common.txt -x php,aspx,txt -b 404,403
- Parameter discovery:
  - gauplus -t 20 -random-agent -subs example.com | unfurl -u keys | anew params.txt
  - arjun -u https://example.com/page -w big.txt

## 10. Application and Stack Fingerprinting
- HTTP enumerations:
  - httpx -l hosts.txt -ports 80,443,8080,8443 -title -tech-detect -status-code -follow-redirects -json -o httpx.json
  - whatweb https://example.com; wappalyzer (cli)
- Headers and behaviors:
  - curl -Iks https://example.com
  - nuclei -u https://example.com -tags tech,misc -severity info,low
- Service fingerprinting:
  - nmap -sV -p 80,443,8080,8443 --script http-enum,http-headers TARGET

## 11. API and Microservice Surface Discovery
- Swagger/OpenAPI, GraphQL, gRPC endpoints.
- Techniques:
  - ffuf -u https://api.example.com/FUZZ -w apis.txt -fc 404
  - nuclei -u https://example.com -t http/exposures -tags swagger,openapi,graphql
  - graphql-introspection: python -m sgqlc.introspection https://example.com/graphql

## 12. Account Enumeration and Authentication Footprinting
- Username/email patterns, password policy hints, MFA flows, rate limits.
- Checks:
  - ffuf POST-based enum with response matcher for invalid/valid prompts
  - wfuzz --hc 404 -w users.txt -d "user=FUZZ&pass=x" https://example.com/login
- Caution: obey scope and no-DoS; throttle.

## 13. Content Leakage and Secrets Discovery
- Sources: GitHub, JS files, backups, exposed buckets.
- Commands:
  - github-dorks 'org:example key secret password token'
  - trufflehog filesystem --regex --entropy=False .
  - ripgrep -n "(api[_-]?key|secret|token)" --hidden
  - s3scanner, gcpbucketbrute, az cli: az storage blob list --account-name NAME

## 14. Infrastructure and Cloud Footprinting
- ASN, netblocks, CDN mapping, WAF/CDN bypass candidates.
- Tools:
  - amass intel -org "Example Inc"
  - bgpq4, whois -h whois.radb.net 'ASXXXXX'
  - dnsx -cname -resp -l subs.txt | grep -i cloudfront|azureedge|fastly
- IP scanning (lightweight, web-only scope):
  - httpx -l ips.txt -ports 80,443,8080,8443 -path / -title -tech-detect

## 15. Screenshotting and Evidence Collection
- Aquatone/Eyewitness/Gowitness for visual baselining.
- Examples:
  - gowitness file -f alive.txt --threads 10 --destination shots/
  - eyewitness -f urls.txt --web --timeout 10 --no-prompt -d eyewitness/
- Keep timestamps, tool versions, and exact commands.

## 16. Prioritization and Attack Surface Mapping
- De-dup, resolve only-live, tag by tech and risk.
- Build graph: domain → subdomain → vhost → service → route → parameters.
- Score quick wins: default creds, exposed panels, known CVEs, debug endpoints.

## 17. Automation Pipelines
- Makefiles/GitHub Actions/local scripts to chain: subfinder → amass → puredns → httpx → nuclei → screenshots.
- Example one-liner:
  - subfinder -d example.com | anew subs.txt; puredns resolve subs.txt -r resolvers.txt -w alive.txt; httpx -l alive.txt -title -tech-detect -o httpx.txt; nuclei -l alive.txt -severity info,low,medium -o nuclei.txt

## 18. Reporting and Documentation
- Structure: scope, methods, evidence, findings, risk, reproduction, remediation.
- Include raw lists (resolved hosts, URLs, parameters) as appendices.
- Use CVSS/CWE mapping where relevant.

## 19. Skills Assessment Checklist
- Can enumerate DNS and perform passive+active subdomain discovery at scale.
- Can detect vhosts, crawl content, fingerprint stacks, and identify API surfaces.
- Can collect clean evidence and map to attack paths.

---

References and Wordlists
- SecLists: https://github.com/danielmiessler/SecLists
- ProjectDiscovery: subfinder, httpx, nuclei, dnsx
- OWASP: Testing Guide (OTG-INFO-*)
- HTB module for screenshots and exact flow alignment.
