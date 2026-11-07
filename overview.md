### Project: Phishing Triage Automation and Incident Response Report

**Overview**
Build a Python tool that takes a suspicious email file (.eml), extracts headers, URLs and attachments, checks them against threat intelligence sources and produces a verdict. Then run a full incident response exercise on a sample case and write a professional IR report.

**Why it is important**
Phishing is the most common alert type in many SOCs. Automating triage shows scripting and SOAR thinking. The IR report shows you can handle an incident from start to finish.

SOAR thinking = Security Orchestration, Automation, and Response. 

**Goals**

- Parse email headers (SPF - Sender Policy Framework, DKIM DomainKeys Identified Mail, DMARC - Domain-based Message Authentication, Reporting and Conformance, sender path)
- Extract and defang IOCs (URLs, domains, IPs, file hashes)
- Enrich IOCs with threat intelligence APIs
- Output a verdict (benign, suspicious, malicious) with reasons
- Complete one incident response case from a public PCAP or memory image

**Scope**

- In scope: sample phishing emails, public PCAP and memory images, free API tiers
- Out of scope: opening live malware outside a sandbox, sending any email

**Boundaries**

- Handle malicious samples only in an isolated VM
- Respect API rate limits and terms of service
- Store API keys in environment variables, never in the repository

**Tech spec**

| Component | Tool |
|---|---|
| Language | Python 3 |
| Libraries | email, re, requests, tldextract |
| Threat intelligence | VirusTotal API (free tier), AbuseIPDB, URLScan.io |
| Forensics | Wireshark, Volatility 3 |
| Sample data | Public phishing samples, Malware-Traffic-Analysis.net exercises |
| Framework | NIST SP 800-61 incident response lifecycle |

**Deliverables**

- GitHub repository with CLI tool, tests and sample output
- Incident response report: timeline, IOCs, scope, root cause, containment, lessons learned
- Write-up: "Automating phishing triage for a SOC"

**Estimated time**

| Phase | Time |
|---|---|
| Parser and IOC extraction | 1 week |
| Enrichment and verdict logic | 1 - 1.5 weeks |
| IR exercise and report | 1 - 2 weeks |
| Documentation | 0.5 week |

**Resources**

- VirusTotal API documentation
- AbuseIPDB and URLScan.io documentation
- Malware-Traffic-Analysis.net
- Volatility 3 documentation
- NIST SP 800-61 (Computer Security Incident Handling Guide)
