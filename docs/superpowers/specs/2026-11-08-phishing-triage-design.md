# Design: Phishing Triage Automation + IR Report (mentor mode)

## Context
Portfolio project for a SOC / Tier 1 analyst job search (source: `overview.md`). The user builds everything themselves to learn; Claude acts as **mentor**: writes the spec and a task plan, gives hints, tests to pass and pitfalls, and reviews diffs. Claude does not write product code. The user is comfortable with Python and mostly new to the security side. They need an isolated lab VM. The agreed sequencing is **thin slice first**: an end-to-end crude pipeline in week 1, then each stage gets deepened.

Success means a public repo whose CLI triages real sample .eml files with passing offline tests, plus a NIST 800-61 IR report on a malspam case that reads like real SOC work, plus a write-up.

## Architecture
Python package `phishtriage`, one pipeline, each stage a pure-ish function over plain dataclasses:

```
.eml ─► parse ─► iocs ─► enrich (vt / abuseipdb / urlscan, cached) ─► verdict ─► report (text | json | md)
```

```
PTA/
  phishtriage/
    models.py     # dataclasses: ParsedEmail, Attachment, IOC, Enrichment, Verdict
    parse.py      # stdlib email (policy=default): headers, Received hops, Authentication-Results, bodies, attachments (hash only)
    iocs.py       # URLs/domains/IPs/hashes via re + html.parser (href) + tldextract; defang/refang
    enrich/
      vt.py  abuseipdb.py  urlscan.py   # one small module per provider, same function shape
      cache.py    # stdlib sqlite3, TTL, keyed (provider, ioc)
    verdict.py    # list of scored rules → label + reasons
    report.py     # render text / JSON / Markdown
    cli.py        # argparse entry point
  tests/  fixtures/eml/  fixtures/api/   # crafted samples + recorded API JSON
  samples/        # sanitized/defanged real samples only
  ir/             # IR case notes, evidence screenshots, report
  docs/superpowers/specs/  docs/WRITEUP.md
```

Dependencies: `requests` and `tldextract`. Dev dependency: `pytest`. Nothing else unless a task justifies it.

## Key design decisions (security learning points)
- **Email auth:** read the receiving server's `Authentication-Results` header (spf/dkim/dmarc). Do not re-verify after the fact, because DNS records change and saved .eml files break DKIM. Also flag From vs Reply-To vs Return-Path mismatches and lookalike domains. Stretch goal: offline DKIM check with `dkimpy`.
- **Attachments:** compute SHA256 in memory only. Never write them to disk or execute them. Look up the **hash** on VT and never upload (uploads become public, which is a ToS and OPSEC issue).
- **URLScan:** search existing scans by default. A `--submit` flag submits with `visibility=unlisted`. Phishing URLs can carry victim tokens, so public submission leaks data.
- **HTML links:** a mismatch between the visible link text and the `href` domain is a scored signal.
- **Rate limits:** VT free tier allows 4 req/min and 500/day. Use the sqlite cache plus a simple per-provider sleep. `--offline` uses the cache only.
- **Secrets:** API keys come from env vars (`VT_API_KEY`, `ABUSEIPDB_API_KEY`, `URLSCAN_API_KEY`). Keep `.env` in `.gitignore`. A missing key skips that provider with a note instead of crashing.
- **tldextract** fetches the public suffix list on first run. Configure it to use the bundled snapshot so tests and offline runs stay deterministic.

## Verdict logic
Rules are additive. Each returns `(points, reason)`. All rules live in one list in `verdict.py` with their weights documented in a table in the README. Score thresholds: under 30 is **benign**, 30–69 is **suspicious**, 70 or more is **malicious**. Hard overrides: an attachment hash or URL flagged by at least N VT engines → malicious. Example rules: SPF/DKIM/DMARC fail, Reply-To mismatch, lookalike sender domain, href/text mismatch, IP with a high AbuseIPDB score, newly-seen URL, risky attachment extension (.docm/.iso/.html/.lnk). If enrichment is incomplete, add a reason line saying so.

**Exit codes** (useful for SOAR chaining): 0 benign, 1 suspicious, 2 malicious, 3 error.

## Error handling
- Malformed .eml: parse best-effort and collect warnings in `ParsedEmail.warnings`.
- Provider errors (timeout, 429, 401): record them on the `Enrichment` and keep going. The verdict notes the gap. One retry on 429, after a wait.
- Exit code 3 only when the input can't be read at all.

## Testing
- pytest, TDD per task (the user writes the tests from the acceptance criteria given in each task).
- Crafted fixture emails: benign, spoofed sender, encoded headers (RFC 2047), multipart HTML with href mismatch, attachment, malformed.
- API calls are tested with `monkeypatch` on `requests` against recorded JSON in `fixtures/api/`. **The whole suite runs offline with no keys.**
- One optional live smoke test, marked and skipped unless keys are present.

## IR exercise
- Pick a Malware-Traffic-Analysis.net exercise that starts from malspam and includes the email if possible. Run `phishtriage` on that email to tie the two halves together.
- Tools: Wireshark/tshark on the PCAP (HTTP objects, DNS, TLS SNI, C2 beacons). Volatility 3 is a stretch goal if a matching memory image is available (e.g. CyberDefenders/MemLabs).
- Report sections (NIST SP 800-61 Rev 2 lifecycle, noting Rev 3/CSF 2.0 mapping): executive summary, timeline (UTC), IOC table (defanged), scope/affected hosts, root cause, containment/eradication/recovery, lessons learned, MITRE ATT&CK mapping.

## Schedule (about 10–15 hrs/week)
| Week | Work |
|---|---|
| 0 | Lab: UTM + ARM Ubuntu VM, host-only network, no shared folders, snapshot. API keys. `git init`, repo skeleton, samples collected (phishing_pot + own benign emails) |
| 1 | Thin slice: parse basic headers/body → regex URLs → VT URL lookup → 2–3 rules → text output → CLI. Runs end to end |
| 2 | Deepen: Authentication-Results, Received hops, RFC 2047, HTML hrefs, attachments + hashes, defang, sqlite cache, offline tests |
| 3 | AbuseIPDB + URLScan, full rule set + weights table, JSON/Markdown output, exit codes |
| 4 | IR case: analysis + report in `ir/` |
| 5 | README (demo GIF, sample output, weights table), WRITEUP.md, cleanup |

## Mentor workflow
Each task in the plan gives: goal, acceptance criteria (tests to write), hints, pitfalls, and a "done when" check. The loop: the user implements and commits, then asks for a review. Claude reviews `git diff` and comments without rewriting. When the user is stuck, Claude escalates hints in steps (concept → API pointer → pseudocode), never a full solution unless asked.

## Next steps after approval
1. `git init` in `PTA/`, write this spec to `docs/superpowers/specs/2026-11-08-phishing-triage-design.md` and commit it (Claude writes docs only).
2. User reviews the spec.
3. Invoke writing-plans to produce the mentor-style task plan (week 0–5).

## Verification
- `pytest` passes offline with no API keys.
- `python -m phishtriage samples/<phish>.eml` gives a malicious/suspicious verdict with reasons. A benign sample gives benign. The exit code matches the label.
- `git grep -i "api_key\s*="` finds no secrets, and `.env` is gitignored.
- The IR report contains every section listed above, with a defanged IOC table.
