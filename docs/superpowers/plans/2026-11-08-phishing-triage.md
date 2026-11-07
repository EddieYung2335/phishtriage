# Phishing Triage + IR Report Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Mentor mode:** in this project the implementer is the human (Eddie). Claude does not write product code or tests. After each task: commit, then ask Claude "review task N". Claude reviews `git diff`. When stuck, ask for a hint. Hints escalate concept → API pointer → pseudocode.

**Goal:** CLI `phishtriage` that turns a `.eml` file into IOCs, threat-intel enrichment and a scored verdict with reasons. Plus a NIST 800-61 IR report on a malspam case and a write-up.

**Architecture:** A single package with a linear pipeline `parse → iocs → enrich → verdict → report`. Stages share plain dataclasses from `models.py`. Providers are small modules with the same `lookup()` shape, sitting behind a sqlite cache. Week 1 builds a thin version of every stage. Later weeks deepen each stage without changing its interface.

**Tech Stack:** Python ≥3.11, stdlib `email`/`re`/`html.parser`/`sqlite3`/`hashlib`/`ipaddress`/`difflib`, `requests`, `tldextract`, `pytest`. Wireshark/tshark and Volatility 3 for the IR case.

**Spec:** `docs/superpowers/specs/2026-11-08-phishing-triage-design.md`

## Global Constraints

- Runtime deps are only `requests` and `tldextract`. The only dev dep is `pytest`. Any new dep needs a reason in the commit message.
- API keys come from the env vars `VT_API_KEY`, `ABUSEIPDB_API_KEY`, `URLSCAN_API_KEY`. Never put them in code, tests, fixtures or commits.
- Never upload files to VT and never POST URLs to VT. GET lookups only.
- URLScan searches by default. It submits only with `--submit`, always with `"visibility": "unlisted"`.
- Attachments are hashed in memory only. Never write them to disk.
- The test suite runs offline with no keys. The live test is marked `live` and skipped without keys.
- Every IOC printed in any output format is defanged.
- Verdict thresholds: score <30 is `benign`, 30–69 is `suspicious`, ≥70 is `malicious`. `VT_HARD_THRESHOLD = 5`. VT engines ≥5 on any IOC gives `malicious` regardless of score.
- Exit codes: 0 benign, 1 suspicious, 2 malicious, 3 unreadable input.
- Fixtures use only reserved names and addresses: `example.com/.org/.net`, `*.example`, `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`. Real samples live in `raw_samples/` (gitignored), inside the VM.
- `tldextract` always uses `tldextract.TLDExtract(suffix_list_urls=())`, the bundled list with no network.

## Review Focus

1. **A user-reported phish arrives as a forwarded email** (`message/rfc822` attachment). That's the most common case in a real SOC. Expect the inner message's IOCs and auth results to be analysed. Test: Task 10.
2. **The body already contains defanged IOCs** (`hxxps://evil[.]example`), because analysts paste them that way. Expect them to be refanged and extracted. Test: Task 2.
3. **URLs wrapped in punctuation** such as `(http://example.org/a).` or `<http://…>`. Expect the URL without the trailing `).>` characters. Test: Task 2.
4. **No keys and no network.** Expect a verdict from header rules alone, plus a "enrichment incomplete" reason, and an exit code that matches the label (not 3). Test: Task 14.
5. **The same URL appears 10 times** in text and HTML. Expect one IOC and one API call, so the VT quota isn't burned. Test: Task 2 (dedupe) and Task 11 (cache).

---

## Interfaces (shared by all tasks — `phishtriage/models.py`)

```python
@dataclass(frozen=True)
class IOC:
    type: Literal["url", "domain", "ip", "sha256"]
    value: str                      # always refanged/normal form

@dataclass
class AuthResults:
    spf: str | None = None          # lowercase result: "pass","fail","softfail","neutral","none",...
    dkim: str | None = None
    dmarc: str | None = None

@dataclass
class Hop:
    from_host: str | None
    by_host: str | None
    ip: str | None
    timestamp: datetime | None

@dataclass
class Link:
    href: str
    text: str

@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str

@dataclass
class ParsedEmail:
    subject: str = ""
    from_addr: str = ""             # bare address, lowercase
    reply_to: str | None = None     # bare address, lowercase
    return_path: str | None = None  # bare address, lowercase
    to: list[str] = field(default_factory=list)
    date: datetime | None = None
    message_id: str | None = None
    auth: AuthResults = field(default_factory=AuthResults)
    hops: list[Hop] = field(default_factory=list)       # index 0 = top (newest)
    body_text: str = ""
    body_html: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    inner: list["ParsedEmail"] = field(default_factory=list)  # forwarded message/rfc822
    warnings: list[str] = field(default_factory=list)

@dataclass
class Enrichment:
    provider: Literal["virustotal", "abuseipdb", "urlscan"]
    ioc: IOC
    score: int | None               # VT: malicious engine count; AbuseIPDB: abuseConfidenceScore 0-100; URLScan: 1 if verdict malicious else 0
    summary: str                    # one human line, e.g. "12/93 engines malicious"
    error: str | None = None        # set on failure; score is None then

@dataclass
class Verdict:
    label: Literal["benign", "suspicious", "malicious"]
    score: int
    reasons: list[str]
```

Function signatures used across tasks:

| Function | File | Task |
|---|---|---|
| `parse_eml(raw: bytes) -> ParsedEmail` | `parse.py` | 1 (deepened 6–10) |
| `parse_file(path: str \| Path) -> ParsedEmail` (raises `OSError`) | `parse.py` | 1 |
| `refang(s: str) -> str`, `defang(s: str) -> str` | `iocs.py` | 2 |
| `registered_domain(host_or_url: str) -> str` | `iocs.py` | 2 |
| `extract_iocs(email: ParsedEmail) -> list[IOC]` (deduped, first-seen order) | `iocs.py` | 2 (deepened 7, 9, 10) |
| `vt.lookup(ioc: IOC, api_key: str) -> Enrichment \| None` (None = type unsupported) | `enrich/vt.py` | 3 |
| `abuseipdb.lookup(ioc, api_key) -> Enrichment \| None` | `enrich/abuseipdb.py` | 12 |
| `urlscan.lookup(ioc, api_key, submit: bool = False) -> Enrichment \| None` | `enrich/urlscan.py` | 13 |
| `Cache(path: str \| Path, ttl_seconds: int = 86400)` with `.get(provider: str, ioc: IOC) -> Enrichment \| None`, `.put(e: Enrichment) -> None` | `enrich/cache.py` | 11 |
| `enrich_all(iocs: list[IOC], *, offline: bool = False, submit: bool = False, cache: Cache \| None = None) -> list[Enrichment]` | `enrich/__init__.py` | 3 (deepened 11–13) |
| `score_email(email: ParsedEmail, enrichments: list[Enrichment]) -> Verdict` | `verdict.py` | 4 (deepened 6, 9, 10, 14) |
| `render(email, iocs, enrichments, verdict, fmt: Literal["text","json","md"] = "text") -> str` | `report.py` | 5 (deepened 15) |
| `main(argv: list[str] \| None = None) -> int` | `cli.py` | 5 |

**Rule shape** (`verdict.py`): `Rule = Callable[[ParsedEmail, list[Enrichment]], list[tuple[int, str]]]`, with `RULES: list[Rule]`. Each rule returns zero or more `(points, reason)`. Every rule also runs over `email.inner` messages, so findings bubble up.

**Weights** (pinned. These are also the README table in Task 14):

| Rule | Points |
|---|---|
| SPF `fail`/`softfail` | 15 |
| DKIM `fail` | 15 |
| DMARC `fail` | 25 |
| Reply-To registered domain ≠ From registered domain | 20 |
| Return-Path registered domain ≠ From registered domain | 10 |
| Lookalike sender domain | 25 |
| Link text shows a domain ≠ href domain | 25 |
| URL host is a raw IP or a known shortener | 15 |
| Risky attachment extension | 30 |
| VT 1–4 engines on any IOC | 20 (once per IOC) |
| VT ≥5 engines | hard override → malicious |
| AbuseIPDB score ≥75 on a hop/body IP | 20 |
| URLScan verdict malicious | 30 |

---

## Week 0 — Lab and skeleton

### Task 0: Isolated lab VM (no code)

- [ ] **Step 1:** Install UTM. Create an Ubuntu 24.04 ARM64 VM with 4 GB RAM and a 40 GB disk.
- [ ] **Step 2:** VM settings: shared folders **off**, clipboard sharing **off**, network = *Shared/NAT* during setup only.
- [ ] **Step 3:** Inside the VM, install `python3-venv git wireshark tshark` and `pipx install volatility3`.
- [ ] **Step 4:** Shut down and take a snapshot named `clean-base`.
- [ ] **Step 5:** For sample work, switch the network to *Host Only*. Re-enable NAT only for API runs, and only on the tool, never on opened samples.
- [ ] **Done when:** the snapshot exists, and with Host Only on, `ping 1.1.1.1` fails inside the VM.

Learn: why host-only? Malware can beacon out, and shared folders give it a path back to your Mac.
Pitfall: REMnux is x86-only. On Apple Silicon, use ARM Ubuntu and install the tools yourself.

### Task 1-pre: Repo skeleton, keys, fixtures

**Files:** create `pyproject.toml`, `phishtriage/__init__.py`, `phishtriage/__main__.py`, `phishtriage/models.py`, `tests/conftest.py`, `.env.example`, `fixtures/eml/*.eml`

- [ ] **Step 1:** Write `pyproject.toml`: `requires-python = ">=3.11"`, deps `requests`, `tldextract`, optional `dev = ["pytest"]`, script `phishtriage = "phishtriage.cli:main"`, and a pytest marker `live`. Run `python -m venv .venv && pip install -e '.[dev]'`.
- [ ] **Step 2:** Copy the dataclasses from the Interfaces section above into `models.py`.
- [ ] **Step 3:** Create free accounts on VirusTotal, AbuseIPDB and URLScan. Put the keys in `.env` (gitignored) and the empty names in `.env.example`. Load them with `set -a; source .env; set +a`.
- [ ] **Step 4:** Hand-craft these fixtures. They are plain-text RFC 5322 files, and writing them teaches you the format.

| File | Must contain |
|---|---|
| `benign_plain.eml` | `From: alice@example.com`, no Reply-To, `Authentication-Results: mx.example.net; spf=pass ...; dkim=pass ...; dmarc=pass ...`, body with `https://www.example.com/docs` |
| `spoofed_replyto.eml` | `From: "PayPal" <service@paypal.com>`, `Reply-To: support@paypa1-help.example`, `Return-Path: <bounce@mailer.example>`, Auth-Results `spf=fail`, `dkim=none`, `dmarc=fail`, two `Received:` headers: first (top) contains `[203.0.113.5]`, second (bottom) contains `[10.0.0.2]` |
| `encoded_subject.eml` | `Subject: =?UTF-8?B?w4RyZ2VyIG1pdCBkZXIgUmVjaG51bmc=?=` (decodes to `Ärger mit der Rechnung`) |
| `html_mismatch.eml` | multipart/alternative. HTML part `<a href="http://198.51.100.7/login">https://www.paypal.com</a>` and `<a href="https://bit.ly/x">click</a>` |
| `attachment.eml` | multipart/mixed, attachment `invoice.docm`, base64 of the bytes `hello\n` |
| `forwarded.eml` | From `user@example.org`, body "pls check", `message/rfc822` attachment = the full content of `spoofed_replyto.eml` |
| `defanged_body.eml` | body: `see hxxps://evil[.]example/login and (http://example.org/a).` plus the same `https://www.example.com/docs` repeated 3 times |
| `malformed.eml` | No `From`/`Date`, `Content-Type: multipart/mixed; boundary="X"` but the closing boundary is missing |

- [ ] **Step 5:** In the **VM only**, clone `rf-peixoto/phishing_pot` into `~/raw_samples/` and pick 5 samples to test by hand later. Export 2 of your own benign emails as `.eml`.
- [ ] **Step 6:** Write `tests/conftest.py` with a fixture `load_eml(name) -> bytes` that reads from `fixtures/eml/`. Run `pytest`. **Expected:** "no tests ran", exit code 5, no errors.
- [ ] **Step 7:** Commit (`chore: project skeleton and fixtures`). Ask: "review task 1-pre".

Pitfall: `.eml` files need CRLF or LF line endings consistently. Python accepts both, but a mix inside one MIME part can confuse boundaries.

---

## Week 1 — Thin slice (end to end, crude)

### Task 1: Basic parser

**Files:** create `phishtriage/parse.py`, `tests/test_parse.py`
**Interfaces:** Produces `parse_eml`, `parse_file`. Fills subject, from_addr, reply_to, return_path, to, date, message_id, body_text, body_html, warnings.

- [ ] **Step 1: Write tests**
  - `test_basic_headers`: `benign_plain` → `from_addr == "alice@example.com"`, `reply_to is None`, and the subject matches what you wrote.
  - `test_spoofed_addresses`: `spoofed_replyto` → `from_addr == "service@paypal.com"`, `reply_to == "support@paypa1-help.example"`, `return_path == "bounce@mailer.example"`.
  - `test_body_text`: `benign_plain` → `"https://www.example.com/docs" in body_text`.
  - `test_html_body`: `html_mismatch` → `"198.51.100.7" in body_html`.
  - `test_parse_file_missing`: `parse_file("nope.eml")` raises `OSError`.
- [ ] **Step 2:** Run `pytest tests/test_parse.py -v`. **Expected:** FAIL (ImportError).
- [ ] **Step 3:** Implement. Hints: `email.message_from_bytes(raw, policy=email.policy.default)`; `msg.get_body(preferencelist=("plain",))` and `("html",)`; `email.utils.parseaddr` for bare addresses; `msg["Date"].datetime`.
- [ ] **Step 4:** Run tests. **Expected:** PASS.
- [ ] **Step 5:** Commit `feat(parse): basic headers and bodies`. Ask for review.

Learn: `policy.default` vs the legacy `compat32` policy (string vs header objects).
Pitfall: `msg["Reply-To"]` returns `None` when the header is absent, so guard before `parseaddr`.

### Task 2: IOC extraction + defang

**Files:** create `phishtriage/iocs.py`, `tests/test_iocs.py`
**Interfaces:** Consumes `ParsedEmail`. Produces `refang`, `defang`, `registered_domain`, `extract_iocs`. In week 1, extract URLs and their domains from `body_text` + `body_html` text only.

- [ ] **Step 1: Write tests**
  - `test_defang`: `defang("https://evil.example/a") == "hxxps://evil[.]example/a"`. `defang("203.0.113.5") == "203[.]0[.]113[.]5"`.
  - `test_refang_roundtrip`: `refang(defang(x)) == x` for the 2 values above. Also `refang("hxxp://a[.]b") == "http://a.b"`.
  - `test_registered_domain`: `registered_domain("https://login.paypal.co.uk/x") == "paypal.co.uk"`.
  - `test_extracts_defanged_urls` (Review Focus 2): `defanged_body` → `IOC("url","https://evil.example/login")` is in the result.
  - `test_strips_trailing_punct` (Review Focus 3): `defanged_body` → `IOC("url","http://example.org/a")` is in the result, and nothing ends in `)` or `.`.
  - `test_dedupes` (Review Focus 5): `defanged_body` → `www.example.com/docs` URL appears exactly once. Domain IOC `www.example.com` appears once.
- [ ] **Step 2:** Run. **Expected:** FAIL.
- [ ] **Step 3:** Implement. Hints: refang the text before matching. A simple URL regex `https?://[^\s<>"']+`, then `rstrip(".,);:!?>]")`. Dedupe with `dict.fromkeys`. Domain = `urlsplit(url).hostname`. Use the module-level `TLDExtract(suffix_list_urls=())`.
- [ ] **Step 4:** Run. **Expected:** PASS.
- [ ] **Step 5:** Commit `feat(iocs): extract and defang URLs/domains`. Ask for review.

Learn: why SOCs defang (accidental clicks, link auto-preview in Slack/Jira).
Pitfall: stripping `)` blindly breaks Wikipedia-style URLs with balanced parens. Document that as a known limitation in a `ponytail:` comment.

### Task 3: VirusTotal lookup + `enrich_all`

**Files:** create `phishtriage/enrich/__init__.py`, `phishtriage/enrich/vt.py`, `tests/test_vt.py`, `fixtures/api/vt_url_malicious.json`, `fixtures/api/vt_domain_clean.json`
**Interfaces:** Consumes `IOC`. Produces `vt.lookup`, `enrich_all` (week 1: VT only, no cache, `offline=True` returns `[]`).

- [ ] **Step 1:** Record fixtures: one manual `curl -H "x-apikey: $VT_API_KEY"` call for a known-bad URL and one for `example.com`. Trim them to `data.attributes.last_analysis_stats` and save. Strip anything identifying you.
- [ ] **Step 2: Write tests** (monkeypatch `requests.get` to return a fake response with `.status_code` and `.json()`)
  - `test_url_endpoint`: for `IOC("url","http://x.example/")`, the requested URL is `https://www.virustotal.com/api/v3/urls/` + `base64.urlsafe_b64encode(b"http://x.example/").decode().rstrip("=")`, and the header `x-apikey` is set.
  - `test_malicious_count`: the malicious fixture → `score == <malicious value in fixture>` and `"engines malicious" in summary`.
  - `test_404_unknown`: status 404 → `score == 0`, `error is None`, `"not found" in summary`.
  - `test_http_error`: status 401 → `score is None` and `error` contains `"401"`.
  - `test_ip_routes`: `IOC("ip", ...)` → endpoint `/api/v3/ip_addresses/<ip>`. `sha256` → `/api/v3/files/<hash>`. `domain` → `/api/v3/domains/<domain>`.
  - `test_enrich_all_no_key`: with `VT_API_KEY` unset (`monkeypatch.delenv`), `enrich_all([...])` returns `[]` and makes no HTTP calls.
- [ ] **Step 3:** Run. **Expected:** FAIL.
- [ ] **Step 4:** Implement. Use `timeout=15` on every request. Rate limit: module constant `VT_MIN_INTERVAL = 15.0` seconds between live calls, with `time.monotonic()` tracking and `time.sleep`. Monkeypatch `time.sleep` in tests.
- [ ] **Step 5:** Run. **Expected:** PASS.
- [ ] **Step 6:** Commit `feat(enrich): VirusTotal lookups`. Ask for review.

Learn: VT v3 URL identifiers. Why GET-only matters: POST `/urls` triggers a fresh scan that the whole VT community can see.
Pitfall: catch `requests.RequestException` and turn it into `Enrichment(error=...)`. Never let it crash the pipeline.

### Task 4: Minimal verdict

**Files:** create `phishtriage/verdict.py`, `tests/test_verdict.py`
**Interfaces:** Consumes `ParsedEmail`, `Enrichment`. Produces `score_email`, `RULES`, constants `SUSPICIOUS_AT = 30`, `MALICIOUS_AT = 70`, `VT_HARD_THRESHOLD = 5`. Week 1 rules: Reply-To mismatch (20) and VT counts (20 / hard override).

- [ ] **Step 1: Write tests** (build `ParsedEmail`/`Enrichment` objects directly, no fixtures needed)
  - `test_benign_default`: an empty `ParsedEmail()` with no enrichments → `label == "benign"`, `score == 0`.
  - `test_replyto_mismatch`: from `a@paypal.com`, reply_to `b@paypa1-help.example` → `score == 20` and one reason mentions `Reply-To`.
  - `test_replyto_same_org`: from `a@mail.example.com`, reply_to `b@example.com` → score 0 (registered domains match).
  - `test_vt_low`: one VT enrichment with `score=2` → +20.
  - `test_vt_hard_override`: VT `score=5` → `label == "malicious"` even though the total points are below 70.
  - `test_thresholds`: points 29 → benign, 30 → suspicious, 70 → malicious. Use a fake rule via `monkeypatch.setattr(verdict, "RULES", [...])`.
- [ ] **Step 2:** Run. **Expected:** FAIL.
- [ ] **Step 3:** Implement `score_email`: sum points from every rule across the email and its `inner` messages, collect reasons, apply the hard override, map to a label.
- [ ] **Step 4:** Run. **Expected:** PASS.
- [ ] **Step 5:** Commit `feat(verdict): scored rules engine`. Ask for review.

Learn: why rule-based, explainable scoring beats a black box in a SOC (the analyst must justify the escalation).

### Task 5: CLI + text report (slice complete)

**Files:** create `phishtriage/report.py`, `phishtriage/cli.py`, update `phishtriage/__main__.py`, add `tests/test_cli.py`
**Interfaces:** Consumes everything above. Produces `render(..., fmt="text")` and `main(argv) -> int`. CLI args: positional `eml`, `--format {text,json,md}` (only `text` works this week), `--offline`, `--submit`, `--cache PATH`.

- [ ] **Step 1: Write tests**
  - `test_exit_benign`: `main([path_to_benign_plain, "--offline"]) == 0`.
  - `test_exit_suspicious`: `spoofed_replyto --offline` → returns `0` this week (only Reply-To 20 points). Change it to `1` in Task 6 and `2` in Task 14.
  - `test_unreadable`: `main(["missing.eml"]) == 3`, and stderr mentions the path (`capsys`).
  - `test_text_is_defanged`: on `defanged_body --offline`, stdout contains `evil[.]example` and does **not** contain `https://evil.example`.
  - `test_text_has_reasons`: stdout contains `Verdict:` and each reason on its own line.
- [ ] **Step 2:** Run. **Expected:** FAIL.
- [ ] **Step 3:** Implement. `__main__.py`: `raise SystemExit(main())`. Map label → exit code with a dict.
- [ ] **Step 4:** Run the full suite with `pytest -v`. **Expected:** all PASS.
- [ ] **Step 5:** Manual check in the VM with keys loaded: `python -m phishtriage ~/raw_samples/<one>.eml`. **Expected:** a verdict with at least one VT line.
- [ ] **Step 6:** Commit `feat(cli): end-to-end thin slice`. Ask for review. **Milestone: demo-able.**

---

## Week 2 — Deepen

### Task 6: Authentication-Results + auth rules

**Files:** modify `parse.py`, `verdict.py`, and their tests

- [ ] **Step 1: Tests**
  - `test_auth_parsed`: `spoofed_replyto` → `auth == AuthResults(spf="fail", dkim="none", dmarc="fail")`. `benign_plain` → all `"pass"`.
  - `test_topmost_auth_wins`: in a modified copy with a second, lower `Authentication-Results: ...; spf=pass; dmarc=pass` header (the attacker-injected one), the **first** occurrence is used.
  - `test_auth_rules`: spf fail +15, softfail +15, dkim fail +15, dkim `none` +0, dmarc fail +25.
  - Update `test_exit_suspicious` in `test_cli.py`: expect `1` (20 + 15 + 25 = 60).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement with `msg.get_all("Authentication-Results")[0]` and a regex `\b(spf|dkim|dmarc)=(\w+)`. **Step 4:** Run → PASS. **Step 5:** Commit and review.

Learn: SPF checks the envelope sender (Return-Path), DKIM signs the domain in `d=`, DMARC checks alignment with the `From:` header. Spoofers pass SPF on their own domain all the time, which is why DMARC alignment is the one that matters.

### Task 7: Received hops → IP IOCs

**Files:** modify `parse.py`, `iocs.py`, and their tests

- [ ] **Step 1: Tests**
  - `test_hops`: `spoofed_replyto` → 2 hops, `hops[0].ip == "203.0.113.5"`, `hops[-1].ip == "10.0.0.2"`. Timestamps are parsed.
  - `test_private_ips_skipped`: `extract_iocs(spoofed_replyto)` contains `IOC("ip","203.0.113.5")` and **not** `10.0.0.2`.
- [ ] **Step 2:** Implement with `msg.get_all("Received")`, the regex `\[(\d{1,3}(?:\.\d{1,3}){3})\]`, and timestamps from the text after the last `;` via `email.utils.parsedate_to_datetime`.

Pitfall: Python counts documentation ranges (`203.0.113.0/24` etc.) as `is_private` **and** not `is_global`, so neither flag works with the fixtures. Skip only RFC1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback and link-local, via `ip in ipaddress.ip_network(...)`, and comment why.
Learn: read hops bottom-up. The bottom hop is closest to the sender, and every hop below your own MX can be forged.

### Task 8: Encoded headers + malformed input

- [ ] **Tests:** `test_rfc2047`: `encoded_subject.subject == "Ärger mit der Rechnung"`. `test_malformed_no_crash`: `parse_eml(malformed)` returns, `from_addr == ""`, `len(warnings) >= 1`. `test_non_utf8_body`: a body with `charset=windows-1252` byte `\x93` decodes without an exception.
- [ ] **Implement:** copy `msg.defects` and every `part.defects` into `warnings` as strings. Wrap `get_content()` in `try/except (LookupError, UnicodeDecodeError)`, fall back to `get_payload(decode=True).decode("utf-8", "replace")`, and add a warning.
- [ ] Commit and review.

### Task 9: HTML links + mismatch/shortener rules

- [ ] **Tests:**
  - `test_links`: `html_mismatch.links` contains `Link("http://198.51.100.7/login", "https://www.paypal.com")`.
  - `test_href_iocs`: `extract_iocs` includes both hrefs as URLs, the IP `198.51.100.7`, and the domain `bit.ly`.
  - `test_mismatch_rule`: +25 when the link text parses to a domain whose registered domain ≠ the href's registered domain (an IP href has registered domain `""`, which counts as a mismatch). `click` text → no mismatch.
  - `test_ip_or_shortener_rule`: +15 per email (not per URL) when any URL host is an IP or in `SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","rebrand.ly","cutt.ly"}`.
- [ ] **Implement:** a small `html.parser.HTMLParser` subclass that tracks `<a href>` and collects the text between the open and close tags. Use `ipaddress` to test whether a host is an IP.
- [ ] Commit and review.

### Task 10: Attachments + forwarded messages

- [ ] **Tests:**
  - `test_attachment_hash`: `attachment.eml` → one `Attachment(filename="invoice.docm", size=6, sha256="5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03", ...)`.
  - `test_sha_ioc`: `extract_iocs` includes `IOC("sha256", <that hash>)`.
  - `test_risky_ext`: +30 for extensions in `RISKY_EXT = {".docm",".xlsm",".iso",".img",".lnk",".html",".htm",".js",".vbs",".hta",".exe",".scr",".zip",".rar",".7z",".one"}`. A `.pdf` scores +0.
  - `test_forwarded` (Review Focus 1): `forwarded.eml` → `len(email.inner) == 1`, `inner[0].reply_to == "support@paypa1-help.example"`, and `score_email` includes the inner auth and Reply-To points with `label != "benign"`.
- [ ] **Implement:** `msg.iter_attachments()`. Use `part.get_content()` for bytes and `hashlib.sha256` in memory. For `get_content_type() == "message/rfc822"`, recurse with `parse_eml(part.get_content().as_bytes())` into `inner`, and don't hash it as a file. Extend `extract_iocs` to recurse into `inner`.
- [ ] Commit and review.

Pitfall: never call `open(filename, "wb")` with the attachment's filename. Attacker-controlled names like `../../.zshrc` cause path traversal.

### Task 11: sqlite cache + `--offline`

**Files:** create `phishtriage/enrich/cache.py`, `tests/test_cache.py`, and modify `enrich/__init__.py`

- [ ] **Tests:**
  - `test_roundtrip`: `put` then `get` returns an equal `Enrichment`, using `tmp_path`.
  - `test_ttl_expired`: with `ttl_seconds=0` (or a patched clock), `get` returns `None`.
  - `test_errors_not_cached`: `put(Enrichment(error="timeout", ...))` → `get` returns `None`.
  - `test_enrich_all_uses_cache` (Review Focus 5): the same IOC twice across two `enrich_all` calls → the fake `requests.get` is called once.
  - `test_offline_cache_only`: `offline=True` returns the cached entries and makes zero HTTP calls.
- [ ] **Implement:** a table with `PRIMARY KEY (provider, ioc_type, ioc_value)` and columns `json`, `fetched_at`. Serialize with `json.dumps(asdict(e))`. Default path `~/.cache/phishtriage/cache.sqlite3`, created with `mkdir(parents=True, exist_ok=True)`.
- [ ] Commit and review.

---

## Week 3 — More intel, full rules, output formats

### Task 12: AbuseIPDB

- [ ] **Tests** (monkeypatch, plus a fixture `fixtures/api/abuseipdb_bad.json`): request goes to `GET https://api.abuseipdb.com/api/v2/check` with params `ipAddress`, `maxAgeInDays=90` and headers `Key`, `Accept: application/json`. `score == data.abuseConfidenceScore`. Non-IP IOC → `None`. Rule: `score >= 75` → +20.
- [ ] **Implement and wire** into `enrich_all` (skip when the key is missing). Commit and review.

### Task 13: URLScan (search by default, unlisted submit)

- [ ] **Tests** (fixtures `urlscan_search.json`, `urlscan_result.json`):
  - The default call is `GET https://urlscan.io/api/v1/search/?q=domain:<domain>` with header `API-Key`. It takes `results[0]["task"]["uuid"]`, fetches `/api/v1/result/<uuid>/`, and sets `score = 1 if verdicts.overall.malicious else 0`.
  - No results and `submit=False` → `score is None`, summary `"no existing scan"`, **no POST made**.
  - `submit=True` → POST `https://urlscan.io/api/v1/scan/` with JSON body exactly `{"url": <url>, "visibility": "unlisted"}`. Then poll the result up to 6 times at 10s intervals (patch `sleep`).
  - Rule: malicious → +30.
- [ ] **Implement and wire.** `--submit` flows from the CLI into `enrich_all(submit=True)`. Commit and review.

Learn: why `unlisted`: a phishing URL often carries the victim's email or a session token in its query string.

### Task 14: Remaining rules + README weights table

- [ ] **Tests:**
  - `test_return_path_mismatch`: +10.
  - `test_lookalike`: `paypa1.com`, `rnicrosoft.com` and `xn--pypal-4ve.com` are flagged (+25). `paypal.com` and `example.com` are not. Brands: `BRANDS = {"paypal","microsoft","apple","amazon","google","docusign","dhl","netflix","office365","outlook"}`.
  - `test_incomplete_enrichment` (Review Focus 4): with no enrichments for some IOCs, or any `Enrichment.error`, `reasons` contains `"enrichment incomplete"` and the score is unchanged. `main([spoofed_replyto, "--offline"]) == 2` (60 + Return-Path 10 = 70), not 3. Update `test_exit_suspicious` to match, and add a fixture variant without Return-Path that still returns 1.
- [ ] **Implement lookalike:** take the registered domain's label, IDNA-decode `xn--` labels, normalize `0→o, 1→l, rn→m, vv→w`, then flag when `difflib.SequenceMatcher(None, label, brand).ratio() >= 0.8` and the original label ≠ brand.
- [ ] **README:** add the Weights table from this plan. It must match the code, so add a test that the README table's points equal the rule constants (optional but nice).
- [ ] Commit and review.

### Task 15: JSON + Markdown output

- [ ] **Tests:**
  - `test_json_shape`: `json.loads(render(..., "json"))` has top-level keys `verdict`, `email`, `iocs`, `enrichments`, `warnings`. Each IOC has `type`, `value`, `defanged`, and `value` is **defanged** too (the Global Constraint applies to all output).
  - `test_md`: output starts with `# Phishing triage:`, has a `| Type | IOC |` table, and contains no raw `http://`.
  - CLI: `--format json` output parses as JSON.
- [ ] **Implement:** use `dataclasses.asdict` with `json.dumps(default=str)` for datetimes. Commit and review.

### Task 16: Live smoke test

- [ ] `tests/test_live.py` with `@pytest.mark.live` and `skipif(not os.getenv("VT_API_KEY"))`: run `main` on `benign_plain` and assert the return code is 0. Run with `pytest -m live` (VM, NAT on).
- [ ] Add `addopts = "-m 'not live'"` in pyproject. Run plain `pytest`. **Expected:** all pass, with the live test deselected.
- [ ] Commit and review.

---

## Week 4 — Incident response case (no code)

### Task 17: Pick the case and analyse

- [ ] **Step 1:** On malware-traffic-analysis.net, choose an exercise whose description starts with malspam or an email, and preferably one that includes the `.eml`. Download it **inside the VM only** into `~/raw_samples/ir/`. Record the archive SHA256 in `ir/evidence.md`.
- [ ] **Step 2:** If an email is included, run `phishtriage` on it and save the JSON to `ir/triage.json`.
- [ ] **Step 3:** PCAP analysis. Log each finding with UTC time, packet number and filter in `ir/analysis-log.md`:
  - Victim host, user and MAC: `dhcp`, `nbns`, `kerberos.CNameString`, `ldap`.
  - Initial download: `http.request`, File → Export Objects → HTTP (hash only, don't open).
  - Domains and C2: `dns.flags.response == 0`, `tls.handshake.type == 1` (SNI), Statistics → Conversations sorted by bytes, regular-interval beacons.
  - Use `tshark -r x.pcap -Y '<filter>' -T fields -e frame.time_utc -e ...` to make timeline rows you can paste.
- [ ] **Step 4 (stretch):** find a memory image of the same family (CyberDefenders/MemLabs) and run Volatility 3 `windows.pslist`, `windows.pstree`, `windows.netscan`, `windows.malfind`. Note any processes/IPs that match the PCAP.
- [ ] **Done when:** the analysis log has the full chain from email to C2, with a timestamp for every step. Ask: "review IR analysis".

### Task 18: Write the IR report

**File:** `ir/IR-report.md`

- [ ] Sections in this order: Executive summary (≤150 words, non-technical) · Incident details (ID, severity, dates, analyst) · Timeline (UTC table) · IOCs (defanged table: type / value / context / source) · Scope (hosts, users, data) · Root cause · Containment · Eradication · Recovery · Lessons learned (≥3, each with an owner-style action) · MITRE ATT&CK mapping (technique ID + evidence, e.g. T1566.001 Spearphishing Attachment) · Appendix: tool output and filters.
- [ ] Add a note mapping the phases to NIST SP 800-61 Rev 2 (Preparation / Detection & Analysis / Containment-Eradication-Recovery / Post-Incident) and one line on Rev 3's CSF 2.0 alignment.
- [ ] **Done when:** someone who never saw the PCAP can understand what happened and what to do. Ask: "review IR report" (Claude reviews it like a SOC lead would).

---

## Week 5 — Ship

### Task 19: README, write-up, final checks

- [ ] `README.md`: one-paragraph pitch, demo GIF (record with `asciinema` + `agg`, or a screen capture), install, usage for each `--format`, sample output (from fixtures only), weights table, safety notes (GET-only VT, unlisted URLScan, no disk writes), limitations, link to the IR report.
- [ ] `docs/WRITEUP.md` "Automating phishing triage for a SOC": the problem, the design choices (and why), what the auth headers taught you, one triage walkthrough, limits and next steps (SOAR integration, mailbox polling).
- [ ] Final verification, each with its expected result:
  - `pytest` → all pass, offline, no keys set (`env -u VT_API_KEY -u ABUSEIPDB_API_KEY -u URLSCAN_API_KEY pytest`).
  - `git grep -nE "(x-apikey|API-Key|Key)\s*[:=]\s*['\"][A-Za-z0-9]{20,}"` → no output.
  - `git log -p | grep -c "$VT_API_KEY"` → `0`.
  - `phishtriage fixtures/eml/benign_plain.eml --offline; echo $?` → `0`. `forwarded.eml --offline` → `1` or `2`.
- [ ] Push to a public GitHub repo. Ask: "final review" (whole-repo review before you share the link).
