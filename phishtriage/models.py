from dataclasses import dataclass, field
from typing import Literal
from datetime import datetime


@dataclass(frozen=True)
class IOC:
    """
    This class acts like a label that is attached to a suspicious item.
    the label have two information, TYPE VALUE.
    EXAMPLE:
        1.
            TYPE: url
            VALUE: https://google.com
        2.
            TYPE: domain
            VALUE: google.com
        3.
            TYPE: ip
            VALUE: 1.0.0.0
        4.
            TYPE: SHA256
            VALUE: kasdjfkljaslkdfjlkasjdfl
     TYPE: URL, DOMAIN, IP, SHA256
     VALUE: The value corresponding to the type
     When DISPLAYING the value, the value is DEFANGED
     When STORING the value, the value is the ACTUAL value
    """

    type: Literal["url", "domain", "ip", "sha256"]
    value: str


@dataclass
class AuthResults:
    """
    The front desk checks a delivered parcel

    It run three checks and staples a result slip to it:
    EXAMPLE:
        1. SPF - Is the sending server's IP on the domain's published list of ALLOWED SENDERS
        2. DKIM - Is there a VALID cryptographic signature from the domain, meaning the content was NOT ALTERED
        3. DMARC - Ties SPF and DKIM to the visible From address and says what to do on failure

    The receiving mail server already ran these checks and wrote the results into a header:
        Authentication-Results: mx.example.net;
            spf=fail
            dkim=none
            dmarc=fail

    Read the slip and do not redo the checks.
    Fill into
        AuthResults(spf="fail", dkim="none", dmarc="fail")
    Set the value to none if there is no header
    """

    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None


@dataclass
class Hop:
    """
    from_host = who hand it over (sender)
    by_host = who wrote it (receiver)
    ip = sender's IP address
    timestamp = when the handover happened, written by the receiver

    EXAMPLE:
                      (from)  (by) (timestamp)
        RECEIVED: from abc by def; Sat, 14 Nov 2026 10:05:00
        RECEIVED: from xyz by abc; Sat, 13 Nov 2026 09:00:00
    """

    from_host: str | None
    by_host: str | None
    ip: str | None
    timestamp: datetime | None


@dataclass
class Link:
    """
    Emails are often written in HTML.

    Example:
        <a href="http://198.51.100.7/login">https://www.paypal.com</a>
             └──────── href ─────────────┘   └──── text ──────────┘
    Users will only see the text, but when they click on it, they will be redirect to href.

    href: the truth
    text: the outside
    """

    href: str
    text: str


@dataclass
class Attachment:
    """
    filename: The name of file, sender can write anything as the filename
              sus filename:
                *.docs, *.iso, *.html, *.lnk
    content_type: The type of the content, sender can write this
                text/plain text/html
    size: file size
    sha256: alsdflskdfjljaskldfjlkajsfiuhrh2838
    """

    filename: str
    content_type: str
    size: int
    sha256: int


@dataclass
class ParsedEmail:
    """
    subject: The title line.

    The three addresses
    1. from_addr: From: header, which is what the user sees
    2. reply_to: Where the reply goes when the user click reply
    3. return_path: Bounce address.

    to: receipients, a email can go to multiple people
    date: the date the writer wrote the top of the letter
    message_id: A unique number that created by sending system

    auth: AuthResults
    hops: list[Hop]

    body_text: email message in plain text
    body_html: email message in html
    links: list[link]: every <a href> found in the HTML

    attachments: list[Attachment]
    inner: list["ParsedEmail"]
    warnings: list[str]
    """

    subject: str = ""
    from_addr: str = ""  # bare address, lowercase
    reply_to: str | None = None  # bare address, lowercase
    return_path: str | None = None  # bare address, lowercase
    to: list[str] = field(default_factory=list)
    date: datetime | None = None
    message_id: str | None = None
    auth: AuthResults = field(default_factory=AuthResults)
    hops: list[Hop] = field(default_factory=list)  # index 0 = top (newest)
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
    score: (
        int | None
    )  # VT: malicious engine count; AbuseIPDB: abuseConfidenceScore 0-100; URLScan: 1 if verdict malicious else 0
    summary: str  # one human line, e.g. "12/93 engines malicious"
    error: str | None = None  # set on failure; score is None then


@dataclass
class Verdict:
    label: Literal["benign", "suspicious", "malicious"]
    score: int
    reasons: list[str]
