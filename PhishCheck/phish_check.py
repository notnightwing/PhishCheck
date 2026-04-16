#!/usr/bin/env python3
"""
phish_check.py - Phishing email triage tool
Usage: phishcheck email.eml [--gsb-key YOUR_KEY]

Dependencies:
  pip install dnspython python-whois requests pypdf

Optional:
  Google Safe Browsing API key — https://developers.google.com/safe-browsing/v4/get-started
  Set via --gsb-key flag or GSB_API_KEY environment variable.
"""

import argparse
import email
import email.policy
import hashlib
import io
import ipaddress
import os
import re
import socket
import sys
import urllib.parse
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import decode_header, make_header

import dns.resolver
import requests
import whois

try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

# ── Terminal colors ────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.co.uk", "hotmail.com", "hotmail.co.uk",
    "outlook.com", "live.com", "icloud.com", "me.com", "mac.com",
    "aol.com", "protonmail.com", "proton.me", "tutanota.com",
    "zoho.com", "yandex.com", "mail.com", "gmx.com", "gmx.net",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "short.link", "rb.gy",
}

DANGEROUS_EXTS = {
    ".exe", ".bat", ".cmd", ".vbs", ".js", ".hta", ".ps1",
    ".scr", ".pif", ".com", ".lnk", ".jar", ".msi", ".reg",
}

URGENCY_PATTERNS = [
    (r'\b(urgent|immediately|right away|asap|action required)\b', "Urgency language"),
    (r'\b(verify|confirm|validate)\s+(your\s+)?(account|identity|password|login)\b', "Account verification request"),
    (r'\b(wire transfer|bank transfer|payment|invoice|gift card)\b', "Financial action request"),
    (r'\bpassword\s+(expire|expir|reset|change)\b', "Password expiry/reset language"),
    (r'\b(suspended|locked|disabled|terminated|deactivated)\b', "Account threat language"),
    (r'\bclick\s+(here|below|the link|this link)\b', "Click-here link prompt"),
    (r'\b(ceo|cfo|president|executive)\b.*\b(request|ask|need|want)\b', "Executive impersonation pattern"),
]

# ── Helpers ────────────────────────────────────────────────────────────────────

def banner(title):
    width = 70
    print(f"\n{BOLD}{CYAN}{'─' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * width}{RESET}")

def section(title):
    print(f"\n{BOLD}  {title}{RESET}")
    print(f"  {'─' * 50}")

def flag(level, label, detail=""):
    icons = {"PASS": f"{GREEN}✓ PASS {RESET}", "WARN": f"{YELLOW}⚠ WARN {RESET}",
             "FAIL": f"{RED}✗ FAIL {RESET}", "INFO": f"{CYAN}ℹ INFO {RESET}"}
    icon = icons.get(level, "  ")
    detail_str = f"  {DIM}{detail}{RESET}" if detail else ""
    print(f"    {icon} {label}{detail_str}")

def decode_str(value):
    if value is None:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value

def extract_address(header_val):
    if not header_val:
        return "", ""
    m = re.search(r'<([^>]+)>', header_val)
    addr = m.group(1).strip().lower() if m else header_val.strip().lower()
    name = re.sub(r'<[^>]+>', '', header_val).strip().strip('"').strip("'")
    return name, addr

def domain_of(email_addr):
    parts = email_addr.split("@")
    return parts[-1].lower() if len(parts) == 2 else ""

def registered_domain(fqdn):
    """Extract eTLD+1 (e.g. info.knowbe4.com -> knowbe4.com)."""
    parts = fqdn.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn

def extract_urls(text):
    pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
    raw = re.findall(pattern, text or "")
    cleaned = []
    for u in raw:
        u = u.rstrip(".,;!?)")
        if not u.startswith("http"):
            u = "http://" + u
        cleaned.append(u)
    return list(dict.fromkeys(cleaned))

def get_body_text(msg):
    text = ""
    for part in msg.walk():
        ct = part.get_content_type()
        if ct in ("text/plain", "text/html"):
            try:
                charset = part.get_content_charset() or "utf-8"
                payload = part.get_payload(decode=True)
                if payload:
                    text += payload.decode(charset, errors="replace")
            except Exception:
                pass
    return text

def get_attachments(msg):
    attachments = []
    for part in msg.walk():
        disp = part.get_content_disposition() or ""
        if "attachment" in disp or (part.get_filename() and part.get_content_type() != "text/plain"):
            fname = part.get_filename() or "unknown"
            payload = part.get_payload(decode=True)
            if payload:
                md5 = hashlib.md5(payload).hexdigest()
                sha256 = hashlib.sha256(payload).hexdigest()
                encrypted = False
                ext = os.path.splitext(fname)[-1].lower()
                if ext == ".pdf" and PYPDF_AVAILABLE:
                    try:
                        reader = PdfReader(io.BytesIO(payload))
                        encrypted = reader.is_encrypted
                    except Exception:
                        pass
                attachments.append({
                    "name": fname,
                    "md5": md5,
                    "sha256": sha256,
                    "size": len(payload),
                    "encrypted": encrypted,
                })
    return attachments

def detect_body_password(text):
    """Return candidate passwords found in body text."""
    patterns = [
        r'password\s*[:\-is]+\s*(\S+)',
        r'passcode\s*[:\-is]+\s*(\S+)',
        r'open\s+with\s*[:\-]+\s*(\S+)',
        r'use\s+(?:the\s+)?password\s*[:\-]+\s*(\S+)',
        r'the\s+password\s+is\s+(\S+)',
        r'pwd\s*[:\-]+\s*(\S+)',
    ]
    found = []
    for pat in patterns:
        matches = re.findall(pat, text, re.IGNORECASE)
        found.extend(matches)
    return list(dict.fromkeys(found))

def parse_auth_results(header_val):
    results = {}
    if not header_val:
        return results
    for proto in ("spf", "dkim", "dmarc"):
        m = re.search(rf'\b{proto}=(\S+)', header_val, re.IGNORECASE)
        if m:
            results[proto.upper()] = m.group(1).lower().rstrip(";")
    return results

def parse_received_chain(msg):
    received = msg.get_all("Received") or []
    ips = []
    for r in received:
        matches = re.findall(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', r)
        matches += re.findall(r'from\s+\S+\s+\((\d{1,3}(?:\.\d{1,3}){3})\)', r)
        for ip in matches:
            try:
                obj = ipaddress.ip_address(ip)
                if not obj.is_private and not obj.is_loopback:
                    ips.append(ip)
            except ValueError:
                pass
    return ips

# ── DNS / WHOIS ────────────────────────────────────────────────────────────────

def get_spf_record(domain):
    try:
        txt = dns.resolver.resolve(domain, "TXT")
        for r in txt:
            val = r.to_text().strip('"')
            if val.startswith("v=spf1"):
                return val
    except Exception:
        pass
    return None

def get_dmarc_record(domain):
    try:
        txt = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for r in txt:
            val = r.to_text().strip('"')
            if "v=DMARC1" in val:
                return val
    except Exception:
        pass
    return None

def check_domain_age(domain):
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - created).days
            return age, created.strftime("%Y-%m-%d")
    except Exception:
        pass
    return None, None

def ip_to_rdns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# ── Google Safe Browsing ───────────────────────────────────────────────────────

def check_safe_browsing(urls, api_key):
    if not urls or not api_key:
        return {}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phish_check", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls],
        },
    }
    try:
        resp = requests.post(endpoint, json=payload, timeout=10)
        data = resp.json()
        return {m.get("threat", {}).get("url", ""): m.get("threatType", "UNKNOWN")
                for m in data.get("matches", [])}
    except Exception as e:
        print(f"    {DIM}GSB API error: {e}{RESET}")
        return {}

# ── Main analysis ──────────────────────────────────────────────────────────────

def analyze(eml_path, gsb_key=None):
    with open(eml_path, "rb") as f:
        raw = f.read()

    msg = message_from_bytes(raw, policy=email.policy.compat32)

    banner(f"PHISH CHECK  ·  {os.path.basename(eml_path)}")
    print(f"  {DIM}Analyzed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")

    findings = {"FAIL": [], "WARN": [], "PASS": [], "INFO": []}

    def record(level, label, detail=""):
        findings[level].append(label)
        flag(level, label, detail)

    # ── 1. Sender identity ─────────────────────────────────────────────────────
    section("1. Sender Identity")

    from_raw = decode_str(msg.get("From", ""))
    from_name, from_addr = extract_address(from_raw)
    from_domain = domain_of(from_addr)
    reply_to_raw = decode_str(msg.get("Reply-To", ""))
    _, reply_to_addr = extract_address(reply_to_raw)
    reply_to_domain = domain_of(reply_to_addr)
    subject = decode_str(msg.get("Subject", "(no subject)"))
    date_hdr = msg.get("Date", "")

    print(f"    {DIM}From      :{RESET} {from_name} <{from_addr}>")
    print(f"    {DIM}Subject   :{RESET} {subject}")
    print(f"    {DIM}Date      :{RESET} {date_hdr}")
    if reply_to_addr:
        print(f"    {DIM}Reply-To  :{RESET} {reply_to_addr}")

    if from_name and "@" in from_name:
        name_domain = domain_of(from_name.split()[-1])
        if name_domain and name_domain != from_domain:
            record("FAIL", "Display name contains a different email address than From",
                   f"Name shows '{from_name}', actual sender domain is '{from_domain}'")
        else:
            record("PASS", "Display name email matches From domain")
    else:
        record("INFO", f"Display name: '{from_name}'  |  Address domain: {from_domain}")

    if from_domain in FREEMAIL_DOMAINS:
        record("WARN", f"Sending domain is a freemail provider ({from_domain})",
               "Auth pass is not a trust signal for freemail — evaluate content and context")
    else:
        record("PASS", f"Sending domain is not a freemail provider ({from_domain})")

    if reply_to_addr and reply_to_domain and reply_to_domain != from_domain:
        record("FAIL", "Reply-To domain differs from From domain",
               f"Replies go to '{reply_to_domain}', not '{from_domain}'")
    elif reply_to_addr:
        record("PASS", "Reply-To matches From domain")

    # ── 2. Authentication ──────────────────────────────────────────────────────
    section("2. Email Authentication (SPF / DKIM / DMARC)")

    all_auth = msg.get_all("Authentication-Results") or []
    auth_header = " ".join(all_auth)
    auth = parse_auth_results(auth_header)

    if not auth:
        record("WARN", "No Authentication-Results header found",
               "May have been stripped in transit — check raw headers manually")
    else:
        for proto in ("SPF", "DKIM", "DMARC"):
            result = auth.get(proto)
            if result is None:
                record("WARN", f"{proto}: not evaluated")
            elif result == "pass":
                record("PASS", f"{proto}: pass")
            elif result in ("fail", "hardfail"):
                record("FAIL", f"{proto}: {result}", "Sending server not authorized by domain owner")
            else:
                record("WARN", f"{proto}: {result}")

    # ── 3. DNS ─────────────────────────────────────────────────────────────────
    section(f"3. DNS Records for Sending Domain  ({from_domain})")

    spf = get_spf_record(from_domain)
    if spf:
        record("INFO", "SPF record found", spf[:80] + ("…" if len(spf) > 80 else ""))
    else:
        record("WARN", f"No SPF record found for {from_domain}")

    dmarc = get_dmarc_record(from_domain)
    if dmarc:
        if "p=reject" in dmarc:
            record("PASS", "DMARC policy: reject", dmarc[:80])
        elif "p=quarantine" in dmarc:
            record("WARN", "DMARC policy: quarantine (not reject)", dmarc[:80])
        elif "p=none" in dmarc:
            record("WARN", "DMARC policy: none (monitoring only — no enforcement)")
        else:
            record("INFO", "DMARC record found", dmarc[:80])
    else:
        record("FAIL", f"No DMARC record for {from_domain}",
               "Domain has no protection against spoofing")

    # ── 4. Domain age ──────────────────────────────────────────────────────────
    section(f"4. Domain Age  ({from_domain})")

    age_days, created = check_domain_age(from_domain)
    if age_days is None:
        record("WARN", f"Could not determine registration date for {from_domain}")
    elif age_days < 30:
        record("FAIL", f"Domain registered only {age_days} days ago ({created})",
               "Newly registered domains are a strong phishing indicator")
    elif age_days < 180:
        record("WARN", f"Domain registered {age_days} days ago ({created})",
               "Less than 6 months old — treat with caution")
    else:
        record("PASS", f"Domain registered {created}",
               f"{age_days} days (~{age_days // 365} years) old")

    body_text = get_body_text(msg)
    urls = extract_urls(body_text)
    link_reg_domains = list(dict.fromkeys(
        registered_domain(urllib.parse.urlparse(u).netloc.lower().split(":")[0])
        for u in urls if urllib.parse.urlparse(u).netloc
    ))
    extra_domains = [d for d in link_reg_domains
                     if d != registered_domain(from_domain) and d not in FREEMAIL_DOMAINS][:5]

    if extra_domains:
        print(f"\n    {DIM}Checking age of linked domains…{RESET}")
        for d in extra_domains:
            age2, created2 = check_domain_age(d)
            if age2 is None:
                record("WARN", f"Link domain age unknown: {d}")
            elif age2 < 30:
                record("FAIL", f"Link domain registered {age2} days ago: {d} ({created2})")
            elif age2 < 180:
                record("WARN", f"Link domain {d} is only {age2} days old ({created2})")
            else:
                record("PASS", f"Link domain {d} established ({created2}, {age2}d)")

    # ── 5. Received chain ──────────────────────────────────────────────────────
    section("5. Received Chain / Originating IP")

    ips = parse_received_chain(msg)
    if not ips:
        record("WARN", "Could not extract public IPs from Received headers")
    else:
        originating_ip = ips[-1]
        print(f"    {DIM}Originating IP:{RESET} {originating_ip}")
        rdns = ip_to_rdns(originating_ip)
        if rdns:
            print(f"    {DIM}Reverse DNS   :{RESET} {rdns}")
            if from_domain and from_domain in rdns:
                record("PASS", "Originating IP reverse DNS matches sending domain")
            elif any(p in rdns for p in ["google", "outlook", "microsoft", "yahoo",
                                          "amazon", "sendgrid", "mailchimp", "postmark", "sparkpost"]):
                if from_domain in FREEMAIL_DOMAINS:
                    record("PASS", f"Freemail sender routes through expected provider ({rdns})")
                else:
                    record("WARN", f"Originating IP belongs to third-party mail provider ({rdns})",
                           "Verify this vendor uses this provider for outbound email")
            else:
                record("WARN", f"Originating IP rDNS: {rdns}",
                       "Manually verify this is expected infrastructure for the sending domain")
        else:
            record("WARN", f"No reverse DNS for {originating_ip}",
                   "Legitimate mail servers almost always have rDNS configured")

    # ── 6. URLs ────────────────────────────────────────────────────────────────
    section("6. URLs Found in Body")

    if not urls:
        record("INFO", "No URLs found in email body")
    else:
        print(f"    {DIM}Found {len(urls)} URL(s){RESET}")
        seen_domains = set()
        for u in urls[:10]:
            parsed = urllib.parse.urlparse(u)
            netloc = parsed.netloc.lower().split(":")[0]
            reg = registered_domain(netloc)
            if netloc in SHORTENERS:
                record("FAIL", f"URL shortener detected: {netloc}",
                       f"{u[:80]} — destination hidden, treat as suspicious")
            elif reg == registered_domain(from_domain):
                if reg not in seen_domains:
                    record("PASS", f"Link domain matches sender: {netloc}")
            else:
                if reg not in seen_domains:
                    record("WARN", f"Link domain differs from sender: {netloc}",
                           f"Sender domain: {from_domain}")
            seen_domains.add(reg)

        if len(urls) > 10:
            record("INFO", f"{len(urls) - 10} additional URLs not shown")

        if gsb_key:
            print(f"\n    {DIM}Checking URLs against Google Safe Browsing…{RESET}")
            flagged = check_safe_browsing(urls, gsb_key)
            if flagged:
                for url, threat in flagged.items():
                    record("FAIL", f"GSB hit: {threat}", url[:80])
            else:
                record("PASS", f"No URLs flagged by Google Safe Browsing ({len(urls)} checked)")
        else:
            record("INFO", "Google Safe Browsing check skipped (no API key)",
                   "Pass --gsb-key YOUR_KEY or set GSB_API_KEY env var to enable")

    # ── 7. Attachments ─────────────────────────────────────────────────────────
    section("7. Attachments")

    attachments = get_attachments(msg)
    body_passwords = detect_body_password(body_text)

    if not attachments:
        record("INFO", "No attachments found")
    else:
        has_encrypted_pdf = any(a.get("encrypted") for a in attachments)
        has_encrypted_archive = any(
            os.path.splitext(a["name"])[-1].lower() in {".zip", ".rar", ".7z"} for a in attachments
        )

        if body_passwords and (has_encrypted_pdf or has_encrypted_archive):
            pw_display = ", ".join(f'"{p}"' for p in body_passwords[:3])
            record("FAIL",
                   "Password provided in email body for an encrypted attachment",
                   f"Candidate password(s): {pw_display} — this is a scanner evasion technique. "
                   "Do not open in any application including browser PDF viewers. "
                   "Check hash on VirusTotal first, then submit to Any.run or Hybrid Analysis if no VT hit.")
        elif body_passwords:
            record("WARN", "Password-like string found in body but no encrypted attachment detected",
                   f"Candidate: {body_passwords[0]}")

        for a in attachments:
            ext = os.path.splitext(a["name"])[-1].lower()
            size_kb = a["size"] // 1024
            print(f"    {DIM}File    :{RESET} {a['name']} ({size_kb} KB)")
            print(f"    {DIM}MD5     :{RESET} {a['md5']}")
            print(f"    {DIM}SHA-256 :{RESET} {a['sha256']}")

            if ext == ".pdf":
                if a.get("encrypted"):
                    if body_passwords:
                        record("FAIL", f"Encrypted PDF with password supplied in body: {a['name']}",
                               "High-confidence evasion pattern — do not open in any application "
                               "including browser PDF viewers. "
                               f"VT: https://www.virustotal.com/gui/file/{a['sha256']} | "
                               "Sandbox: https://any.run or https://hybrid-analysis.com")
                    else:
                        record("WARN", f"Encrypted/password-protected PDF: {a['name']}",
                               "Cannot be scanned without password — submit hash to VirusTotal. "
                               "Do not open until cleared.")
                else:
                    record("INFO", f"PDF attachment: {a['name']}",
                           f"Submit to VirusTotal if suspicious: "
                           f"https://www.virustotal.com/gui/file/{a['sha256']}")
            elif ext in DANGEROUS_EXTS:
                record("FAIL", f"Dangerous attachment type: {ext}",
                       "Do not open — submit hash to VirusTotal")
            elif ext in {".zip", ".rar", ".7z", ".gz", ".tar"}:
                if body_passwords:
                    record("FAIL", f"Compressed archive with password supplied in body: {a['name']}",
                           "Scanner evasion pattern — do not open. Submit hash to VirusTotal first.")
                else:
                    record("WARN", f"Compressed archive: {a['name']}",
                           "Password-protected archives are commonly used to evade scanning")
            elif ext in {".docm", ".xlsm", ".pptm", ".doc", ".xls"}:
                record("WARN", f"Office file with potential macro support: {a['name']}",
                       f"Submit hash to VirusTotal: https://www.virustotal.com/gui/file/{a['sha256']}")
            else:
                record("INFO", f"Attachment: {a['name']} — submit hash to VirusTotal if suspicious")

    # ── 8. Content signals ─────────────────────────────────────────────────────
    section("8. Content Signals")

    body_lower = body_text.lower()
    signals_found = [label for pat, label in URGENCY_PATTERNS
                     if re.search(pat, body_lower, re.IGNORECASE)]

    if not body_text:
        record("WARN", "Could not extract body text (HTML-only or encoded)")
    elif not signals_found:
        record("PASS", "No common social engineering patterns detected in body text")
    else:
        for s in signals_found:
            record("WARN", f"Social engineering signal: {s}")

    # ── Summary ────────────────────────────────────────────────────────────────
    banner("SUMMARY")

    fail_count = len(findings["FAIL"])
    warn_count = len(findings["WARN"])
    pass_count = len(findings["PASS"])

    if fail_count > 0:
        verdict = f"{RED}{BOLD}HIGH RISK — Treat as phishing. Escalate.{RESET}"
    elif warn_count >= 3:
        verdict = f"{YELLOW}{BOLD}SUSPICIOUS — Multiple warning signals. Investigate further.{RESET}"
    elif warn_count >= 1:
        verdict = f"{YELLOW}{BOLD}REVIEW — Some signals present. Use judgment.{RESET}"
    else:
        verdict = f"{GREEN}{BOLD}LIKELY BENIGN — No significant indicators found.{RESET}"

    print(f"\n  Verdict: {verdict}")
    print(f"\n  {GREEN}✓ PASS:{RESET} {pass_count}   {YELLOW}⚠ WARN:{RESET} {warn_count}   {RED}✗ FAIL:{RESET} {fail_count}")

    if fail_count > 0:
        print(f"\n  {RED}Failures:{RESET}")
        for f in findings["FAIL"]:
            print(f"    • {f}")

    print(f"\n  {DIM}Next steps if escalating:{RESET}")
    print(f"  {DIM}  1. Google Admin Email Log Search → pull from all inboxes{RESET}")
    print(f"  {DIM}  2. Block sender in Gmail Blocked Senders{RESET}")
    print(f"  {DIM}  3. Submit attachment hashes/URLs to VirusTotal{RESET}")
    print(f"  {DIM}  4. If encrypted attachment: submit to Any.run (interactive) or Hybrid Analysis{RESET}")
    print(f"  {DIM}  5. Open a Jira incident ticket and follow the phishing playbook{RESET}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Phishing email triage tool — analyze a raw .eml file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  phishcheck suspicious.eml
  phishcheck suspicious.eml --gsb-key YOUR_GOOGLE_SAFE_BROWSING_KEY
  GSB_API_KEY=yourkey phishcheck suspicious.eml

How to get the .eml from Gmail:
  Open email → three-dot menu (⋮) → Download message
        """
    )
    parser.add_argument("eml_file", help="Path to the .eml file to analyze")
    parser.add_argument("--gsb-key", default=os.environ.get("GSB_API_KEY"),
                        help="Google Safe Browsing API key (or set GSB_API_KEY env var)")
    args = parser.parse_args()

    if not os.path.isfile(args.eml_file):
        print(f"{RED}Error: file not found: {args.eml_file}{RESET}")
        sys.exit(1)

    analyze(args.eml_file, gsb_key=args.gsb_key)


if __name__ == "__main__":
    main()
