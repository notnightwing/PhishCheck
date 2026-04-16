"""
phish_check_ui.py - Streamlit GUI for phishing email triage

Run:
  streamlit run phish_check_ui.py

Or add to .zshrc:
  alias phishui="~/scripts/PhishCheck/venv/bin/python -m streamlit run ~/scripts/PhishCheck/phish_check_ui.py"

Dependencies:
  pip install streamlit dnspython python-whois requests pypdf
"""

import email
import email.policy
import hashlib
import io
import ipaddress
import os
import re
import socket
import urllib.parse
from datetime import datetime, timezone
from email import message_from_bytes
from email.header import decode_header, make_header

import dns.resolver
import requests
import streamlit as st
import whois

try:
    from pypdf import PdfReader
    PYPDF_AVAILABLE = True
except ImportError:
    PYPDF_AVAILABLE = False

# ── Constants ──────────────────────────────────────────────────────────────────

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
        found.extend(re.findall(pat, text, re.IGNORECASE))
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

def check_safe_browsing(urls, api_key):
    if not urls or not api_key:
        return {}
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    payload = {
        "client": {"clientId": "phish_check_ui", "clientVersion": "1.0"},
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
    except Exception:
        return {}

# ── Core analysis ──────────────────────────────────────────────────────────────

def analyze_eml(raw_bytes, gsb_key=None):
    msg = message_from_bytes(raw_bytes, policy=email.policy.compat32)
    findings = []

    def add(section, level, label, detail=""):
        findings.append({"section": section, "level": level, "label": label, "detail": detail})

    # Identity
    sec = "Sender Identity"
    from_raw = decode_str(msg.get("From", ""))
    from_name, from_addr = extract_address(from_raw)
    from_domain = domain_of(from_addr)
    reply_to_raw = decode_str(msg.get("Reply-To", ""))
    _, reply_to_addr = extract_address(reply_to_raw)
    reply_to_domain = domain_of(reply_to_addr)
    subject = decode_str(msg.get("Subject", "(no subject)"))
    date_hdr = msg.get("Date", "")

    if from_name and "@" in from_name:
        name_domain = domain_of(from_name.split()[-1])
        if name_domain and name_domain != from_domain:
            add(sec, "FAIL", "Display name contains a different email address than From",
                f"Name shows '{from_name}', actual sender domain is '{from_domain}'")
        else:
            add(sec, "PASS", "Display name email matches From domain")
    else:
        add(sec, "INFO", f"Display name: '{from_name}'", f"Actual address: {from_addr}")

    if from_domain in FREEMAIL_DOMAINS:
        add(sec, "WARN", f"Sending domain is a freemail provider ({from_domain})",
            "Auth pass is not a trust signal for freemail — evaluate content and context")
    else:
        add(sec, "PASS", f"Sending domain is not a freemail provider ({from_domain})")

    if reply_to_addr and reply_to_domain and reply_to_domain != from_domain:
        add(sec, "FAIL", "Reply-To domain differs from From domain",
            f"Replies go to '{reply_to_domain}', not '{from_domain}'")
    elif reply_to_addr:
        add(sec, "PASS", "Reply-To matches From domain")

    # Auth
    sec = "Email Authentication"
    all_auth = msg.get_all("Authentication-Results") or []
    auth = parse_auth_results(" ".join(all_auth))

    if not auth:
        add(sec, "WARN", "No Authentication-Results header found",
            "May have been stripped in transit — check raw headers manually")
    else:
        for proto in ("SPF", "DKIM", "DMARC"):
            result = auth.get(proto)
            if result is None:
                add(sec, "WARN", f"{proto}: not evaluated")
            elif result == "pass":
                add(sec, "PASS", f"{proto}: pass")
            elif result in ("fail", "hardfail"):
                add(sec, "FAIL", f"{proto}: {result}", "Sending server not authorized by domain owner")
            else:
                add(sec, "WARN", f"{proto}: {result}")

    # DNS
    sec = "DNS Records"
    spf = get_spf_record(from_domain)
    if spf:
        add(sec, "INFO", "SPF record found", spf[:120] + ("…" if len(spf) > 120 else ""))
    else:
        add(sec, "WARN", f"No SPF record found for {from_domain}")

    dmarc = get_dmarc_record(from_domain)
    if dmarc:
        if "p=reject" in dmarc:
            add(sec, "PASS", "DMARC policy: reject", dmarc[:120])
        elif "p=quarantine" in dmarc:
            add(sec, "WARN", "DMARC policy: quarantine (not reject)", dmarc[:120])
        elif "p=none" in dmarc:
            add(sec, "WARN", "DMARC policy: none (monitoring only — no enforcement)")
        else:
            add(sec, "INFO", "DMARC record found", dmarc[:120])
    else:
        add(sec, "FAIL", f"No DMARC record for {from_domain}",
            "Domain has no protection against spoofing")

    # Domain age
    sec = "Domain Age"
    age_days, created = check_domain_age(from_domain)
    if age_days is None:
        add(sec, "WARN", f"Could not determine registration date for {from_domain}")
    elif age_days < 30:
        add(sec, "FAIL", f"Sending domain registered only {age_days} days ago ({created})",
            "Newly registered domains are a strong phishing indicator")
    elif age_days < 180:
        add(sec, "WARN", f"Sending domain registered {age_days} days ago ({created})",
            "Less than 6 months old — treat with caution")
    else:
        add(sec, "PASS", f"Sending domain {from_domain} registered {created}",
            f"{age_days} days (~{age_days // 365} years) old")

    body_text = get_body_text(msg)
    urls = extract_urls(body_text)
    link_reg_domains = list(dict.fromkeys(
        registered_domain(urllib.parse.urlparse(u).netloc.lower().split(":")[0])
        for u in urls if urllib.parse.urlparse(u).netloc
    ))
    extra_domains = [d for d in link_reg_domains
                     if d != registered_domain(from_domain) and d not in FREEMAIL_DOMAINS][:5]

    for d in extra_domains:
        age2, created2 = check_domain_age(d)
        if age2 is None:
            add(sec, "WARN", f"Link domain age unknown: {d}")
        elif age2 < 30:
            add(sec, "FAIL", f"Link domain registered {age2} days ago: {d} ({created2})")
        elif age2 < 180:
            add(sec, "WARN", f"Link domain {d} is only {age2} days old ({created2})")
        else:
            add(sec, "PASS", f"Link domain {d} established ({created2}, {age2}d)")

    # Received chain
    sec = "Received Chain"
    ips = parse_received_chain(msg)
    originating_ip = None
    rdns = None
    if not ips:
        add(sec, "WARN", "Could not extract public IPs from Received headers")
    else:
        originating_ip = ips[-1]
        rdns = ip_to_rdns(originating_ip)
        if rdns:
            if from_domain and from_domain in rdns:
                add(sec, "PASS", "Originating IP rDNS matches sending domain",
                    f"{originating_ip} → {rdns}")
            elif any(p in rdns for p in ["google", "outlook", "microsoft", "yahoo",
                                          "amazon", "sendgrid", "mailchimp", "postmark", "sparkpost"]):
                if from_domain in FREEMAIL_DOMAINS:
                    add(sec, "PASS", "Freemail sender routes through expected provider",
                        f"{originating_ip} → {rdns}")
                else:
                    add(sec, "WARN", "Originating IP belongs to third-party mail provider",
                        f"{originating_ip} → {rdns} — verify this vendor uses this provider")
            else:
                add(sec, "WARN", f"Originating IP rDNS: {rdns}",
                    f"{originating_ip} — manually verify this is expected for {from_domain}")
        else:
            add(sec, "WARN", f"No reverse DNS for originating IP {originating_ip}",
                "Legitimate mail servers almost always have rDNS configured")

    # URLs
    sec = "URLs"
    if not urls:
        add(sec, "INFO", "No URLs found in email body")
    else:
        seen_domains = set()
        for u in urls:
            parsed = urllib.parse.urlparse(u)
            netloc = parsed.netloc.lower().split(":")[0]
            reg = registered_domain(netloc)
            if netloc in SHORTENERS:
                add(sec, "FAIL", f"URL shortener detected: {netloc}",
                    f"{u[:100]} — destination hidden, treat as suspicious")
            elif reg == registered_domain(from_domain):
                if reg not in seen_domains:
                    add(sec, "PASS", f"Link domain matches sender: {netloc}")
            else:
                if reg not in seen_domains:
                    add(sec, "WARN", f"Link domain differs from sender: {netloc}",
                        f"Sender domain: {from_domain}")
            seen_domains.add(reg)

        if gsb_key:
            flagged = check_safe_browsing(urls, gsb_key)
            if flagged:
                for url, threat in flagged.items():
                    add(sec, "FAIL", f"Google Safe Browsing: {threat}", url[:100])
            else:
                add(sec, "PASS", f"No URLs flagged by Google Safe Browsing ({len(urls)} checked)")
        else:
            add(sec, "INFO", "Google Safe Browsing check skipped — no API key configured")

    # Attachments
    sec = "Attachments"
    attachments = get_attachments(msg)
    body_passwords = detect_body_password(body_text)

    if not attachments:
        add(sec, "INFO", "No attachments found")
    else:
        has_encrypted_pdf = any(a.get("encrypted") for a in attachments)
        has_encrypted_archive = any(
            os.path.splitext(a["name"])[-1].lower() in {".zip", ".rar", ".7z"} for a in attachments
        )

        if body_passwords and (has_encrypted_pdf or has_encrypted_archive):
            pw_display = ", ".join(f'"{p}"' for p in body_passwords[:3])
            add(sec, "FAIL",
                "Password provided in email body for an encrypted attachment",
                f"Candidate password(s): {pw_display} — scanner evasion technique. "
                "Do not open in any application including browser PDF viewers. "
                "Check hash on VirusTotal first, then submit to Any.run or Hybrid Analysis.")
        elif body_passwords:
            add(sec, "WARN", "Password-like string found in body but no encrypted attachment detected",
                f"Candidate: {body_passwords[0]}")

        for a in attachments:
            ext = os.path.splitext(a["name"])[-1].lower()
            if ext == ".pdf":
                if a.get("encrypted"):
                    if body_passwords:
                        add(sec, "FAIL", f"Encrypted PDF with password supplied in body: {a['name']}",
                            f"SHA-256: {a['sha256']} — do not open in any application including "
                            "browser PDF viewers. Submit to VirusTotal, then Any.run (interactive mode).")
                    else:
                        add(sec, "WARN", f"Encrypted/password-protected PDF: {a['name']}",
                            f"SHA-256: {a['sha256']} — cannot be scanned without password. "
                            "Do not open until hash is cleared on VirusTotal.")
                else:
                    add(sec, "INFO", f"PDF attachment: {a['name']} ({a['size'] // 1024} KB)",
                        f"SHA-256: {a['sha256']}")
            elif ext in DANGEROUS_EXTS:
                add(sec, "FAIL", f"Dangerous attachment: {a['name']}",
                    f"SHA-256: {a['sha256']} — do not open, submit to VirusTotal")
            elif ext in {".zip", ".rar", ".7z", ".gz", ".tar"}:
                if body_passwords:
                    add(sec, "FAIL", f"Compressed archive with password supplied in body: {a['name']}",
                        f"SHA-256: {a['sha256']} — scanner evasion pattern. Do not open.")
                else:
                    add(sec, "WARN", f"Compressed archive: {a['name']}",
                        f"SHA-256: {a['sha256']} — password-protected archives evade scanning")
            elif ext in {".docm", ".xlsm", ".pptm", ".doc", ".xls"}:
                add(sec, "WARN", f"Office file (potential macro): {a['name']}",
                    f"SHA-256: {a['sha256']} — submit to VirusTotal")
            else:
                add(sec, "INFO", f"Attachment: {a['name']} ({a['size'] // 1024} KB)",
                    f"SHA-256: {a['sha256']}")

    # Content signals
    sec = "Content Signals"
    body_lower = body_text.lower()
    signals = [label for pat, label in URGENCY_PATTERNS
               if re.search(pat, body_lower, re.IGNORECASE)]
    if not body_text:
        add(sec, "WARN", "Could not extract body text (HTML-only or encoded)")
    elif not signals:
        add(sec, "PASS", "No social engineering patterns detected in body text")
    else:
        for s in signals:
            add(sec, "WARN", f"Social engineering signal: {s}")

    fail_count = sum(1 for f in findings if f["level"] == "FAIL")
    warn_count = sum(1 for f in findings if f["level"] == "WARN")
    pass_count = sum(1 for f in findings if f["level"] == "PASS")

    if fail_count > 0:
        verdict, verdict_detail = "HIGH RISK", "Treat as phishing. Escalate immediately."
    elif warn_count >= 3:
        verdict, verdict_detail = "SUSPICIOUS", "Multiple warning signals. Investigate further before clearing."
    elif warn_count >= 1:
        verdict, verdict_detail = "REVIEW", "Some signals present. Use judgment."
    else:
        verdict, verdict_detail = "LIKELY BENIGN", "No significant indicators found."

    return {
        "subject": subject,
        "from_name": from_name,
        "from_addr": from_addr,
        "from_domain": from_domain,
        "reply_to_addr": reply_to_addr,
        "date": date_hdr,
        "originating_ip": originating_ip,
        "rdns": rdns,
        "urls": urls,
        "attachments": attachments,
        "body_passwords": body_passwords,
        "findings": findings,
        "fail_count": fail_count,
        "warn_count": warn_count,
        "pass_count": pass_count,
        "verdict": verdict,
        "verdict_detail": verdict_detail,
    }

# ── UI rendering ───────────────────────────────────────────────────────────────

LEVEL_EMOJI = {"PASS": "✅", "WARN": "⚠️", "FAIL": "🚨", "INFO": "ℹ️"}
LEVEL_COLOR = {"PASS": "#1a7a4a", "WARN": "#b45309", "FAIL": "#b91c1c", "INFO": "#1e40af"}

VERDICT_STYLE = {
    "HIGH RISK":     ("#fef2f2", "#ef4444", "#7f1d1d"),
    "SUSPICIOUS":    ("#fff7ed", "#f97316", "#7c2d12"),
    "REVIEW":        ("#fefce8", "#eab308", "#713f12"),
    "LIKELY BENIGN": ("#f0fdf4", "#22c55e", "#14532d"),
}


def render_verdict(r):
    v = r["verdict"]
    bg, border, text = VERDICT_STYLE[v]
    st.markdown(f"""
    <div style="background:{bg};border-left:6px solid {border};border-radius:6px;
                padding:20px 24px;margin-bottom:16px;">
      <div style="font-size:22px;font-weight:700;color:{text};margin-bottom:4px;">{v}</div>
      <div style="font-size:15px;color:{text};opacity:0.85;">{r['verdict_detail']}</div>
    </div>
    """, unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    c1.metric("🚨 Failures", r["fail_count"])
    c2.metric("⚠️ Warnings", r["warn_count"])
    c3.metric("✅ Passes", r["pass_count"])


def render_finding(f):
    emoji = LEVEL_EMOJI[f["level"]]
    color = LEVEL_COLOR[f["level"]]
    detail_html = (f'<div style="font-size:12px;color:#6b7280;margin-top:2px;">{f["detail"]}</div>'
                   if f["detail"] else "")
    st.markdown(f"""
    <div style="display:flex;align-items:flex-start;gap:10px;
                padding:8px 12px;border-radius:5px;margin-bottom:4px;background:#f9fafb;">
      <span style="font-size:16px;line-height:1.4;">{emoji}</span>
      <div>
        <span style="font-size:13px;font-weight:500;color:{color};">{f['label']}</span>
        {detail_html}
      </div>
    </div>
    """, unsafe_allow_html=True)


def render_section(title, findings):
    section_findings = [f for f in findings if f["section"] == title]
    if not section_findings:
        return
    fail = sum(1 for f in section_findings if f["level"] == "FAIL")
    warn = sum(1 for f in section_findings if f["level"] == "WARN")
    icon = "🚨" if fail else ("⚠️" if warn else "✅")
    with st.expander(f"{icon}  {title}", expanded=(fail > 0 or warn > 0)):
        for f in section_findings:
            render_finding(f)


def render_metadata(r):
    st.markdown("#### Email Details")
    rows = [("Subject", r["subject"]),
            ("From", f'{r["from_name"]} &lt;{r["from_addr"]}&gt;' if r["from_name"] else r["from_addr"]),
            ("Date", r["date"])]
    if r["reply_to_addr"] and r["reply_to_addr"] != r["from_addr"]:
        rows.append(("Reply-To", r["reply_to_addr"]))
    if r["originating_ip"]:
        rdns_str = f" ({r['rdns']})" if r["rdns"] else ""
        rows.append(("Originating IP", f'{r["originating_ip"]}{rdns_str}'))

    html = '<table style="width:100%;border-collapse:collapse;font-size:13px;">'
    for label, val in rows:
        html += (f'<tr><td style="padding:6px 12px 6px 0;color:#6b7280;white-space:nowrap;'
                 f'vertical-align:top;width:110px;">{label}</td>'
                 f'<td style="padding:6px 0;color:#111827;word-break:break-all;">{val}</td></tr>')
    html += "</table>"
    st.markdown(html, unsafe_allow_html=True)


def render_attachments(r):
    if not r["attachments"]:
        return
    with st.expander(f"📎  Attachments ({len(r['attachments'])} found)", expanded=True):
        for a in r["attachments"]:
            ext = os.path.splitext(a["name"])[-1].lower()
            encrypted_badge = " 🔒 ENCRYPTED" if a.get("encrypted") else ""
            st.markdown(f"**{a['name']}**{encrypted_badge} ({a['size'] // 1024} KB)")
            if a.get("encrypted") and r.get("body_passwords"):
                st.warning("Password supplied in email body — high-confidence evasion pattern. "
                           "Do not open in any application including browser PDF viewers.")
            st.code(f"SHA-256: {a['sha256']}", language=None)
            vt_url = f"https://www.virustotal.com/gui/file/{a['sha256']}"
            col1, col2 = st.columns(2)
            col1.markdown(f"[Check on VirusTotal ↗]({vt_url})")
            if ext == ".pdf":
                col2.markdown("[Sandbox on Any.run ↗](https://any.run)")
            st.divider()


def render_urls(r):
    if not r["urls"]:
        return
    with st.expander(f"🔗  All URLs ({len(r['urls'])} found)", expanded=False):
        for u in r["urls"]:
            st.code(u, language=None)


def render_next_steps(r):
    if r["fail_count"] == 0 and r["warn_count"] < 3:
        return
    st.markdown("#### Next Steps")
    steps = [
        "Google Admin Console → Reports → Email Log Search: find and delete from all inboxes (search by sender or subject)",
        "Gmail Admin → Blocked Senders: block the specific sender address",
        "If credentials entered: Admin Console → User → Security → Sign out all sessions, reset password, force MFA re-enrollment, audit OAuth apps",
        "If attachment opened: CrowdStrike → isolate endpoint before rebooting",
        "If encrypted PDF/archive: submit hash to VirusTotal, then Any.run in interactive mode with the password",
        "Open a Jira incident ticket and follow the phishing playbook",
    ]
    for i, step in enumerate(steps, 1):
        st.markdown(f"{i}. {step}")


def main():
    st.set_page_config(
        page_title="PhishCheck",
        page_icon="🎣",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    st.markdown("""
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:4px;">
      <span style="font-size:32px;">🎣</span>
      <div>
        <div style="font-size:24px;font-weight:700;color:#111827;line-height:1.2;">PhishCheck</div>
        <div style="font-size:13px;color:#6b7280;">Phishing email triage — drop in a .eml file for an instant report</div>
      </div>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    with st.sidebar:
        st.markdown("### ⚙️ Settings")
        gsb_key = st.text_input(
            "Google Safe Browsing API Key",
            value=os.environ.get("GSB_API_KEY", ""),
            type="password",
            help="Optional. Enables URL reputation checks.",
        )
        st.caption("Get a key: [Google Cloud Console ↗](https://console.cloud.google.com/apis/library/safebrowsing.googleapis.com)")
        st.divider()
        st.markdown("**How to export a .eml from Gmail:**")
        st.markdown("Open email → ⋮ menu → *Download message*")
        st.divider()
        st.markdown("**Encrypted PDF?**")
        st.markdown("Submit to [Any.run ↗](https://any.run) in interactive mode with the password to see what it does.")

    uploaded = st.file_uploader(
        "Drop a .eml file here or click to browse",
        type=["eml"],
        label_visibility="collapsed",
    )

    if not uploaded:
        st.markdown("""
        <div style="border:2px dashed #d1d5db;border-radius:8px;padding:48px;text-align:center;
                    color:#9ca3af;margin-top:16px;">
          <div style="font-size:40px;margin-bottom:8px;">📧</div>
          <div style="font-size:15px;">Upload a <strong>.eml</strong> file to analyze it</div>
          <div style="font-size:12px;margin-top:6px;">In Gmail: open email → ⋮ → Download message</div>
        </div>
        """, unsafe_allow_html=True)
        return

    raw_bytes = uploaded.read()

    with st.spinner("Analyzing…"):
        try:
            results = analyze_eml(raw_bytes, gsb_key=gsb_key or None)
        except Exception as e:
            st.error(f"Analysis failed: {e}")
            return

    left, right = st.columns([2, 3], gap="large")

    with left:
        render_verdict(results)
        st.divider()
        render_metadata(results)
        st.divider()
        render_next_steps(results)
        render_attachments(results)
        render_urls(results)

    with right:
        st.markdown("#### Check Results")
        for s in ["Sender Identity", "Email Authentication", "DNS Records", "Domain Age",
                  "Received Chain", "URLs", "Attachments", "Content Signals"]:
            render_section(s, results["findings"])


if __name__ == "__main__":
    main()
