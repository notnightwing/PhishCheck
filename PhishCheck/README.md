# PhishCheck 🎣

Phishing email triage tool for security teams. Drop in a `.eml` file and get an instant report covering sender identity, SPF/DKIM/DMARC authentication, domain age, received chain analysis, URL inspection, attachment hashing, encrypted PDF detection, and social engineering content signals.

Available as a CLI script or a Streamlit web UI.

---

## What It Checks

| Check | What It Does |
|---|---|
| Sender Identity | Display name vs. actual address mismatch, freemail detection, Reply-To mismatch |
| Email Authentication | SPF, DKIM, DMARC results from `Authentication-Results` header |
| DNS Records | Live SPF and DMARC record lookup for the sending domain |
| Domain Age | WHOIS registration date for sending domain and linked domains |
| Received Chain | Originating IP extraction and reverse DNS analysis |
| URLs | Shortener detection, cross-domain link flagging, optional Google Safe Browsing lookup |
| Attachments | File hashing (MD5 + SHA-256), dangerous extension flagging, encrypted PDF detection |
| Password-in-body | Detects when a password is provided in the body for an encrypted attachment — a common scanner evasion technique |
| Content Signals | Urgency language, financial requests, executive impersonation patterns |

---

## Requirements

- Python 3.9+
- pip packages: `dnspython`, `python-whois`, `requests`, `pypdf`
- For the web UI: also `streamlit`

---

## Installation

```bash
git clone https://github.com/YOUR_ORG/phishcheck.git
cd phishcheck

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

---

## Usage

### Getting a .eml file from Gmail

Open the email → click the three-dot menu (⋮) → **Download message**.

---

### CLI

```bash
python phish_check.py suspicious.eml

# With Google Safe Browsing URL checks
python phish_check.py suspicious.eml --gsb-key YOUR_API_KEY

# Or set the key as an environment variable
export GSB_API_KEY=your_key
python phish_check.py suspicious.eml
```

**Add a shell alias for quick access** — add to `~/.zshrc` or `~/.bashrc`:

```bash
alias phishcheck="/path/to/phishcheck/venv/bin/python /path/to/phishcheck/phish_check.py"
```

Then reload:

```bash
source ~/.zshrc
```

---

### Web UI (Streamlit)

```bash
streamlit run phish_check_ui.py
```

Opens in your browser. Drag and drop a `.eml` file to analyze it. Enter your Google Safe Browsing API key in the sidebar to enable URL reputation checks.

**Add a shell alias:**

```bash
alias phishui="/path/to/phishcheck/venv/bin/python -m streamlit run /path/to/phishcheck/phish_check_ui.py"
```

---

## Google Safe Browsing API Key (Optional)

URL reputation checks require a Google Safe Browsing API v4 key. The tool runs all other checks without it.

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create or select a project
3. Enable the **Safe Browsing API**
4. Create an API key under **Credentials**
5. Pass via `--gsb-key` or set `GSB_API_KEY` in your environment

Free tier: 10,000 lookups/day.

---

## Encrypted PDF Detection

PhishCheck detects when an email contains both an encrypted/password-protected PDF (or archive) and a password provided in the email body. This is a common scanner evasion technique — the password prevents automated scanners from opening the file while a real user can.

When this pattern is detected, the tool flags it as HIGH RISK and directs you to:

1. **Do not open the file in any application, including browser PDF viewers.** Browser sandboxing reduces risk compared to Acrobat, but does not protect against credential harvesting or OAuth phishing on linked pages.
2. **Submit the SHA-256 hash to VirusTotal first.** Note that a 0/63 result on an encrypted PDF is not a clean bill of health — most vendors cannot analyze encrypted files.
3. **Submit to Any.run in interactive mode** — `https://any.run` — with the password so the sandbox can actually open and detonate the file. This is the most reliable way to see what the payload does.
4. **Submit to Hybrid Analysis** — `https://hybrid-analysis.com` — as a secondary sandbox.

---

## Verdict Levels

| Verdict | Criteria |
|---|---|
| 🚨 HIGH RISK | One or more hard failures |
| ⚠️ SUSPICIOUS | Three or more warnings, no hard failures |
| 🔍 REVIEW | One or two warnings |
| ✅ LIKELY BENIGN | No significant indicators |

**When in doubt, treat it as phishing.** The cost of a false positive is low. The cost of a missed phish is not.

---

## Project Structure

```
phishcheck/
├── phish_check.py       # CLI tool
├── phish_check_ui.py    # Streamlit web UI
├── requirements.txt     # Python dependencies
└── README.md
```

---

## Limitations

- WHOIS lookups can be slow or rate-limited depending on the registrar. Domain age checks may occasionally time out.
- `Authentication-Results` headers are set by the receiving mail server. The tool reads these results; it does not re-evaluate SPF/DKIM/DMARC from scratch.
- URL analysis is based on the raw `.eml` source. Redirects and tracking wrappers are not followed.
- A clean VirusTotal result on an encrypted PDF or archive does not mean the file is safe — most vendors cannot scan encrypted content without the password.
- Google Workspace Email Log Search does not support attachment hash search via the Admin Console UI. Use the subject line or sender address to find related emails. For broader attachment-based search across all mailboxes, use Google Vault.
- This tool is an aid for triage, not a replacement for analyst judgment.
