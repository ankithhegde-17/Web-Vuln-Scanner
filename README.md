# Web-Vuln-Scanner

A command-line web vulnerability scanner written in Python, built in phases as a learning / portfolio project.

**Phase 1 (this version):** a same-domain crawler plus **passive** security checks. It never sends attack payloads, never submits forms, and only ever makes `GET` requests.

| Phase | Scope | Status |
|---|---|---|
| 1 | Crawler, form inventory, passive checks, JSON + terminal reports | ✅ done |
| 2 | Active checks (XSS, SQLi, ...) against the form inventory | planned |
| 3 | LLM triage layer that reads the JSON findings | planned |

---

## ⚠️ Authorized use only

**Only scan systems you own or have explicit written permission to test.** Scanning other people's sites without permission can be a crime (for example under India's IT Act 2000, the US Computer Fraud and Abuse Act, or the UK Computer Misuse Act), even when the scan is "only passive".

The tool enforces this:

* It refuses to send **any** request unless you pass `--i-have-permission`, **or** you confirm interactively by typing the target's hostname.
* When it isn't running in an interactive terminal (scripts, CI) and the flag is missing, it exits with code `2` without contacting the target.

Good practice targets: **OWASP Juice Shop on your own machine** (instructions below) and **your own deployed apps**.

---

## Setup

Requires Python 3.9+.

```bash
cd webvuln-scanner
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Runtime dependencies are just `requests` and `beautifulsoup4`; `pytest` is only for the tests.

## Spin up a safe target: OWASP Juice Shop (Docker)

[Juice Shop](https://owasp.org/www-project-juice-shop/) is an intentionally vulnerable web shop maintained by OWASP for exactly this kind of practice.

```bash
docker pull bkimminich/juice-shop
docker run --rm -d --name juice-shop -p 127.0.0.1:3000:3000 bkimminich/juice-shop
# wait ~10-20 seconds for it to start, then open http://localhost:3000
```

Binding to `127.0.0.1` keeps the vulnerable app reachable only from your own machine, not your Wi-Fi network. Stop it with `docker stop juice-shop`.

## Usage

```bash
# Basic scan of Juice Shop
python -m scanner http://localhost:3000 --i-have-permission

# Or confirm interactively (you'll be asked to type "localhost")
python -m scanner http://localhost:3000

# Gentler / bigger crawl, custom report path
python -m scanner https://my-app.example.com --i-have-permission --delay 2 --max-pages 100 -o reports/my-app.json

# Show every request as it is made
python -m scanner http://localhost:3000 --i-have-permission -v
```

| Option | Default | Meaning |
|---|---|---|
| `--i-have-permission` | off | Confirm authorization (otherwise interactive prompt, or refusal) |
| `--delay SECONDS` | `1.0` | Minimum time between requests. A robots.txt `Crawl-delay` can raise it |
| `--max-pages N` | `50` | Stop after N pages |
| `--max-depth N` | `3` | How many links away from the start URL to go |
| `--timeout SECONDS` | `10` | Per-request timeout |
| `-o, --output PATH` | `scan-results.json` | Where to write the JSON report |
| `--no-path-probes` | off | Skip the `/.git/`, `/.env`, ... probes |
| `--ignore-robots` | off | Ignore robots.txt (only for apps you own) |
| `--insecure` | off | Skip TLS verification (your own self-signed apps) |
| `-v, --verbose` | off | Log each request |

Exit codes: `0` scan completed, `1` error, `2` not authorized.

### Run the tests

```bash
python -m pytest -q
```

The tests start a small, deliberately insecure web server on `127.0.0.1` inside the test process, so they never touch a real site. They also check the safety properties: no requests without permission, GET only, forms never submitted, cookie values never written to the report.

---

## Project structure

```
webvuln-scanner/
├── scanner/
│   ├── __main__.py          `python -m scanner` entry point
│   ├── cli.py               argument parsing and the authorization gate
│   ├── config.py            ScanConfig: every tunable setting in one place
│   ├── core.py              wires crawler + checks + findings together
│   ├── http_client.py       rate-limited, GET-only HTTP client (the only code that talks to the network)
│   ├── crawler.py           same-domain BFS crawler, robots.txt, form extraction
│   ├── models.py            Finding / Form / Page dataclasses + de-duplication
│   ├── checks/
│   │   ├── base.py          ResponseCheck and SiteCheck interfaces
│   │   ├── headers.py       security headers
│   │   ├── cookies.py       cookie flags
│   │   ├── disclosure.py    Server / X-Powered-By disclosure
│   │   └── sensitive_paths.py  exposed files + robots.txt disclosure
│   └── reporting/
│       ├── json_report.py   machine-readable report
│       └── terminal.py      human-readable summary
├── tests/                   pytest suite with a local test server
└── examples/juice-shop-report.json   real output from a Juice Shop scan
```

### Design choices (and why)

* **`requests` over `httpx`.** The scanner is deliberately rate-limited to about one request per second, so async concurrency (httpx's big advantage) wouldn't make it faster. `requests` is synchronous and easier to read and debug.
* **One HTTP client for everything.** `RateLimitedClient` is the only object that sends requests. That makes rate limiting impossible to bypass, and because it only has a `get()` method, Phase 1 code *can't* POST a form even by mistake.
* **Breadth-first crawl.** Visiting pages nearest the start URL first means the most-linked pages get covered before `--max-pages` runs out.
* **Redirects followed manually.** Automatic redirect-following could take the scanner to another domain before we get a chance to check scope. The crawler reads the `Location` header and only follows it if it stays on the same host.
* **Strict scope.** Same hostname and port only. `app.example.com` being yours doesn't make `mail.example.com` fair game, so subdomains are out of scope.
* **Bounded downloads.** Bodies are streamed and cut off at 2 MB (64 KB for probes), so discovering a huge `backup.zip` doesn't mean downloading it.
* **De-duplicated findings.** "CSP missing" on 50 pages becomes one finding with 50 `affected_urls`, not 50 findings. Finding ids are derived from the rule and a key (e.g. cookie name), so the same issue gets the same id across scans, which makes it easy to diff two reports.
* **Checks behind an interface.** Each check is a class with one method. The core runs whatever is in `scanner/checks/__init__.py`, so Phase 2 active checks can be added without touching the crawler.

---

## How each passive check works, and why it matters

### 1. Security headers (`checks/headers.py`)

Runs on every HTML page that returned 2xx. These headers are instructions to the browser; adding them costs nothing and shuts down whole classes of attack.

| Header | What we check | Why it matters |
|---|---|---|
| **Content-Security-Policy** | Missing (MEDIUM); report-only (LOW); script policy contains `'unsafe-inline'`, `'unsafe-eval'`, `*`, `data:`, `http:` or `https:` (LOW); no `script-src`/`default-src` at all (MEDIUM) | CSP tells the browser which scripts may run. With a good CSP, an XSS bug often can't execute attacker code. It's the main defence-in-depth layer against XSS. |
| **Strict-Transport-Security** (HTTPS only) | Missing (MEDIUM); `max-age` below 180 days (LOW) | Tells the browser "only ever use HTTPS for this site". Without it, the first plain-HTTP request can be intercepted and downgraded (SSL stripping). |
| **X-Frame-Options** / CSP `frame-ancestors` | Neither present (MEDIUM); XFO value other than `DENY`/`SAMEORIGIN` (LOW) | Stops other sites from loading yours in an invisible iframe and tricking users into clicking things (clickjacking). |
| **X-Content-Type-Options** | Not `nosniff` (LOW) | Stops browsers from "guessing" a file is HTML/JS when the server said it's something else, which can turn an upload into XSS. |
| **Referrer-Policy** | Missing, or `unsafe-url` / `no-referrer-when-downgrade` (LOW) | Controls whether full URLs (which may include tokens or IDs) leak to third-party sites in the `Referer` header. LOW because modern browsers already default to a safer policy. |

The check also flags pages served over **plain HTTP**: MEDIUM on real hosts, INFO on `localhost` because that's expected for local practice apps.

### 2. Cookie flags (`checks/cookies.py`)

Reads every raw `Set-Cookie` header (the parsed cookie jar in `requests` throws the flags away).

| Flag | Flagged when | Why it matters |
|---|---|---|
| **Secure** | Missing | Without it the cookie is also sent over unencrypted HTTP, where it can be sniffed. |
| **HttpOnly** | Missing | JavaScript can read the cookie, so any XSS can steal the session. |
| **SameSite** | Missing, or `None` without `Secure` | Controls whether the cookie is attached to requests from other sites, the core ingredient of CSRF. |

Cookies whose names look like sessions (`session`, `sid`, `token`, `auth`, `jwt`...) get MEDIUM severity; others get LOW. Cookie **values are never stored** in the report, only names, because a value may be a live session token.

### 3. Exposed sensitive paths (`checks/sensitive_paths.py`)

Sends a handful of `GET` requests for files that should never be public: `/.git/HEAD`, `/.git/config`, `/.env`, `/.svn/entries`, `/.DS_Store`, `/backup.zip`, `/backup.sql`, `/dump.sql`, `/backup`, `/config.php.bak`, `/phpinfo.php`, `/server-status`, and directory listings on `/backup/`, `/ftp/` and `/uploads/`.

Why it matters: an exposed `.git` folder lets anyone rebuild your source code and history (often including secrets), and a `.env` file usually contains database passwords and API keys. These are some of the most damaging and most common real-world leaks.

The hard part is **avoiding false positives**. Single-page apps like Juice Shop answer *every* unknown URL with `200 OK` and the homepage, so "status 200" proves nothing. The check uses two techniques:

1. **Content signatures.** A real `/.git/HEAD` starts with `ref: refs/`, a real `.env` has `KEY=value` lines, a real zip starts with the bytes `PK\x03\x04`, a directory listing has a title like "Index of". Signature match = `"confidence": "confirmed"`.
2. **Soft-404 baseline.** Before probing, the scanner requests a random path that can't exist and remembers what "not found" looks like. A probe without a signature is only reported if its response differs from that baseline, and then as `"confidence": "tentative"`.

Probes respect robots.txt like the crawler does. A companion INFO finding lists the robots.txt `Disallow` entries, because robots.txt is public and often points straight at the "hidden" areas. robots.txt is a politeness convention, not access control.

### 4. Server / technology disclosure (`checks/disclosure.py`)

Flags `Server` (LOW if it contains a version number like `Apache/2.4.29`, INFO if just a product name), and `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`, `X-Generator`, `X-Drupal-Cache`, `X-Runtime` (LOW).

Why it matters: a version string lets an attacker go straight to a CVE database for that exact version. Hiding it doesn't fix any vulnerability, but it removes free reconnaissance, which is why it's LOW/INFO.

---

## Output

**Terminal:** a colour-coded summary (colour is turned off automatically when piped, or when `NO_COLOR` is set), sorted by severity, plus the list of forms that were found.

**JSON** (`scan-results.json` by default). A trimmed example; see [`examples/juice-shop-report.json`](examples/juice-shop-report.json) for a real one:

```json
{
  "schema_version": 1,
  "scanner": {"name": "webvuln-scanner", "version": "0.1.0", "mode": "passive"},
  "target": "http://localhost:3000",
  "stats": {"pages_crawled": 1, "forms_found": 0, "requests_made": 17,
            "findings_by_severity": {"high": 0, "medium": 1, "low": 1, "info": 2}},
  "findings": [
    {
      "id": "HEADER_CSP_MISSING-3f1c2a9b",
      "rule_id": "HEADER_CSP_MISSING",
      "check": "security_headers",
      "severity": "medium",
      "title": "Content-Security-Policy header missing",
      "url": "http://localhost:3000/",
      "affected_urls": ["http://localhost:3000/"],
      "description": "Without a CSP the browser will run any script ...",
      "remediation": "Add a Content-Security-Policy ...",
      "evidence": "",
      "confidence": "confirmed"
    }
  ],
  "pages": [{"url": "http://localhost:3000/", "status_code": 200, "depth": 0, "content_type": "text/html; charset=UTF-8"}],
  "forms": []
}
```

Every finding has `id`, `severity`, `url`, `description` and `remediation`, plus `rule_id`, `evidence` and `confidence`, which give the Phase 3 LLM layer the context it needs to triage.

---

## What to expect on Juice Shop (and known limitations)

A default scan of Juice Shop reports a missing **CSP**, a missing **Referrer-Policy**, the **robots.txt** entry for `/ftp`, and plain HTTP (INFO on localhost). It correctly does *not* flag X-Frame-Options or X-Content-Type-Options, which Juice Shop does set. With `--ignore-robots` (fine here, since it's your local copy) it also confirms the **directory listing on `/ftp/`**, one of Juice Shop's classic challenges.

You'll notice it crawls only **one page**. That's expected: Juice Shop is an Angular single-page app. Its HTML has no `<a href>` links or `<form>` tags; everything is rendered by JavaScript in the browser. A classic HTML crawler can't see those routes. That's a real limitation of this kind of scanner, and a good Phase 2 topic. Options include parsing JavaScript bundles for route strings, reading `sitemap.xml`, or driving a headless browser (e.g. Playwright). On traditional server-rendered apps the crawler will find many pages and forms.

Other limitations to know about:

* Passive checks find misconfigurations, not logic bugs. "No findings" does **not** mean a site is secure.
* Only cookies set via `Set-Cookie` headers are seen; cookies set by JavaScript (`document.cookie`) are invisible to an HTTP-level scanner.
* No authentication support yet, so pages behind a login aren't crawled.
