# Web-Vuln-Scanner

A command-line web vulnerability scanner written in Python, built in phases as a learning / portfolio project.

- **Passive mode (default):** a same-domain crawler plus non-intrusive checks. Sends no attack payloads, never submits forms, only `GET`.
- **Active mode (opt-in, `--active`):** adds reflected-XSS, safe SQL-injection, and open-redirect detection. All non-destructive detection probes — nothing that deletes, modifies, or submits real data. Gated behind **both** `--i-have-permission` and `--active`.
- **LLM triage (opt-in, `--triage`):** sends the findings to a configurable LLM that re-ranks them by real-world severity, flags false positives and duplicates, and writes plain-language fixes. Needs an API key; skips gracefully without one.
- **HTML dashboard (opt-in, `--html` or `python -m scanner.report`):** turns a JSON report into one self-contained, offline HTML page with severity-coloured finding cards and a severity filter.

| Phase | Scope | Status |
|---|---|---|
| 1 | Crawler, form inventory, passive checks, JSON + terminal reports | ✅ done |
| 2 | Active checks (reflected XSS, safe SQLi detection, open redirect) + seeded targets | ✅ done |
| 3 | LLM triage layer that enriches the JSON findings | ✅ done |
| 4 | Self-contained HTML results dashboard | ✅ done |

---

## ⚠️ Authorized use only

**Only scan systems you own or have explicit written permission to test.** Scanning other people's sites without permission can be a crime (for example under India's IT Act 2000, the US Computer Fraud and Abuse Act, or the UK Computer Misuse Act), even when the scan is "only passive".

The tool enforces this with two gates:

* **Permission gate (`--i-have-permission`).** It refuses to send **any** request unless you pass `--i-have-permission`, **or** you confirm interactively by typing the target's hostname. When it isn't running in an interactive terminal (scripts, CI) and the flag is missing, it exits with code `2` without contacting the target.
* **Active-checks gate (`--active`).** The intrusive checks (XSS/SQLi/open-redirect, which send crafted input) are **off by default** and need a *second*, explicit opt-in. `--active` requires `--i-have-permission` as well; using `--active` alone is refused before any request is sent. Even then, every payload is a non-destructive detection probe.

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

LLM triage (Phase 3) is optional and has its own dependency file, so the core scanner stays light:

```bash
pip install -r requirements-triage.txt   # only if you want --triage (installs the anthropic SDK)
```

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
# Passive scan of Juice Shop (default: no payloads)
python -m scanner http://localhost:3000 --i-have-permission

# Or confirm interactively (you'll be asked to type "localhost")
python -m scanner http://localhost:3000

# ACTIVE scan: passive checks PLUS reflected XSS / SQLi / open redirect.
# Needs both flags. Seed endpoints with --urls so the active checks have
# parameters to test (essential for single-page apps like Juice Shop).
python -m scanner http://localhost:3000 --i-have-permission --active --urls targets/juice-shop.txt

# --urls also accepts a comma-separated list instead of a file
python -m scanner http://localhost:3000 --i-have-permission --active --urls "http://localhost:3000/rest/products/search?q=test"

# Gentler / bigger crawl, custom report path
python -m scanner https://my-app.example.com --i-have-permission --delay 2 --max-pages 100 -o reports/my-app.json
```

| Option | Default | Meaning |
|---|---|---|
| `--i-have-permission` | off | Confirm authorization (otherwise interactive prompt, or refusal) |
| `--active` | off | **Enable active checks (XSS, SQLi, open redirect). Intrusive — requires `--i-have-permission` too.** |
| `--urls FILE_OR_LIST` | – | Seed endpoints for active checks: a file (one URL per line, `#` comments) or a comma-separated list. Seed with query params, e.g. `/search?q=test` |
| `--delay SECONDS` | `1.0` | Minimum time between requests. A robots.txt `Crawl-delay` can raise it |
| `--max-pages N` | `50` | Stop after N pages |
| `--max-depth N` | `3` | How many links away from the start URL to go |
| `--timeout SECONDS` | `10` | Per-request timeout |
| `-o, --output PATH` | `scan-results.json` | Where to write the JSON report |
| `--no-path-probes` | off | Skip the `/.git/`, `/.env`, ... probes |
| `--html` | off | Also write a self-contained HTML dashboard (`<output>.html`); uses the triaged results when `--triage` ran |
| `--ignore-robots` | off | Ignore robots.txt (only for apps you own) |
| `--insecure` | off | Skip TLS verification (your own self-signed apps) |
| `-v, --verbose` | off | Log each request |

Exit codes: `0` scan completed, `1` error, `2` not authorized (includes `--active` without `--i-have-permission`).

### Run the tests

```bash
python -m pytest -q
```

The tests start a small, deliberately insecure web server on `127.0.0.1` inside the test process, so they never touch a real site. They cover both the passive and active checks (the server has endpoints that are vulnerable to reflected XSS, error-based SQLi and open redirect), and they check the safety properties: no requests without permission, `--active` refused without `--i-have-permission`, active checks silent by default, cookie values never written to the report, and the reflected-XSS check ignoring *encoded* reflections so it doesn't false-positive.

---

## Project structure

```
Web-Vuln-Scanner/
├── scanner/
│   ├── __main__.py          `python -m scanner` entry point
│   ├── cli.py               argument parsing + the two authorization gates
│   ├── config.py            ScanConfig: every tunable setting in one place
│   ├── core.py              wires crawler + passive checks + active phase + findings
│   ├── http_client.py       rate-limited GET/POST client (the only code that talks to the network)
│   ├── crawler.py           same-domain BFS crawler, robots.txt, form extraction
│   ├── targets.py           builds injection points from forms + --urls seeds (scope-checked)
│   ├── models.py            Finding / Form / Page dataclasses + de-duplication
│   ├── checks/              PASSIVE checks (inspect responses, send no payloads)
│   │   ├── base.py          ResponseCheck and SiteCheck interfaces
│   │   ├── headers.py       security headers
│   │   ├── cookies.py       cookie flags
│   │   ├── disclosure.py    Server / X-Powered-By disclosure
│   │   └── sensitive_paths.py  exposed files + robots.txt disclosure
│   ├── active/              ACTIVE checks (opt-in; non-destructive probes)
│   │   ├── base.py          InjectionPoint + the injector + ActiveCheck interface
│   │   ├── xss.py           reflected XSS
│   │   ├── sqli.py          SQL injection (error- and boolean-based)
│   │   └── redirect.py      open redirect
│   ├── triage/              LLM TRIAGE (Phase 3; opt-in, needs an API key)
│   │   ├── providers.py     provider-agnostic LLM interface + .env key loading
│   │   ├── engine.py        prompt, JSON parsing, merge + re-rank
│   │   ├── report.py        enriched JSON + Markdown writers
│   │   ├── runner.py        shared driver (used by --triage and the CLI below)
│   │   └── __main__.py      `python -m scanner.triage <report.json>`
│   ├── report.py            `python -m scanner.report <report.json>` (Phase 4)
│   └── reporting/
│       ├── json_report.py   machine-readable report
│       ├── terminal.py      human-readable summary
│       └── html_report.py   self-contained HTML dashboard (Phase 4)
├── targets/juice-shop.txt   seed endpoints for testing the active checks
├── requirements-triage.txt  optional deps for triage only (anthropic SDK)
├── .env.example             template for the triage API key (.env is gitignored)
├── tests/                   pytest suite with a local vulnerable test server
└── examples/juice-shop-report.json   real output from a Juice Shop scan
```

### Design choices (and why)

* **`requests` over `httpx`.** The scanner is deliberately rate-limited to about one request per second, so async concurrency (httpx's big advantage) wouldn't make it faster. `requests` is synchronous and easier to read and debug.
* **One HTTP client for everything.** `RateLimitedClient` is the only object that sends requests, so rate limiting and scope can't be bypassed. It will only ever send `GET` or `POST` and *hard-refuses* any other method — there is no code path that can `PUT`/`DELETE`/`PATCH`, so the scanner physically cannot modify or delete server-side data.
* **Active checks share that same client and the same injector.** Every active probe goes through `send_with()` in `scanner/active/base.py`, which swaps the payload into exactly one parameter and leaves the rest at their baseline values. So active checks inherit the rate limit and scope for free, and each test changes one variable at a time.
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

## Active checks (opt-in, non-destructive)

Active checks only run with **both** `--i-have-permission` and `--active`. They test *injection points* — a query-string parameter or a form field — discovered two ways:

* **Crawler forms.** Every form the crawler found, one injection point per field.
* **`--urls` seeds.** On JavaScript apps the crawler sees one page, so you hand it known endpoints. A seed is one of:
  * `http://host/search?q=test` — a URL; each **query parameter** becomes an injection point.
  * `POST http://host/rest/user/login {"email": "a@b.c", "password": "x"}` — a method, a URL and a **JSON body**; each **string field** becomes an injection point. This is how the scanner reaches JSON APIs (like a login endpoint) that don't accept form or query input. The placeholder values are benign; the scanner swaps each in turn for its payloads.

  Seeds and forms are both **scope-checked**: anything not on the authorized host/port is dropped.

Every injection point is tested by swapping the payload into just that one parameter, keeping the others at their baseline values, and every active finding records the exact `payload` and the `evidence`.

### 1. Reflected XSS (`active/xss.py`)

**Scope: this check detects *reflected* (server-side) XSS only** — where the server copies your input straight into the HTML it returns. Injects a unique, harmless marker containing the characters that matter for XSS — `< > " '` — e.g. `xssa1b2c3d4e5<>"'`. Then:

* If that exact string comes back **unencoded** in an **HTML** response, the app copied input into the page without escaping it — a real reflected-XSS sink. **Reported HIGH.**
* If it comes back **HTML-encoded** (`&lt;...&gt;`), the app is escaping correctly — **not reported.** This is the key to avoiding false positives: lots of sites reflect your input, but safely.
* Reflections in non-HTML responses (e.g. a JSON API) aren't flagged, because the browser won't parse them as HTML.

The payload carries no script, tag name or event handler a browser would act on — the unencoded reflection alone proves the flaw, so the probe stays benign.

> **DOM-based XSS is out of scope.** When the payload never appears in the server's HTML but is instead written into the page by client-side JavaScript (as in Juice Shop's Angular search bar), only a browser that runs the JavaScript can see it. An HTTP-level scanner like this one cannot. Catching DOM XSS would need a JavaScript rendering engine — **planned as future work using a headless browser such as [Playwright](https://playwright.dev/python/)**, which would also solve single-page-app crawling (see Known limitations).

### 2. SQL injection — safe detection only (`active/sqli.py`)

Two techniques, neither of which writes data:

* **Error-based.** Send an unbalanced quote (`'"`). If the input is concatenated into SQL, the database throws an error that often leaks into the response. Matched against known error signatures for MySQL, PostgreSQL, SQLite, MS SQL Server and Oracle — **and** against ORM/driver **stack traces** (e.g. a `sequelize/.../sqlite/query.js` frame), because some apps swallow the raw DB message but still leak a stack trace naming the driver. In every case the signature must be *newly introduced* by the payload (not already on the clean baseline page). **Confirmed, HIGH.**
* **Boolean-based (behavioural).** Send a true condition (`' AND '1'='1`) and a false one (`' AND '1'='2`). If the input reaches a `WHERE` clause, the true response matches the normal page while the false one differs. A consistent difference is reported **HIGH but `tentative`** (behavioural, so confirm by hand).

Deliberately **not** done, because the brief forbids destructive/noisy payloads and they can harm a target: no `DROP`/`DELETE`/`UPDATE`/`INSERT`, no stacked queries (`; DROP ...`), and no time-based `SLEEP()` payloads (those deliberately load the DB). Detection only.

### 3. Open redirect (`active/redirect.py`)

For redirect-style parameters (`redirect`, `url`, `next`, `return`, `dest`, `to`, …, or any parameter whose value already looks like a URL/path), it injects a **non-routable marker host** — `http://vuln-scanner-probe.invalid/`. `.invalid` is reserved by RFC 6761 and can never resolve to a real server, so even if a browser followed the redirect it would go nowhere. If the server tries to send the browser to that marker (via a `Location` header or an HTML meta-refresh), the parameter is an open redirect. **Reported MEDIUM.** The scanner never follows the redirect itself, and never uses a real external host as the marker.

---

## LLM triage (Phase 3, opt-in)

Triage takes the JSON findings and asks a large language model to do three things: **re-rank** each finding by real-world severity (which often differs from the raw label), **reduce noise** by flagging likely false positives and duplicates, and write a **plain-language remediation note** (what the bug is, why it matters, an example fix). It's aimed at the part a scanner is worst at: judgement and prioritisation.

It's strictly opt-in. A normal scan never loads or calls any of it.

```bash
# One: triage during a scan
python -m scanner http://localhost:3000 --i-have-permission --active \
    --urls targets/juice-shop.txt --triage

# Two: triage a report you already saved (no re-scanning)
python -m scanner.triage scan-results.json

# Pick a model or provider
python -m scanner.triage scan-results.json --llm-model claude-opus-5-5
python -m scanner.triage scan-results.json --llm-provider openai --llm-model gpt-4o
python -m scanner.triage scan-results.json --llm-provider gemini
```

Either way it writes `<report>.triaged.json` (the original findings plus a `triage` block on each, re-sorted by adjusted severity with flagged items at the end) and `<report>.triaged.md` (a readable summary).

### API keys — environment / `.env` only

The key is read **only** from an environment variable, or a local `.env` file that the tool loads into the environment (it never overwrites a real env var, and never prints key values). It is never passed on the command line or written to any output.

```bash
cp .env.example .env     # then edit .env and add your key
# .env is gitignored and must never be committed; .env.example holds placeholders only
```

- `--llm-provider anthropic` (default) reads `ANTHROPIC_API_KEY`; default model `claude-sonnet-5-5`.
- `--llm-provider openai` reads `OPENAI_API_KEY`.
- `--llm-provider gemini` reads `GEMINI_API_KEY`; default model `gemini-3.8-flash` (needs `pip install google-genai`; get a key at https://aistudio.google.com/apikey).

**No key set → triage skips gracefully:** it prints how to set one and exits cleanly (exit 0), the scan report is untouched, and **nothing is sent anywhere.** A malformed model reply is also handled: triage retries once, then returns the report unchanged with a note, rather than crashing or dropping findings. Provider-side failures (rejected key, quota, a temporarily overloaded model, network errors) are reported in one line and the scan report is kept — never a traceback.

### Privacy note

Triage necessarily sends the findings — including target URLs and evidence snippets — to whichever LLM provider you configure. That only happens when you invoke triage, which is why it's kept separate from scanning and off by default. For your own apps, use a provider you're comfortable sending that to.

### Adding another provider

Providers sit behind a one-method interface (`LLMProvider.complete(system, user) -> str`) in `scanner/triage/providers.py`. Claude (Anthropic SDK), OpenAI and Gemini (Google Gen AI SDK) are included; a new provider is a small subclass plus one line in the registry — the engine, prompt and reports don't change.

---

## HTML dashboard (Phase 4, opt-in)

Turns a scan's JSON into a single `report.html` you can open in any browser. All CSS and JavaScript are inline and the page makes **no network requests**, so it works offline and can be attached or archived as one file. It only reads a JSON file; it never contacts the target or an LLM.

```bash
# From a saved report (plain or triaged) -> writes scan-results.html next to it
python -m scanner.report scan-results.json
python -m scanner.report scan-results.triaged.json -o report.html

# Or as part of a scan (uses the triaged results when --triage ran)
python -m scanner http://localhost:3000 --i-have-permission --active \
    --urls targets/juice-shop.txt --triage --html
```

What's on the page:

- **Header:** target URL, scan time and duration, mode (passive / active + passive), pages crawled and requests made, plus the LLM's summary when the report was triaged.
- **Severity tiles:** counts for critical, high, medium, low and info, with a stacked bar showing the mix. **Clicking a tile shows or hides that severity**, and "Show all" resets the filter. The browser remembers your filter for that file.
- **Finding cards**, sorted critical → info, with triage-flagged false positives and duplicates dimmed at the end. Each card has a severity-coloured edge and badge. If triage changed the severity, the scanner's original appears struck through next to it. Cards show the URL, payload, evidence, and the triage reason, explanation and example fix. Long evidence collapses.
- **No triage data?** Cards use the scanner's severity and show its own description and remediation instead. A report with no findings shows a clean empty state.
- Light and dark mode follow your system setting; on phones the cards stack and long URLs wrap.

**Escaping:** payloads, evidence, URLs and the LLM's text all come from outside, and some are literally XSS probes. Every value is HTML-escaped before it goes into the page, and the page's script only shows/hides cards and never builds HTML from report data, so a hostile payload is displayed as text and never runs. A test feeds `<script>` payloads through every field to check this.

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

Every finding has `id`, `severity`, `url`, `description`, `remediation` and (for active findings) `payload`, plus `rule_id`, `evidence` and `confidence`, which give the Phase 3 LLM layer the context it needs to triage.

---

## Testing against Juice Shop

Run Juice Shop (see above), then an active scan with the included seed file:

```bash
python -m scanner http://localhost:3000 --i-have-permission --active --urls targets/juice-shop.txt --delay 0.3 --no-path-probes
```

**What fires (verified):**

| Endpoint | Check | Result |
|---|---|---|
| `/rest/products/search?q=` | SQL injection (error-based) | **HIGH, confirmed.** The `'"` payload produces `SQLITE_ERROR: ... syntax error` in the response — Juice Shop builds the search query by string concatenation. This is its signature SQLi. |
| `POST /rest/user/login` (`email`) | SQL injection (error-based) | **HIGH, confirmed.** Seeded as a JSON POST. The quote in `email` makes Juice Shop leak a `sequelize/.../sqlite/query.js` stack trace — the same `email` field is injectable to the known `' OR 1=1--` auth bypass. |
| `/` and crawled pages | passive checks | missing **CSP**, missing **Referrer-Policy**, `/ftp` in **robots.txt**, plain HTTP (INFO on localhost) |

**What correctly does *not* fire, and why** (these matter as much — they show the scanner avoids false positives):

* **Reflected XSS on search** — the search endpoint returns `application/json`, and Juice Shop's XSS challenges are **DOM-based** (the payload is rendered client-side by Angular, never reflected into server HTML). An HTTP-level scanner can't see DOM XSS; that needs a headless browser (planned — see the XSS check's note and Known limitations). To watch the XSS check fire against a genuine server-side reflection, run the tests (`tests/test_active.py`) or point `--urls` at an app that echoes input into its HTML unencoded.
* **Open redirect on `/redirect`** — Juice Shop allow-lists the redirect target, so the harmless marker host is rejected. The check is proven against the test server in `tests/test_active.py`.

### Known limitations

* **Single-page apps.** The crawler sees only **one page** of Juice Shop: it's an Angular app whose HTML has no `<a href>` links or `<form>` tags (JavaScript renders everything). That's why `--urls` exists — you seed the endpoints the crawler can't discover. Future options: parse JS bundles for routes, read `sitemap.xml`, or drive a headless browser (e.g. Playwright). On server-rendered apps the crawler finds many pages and forms on its own.
* **HTTP-level only.** The scanner catches *server-reflected* XSS and *error/boolean* SQLi. DOM-based XSS and other purely client-side bugs are out of reach by design.
* Passive checks find misconfigurations, not logic bugs. "No findings" does **not** mean a site is secure.
* Only cookies set via `Set-Cookie` headers are seen; cookies set by JavaScript (`document.cookie`) are invisible to an HTTP-level scanner.
* No authentication support yet, so pages behind a login aren't crawled.
