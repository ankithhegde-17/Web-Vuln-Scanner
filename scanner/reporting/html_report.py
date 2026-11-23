"""Phase 4: a single-file HTML dashboard for a scan report.

Takes the JSON the scanner writes (or the `.triaged.json` from Phase 3) and
produces ONE self-contained HTML file: all CSS and JS are inline and the page
makes no network requests, so it opens offline straight from disk.

Design notes:
  * Escaping is the security-critical part. Payloads, evidence, URLs and even
    the LLM's text all come from outside (the target, or a model reading the
    target's output) and can contain things like `<script>`. Every value goes
    through `_e()` (html.escape) before it touches the page, and the inline
    JavaScript only toggles classes/attributes -- it never builds HTML from
    report data. So a hostile payload shows up as text, never runs.
  * "Effective severity" = the triage's adjusted severity when present and
    valid, otherwise the scanner's own severity. That one value drives the
    colour, the sort order, the counts and the filter.
  * A report with no triage data is a first-class case: the cards simply show
    the scanner's description and remediation instead of the triage panel.

Only the standard library is used, so this adds no dependencies.
"""

from __future__ import annotations

import html
import re
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

# Most to least severe. Order matters: it's the sort order and the tile order.
SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

# Evidence longer than this is tucked into a collapsible block.
LONG_EVIDENCE = 280


def _e(value) -> str:
    """HTML-escape any value (quotes too, so it's safe inside attributes)."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


_TICKS = re.compile(r"`([^`\n]+)`")


def _prose(value) -> str:
    """Escape free text, then turn `backtick spans` into <code>.

    Order matters: the text is fully escaped FIRST, so it can't contain any
    tags; the regex then only wraps already-escaped characters in our own
    <code> element. LLMs routinely use backticks in explanations and fixes.
    """
    return _TICKS.sub(r'<code class="inline">\1</code>', _e(value))


def _norm_sev(value) -> str | None:
    v = str(value or "").strip().lower()
    return v if v in SEV_RANK else None


def effective_severity(finding: dict) -> str:
    """Triage's adjusted severity if it's a known level, else the scanner's."""
    triage = finding.get("triage") or {}
    return _norm_sev(triage.get("adjusted_severity")) or _norm_sev(finding.get("severity")) or "info"


def is_flagged(finding: dict) -> bool:
    """True if triage marked this as a likely false positive or a duplicate."""
    triage = finding.get("triage") or {}
    return bool(triage.get("likely_false_positive")) or bool(triage.get("duplicate_of"))


def sort_findings(findings: list[dict]) -> list[dict]:
    """Critical first down to info; flagged (FP/duplicate) findings go last.

    sorted() is stable, so findings with equal severity keep the scanner's order.
    """
    return sorted(findings, key=lambda f: (is_flagged(f), SEV_RANK[effective_severity(f)]))


# ------------------------------------------------------------------ helpers
def _fmt_time(iso: str | None) -> str:
    if not iso:
        return "unknown"
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    offset = dt.utcoffset()
    zone = "" if offset is None else (" UTC" if not offset else dt.strftime(" UTC%z"))
    return dt.strftime("%d %b %Y, %H:%M") + zone


def _duration(start: str | None, end: str | None) -> str:
    try:
        secs = (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
    except (TypeError, ValueError):
        return ""
    if secs < 60:
        return f"{secs:.0f}s"
    return f"{int(secs // 60)}m {int(secs % 60)}s"


def _code_block(text: str, label: str) -> str:
    """Monospace block; long text is collapsible so cards stay scannable."""
    body = f'<pre class="code">{_e(text)}</pre>'
    if len(text) > LONG_EVIDENCE:
        return (f'<details class="fold"><summary>{_e(label)} '
                f'<span class="hint">({len(text)} chars)</span></summary>{body}</details>')
    return body


def _field(label: str, inner_html: str) -> str:
    return f'<div class="field"><dt>{_e(label)}</dt><dd>{inner_html}</dd></div>'


# -------------------------------------------------------------------- cards
def _card(f: dict) -> str:
    sev = effective_severity(f)
    triage = f.get("triage") or {}
    original = _norm_sev(f.get("severity"))
    flagged = is_flagged(f)

    # Badges: effective severity, plus the struck-through original if triage changed it.
    badges = f'<span class="badge b-{sev}">{_e(sev)}</span>'
    if triage and original and original != sev:
        badges += f'<s class="badge-orig" title="Scanner severity before triage">{_e(original)}</s>'
    if f.get("confidence"):
        badges += f'<span class="chip">{_e(f["confidence"])}</span>'
    if triage.get("likely_false_positive"):
        badges += '<span class="chip chip-flag">likely false positive</span>'
    if triage.get("duplicate_of"):
        badges += f'<span class="chip chip-flag">duplicate of {_e(triage["duplicate_of"])}</span>'

    # Facts: where, what we sent, what came back.
    fields = []
    if f.get("url"):
        fields.append(_field("URL", f'<code class="inline">{_e(f["url"])}</code>'))
    others = [u for u in (f.get("affected_urls") or []) if u != f.get("url")]
    if others:
        items = "".join(f'<li><code class="inline">{_e(u)}</code></li>' for u in others)
        fields.append(_field(f"Also affects ({len(others)})", f'<ul class="urls">{items}</ul>'))
    if f.get("payload"):
        fields.append(_field("Payload", _code_block(f["payload"], "Show payload")))
    if f.get("evidence"):
        fields.append(_field("Evidence", _code_block(f["evidence"], "Show evidence")))
    facts = f'<dl class="facts">{"".join(fields)}</dl>' if fields else ""

    # Analysis: the triage panel when present, otherwise the scanner's own text.
    if triage:
        parts = []
        if triage.get("severity_reason"):
            parts.append(f'<p class="reason"><span class="label">Why {_e(sev)}</span>{_prose(triage["severity_reason"])}</p>')
        if triage.get("false_positive_reason"):
            parts.append(f'<p class="reason"><span class="label">Flag reason</span>{_prose(triage["false_positive_reason"])}</p>')
        if triage.get("explanation"):
            parts.append(f'<p>{_prose(triage["explanation"])}</p>')
        if triage.get("example_fix"):
            parts.append('<details class="fold fix" open><summary>Example fix</summary>'
                         f'<pre class="code">{_e(_TICKS.sub(r"\1", str(triage["example_fix"]).strip()))}</pre></details>')
        analysis = f'<section class="analysis"><h4>Triage</h4>{"".join(parts)}</section>' if parts else ""
    else:
        parts = []
        if f.get("description"):
            parts.append(f'<p>{_prose(f["description"])}</p>')
        if f.get("remediation"):
            parts.append('<details class="fold fix" open><summary>Remediation</summary>'
                         f'<p>{_prose(f["remediation"])}</p></details>')
        analysis = f'<section class="analysis plain">{"".join(parts)}</section>' if parts else ""

    ident = " · ".join(_e(x) for x in (f.get("rule_id"), f.get("check")) if x)
    return (
        f'<article class="card s-{sev}{" flagged" if flagged else ""}" data-sev="{sev}">'
        f'<header class="card-head"><div class="badges">{badges}</div>'
        f'<h3>{_e(f.get("title") or "Untitled finding")}</h3></header>'
        f'{facts}{analysis}'
        f'<footer class="card-foot">{ident}</footer>'
        f'</article>'
    )


# ------------------------------------------------------------------- page
def build_html(report: dict) -> str:
    findings = sort_findings(list(report.get("findings") or []))
    counts = Counter(effective_severity(f) for f in findings)
    total = len(findings)
    triage = report.get("triage") or {}
    scanner = report.get("scanner") or {}
    stats = report.get("stats") or {}

    mode = str(scanner.get("mode") or "").replace("+", " + ") or "unknown"
    meta = [
        ("Started", _fmt_time(report.get("started_at"))),
        ("Duration", _duration(report.get("started_at"), report.get("finished_at")) or "–"),
        ("Pages crawled", stats.get("pages_crawled", "–")),
        ("Requests", stats.get("requests_made", "–")),
    ]
    meta_html = "".join(f'<div class="meta-item"><span>{_e(k)}</span><strong>{_e(v)}</strong></div>'
                        for k, v in meta)

    triage_html = ""
    if triage.get("enriched"):
        model = " / ".join(_e(x) for x in (triage.get("provider"), triage.get("model")) if x)
        summary = f'<p>{_prose(triage["summary"])}</p>' if triage.get("summary") else ""
        triage_html = (f'<section class="callout"><div class="callout-head">'
                       f'<span class="label">LLM triage</span><span class="muted">{model}</span></div>'
                       f'{summary}</section>')
    elif triage.get("error"):
        triage_html = (f'<section class="callout warn"><span class="label">Triage incomplete</span>'
                       f'<p>{_e(triage["error"])} Scanner severities are shown.</p></section>')

    # Count tiles double as the severity filter (buttons with aria-pressed).
    tiles = "".join(
        f'<button type="button" class="tile t-{s}{" zero" if not counts[s] else ""}" data-sev="{s}" '
        f'aria-pressed="true" title="Show/hide {s} findings">'
        f'<span class="tile-n">{counts[s]}</span><span class="tile-l">{s}</span></button>'
        for s in SEVERITIES
    )
    bar = "".join(
        f'<span class="seg t-{s}" style="flex-grow:{counts[s]}" title="{s}: {counts[s]}"></span>'
        for s in SEVERITIES if counts[s]
    )
    bar_html = f'<div class="mix" aria-hidden="true">{bar}</div>' if total else ""

    if findings:
        cards = "".join(_card(f) for f in findings)
        body = (f'<div class="toolbar"><h2>Findings</h2>'
                f'<span class="status" id="status" aria-live="polite">Showing {total} of {total}</span>'
                f'<button type="button" class="reset" id="reset">Show all</button></div>'
                f'<div class="cards" id="cards">{cards}</div>'
                f'<p class="empty filtered" id="none-shown" hidden>No findings match the selected severities.</p>')
    else:
        body = ('<div class="empty"><strong>No findings</strong>'
                '<p>The scan completed without reporting any issues.</p></div>')

    title = f"Scan report – {report.get('target') or 'unknown target'}"
    return PAGE.format(
        title=_e(title), css=CSS, js=JS,
        target=_e(report.get("target") or "unknown target"),
        mode=_e(mode), mode_cls="active" if "active" in mode else "passive",
        meta=meta_html, triage=triage_html, tiles=tiles, bar=bar_html, total=total, body=body,
        plural="" if total == 1 else "s",
        version=_e(scanner.get("version") or ""),
    )


def write_html_report(report: dict, path: str | Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_html(report), encoding="utf-8")
    return path


def write_html_from_json(json_path: str | Path, out_path: str | Path | None = None) -> Path:
    """Read a saved JSON report and write the HTML beside it (or to out_path)."""
    json_path = Path(json_path)
    report = json.loads(json_path.read_text(encoding="utf-8"))
    return write_html_report(report, out_path or json_path.with_suffix(".html"))


# ---------------------------------------------------------------- template
# Plain str.format template: literal braces in CSS/JS are kept out of it by
# passing CSS and JS in as values rather than writing them inline here.
PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{title}</title>
<style>{css}</style>
</head>
<body>
<main class="wrap">
  <header class="top">
    <p class="eyebrow">webvuln-scanner · security scan report</p>
    <h1 class="target">{target}</h1>
    <div class="meta">
      <div class="meta-item"><span>Mode</span><strong class="pill {mode_cls}">{mode}</strong></div>
      {meta}
    </div>
  </header>
  {triage}
  <section class="summary" aria-label="Findings by severity">
    <div class="summary-head"><h2>{total} finding{plural}</h2><span class="muted">Click a severity to show or hide it</span></div>
    <div class="tiles" id="tiles">{tiles}</div>
    {bar}
  </section>
  {body}
  <footer class="page-foot">Generated by webvuln-scanner {version}. Authorized testing only.</footer>
</main>
<script>{js}</script>
</body>
</html>
"""

CSS = """
:root{
  --bg:#f5f6f8;--surface:#fff;--text:#15181d;--muted:#5d6574;--line:#e2e5ea;--code:#f1f3f6;
  --critical:#c4122f;--high:#e0570f;--medium:#c98f00;--low:#2c6cd6;--info:#7b8392;
  --radius:12px;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0e1014;--surface:#161920;--text:#e6e9ef;--muted:#99a2b1;--line:#272c35;--code:#0f1217;
  --critical:#ff4d63;--high:#ff7d3a;--medium:#efb42c;--low:#5c9dff;--info:#98a1b0;
}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--text);
  font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
.wrap{max-width:980px;margin:0 auto;padding:40px 32px 56px}
h1,h2,h3,h4{margin:0;line-height:1.25}
.muted{color:var(--muted)}
.label{display:block;font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:4px}

.top{margin-bottom:28px}
.eyebrow{margin:0 0 10px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.target{font-family:var(--mono);font-size:clamp(20px,3.4vw,28px);font-weight:600;overflow-wrap:anywhere}
.meta{display:flex;flex-wrap:wrap;gap:12px 32px;margin-top:20px;padding-top:18px;border-top:1px solid var(--line)}
.meta-item span{display:block;font-size:12px;color:var(--muted)}
.meta-item strong{font-weight:600}
.pill{display:inline-block;padding:1px 10px;border-radius:999px;font-size:13px;border:1px solid var(--line)}
.pill.active{border-color:var(--high);color:var(--high)}

.callout{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:18px 20px;margin-bottom:28px}
.callout p{margin:6px 0 0}
.callout-head{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;align-items:baseline}
.callout-head .label{margin:0}
.callout.warn{border-color:var(--medium)}

.summary{margin-bottom:36px}
.summary-head{display:flex;justify-content:space-between;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.summary-head h2{font-size:18px}
.summary-head .muted{font-size:13px}
.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.tile{--c:var(--info);position:relative;display:flex;flex-direction:column;align-items:flex-start;gap:2px;
  padding:14px 16px 12px;background:var(--surface);color:var(--text);border:1px solid var(--line);
  border-radius:var(--radius);cursor:pointer;font:inherit;text-align:left;overflow:hidden;
  transition:opacity .15s,border-color .15s,transform .1s}
.tile::before{content:"";position:absolute;inset:0 0 auto 0;height:3px;background:var(--c)}
.tile:hover{border-color:var(--c)}
.tile:active{transform:scale(.98)}
.tile:focus-visible,.reset:focus-visible{outline:2px solid var(--c,var(--low));outline-offset:2px}
.tile-n{font-size:28px;font-weight:700;line-height:1.1;color:var(--c);font-variant-numeric:tabular-nums}
.tile-l{font-size:12px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.tile.zero .tile-n{color:var(--muted);opacity:.6}
.tile[aria-pressed="false"]{opacity:.42;border-style:dashed}
.tile[aria-pressed="false"]::before{background:var(--line)}
.mix{display:flex;height:6px;border-radius:999px;overflow:hidden;margin-top:14px;background:var(--line);gap:2px}
.seg{background:var(--c)}
.t-critical{--c:var(--critical)}.t-high{--c:var(--high)}.t-medium{--c:var(--medium)}.t-low{--c:var(--low)}.t-info{--c:var(--info)}

.toolbar{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.toolbar h2{font-size:18px;margin-right:auto}
.status{font-size:13px;color:var(--muted)}
.reset{font:inherit;font-size:13px;padding:5px 12px;border-radius:999px;border:1px solid var(--line);
  background:var(--surface);color:var(--text);cursor:pointer}
.reset:hover{border-color:var(--muted)}

.cards{display:flex;flex-direction:column;gap:14px}
.card{--c:var(--info);background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--c);
  border-radius:var(--radius);padding:18px 22px 14px}
.card[hidden]{display:none}
.s-critical{--c:var(--critical)}.s-high{--c:var(--high)}.s-medium{--c:var(--medium)}.s-low{--c:var(--low)}.s-info{--c:var(--info)}
.card.flagged{opacity:.6;border-left-style:dashed}
.card.flagged:hover{opacity:.9}
.card-head h3{font-size:17px;font-weight:650;margin-top:8px;overflow-wrap:anywhere}
.badges{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
.badge{display:inline-block;padding:2px 9px;border-radius:6px;font-size:11px;font-weight:700;letter-spacing:.07em;
  text-transform:uppercase;color:#fff;background:var(--c)}
.b-medium{color:#1d1600}
.badge-orig{font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}
.chip{font-size:12px;padding:1px 8px;border-radius:999px;border:1px solid var(--line);color:var(--muted)}
.chip-flag{border-color:var(--medium);color:var(--medium)}

.facts{margin:14px 0 0;display:grid;gap:10px}
.field{display:grid;grid-template-columns:96px 1fr;gap:12px;align-items:start}
.field dt{font-size:12px;font-weight:600;color:var(--muted);padding-top:3px}
.field dd{margin:0;min-width:0}
code.inline{font-family:var(--mono);font-size:13px;overflow-wrap:anywhere}
.urls{margin:0;padding-left:18px}
.code{margin:0;font-family:var(--mono);font-size:12.5px;line-height:1.5;background:var(--code);
  border:1px solid var(--line);border-radius:8px;padding:9px 12px;white-space:pre-wrap;overflow-wrap:anywhere;
  max-height:340px;overflow:auto}

.analysis{margin-top:16px;padding-top:14px;border-top:1px solid var(--line)}
.analysis h4{font-size:11px;font-weight:650;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-bottom:8px}
.analysis p{margin:0 0 10px}
.reason{padding:8px 12px;border-radius:8px;background:color-mix(in srgb,var(--c) 9%,transparent)}
.reason .label{color:var(--c)}
.fold{margin-top:6px}
.fold summary{cursor:pointer;font-size:13px;font-weight:600;color:var(--muted);padding:2px 0;list-style-position:outside}
.fold summary:hover{color:var(--text)}
.fold[open] summary{margin-bottom:8px}
.fix .code{border-left:3px solid var(--low)}
p code.inline{font-size:.9em;background:var(--code);border:1px solid var(--line);border-radius:4px;padding:0 4px}
.hint{font-weight:400}
.card-foot{margin-top:12px;font-family:var(--mono);font-size:11.5px;color:var(--muted);overflow-wrap:anywhere}

.empty{text-align:center;padding:48px 16px;border:1px dashed var(--line);border-radius:var(--radius);color:var(--muted)}
.empty strong{display:block;font-size:18px;color:var(--text);margin-bottom:6px}
.empty.filtered{padding:28px 16px}
.page-foot{margin-top:40px;font-size:12px;color:var(--muted);text-align:center}

@media (max-width:640px){
  .wrap{padding:24px 16px 40px}
  .tiles{grid-template-columns:repeat(3,1fr)}
  .tile{padding:12px}
  .tile-n{font-size:24px}
  .card{padding:16px 16px 12px}
  .field{grid-template-columns:1fr;gap:4px}
}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""

# The script only flips `hidden` and aria-pressed and sets textContent; it
# never creates HTML from report data. The filter choice is remembered per
# report file in localStorage (wrapped in try/catch: file:// pages or private
# windows may refuse storage, and the page must still work).
JS = """
(function(){
  var tiles=[].slice.call(document.querySelectorAll('.tile'));
  var cards=[].slice.call(document.querySelectorAll('.card'));
  var status=document.getElementById('status');
  var none=document.getElementById('none-shown');
  var reset=document.getElementById('reset');
  var KEY='wvs-filter:'+location.pathname;
  function active(){return tiles.filter(function(t){return t.getAttribute('aria-pressed')==='true';})
    .map(function(t){return t.dataset.sev;});}
  function apply(){
    var on=active(),shown=0;
    cards.forEach(function(c){var vis=on.indexOf(c.dataset.sev)!==-1;c.hidden=!vis;if(vis)shown++;});
    if(status)status.textContent='Showing '+shown+' of '+cards.length;
    if(none)none.hidden=!(cards.length&&shown===0);
    try{localStorage.setItem(KEY,JSON.stringify(on));}catch(e){}
  }
  tiles.forEach(function(t){t.addEventListener('click',function(){
    t.setAttribute('aria-pressed',t.getAttribute('aria-pressed')==='true'?'false':'true');apply();});});
  if(reset)reset.addEventListener('click',function(){tiles.forEach(function(t){t.setAttribute('aria-pressed','true');});apply();});
  try{var saved=JSON.parse(localStorage.getItem(KEY)||'null');
    if(Array.isArray(saved))tiles.forEach(function(t){t.setAttribute('aria-pressed',saved.indexOf(t.dataset.sev)!==-1?'true':'false');});
  }catch(e){}
  apply();
})();
"""
