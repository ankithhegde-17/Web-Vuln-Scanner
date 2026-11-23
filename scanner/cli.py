"""Command-line interface.

The most important code in this file is `confirm_authorization()`. Scanning
a site you don't have permission to test is illegal in most countries (e.g.
the Computer Fraud and Abuse Act in the US, the IT Act 2000 in India, the
Computer Misuse Act in the UK), even when the scan is "only passive". So the
tool refuses to send a single request until the user has explicitly
confirmed authorization, either with --i-have-permission or by typing the
target's hostname at an interactive prompt.
"""

from __future__ import annotations

import argparse
import logging
import sys
from urllib.parse import urlsplit

from scanner import __version__
from scanner.config import ScanConfig

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_AUTHORIZED = 2

AUTH_WARNING = """
======================================================================
  AUTHORIZED USE ONLY
======================================================================
  You are about to scan: {url}

  Only scan systems you own or have explicit written permission to
  test (for example OWASP Juice Shop running on your own machine).
  Unauthorized scanning may be illegal, even if it is passive.
======================================================================
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="webvuln-scanner",
        description="Passive web vulnerability scanner (Phase 1: crawler + non-intrusive checks). "
                    "Authorized targets only.",
    )
    p.add_argument("url", help="Start URL, e.g. http://localhost:3000")
    p.add_argument("--i-have-permission", action="store_true",
                   help="Confirm you are authorized to test the target. Without this flag you will be "
                        "asked to confirm interactively; in non-interactive use the scan is refused.")
    p.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl (default: 50)")
    p.add_argument("--max-depth", type=int, default=3, help="Maximum link depth from the start URL (default: 3)")
    p.add_argument("--delay", type=float, default=1.0,
                   help="Minimum seconds between requests (default: 1.0). robots.txt Crawl-delay can raise it.")
    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)")
    p.add_argument("-o", "--output", default="scan-results.json", help="Path for the JSON report")
    p.add_argument("--no-path-probes", action="store_true",
                   help="Skip the sensitive-path probes (/.git/, /.env, ...); crawl and inspect responses only")

    active = p.add_argument_group("active checks (intrusive; opt-in)")
    active.add_argument("--active", action="store_true",
                        help="Enable active checks: reflected XSS, safe SQL-injection detection, and open "
                             "redirect. Intrusive, so this is a SECOND opt-in and REQUIRES --i-have-permission "
                             "as well. Off by default (passive-only).")
    active.add_argument("--urls", metavar="FILE_OR_LIST",
                        help="Extra endpoints for the active checks: a path to a file (one URL per line, '#' "
                             "comments allowed) or a comma-separated list. Needed for JavaScript apps where the "
                             "crawler sees only one page. Seed URLs with query params, e.g. '/search?q=test'.")

    triage = p.add_argument_group("LLM triage (Phase 3; opt-in, needs an API key)")
    triage.add_argument("--triage", action="store_true",
                        help="After scanning, send the findings to an LLM to re-rank by real-world severity, "
                             "flag false positives/duplicates, and write plain-language fixes. Writes "
                             "<output>.triaged.json and .triaged.md. Skips gracefully if no API key is set. "
                             "The key is read only from the environment or a .env file.")
    triage.add_argument("--llm-provider", default="anthropic",
                        help="LLM provider for --triage (default: anthropic; also: openai)")
    triage.add_argument("--llm-model", default=None,
                        help="Model id for --triage (default: the provider's default, e.g. claude-sonnet-5-5)")
    p.add_argument("--ignore-robots", action="store_true",
                   help="Ignore robots.txt. Only appropriate for apps you own.")
    p.add_argument("--insecure", action="store_true",
                   help="Don't verify TLS certificates (for your own apps with self-signed certs)")
    p.add_argument("-v", "--verbose", action="store_true", help="Show each request as it is made")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def validate_url(url: str) -> str | None:
    """Return an error message, or None if the URL is usable."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return "URL must start with http:// or https://"
    if not parts.hostname:
        return "URL has no hostname"
    return None


def confirm_authorization(url: str, flag_given: bool, stdin=sys.stdin, stderr=sys.stderr) -> bool:
    """The safety gate. Returns True only if the user has confirmed authorization."""
    host = urlsplit(url).hostname or ""
    print(AUTH_WARNING.format(url=url), file=stderr)

    if flag_given:
        print("  --i-have-permission given. Proceeding.\n", file=stderr)
        return True

    # No flag: we may only ask if a human is actually there to answer.
    # In a script or CI pipeline (stdin not a terminal) we refuse outright,
    # so the tool can never be pointed at a target "by accident".
    if not stdin.isatty():
        print("  Refusing to scan: pass --i-have-permission to confirm authorization.", file=stderr)
        return False

    # Typing the hostname (rather than just "y") forces you to look at what
    # you're about to scan, which catches copy-paste mistakes.
    print(f"  To confirm you are authorized, type the hostname ({host}): ", end="", file=stderr, flush=True)
    answer = stdin.readline().strip().lower()
    if answer == host.lower():
        print("  Confirmed. Proceeding.\n", file=stderr)
        return True
    print("  Hostname did not match. Scan cancelled.", file=stderr)
    return False


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="  %(levelname)s %(message)s",
    )

    error = validate_url(args.url)
    if error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR

    # Active checks require a SECOND explicit opt-in. --active alone is not
    # enough; the user must also assert authorization with --i-have-permission.
    # We refuse the combination early, before contacting the target at all.
    if args.active and not args.i_have_permission:
        print("error: --active requires --i-have-permission as well. Active checks are intrusive, so they "
              "need both the authorization flag and the explicit --active opt-in.", file=sys.stderr)
        return EXIT_NOT_AUTHORIZED

    # >>> Safety gate: nothing below this line runs without authorization. <<<
    if not confirm_authorization(args.url, args.i_have_permission):
        return EXIT_NOT_AUTHORIZED

    # Parse the --urls seed list (a file path or a comma-separated list).
    seed_urls = []
    if args.urls:
        from scanner.targets import parse_seed_urls
        seed_urls = parse_seed_urls(args.urls)
        if not args.active:
            print("note: --urls was given but --active was not, so the seeded endpoints won't be tested.",
                  file=sys.stderr)

    # Imported here so that `--help` and the permission check stay fast and
    # don't depend on the scanning modules.
    from scanner.core import run_scan
    from scanner.reporting import print_summary, write_json_report

    config = ScanConfig(
        start_url=args.url,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        delay=max(0.0, args.delay),
        timeout=args.timeout,
        respect_robots=not args.ignore_robots,
        probe_sensitive_paths=not args.no_path_probes,
        verify_tls=not args.insecure,
        active_checks=args.active,
        seed_urls=seed_urls,
    )
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    mode = "active + passive" if config.active_checks else "passive only"
    print(f"Scanning {config.start_url} ({mode}, delay {config.delay}s, max {config.max_pages} pages)...",
          file=sys.stderr)
    try:
        result = run_scan(config)
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        return EXIT_ERROR

    if not result.crawl.pages:
        print("warning: no pages could be fetched. Is the target running and reachable?", file=sys.stderr)

    path = write_json_report(result, args.output)
    print_summary(result, report_path=str(path))

    # Phase 3 (opt-in): LLM triage of the findings. Imported lazily so a plain
    # scan never loads the triage code or its optional dependencies.
    if args.triage:
        from scanner.reporting.json_report import build_report
        from scanner.triage.runner import run_triage
        run_triage(
            build_report(result), args.output,
            provider_name=args.llm_provider, model=args.llm_model,
        )

    return EXIT_OK
