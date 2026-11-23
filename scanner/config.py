"""Scan configuration.

All tunable knobs live in one dataclass so that every module receives the
same settings object instead of a long list of arguments. The CLI builds a
ScanConfig from command-line flags; tests can build one directly.
"""

from dataclasses import dataclass, field

from scanner import __version__


@dataclass
class ScanConfig:
    start_url: str

    # --- Crawl limits -------------------------------------------------------
    # Hard caps stop the crawler from running forever on sites with
    # infinite URL spaces (calendars, paginated search, session IDs in URLs).
    max_pages: int = 50
    max_depth: int = 3

    # --- Politeness ---------------------------------------------------------
    # Minimum seconds between two requests. 1 request/second is a common,
    # conservative default that no reasonable server will notice. If the
    # site's robots.txt asks for a larger Crawl-delay, the larger value wins.
    delay: float = 1.0
    timeout: float = 10.0
    respect_robots: bool = True

    # Identify ourselves honestly so the site owner can recognise the traffic
    # in their logs. Never pretend to be a normal browser.
    user_agent: str = f"webvuln-scanner/{__version__} (authorized security testing)"

    # --- Checks -------------------------------------------------------------
    probe_sensitive_paths: bool = True

    # Active (intrusive) checks. OFF by default. They only run when the user
    # passes BOTH --i-have-permission and --active, so the intrusive tests are
    # behind a second, explicit opt-in.
    active_checks: bool = False
    # Extra endpoints to feed the active checks, from --urls. See scanner/targets.py.
    seed_urls: list = field(default_factory=list)

    # Set to False only for your own apps that use self-signed certificates.
    verify_tls: bool = True

    # Never read more than this many bytes of a body. Protects us from
    # accidentally downloading a 5 GB backup file we just discovered.
    max_body_bytes: int = 2 * 1024 * 1024
