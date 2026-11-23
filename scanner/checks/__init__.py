"""Registry of all passive checks.

To add a check: write a class in its own module and add it to one of the
lists below. The scanner core runs everything listed here.
"""

from scanner.checks.cookies import CookieFlagsCheck
from scanner.checks.disclosure import TechDisclosureCheck
from scanner.checks.headers import SecurityHeadersCheck
from scanner.checks.sensitive_paths import RobotsDisclosureCheck, SensitivePathsCheck


def response_checks():
    """Checks that inspect every response the crawler receives."""
    return [SecurityHeadersCheck(), CookieFlagsCheck(), TechDisclosureCheck()]


def site_checks(probe_sensitive_paths: bool = True):
    """Checks that run once per target after the crawl."""
    checks = [RobotsDisclosureCheck()]
    if probe_sensitive_paths:
        checks.append(SensitivePathsCheck())
    return checks
